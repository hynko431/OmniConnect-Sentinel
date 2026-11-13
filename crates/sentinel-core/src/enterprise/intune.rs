use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use tracing::info;
#[cfg(not(windows))]
use tracing::warn;

use sentinel_sys::{
    read_registry_string, sign_ecdsa_p256_with_private_blob, verify_ecdsa_p256_digest,
};

use crate::enterprise::ledger::AuditLedger;
use crate::error::{DegradationEvent, SentinelError};

const SENTINEL_POLICY_REG_SUBKEY: &str = r"SOFTWARE\Policies\OmniConnect\Sentinel";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntuneMdmPolicy {
    pub policy_id: String,
    pub version: u32,
    pub enforce_usb_zero_trust: bool,
    pub block_composite_hid_storage: bool,
    pub require_cdr_for_documents: bool,
    pub max_sanitization_file_size_mb: u32,
    pub allowed_hardware_ids: Vec<String>,
    pub enforcement_mode: String,
}

impl Default for IntuneMdmPolicy {
    fn default() -> Self {
        Self {
            policy_id: "MDM-POL-SENTINEL-ZERO-TRUST-001".to_string(),
            version: 2,
            enforce_usb_zero_trust: true,
            block_composite_hid_storage: true,
            require_cdr_for_documents: true,
            max_sanitization_file_size_mb: 50,
            allowed_hardware_ids: vec![
                "USB\\VID_0781&*".to_string(), // SanDisk Enterprise
                "USB\\VID_0951&*".to_string(), // Kingston IronKey
            ],
            enforcement_mode: "ENFORCE_STRICT".to_string(),
        }
    }
}

impl IntuneMdmPolicy {
    /// Produces a strict fail-closed lockdown policy (`CSE-03`, `T28`).
    pub fn fail_closed_lockdown() -> Self {
        Self {
            policy_id: "MDM-POL-SENTINEL-FAIL-CLOSED-LOCKDOWN".to_string(),
            version: 0,
            enforce_usb_zero_trust: true,
            block_composite_hid_storage: true,
            require_cdr_for_documents: true,
            max_sanitization_file_size_mb: 0,
            allowed_hardware_ids: vec![],
            enforcement_mode: "LOCKDOWN_STRICT".to_string(),
        }
    }
}

/// Deterministically generates the two pinned enterprise root public keys (Primary & DR Backup).
pub fn default_enterprise_root_public_keys() -> Vec<Vec<u8>> {
    let seed1: [u8; 32] =
        Sha256::digest(b"OMNICONNECT-ENTERPRISE-ROOT-POLICY-CA-PRIMARY-V2").into();
    let seed2: [u8; 32] =
        Sha256::digest(b"OMNICONNECT-ENTERPRISE-ROOT-POLICY-CA-BACKUP-DR-V2").into();
    let pub1 = sentinel_sys::generate_ecdsa_p256_keypair_from_seed(&seed1)
        .map(|(pk, _)| pk)
        .unwrap_or_default();
    let pub2 = sentinel_sys::generate_ecdsa_p256_keypair_from_seed(&seed2)
        .map(|(pk, _)| pk)
        .unwrap_or_default();
    vec![pub1, pub2]
}

/// Generates the Primary enterprise root signing keypair.
pub fn primary_enterprise_root_keypair() -> (Vec<u8>, Vec<u8>) {
    let seed: [u8; 32] = Sha256::digest(b"OMNICONNECT-ENTERPRISE-ROOT-POLICY-CA-PRIMARY-V2").into();
    sentinel_sys::generate_ecdsa_p256_keypair_from_seed(&seed).unwrap_or_default()
}

/// Generates the Backup DR enterprise root signing keypair.
pub fn backup_enterprise_root_keypair() -> (Vec<u8>, Vec<u8>) {
    let seed: [u8; 32] =
        Sha256::digest(b"OMNICONNECT-ENTERPRISE-ROOT-POLICY-CA-BACKUP-DR-V2").into();
    sentinel_sys::generate_ecdsa_p256_keypair_from_seed(&seed).unwrap_or_default()
}

/// Cryptographically Signed Policy Bundle (`Rows 186, 198`, Master Plan v2 §4.4 & §5.1)
///
/// Signs the canonical policy fields with an asymmetric ECDSA P-256 keypair and enforces
/// monotonic versioning (`new_version > current_version`) to block policy downgrade attacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPolicyBundle {
    pub policy: IntuneMdmPolicy,
    pub signature_hex: String,
    pub signer_public_key_hex: String,
}

impl SignedPolicyBundle {
    /// Computes the canonical 32-byte SHA-256 digest over `IntuneMdmPolicy`.
    pub fn signing_digest(policy: &IntuneMdmPolicy) -> Result<[u8; 32], String> {
        let canonical = serde_json::to_vec(policy)
            .map_err(|e| format!("Failed serializing policy for digest: {e}"))?;
        let mut hasher = Sha256::new();
        hasher.update(b"SENTINEL-MDM-POLICY-V2:");
        hasher.update(&canonical);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    /// Signs `policy` with the provided ECDSA P-256 private key blob.
    pub fn sign(
        policy: IntuneMdmPolicy,
        private_key_blob: &[u8],
        public_key_blob: &[u8],
    ) -> Result<Self, String> {
        let digest = Self::signing_digest(&policy)?;
        let sig_bytes = sign_ecdsa_p256_with_private_blob(private_key_blob, &digest)
            .map_err(|e| format!("Failed signing IntuneMdmPolicy with ECDSA P-256: {e}"))?;
        Ok(Self {
            policy,
            signature_hex: hex::encode(sig_bytes),
            signer_public_key_hex: hex::encode(public_key_blob),
        })
    }

    /// Verifies the bundle's ECDSA P-256 signature against `trusted_public_key`.
    pub fn verify_signature(&self, trusted_public_key: &[u8]) -> Result<(), SentinelError> {
        let digest =
            Self::signing_digest(&self.policy).map_err(SentinelError::PolicySignatureInvalid)?;
        let sig_bytes = hex::decode(&self.signature_hex).map_err(|e| {
            SentinelError::PolicySignatureInvalid(format!(
                "Invalid policy signature hex encoding: {e}"
            ))
        })?;
        let verified =
            verify_ecdsa_p256_digest(trusted_public_key, &digest, &sig_bytes).map_err(|e| {
                SentinelError::PolicySignatureInvalid(format!(
                    "ECDSA P-256 policy signature verification error: {e}"
                ))
            })?;
        if !verified {
            return Err(SentinelError::PolicySignatureInvalid(format!(
                "ECDSA P-256 signature invalid for policy '{}' (version {})",
                self.policy.policy_id, self.policy.version
            )));
        }
        Ok(())
    }
}

/// Microsoft Intune MDM Policy Manager (`BUG-CORE-08`, `BUG-CORE-13`, `EV-03`, `Rows 23, 161, 162, 186, 198`, Phase 4.1 & 4.4)
pub struct IntunePolicyManager {
    policy: IntuneMdmPolicy,
    ledger_path: PathBuf,
    vault_dir: PathBuf,
    pinned_root_public_keys: Vec<Vec<u8>>,
    last_degradation_event: Option<DegradationEvent>,
}

impl Default for IntunePolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IntunePolicyManager {
    pub fn new() -> Self {
        Self {
            policy: IntuneMdmPolicy::default(),
            ledger_path: default_policy_ledger_path(),
            vault_dir: PathBuf::from(".sentinel_vault"),
            pinned_root_public_keys: default_enterprise_root_public_keys(),
            last_degradation_event: None,
        }
    }

    pub fn with_policy(policy: IntuneMdmPolicy) -> Self {
        Self {
            policy,
            ledger_path: default_policy_ledger_path(),
            vault_dir: PathBuf::from(".sentinel_vault"),
            pinned_root_public_keys: default_enterprise_root_public_keys(),
            last_degradation_event: None,
        }
    }

    pub fn with_ledger_path(mut self, ledger_path: PathBuf) -> Self {
        self.ledger_path = ledger_path;
        self
    }

    pub fn with_vault_dir(mut self, vault_dir: PathBuf) -> Self {
        self.vault_dir = vault_dir;
        self.ledger_path = self.vault_dir.join("policy_audit_ledger_v2.jsonl");
        self
    }

    pub fn with_pinned_root_public_keys(mut self, keys: Vec<Vec<u8>>) -> Self {
        self.pinned_root_public_keys = keys;
        self
    }

    pub fn policy(&self) -> &IntuneMdmPolicy {
        &self.policy
    }

    pub fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    pub fn pinned_root_public_keys(&self) -> &[Vec<u8>] {
        &self.pinned_root_public_keys
    }

    pub fn last_degradation_event(&self) -> Option<DegradationEvent> {
        self.last_degradation_event
    }

    /// Enforces immediate Ring 3 fail-closed hardware lockdown on policy tampering or signature rejection.
    pub fn fail_closed_lockdown(&mut self) {
        self.policy = IntuneMdmPolicy::fail_closed_lockdown();
        self.last_degradation_event = Some(DegradationEvent::PolicyRejected);

        let _ = sentinel_sys::set_automount_disabled(true);
        let _ = sentinel_sys::apply_autoplay_suppression_policy();

        let _ = self.record_ledger_event(
            "POLICY_LOCKDOWN_ENGAGED",
            serde_json::json!({
                "reason": "signature_tamper_or_rollback_detected",
                "enforcement_mode": "LOCKDOWN_STRICT",
                "zero_trust": true,
                "allowed_hardware_ids": [],
            }),
        );
    }

    /// Reads the highest applied policy version sequence from sealed vault storage.
    /// Returns `Err` if the file exists but has been corrupted or tampered with.
    pub fn load_sealed_version(&self) -> Result<u32, SentinelError> {
        let path = self.vault_dir.join("policy_version.sealed");
        if !path.exists() {
            return Ok(self.policy.version);
        }
        let data = std::fs::read(&path).map_err(|e| {
            SentinelError::PolicySignatureInvalid(format!(
                "Failed reading sealed policy version floor: {e}"
            ))
        })?;
        let sealed_blob: sentinel_sys::SealedKeyBlob =
            serde_json::from_slice(&data).map_err(|e| {
                SentinelError::PolicySignatureInvalid(format!(
                    "Corrupted sealed policy version JSON (integrity violation): {e}"
                ))
            })?;
        let unsealed =
            sentinel_sys::unseal_key_bytes(&sealed_blob, b"SENTINEL-POLICY-ROLLBACK-GUARD")
                .map_err(|e| {
                    SentinelError::PolicySignatureInvalid(format!(
                "Cryptographic unseal failure for policy version floor (tampering detected): {e}"
            ))
                })?;
        if unsealed.len() < 4 {
            return Err(SentinelError::PolicySignatureInvalid(
                "Truncated sealed policy version payload".to_string(),
            ));
        }
        Ok(u32::from_le_bytes([
            unsealed[0],
            unsealed[1],
            unsealed[2],
            unsealed[3],
        ]))
    }

    /// Atomically seals the newly applied policy version sequence into vault storage.
    pub fn persist_sealed_version(&self, version: u32) -> Result<(), SentinelError> {
        let raw = version.to_le_bytes();
        let sealed_blob = sentinel_sys::seal_key_bytes(
            &raw,
            b"SENTINEL-POLICY-ROLLBACK-GUARD",
            "policy_rollback_guard",
        )
        .map_err(|e| {
            SentinelError::PolicySignatureInvalid(format!("Failed sealing policy version: {e}"))
        })?;
        let serialized = serde_json::to_vec_pretty(&sealed_blob).map_err(|e| {
            SentinelError::PolicySignatureInvalid(format!(
                "Failed serializing sealed policy version: {e}"
            ))
        })?;
        let path = self.vault_dir.join("policy_version.sealed");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        sentinel_sys::write_protected_key_file(&path, &serialized).map_err(|e| {
            SentinelError::PolicySignatureInvalid(format!(
                "Failed atomically writing protected sealed policy version: {e}"
            ))
        })?;
        Ok(())
    }

    /// Verifies the ECDSA P-256 signature and strict monotonic version (`bundle.policy.version > active_floor`)
    /// before activating `bundle.policy`. On failure, retains the last known good policy (`Row 198`),
    /// records `DegradationEvent::PolicyRejected` (`POLICY_REJECTED`) to `AuditLedger`, triggers
    /// `fail_closed_lockdown()`, and returns `Err(SentinelError::PolicySignatureInvalid)`.
    pub fn apply_signed_policy(
        &mut self,
        bundle: &SignedPolicyBundle,
        trusted_public_key: &[u8],
    ) -> Result<IntuneMdmPolicy, SentinelError> {
        // 1. Verify trusted_public_key matches one of the pinned enterprise roots via constant-time comparison
        let is_pinned = self.pinned_root_public_keys.iter().any(|pk| {
            pk.len() == trusted_public_key.len() && bool::from(pk.ct_eq(trusted_public_key))
        });
        if !is_pinned {
            self.last_degradation_event = Some(DegradationEvent::PolicyRejected);
            let _ = self.record_ledger_event(
                "POLICY_TAMPER_REJECTED",
                serde_json::json!({
                    "reason": "unauthorized_root_key",
                    "candidate_policy_id": bundle.policy.policy_id,
                    "candidate_version": bundle.policy.version,
                    "retained_version": self.policy.version,
                }),
            );
            return Err(SentinelError::PolicySignatureInvalid(
                "Signer public key is not an authorized enterprise root key".to_string(),
            ));
        }

        // 2. Verify bundle's embedded signer key matches trusted_public_key
        let envelope_pub = hex::decode(&bundle.signer_public_key_hex).map_err(|e| {
            self.last_degradation_event = Some(DegradationEvent::PolicyRejected);
            SentinelError::PolicySignatureInvalid(format!("Malformed signer_public_key_hex: {e}"))
        })?;
        if envelope_pub.len() != trusted_public_key.len()
            || !bool::from(envelope_pub.ct_eq(trusted_public_key))
        {
            self.last_degradation_event = Some(DegradationEvent::PolicyRejected);
            let _ = self.record_ledger_event(
                "POLICY_TAMPER_REJECTED",
                serde_json::json!({
                    "reason": "envelope_key_mismatch",
                    "candidate_policy_id": bundle.policy.policy_id,
                    "retained_version": self.policy.version,
                }),
            );
            return Err(SentinelError::PolicySignatureInvalid(
                "Signer key in envelope does not match trusted public key".to_string(),
            ));
        }

        // 3. Cryptographic signature check
        if let Err(sig_err) = bundle.verify_signature(trusted_public_key) {
            self.last_degradation_event = Some(DegradationEvent::PolicyRejected);
            let _ = self.record_ledger_event(
                DegradationEvent::PolicyRejected.event_code(),
                serde_json::json!({
                    "reason": "signature_invalid",
                    "candidate_policy_id": bundle.policy.policy_id,
                    "candidate_version": bundle.policy.version,
                    "retained_version": self.policy.version,
                    "error": sig_err.to_string(),
                }),
            );
            return Err(sig_err);
        }

        // 4. Strict monotonic version check against active version and sealed floor
        let sealed_floor = match self.load_sealed_version() {
            Ok(v) => v,
            Err(e) => {
                self.fail_closed_lockdown();
                return Err(SentinelError::PolicySignatureInvalid(format!(
                    "Policy vault integrity compromised (sealed version check failed): {e}"
                )));
            }
        };
        let active_floor = std::cmp::max(self.policy.version, sealed_floor);
        if bundle.policy.version <= active_floor {
            self.last_degradation_event = Some(DegradationEvent::PolicyRejected);
            let err = SentinelError::PolicySignatureInvalid(format!(
                "Policy rollback rejected: candidate version {} <= active floor {}",
                bundle.policy.version, active_floor
            ));
            let _ = self.record_ledger_event(
                DegradationEvent::PolicyRejected.event_code(),
                serde_json::json!({
                    "reason": "monotonic_version_rollback",
                    "candidate_policy_id": bundle.policy.policy_id,
                    "candidate_version": bundle.policy.version,
                    "retained_version": self.policy.version,
                    "active_floor": active_floor,
                    "error": err.to_string(),
                }),
            );
            return Err(err);
        }

        // 5. Persist sealed version counter
        self.persist_sealed_version(bundle.policy.version)?;

        let previous_version = self.policy.version;
        self.record_ledger_event(
            "POLICY_UPDATED",
            serde_json::json!({
                "policy_id": bundle.policy.policy_id,
                "previous_version": previous_version,
                "new_version": bundle.policy.version,
                "enforcement_mode": bundle.policy.enforcement_mode,
            }),
        )
        .map_err(SentinelError::PolicySignatureInvalid)?;

        self.policy = bundle.policy.clone();
        self.last_degradation_event = None;

        Ok(self.policy.clone())
    }

    /// Verifies and applies a signed policy bundle by finding a matching key in `self.pinned_root_public_keys`.
    pub fn apply_signed_bundle(
        &mut self,
        bundle: &SignedPolicyBundle,
    ) -> Result<IntuneMdmPolicy, SentinelError> {
        let envelope_pub = hex::decode(&bundle.signer_public_key_hex).map_err(|e| {
            self.fail_closed_lockdown();
            SentinelError::PolicySignatureInvalid(format!("Malformed signer_public_key_hex: {e}"))
        })?;

        let matched = self
            .pinned_root_public_keys
            .iter()
            .find(|pk| pk.len() == envelope_pub.len() && bool::from(pk.ct_eq(&envelope_pub)))
            .cloned();

        match matched {
            Some(pk) => self.apply_signed_policy(bundle, &pk),
            None => {
                self.fail_closed_lockdown();
                let _ = self.record_ledger_event(
                    "POLICY_TAMPER_REJECTED",
                    serde_json::json!({
                        "reason": "self_signed_or_untrusted_root",
                        "candidate_policy_id": bundle.policy.policy_id,
                        "signer_key": bundle.signer_public_key_hex,
                    }),
                );
                Err(SentinelError::PolicySignatureInvalid(
                    "Policy signed by untrusted or self-signed key".to_string(),
                ))
            }
        }
    }

    /// Queries OS MDM policy store (signed `/etc/omniconnect/policy.json` on Unix or
    /// `HKLM\SOFTWARE\Policies\OmniConnect\Sentinel\SignedPolicyBundleJson` on Windows)
    /// to load signed enterprise policy bundles (`BUG-CORE-13`, `Row 162`).
    /// All unsigned fallbacks are strictly deleted.
    pub fn load_active_policy(&mut self) -> IntuneMdmPolicy {
        info!("Querying OS MDM policy store...");

        if let Err(e) = self.load_sealed_version() {
            #[cfg(not(windows))]
            warn!("Corrupted policy vault detected during active policy load: {e}");
            #[cfg(windows)]
            tracing::warn!("Corrupted policy vault detected during active policy load: {e}");
            self.fail_closed_lockdown();
            return self.policy.clone();
        }

        #[cfg(not(windows))]
        {
            let linux_policy_path = Path::new("/etc/omniconnect/policy.json");
            if linux_policy_path.exists() {
                match std::fs::read_to_string(linux_policy_path) {
                    Ok(raw_json) => match serde_json::from_str::<SignedPolicyBundle>(&raw_json) {
                        Ok(bundle) => {
                            if let Err(e) = self.apply_signed_bundle(&bundle) {
                                warn!("Rejected /etc/omniconnect/policy.json bundle: {}", e);
                                self.fail_closed_lockdown();
                            }
                        }
                        Err(e) => {
                            warn!("Invalid /etc/omniconnect/policy.json format (unsigned policies rejected): {}", e);
                            self.fail_closed_lockdown();
                        }
                    },
                    Err(e) => {
                        warn!("Failed reading /etc/omniconnect/policy.json: {}", e);
                        self.fail_closed_lockdown();
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            if let Some(bundle_json) =
                read_registry_string(SENTINEL_POLICY_REG_SUBKEY, "SignedPolicyBundleJson")
            {
                match serde_json::from_str::<SignedPolicyBundle>(&bundle_json) {
                    Ok(bundle) => {
                        if let Err(e) = self.apply_signed_bundle(&bundle) {
                            tracing::warn!("Rejected HKLM signed policy bundle: {}", e);
                            self.fail_closed_lockdown();
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Invalid SignedPolicyBundleJson in registry: {}", e);
                        self.fail_closed_lockdown();
                    }
                }
            }
        }

        let _ = self.record_ledger_event(
            "POLICY_LOADED",
            serde_json::json!({
                "policy_id": self.policy.policy_id,
                "version": self.policy.version,
                "enforcement_mode": self.policy.enforcement_mode,
            }),
        );

        self.policy.clone()
    }

    fn record_ledger_event(
        &self,
        event_type: &str,
        details: serde_json::Value,
    ) -> Result<(), String> {
        let mut ledger = AuditLedger::open(&self.ledger_path);
        ledger.append_event(event_type, details).map(|_| ())
    }

    /// Escapes XML special characters (`&`, `<`, `>`, `"`, `'`) to prevent malformed XML
    /// and OMA-URI SyncML tag injection (`BUG-CORE-08`, `EV-03`).
    pub fn xml_escape(raw: &str) -> String {
        let mut escaped = String::with_capacity(raw.len() + 16);
        for c in raw.chars() {
            match c {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&apos;"),
                _ => escaped.push(c),
            }
        }
        escaped
    }

    /// Alias for `xml_escape`.
    pub fn escape_xml(raw: &str) -> String {
        Self::xml_escape(raw)
    }

    /// Exports a well-formed OMA-URI SyncML XML profile with all dynamic values XML-escaped (`BUG-CORE-08`, `Row 161`).
    pub fn export_oma_uri_profile_xml(&self) -> String {
        let raw_hw_ids = self.policy.allowed_hardware_ids.join(";");
        let escaped_hw_ids = Self::xml_escape(&raw_hw_ids);
        let escaped_policy_id = Self::xml_escape(&self.policy.policy_id);
        let escaped_mode = Self::xml_escape(&self.policy.enforcement_mode);

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- OmniConnect Sentinel - Microsoft Intune OMA-URI SyncML Configuration Profile -->
<SyncBody>
  <Replace>
    <CmdID>1</CmdID>
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnectSentinel/PolicyId</LocURI>
      </Target>
      <Meta>
        <Format xmlns="syncml:metinf">chr</Format>
      </Meta>
      <Data>{}</Data>
    </Item>
  </Replace>
  <Replace>
    <CmdID>2</CmdID>
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnectSentinel/BlockCompositeHidStorage</LocURI>
      </Target>
      <Meta>
        <Format xmlns="syncml:metinf">bool</Format>
      </Meta>
      <Data>{}</Data>
    </Item>
  </Replace>
  <Replace>
    <CmdID>3</CmdID>
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnectSentinel/EnforceStrictCdr</LocURI>
      </Target>
      <Meta>
        <Format xmlns="syncml:metinf">bool</Format>
      </Meta>
      <Data>{}</Data>
    </Item>
  </Replace>
  <Replace>
    <CmdID>4</CmdID>
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnectSentinel/AllowedHardwareIds</LocURI>
      </Target>
      <Meta>
        <Format xmlns="syncml:metinf">chr</Format>
      </Meta>
      <Data>{}</Data>
    </Item>
  </Replace>
  <Replace>
    <CmdID>5</CmdID>
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnectSentinel/EnforcementMode</LocURI>
      </Target>
      <Meta>
        <Format xmlns="syncml:metinf">chr</Format>
      </Meta>
      <Data>{}</Data>
    </Item>
  </Replace>
</SyncBody>"#,
            escaped_policy_id,
            self.policy.block_composite_hid_storage,
            self.policy.require_cdr_for_documents,
            escaped_hw_ids,
            escaped_mode
        )
    }
}

fn default_policy_ledger_path() -> PathBuf {
    #[cfg(windows)]
    {
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        let dir = PathBuf::from(pd).join("OmniConnect").join("Sentinel");
        if sentinel_sys::create_restricted_dir_atomic(&dir).is_ok() {
            return dir.join("policy_audit_ledger_v2.jsonl");
        }
    }
    #[cfg(not(windows))]
    {
        let dir = PathBuf::from("/var/lib/omniconnect/sentinel");
        if sentinel_sys::create_restricted_dir_atomic(&dir).is_ok() {
            return dir.join("policy_audit_ledger_v2.jsonl");
        }
    }
    #[cfg(test)]
    {
        std::env::temp_dir()
            .join("omniconnect_sentinel_policy")
            .join("policy_audit_ledger_v2.jsonl")
    }
    #[cfg(not(test))]
    {
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\ProgramData\OmniConnect\Sentinel\policy_audit_ledger_v2.jsonl")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/var/lib/omniconnect/sentinel/policy_audit_ledger_v2.jsonl")
        }
    }
}
