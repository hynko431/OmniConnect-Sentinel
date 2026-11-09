use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::info;
#[cfg(not(windows))]
use tracing::warn;

use sentinel_sys::{
    read_registry_dword, read_registry_string, sign_ecdsa_p256_with_private_blob,
    verify_ecdsa_p256_digest,
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
            last_degradation_event: None,
        }
    }

    pub fn with_policy(policy: IntuneMdmPolicy) -> Self {
        Self {
            policy,
            ledger_path: default_policy_ledger_path(),
            last_degradation_event: None,
        }
    }

    pub fn with_ledger_path(mut self, ledger_path: PathBuf) -> Self {
        self.ledger_path = ledger_path;
        self
    }

    pub fn policy(&self) -> &IntuneMdmPolicy {
        &self.policy
    }

    pub fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    pub fn last_degradation_event(&self) -> Option<DegradationEvent> {
        self.last_degradation_event
    }

    /// Verifies the ECDSA P-256 signature and strict monotonic version (`bundle.policy.version > self.policy.version`)
    /// before activating `bundle.policy`. On failure, retains the last known good policy (`Row 198`),
    /// records `DegradationEvent::PolicyRejected` (`POLICY_REJECTED`) to `AuditLedger`, and returns
    /// `Err(SentinelError::PolicySignatureInvalid)`.
    pub fn apply_signed_policy(
        &mut self,
        bundle: &SignedPolicyBundle,
        trusted_public_key: &[u8],
    ) -> Result<IntuneMdmPolicy, SentinelError> {
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

        if bundle.policy.version <= self.policy.version {
            let err = SentinelError::PolicySignatureInvalid(format!(
                "Policy rollback rejected: candidate version {} <= active version {}",
                bundle.policy.version, self.policy.version
            ));
            self.last_degradation_event = Some(DegradationEvent::PolicyRejected);
            let _ = self.record_ledger_event(
                DegradationEvent::PolicyRejected.event_code(),
                serde_json::json!({
                    "reason": "monotonic_version_rollback",
                    "candidate_policy_id": bundle.policy.policy_id,
                    "candidate_version": bundle.policy.version,
                    "retained_version": self.policy.version,
                    "error": err.to_string(),
                }),
            );
            return Err(err);
        }

        let previous_version = self.policy.version;
        self.policy = bundle.policy.clone();
        self.last_degradation_event = None;

        self.record_ledger_event(
            "POLICY_UPDATED",
            serde_json::json!({
                "policy_id": self.policy.policy_id,
                "previous_version": previous_version,
                "new_version": self.policy.version,
                "enforcement_mode": self.policy.enforcement_mode,
            }),
        )
        .map_err(SentinelError::PolicySignatureInvalid)?;

        Ok(self.policy.clone())
    }

    /// Queries `HKLM\SOFTWARE\Policies\OmniConnect\Sentinel` (or `/etc/omniconnect/policy.json`
    /// on Linux) via `sentinel_sys` to load live MDM/GPO overrides (`BUG-CORE-13`, `Row 162`).
    pub fn load_active_policy(&mut self) -> IntuneMdmPolicy {
        info!(
            "Querying OS MDM policy store (HKLM\\{})...",
            SENTINEL_POLICY_REG_SUBKEY
        );

        #[cfg(not(windows))]
        {
            let linux_policy_path = Path::new("/etc/omniconnect/policy.json");
            if let Ok(raw_json) = std::fs::read_to_string(linux_policy_path) {
                if let Ok(parsed_bundle) = serde_json::from_str::<SignedPolicyBundle>(&raw_json) {
                    if let Ok(pub_bytes) = hex::decode(&parsed_bundle.signer_public_key_hex) {
                        if let Err(e) = self.apply_signed_policy(&parsed_bundle, &pub_bytes) {
                            warn!("Rejected /etc/omniconnect/policy.json bundle: {}", e);
                        }
                    }
                } else if let Ok(parsed_policy) = serde_json::from_str::<IntuneMdmPolicy>(&raw_json)
                {
                    if parsed_policy.version >= self.policy.version {
                        self.policy = parsed_policy;
                    }
                }
            }
        }

        if let Some(val) =
            read_registry_dword(false, SENTINEL_POLICY_REG_SUBKEY, "EnforceUsbZeroTrust")
        {
            self.policy.enforce_usb_zero_trust = val != 0;
        }
        if let Some(val) = read_registry_dword(
            false,
            SENTINEL_POLICY_REG_SUBKEY,
            "BlockCompositeHidStorage",
        ) {
            self.policy.block_composite_hid_storage = val != 0;
        }
        if let Some(val) =
            read_registry_dword(false, SENTINEL_POLICY_REG_SUBKEY, "EnforceStrictCdr")
        {
            self.policy.require_cdr_for_documents = val != 0;
        }
        if let Some(val) = read_registry_dword(false, SENTINEL_POLICY_REG_SUBKEY, "MaxCdrSizeMb") {
            if val > 0 && val <= 2048 {
                self.policy.max_sanitization_file_size_mb = val;
            }
        }
        if let Some(hw_ids) = read_registry_string(SENTINEL_POLICY_REG_SUBKEY, "AllowedHardwareIds")
        {
            let parsed: Vec<String> = hw_ids
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !parsed.is_empty() {
                self.policy.allowed_hardware_ids = parsed;
            }
        }
        if let Some(mode) = read_registry_string(SENTINEL_POLICY_REG_SUBKEY, "EnforcementMode") {
            if !mode.trim().is_empty() {
                self.policy.enforcement_mode = mode.trim().to_string();
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
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir.join("policy_audit_ledger_v2.jsonl");
        }
    }
    std::env::temp_dir()
        .join("omniconnect_sentinel_policy")
        .join("policy_audit_ledger_v2.jsonl")
}
