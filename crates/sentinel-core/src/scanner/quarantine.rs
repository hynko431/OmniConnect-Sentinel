use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

use sentinel_sys::{
    create_restricted_dir_atomic, create_restricted_file_handle_atomic,
    decrypt_kek_from_soc_escrow, default_soc_rsa_public_blob, encrypt_kek_for_soc_escrow,
    seal_key_bytes, sync_directory, to_verbatim_path, unseal_key_bytes, write_protected_key_file,
    zeroize_slice, KeyProtectionPosture, SealedKeyBlob, SocEscrowBlob, ZeroizingBytes,
};

use crate::enterprise::ledger::{AuditLedger, AuditSubsystem, SharedAuditLedger};
use crate::error::{DegradationEvent, SentinelError};
use crate::scanner::secure_shredder::{SecureShredder, ShredMethod};

pub const ENVELOPE_MAGIC_V2_FULL: &[u8; 8] = b"SNTLQV02";
pub const ENVELOPE_VERSION: u16 = 2;
pub const HKDF_INFO_QUARANTINE_V2: &[u8] = b"OMNICONNECT_SENTINEL_QUARANTINE_V2";
const SEALED_KEK_FILENAME: &str = "vault_kek.sealed";
const ESCROW_KEK_FILENAME: &str = "vault_kek.escrow";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegacyMigrationAction {
    /// Keep legacy key-less `.quar` files as inert ciphertext and mark them `UNRECOVERABLE_LEGACY`
    Keep,
    /// Cryptographically shred and remove legacy key-less `.quar` files after recording in the ledger
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineEntry {
    pub entry_id: String,
    pub kek_id: String,
    pub original_path: String,
    pub original_sha256: String,
    pub original_size_bytes: u64,
    pub vault_file_path: String,
    pub threat_reason: String,
    pub threat_score: u8,
    pub quarantined_at_utc: String,
    pub quarantined_at_unix: u64,
    pub encryption_algorithm: String,
    pub nonce_hex: String,
    pub recovery_status: String,
}

/// Authenticated Quarantine Envelope Header (`Master Plan v2 §1.1 #4`).
///
/// Exact binary file layout on disk: `[header_len: u32 LE][header JSON][ciphertext]`.
/// The serialized `header JSON` bytes are bound as the AES-256-GCM AEAD Associated Data (AAD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEnvelopeHeader {
    #[serde(default = "default_header_magic")]
    pub magic: [u8; 8],
    pub version: u16,
    pub kek_id: String,
    pub file_salt: [u8; 32],
    pub nonce: [u8; 12],
    pub original_path: String,
    #[serde(alias = "original_size_bytes")]
    pub original_size: u64,
    #[serde(alias = "original_sha256")]
    pub sha256_plaintext: String,
    #[serde(alias = "threat_reason")]
    pub threat_name: String,
    #[serde(default = "default_threat_score")]
    pub threat_score: u8,
    pub quarantined_at_unix: u64,
    #[serde(default)]
    pub entry_id: String,
    #[serde(default)]
    pub quarantined_at_utc: String,
    #[serde(default = "default_recovery_status")]
    pub recovery_status: String,
}

fn default_header_magic() -> [u8; 8] {
    *ENVELOPE_MAGIC_V2_FULL
}

fn default_threat_score() -> u8 {
    95
}

fn default_recovery_status() -> String {
    "RECOVERABLE".to_string()
}

/// Cryptographic Quarantine Vault (`BUG-CORE-02`, `BUG-CLI-01`, `ADR-005`, Phase 1.1)
///
/// - Protects the 256-bit Master KEK via TPM 2.0 PCP RSA-2048 OAEP (`MS_PLATFORM_CRYPTO_PROVIDER`),
///   falling back to DPAPI `CRYPTPROTECT_LOCAL_MACHINE` with `DegradationEvent::PostureReducedNoTpm`.
/// - Asymmetrically escrows the Master KEK to an offline SOC RSA-2048 public key (`vault_kek.escrow`)
///   via CNG `BCryptEncrypt(BCRYPT_PAD_OAEP)` so recovery survives total hardware failure.
/// - Fails closed (`VAULT_INTEGRITY_FAIL`) if `vault_kek.sealed` exists on disk and cannot be unsealed —
///   never silently regenerating or overwriting an existing KEK.
/// - Derives per-file wrapping keys via `HKDF-SHA256(KEK, file_salt, "OMNICONNECT_SENTINEL_QUARANTINE_V2")`
///   and stores a wrapped per-entry DEK (`<entry_id>.dek`) so `purge()` performs true cryptographic erasure.
pub struct QuarantineVault {
    vault_dir: PathBuf,
    master_kek: ZeroizingBytes<32>,
    kek_id: String,
    posture: KeyProtectionPosture,
    degradation_event: Option<DegradationEvent>,
    init_error: Option<String>,
    shared_ledger: Option<SharedAuditLedger>,
}

impl std::fmt::Debug for QuarantineVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuarantineVault")
            .field("vault_dir", &self.vault_dir)
            .field("master_kek", &"[REDACTED]")
            .field("kek_id", &self.kek_id)
            .field("posture", &self.posture)
            .field("degradation_event", &self.degradation_event)
            .field("init_error", &self.init_error)
            .finish()
    }
}

impl QuarantineVault {
    /// Opens or provisions the Quarantine Vault, returning `Err` (`VAULT_INTEGRITY_FAIL`) if
    /// directory creation, DACL hardening, or existing KEK unsealing fails.
    pub fn open(vault_dir: PathBuf) -> Result<Self, String> {
        let soc_pub = default_soc_rsa_public_blob();
        Self::open_with_soc_public_key(vault_dir, &soc_pub)
    }

    /// Opens or provisions the Quarantine Vault using an explicit offline SOC RSA-2048 public key blob.
    pub fn open_with_soc_public_key(
        vault_dir: PathBuf,
        soc_rsa_pub_blob: &[u8],
    ) -> Result<Self, String> {
        create_restricted_dir_atomic(&vault_dir).map_err(|e| {
            format!(
                "Failed creating quarantine vault directory {}: {}",
                vault_dir.display(),
                e
            )
        })?;

        let (master_kek, posture, degradation_event) =
            Self::load_or_init_master_kek(&vault_dir, soc_rsa_pub_blob)?;
        let kek_id = Self::compute_kek_id(master_kek.as_slice());

        Ok(Self {
            vault_dir,
            master_kek,
            kek_id,
            posture,
            degradation_event,
            init_error: None,
            shared_ledger: None,
        })
    }

    /// Attaches a unified `SharedAuditLedger` to the Quarantine Vault (`CSE-13`).
    pub fn with_shared_ledger(mut self, shared_ledger: SharedAuditLedger) -> Self {
        self.shared_ledger = Some(shared_ledger);
        self
    }

    /// Convenience constructor that preserves fail-closed semantics: if `open()` fails
    /// (for instance, because an existing `vault_kek.sealed` was tampered with), it never
    /// overwrites `vault_kek.sealed` and latches `init_error` so all vault operations fail closed
    /// with `VAULT_INTEGRITY_FAIL`.
    pub fn new(vault_dir: PathBuf) -> Self {
        match Self::open(vault_dir.clone()) {
            Ok(vault) => vault,
            Err(err) => {
                warn!("QuarantineVault initialization failed closed: {}", err);
                Self {
                    vault_dir,
                    master_kek: ZeroizingBytes::zeroed(),
                    kek_id: "INVALID-UNSEAL-FAILED".to_string(),
                    posture: KeyProtectionPosture::DpapiLocalMachine,
                    degradation_event: Some(DegradationEvent::VaultIntegrityFail),
                    init_error: Some(err),
                    shared_ledger: None,
                }
            }
        }
    }

    /// Recovers a Quarantine Vault whose host TPM/DPAPI `vault_kek.sealed` was lost or corrupted
    /// using the offline SOC RSA-2048 private key and `vault_kek.escrow` (`Master Plan v2 §1.1 #2, §5.1`).
    pub fn recover_from_soc_escrow(
        vault_dir: PathBuf,
        soc_rsa_priv_blob: &[u8],
    ) -> Result<Self, String> {
        let escrow_path = vault_dir.join(ESCROW_KEK_FILENAME);
        let raw_escrow = fs::read(&escrow_path).map_err(|e| {
            format!(
                "VAULT_INTEGRITY_FAIL: Failed reading offline SOC escrow file {}: {}",
                escrow_path.display(),
                e
            )
        })?;
        let escrow_blob: SocEscrowBlob = serde_json::from_slice(&raw_escrow)
            .map_err(|e| format!("VAULT_INTEGRITY_FAIL: Corrupted offline SOC escrow JSON: {e}"))?;

        let mut recovered_kek = decrypt_kek_from_soc_escrow(&escrow_blob, soc_rsa_priv_blob)
            .map_err(|e| {
                format!("VAULT_INTEGRITY_FAIL: Offline SOC RSA-OAEP decryption failed: {e}")
            })?;
        let computed_id = Self::compute_kek_id(&recovered_kek);
        if computed_id != escrow_blob.kek_id {
            zeroize_slice(&mut recovered_kek);
            return Err(format!(
                "VAULT_INTEGRITY_FAIL: Recovered KEK ID '{}' does not match escrow KEK ID '{}'",
                computed_id, escrow_blob.kek_id
            ));
        }

        let zeroizing = ZeroizingBytes::new(recovered_kek);
        zeroize_slice(&mut recovered_kek);

        let context = format!("OmniConnect-Sentinel-Vault:{}", vault_dir.display());
        let sealed_blob = seal_key_bytes(zeroizing.as_slice(), context.as_bytes(), &computed_id)
            .map_err(|e| format!("Failed re-sealing recovered KEK: {e}"))?;
        let posture = sealed_blob.posture;
        let degradation_event = if posture == KeyProtectionPosture::Tpm2Assisted {
            None
        } else {
            Some(DegradationEvent::PostureReducedNoTpm)
        };

        let serialized = serde_json::to_vec_pretty(&sealed_blob)
            .map_err(|e| format!("Failed serializing re-sealed KEK: {e}"))?;
        let sealed_path = vault_dir.join(SEALED_KEK_FILENAME);
        write_protected_key_file(&sealed_path, &serialized)
            .map_err(|e| format!("Failed persisting re-sealed KEK: {e}"))?;

        let vault = Self {
            vault_dir,
            master_kek: zeroizing,
            kek_id: computed_id.clone(),
            posture,
            degradation_event,
            init_error: None,
            shared_ledger: None,
        };
        vault.append_ledger_event(
            "VAULT_ESCROW_RECOVERED",
            &format!("Recovered master KEK '{computed_id}' via offline SOC RSA-2048 OAEP escrow"),
        )?;
        Ok(vault)
    }

    pub fn key_posture(&self) -> KeyProtectionPosture {
        self.posture
    }

    pub fn degradation_event(&self) -> Option<DegradationEvent> {
        self.degradation_event
    }

    pub fn kek_id(&self) -> &str {
        &self.kek_id
    }

    fn check_healthy(&self) -> Result<(), String> {
        if let Some(err) = &self.init_error {
            return Err(err.clone());
        }
        Ok(())
    }

    fn ledger_file_path(&self) -> PathBuf {
        self.vault_dir.join("vault_audit.jsonl")
    }

    fn append_ledger_event(&self, event: &str, data: &str) -> Result<(), String> {
        if let Some(shared) = &self.shared_ledger {
            if let Ok(mut guard) = shared.lock() {
                guard.append_subsystem_event(
                    AuditSubsystem::Quarantine,
                    event,
                    serde_json::Value::String(data.to_string()),
                )?;
                return Ok(());
            }
        }
        let mut ledger = AuditLedger::open_result(self.ledger_file_path())?;
        ledger.append_subsystem_event(
            AuditSubsystem::Quarantine,
            event,
            serde_json::Value::String(data.to_string()),
        )?;
        Ok(())
    }

    fn load_or_init_master_kek(
        vault_dir: &Path,
        soc_rsa_pub_blob: &[u8],
    ) -> Result<
        (
            ZeroizingBytes<32>,
            KeyProtectionPosture,
            Option<DegradationEvent>,
        ),
        String,
    > {
        let sealed_path = vault_dir.join(SEALED_KEK_FILENAME);
        let context = format!("OmniConnect-Sentinel-Vault:{}", vault_dir.display());

        // CRITICAL (#3, Row 45b, Row 197): If `vault_kek.sealed` already exists on disk,
        // NEVER overwrite or regenerate it on read/parse/unseal failure!
        if sealed_path.exists() {
            let raw_json = fs::read(&sealed_path).map_err(|e| {
                SentinelError::QuarantineIntegrityFail(format!(
                    "Failed reading existing {}: {}",
                    sealed_path.display(),
                    e
                ))
                .to_string()
            })?;
            let blob = serde_json::from_slice::<SealedKeyBlob>(&raw_json).map_err(|e| {
                SentinelError::QuarantineIntegrityFail(format!(
                    "Corrupted JSON in existing {}: {}",
                    sealed_path.display(),
                    e
                ))
                .to_string()
            })?;
            let posture = blob.posture;
            let mut unsealed = unseal_key_bytes(&blob, context.as_bytes()).map_err(|e| {
                SentinelError::QuarantineIntegrityFail(format!(
                    "Failed unsealing existing {} ({}); refusing to regenerate KEK. Use offline SOC escrow recovery.",
                    sealed_path.display(),
                    e
                ))
                .to_string()
            })?;
            if unsealed.len() != 32 {
                zeroize_slice(&mut unsealed);
                return Err(SentinelError::QuarantineIntegrityFail(
                    "Unsealed KEK length is not 32 bytes".to_string(),
                )
                .to_string());
            }
            let actual_kek_id = Self::compute_kek_id(&unsealed);
            if actual_kek_id != blob.kek_id {
                zeroize_slice(&mut unsealed);
                return Err(SentinelError::QuarantineIntegrityFail(format!(
                    "Unsealed KEK ID mismatch (expected {}, got {})",
                    blob.kek_id, actual_kek_id
                ))
                .to_string());
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&unsealed);
            zeroize_slice(&mut unsealed);
            let zeroizing = ZeroizingBytes::new(arr);
            zeroize_slice(&mut arr);

            let degradation = if posture == KeyProtectionPosture::Tpm2Assisted {
                None
            } else {
                Some(DegradationEvent::PostureReducedNoTpm)
            };
            return Ok((zeroizing, posture, degradation));
        }

        // First-time provisioning of a new Quarantine Vault
        let mut fresh_kek = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut fresh_kek);
        let zeroizing = ZeroizingBytes::new(fresh_kek);
        zeroize_slice(&mut fresh_kek);
        let kek_id = Self::compute_kek_id(zeroizing.as_slice());

        let blob = seal_key_bytes(zeroizing.as_slice(), context.as_bytes(), &kek_id)
            .map_err(|e| format!("Failed sealing new Master KEK: {e}"))?;
        let posture = blob.posture;
        let mut degradation = if posture == KeyProtectionPosture::Tpm2Assisted {
            None
        } else {
            warn!(
                "Degradation event {}: QuarantineVault KEK '{}' using {:?}",
                DegradationEvent::PostureReducedNoTpm.event_code(),
                kek_id,
                posture
            );
            Some(DegradationEvent::PostureReducedNoTpm)
        };

        let serialized = serde_json::to_vec_pretty(&blob)
            .map_err(|e| format!("Failed serializing sealed KEK blob: {e}"))?;
        write_protected_key_file(&sealed_path, &serialized)
            .map_err(|e| format!("Failed writing {}: {}", sealed_path.display(), e))?;

        // Provision offline SOC RSA-2048-OAEP recovery escrow blob (`vault_kek.escrow`, Master Plan v2 §1.1 #2)
        if soc_rsa_pub_blob.is_empty() {
            warn!(
                "Degradation event {}: QuarantineVault KEK '{}' provisioned without offline SOC RSA public key; vault_kek.escrow skipped",
                DegradationEvent::SocEscrowUnconfigured.event_code(),
                kek_id
            );
            degradation = Some(DegradationEvent::SocEscrowUnconfigured);
        } else {
            let escrow_path = vault_dir.join(ESCROW_KEK_FILENAME);
            let mut kek_arr = [0u8; 32];
            kek_arr.copy_from_slice(zeroizing.as_slice());
            let escrow_res = encrypt_kek_for_soc_escrow(&kek_arr, soc_rsa_pub_blob, &kek_id);
            zeroize_slice(&mut kek_arr);
            let escrow_blob = escrow_res
                .map_err(|e| format!("Failed encrypting Master KEK for offline SOC escrow: {e}"))?;
            let escrow_json = serde_json::to_vec_pretty(&escrow_blob)
                .map_err(|e| format!("Failed serializing SOC escrow blob: {e}"))?;
            write_protected_key_file(&escrow_path, &escrow_json)
                .map_err(|e| format!("Failed writing {}: {}", escrow_path.display(), e))?;
        }

        Ok((zeroizing, posture, degradation))
    }

    fn compute_kek_id(kek: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"SENTINEL-KEK-ID-V2:");
        hasher.update(kek);
        let digest = hex::encode(hasher.finalize());
        digest[..16].to_string()
    }

    /// RFC 5869 HMAC-SHA256 Extract-and-Expand Key Derivation Function (HKDF-SHA256)
    /// for 32-byte per-file key derivation (`HKDF-SHA256(KEK, salt_32B, "OMNICONNECT_SENTINEL_QUARANTINE_V2")`).
    fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> ZeroizingBytes<32> {
        let actual_salt = if salt.is_empty() {
            &[0u8; 32][..]
        } else {
            salt
        };
        let prk = Self::hmac_sha256(actual_salt, ikm);
        let mut expand_input = Vec::with_capacity(info.len() + 1);
        expand_input.extend_from_slice(info);
        expand_input.push(0x01);
        let okm = Self::hmac_sha256(prk.as_slice(), &expand_input);
        zeroize_slice(&mut expand_input);
        okm
    }

    fn hmac_sha256(key: &[u8], message: &[u8]) -> ZeroizingBytes<32> {
        const BLOCK_SIZE: usize = 64;
        let mut key_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let hashed = hasher.finalize();
            key_block[..32].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; BLOCK_SIZE];
        let mut opad = [0x5cu8; BLOCK_SIZE];
        for ((ip, op), &kb) in ipad.iter_mut().zip(opad.iter_mut()).zip(key_block.iter()) {
            *ip ^= kb;
            *op ^= kb;
        }
        zeroize_slice(&mut key_block);

        let mut inner = Sha256::new();
        inner.update(ipad);
        inner.update(message);
        let inner_hash = inner.finalize();
        zeroize_slice(&mut ipad);

        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner_hash);
        let final_hash = outer.finalize();
        zeroize_slice(&mut opad);

        let mut out = [0u8; 32];
        out.copy_from_slice(&final_hash);
        let res = ZeroizingBytes::new(out);
        zeroize_slice(&mut out);
        res
    }

    fn write_wrapped_entry_dek(
        &self,
        entry_id: &str,
        file_salt: &[u8; 32],
        entry_dek: &ZeroizingBytes<32>,
    ) -> Result<PathBuf, String> {
        let wrapping_key = Self::hkdf_sha256(
            self.master_kek.as_slice(),
            file_salt,
            HKDF_INFO_QUARANTINE_V2,
        );
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrapping_key.as_slice()));
        let mut wrap_nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut wrap_nonce);
        let wrapped_ct = cipher
            .encrypt(
                Nonce::from_slice(&wrap_nonce),
                Payload {
                    msg: entry_dek.as_slice(),
                    aad: entry_id.as_bytes(),
                },
            )
            .map_err(|e| format!("Failed wrapping per-entry DEK: {e}"))?;

        let mut dek_blob = Vec::with_capacity(12 + wrapped_ct.len());
        dek_blob.extend_from_slice(&wrap_nonce);
        dek_blob.extend_from_slice(&wrapped_ct);

        let dek_path = self.vault_dir.join(format!("{entry_id}.dek"));
        write_protected_key_file(&dek_path, &dek_blob).map_err(|e| {
            format!(
                "Failed persisting wrapped DEK {}: {}",
                dek_path.display(),
                e
            )
        })?;
        Ok(dek_path)
    }

    fn unwrap_entry_dek(
        &self,
        entry_id: &str,
        file_salt: &[u8; 32],
    ) -> Result<ZeroizingBytes<32>, String> {
        let dek_path = self.vault_dir.join(format!("{entry_id}.dek"));
        let dek_blob = fs::read(&dek_path).map_err(|e| {
            format!(
                "VAULT_INTEGRITY_FAIL: Wrapped DEK '{}' missing or crypto-erased: {}",
                dek_path.display(),
                e
            )
        })?;
        if dek_blob.len() < 12 + 32 + 16 {
            return Err("VAULT_INTEGRITY_FAIL: Truncated wrapped DEK file".to_string());
        }
        let wrap_nonce = &dek_blob[..12];
        let wrapped_ct = &dek_blob[12..];

        let wrapping_key = Self::hkdf_sha256(
            self.master_kek.as_slice(),
            file_salt,
            HKDF_INFO_QUARANTINE_V2,
        );
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrapping_key.as_slice()));
        let mut raw_dek = cipher
            .decrypt(
                Nonce::from_slice(wrap_nonce),
                Payload {
                    msg: wrapped_ct,
                    aad: entry_id.as_bytes(),
                },
            )
            .map_err(|_| {
                "VAULT_INTEGRITY_FAIL: Failed unwrapping per-entry DEK (AEAD tag mismatch)"
                    .to_string()
            })?;
        if raw_dek.len() != 32 {
            zeroize_slice(&mut raw_dek);
            return Err("VAULT_INTEGRITY_FAIL: Unwrapped DEK length invalid".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw_dek);
        zeroize_slice(&mut raw_dek);
        let z = ZeroizingBytes::new(arr);
        zeroize_slice(&mut arr);
        Ok(z)
    }

    /// Encrypts and isolates a file inside the Quarantine Vault using a single
    /// authenticated `.quar` envelope (`[header_len: u32 LE][header JSON][ciphertext]`),
    /// verifies the synced copy on disk (Invariant I4), and then runs `SecureShredder::shred_file`.
    pub fn quarantine_file(
        &self,
        file_path: &Path,
        threat_name: &str,
    ) -> Result<QuarantineEntry, String> {
        self.quarantine_file_with_score(file_path, threat_name, 95)
    }

    pub fn quarantine_file_with_score(
        &self,
        file_path: &Path,
        threat_name: &str,
        threat_score: u8,
    ) -> Result<QuarantineEntry, String> {
        self.check_healthy()?;

        // Check if `file_path` specifies an NTFS Alternate Data Stream `host:stream`
        let path_str = file_path.to_string_lossy();
        let without_verbatim = path_str.strip_prefix(r"\\?\").unwrap_or(&path_str);
        if without_verbatim.len() > 3 {
            if let Some(colon_rel) = without_verbatim[2..].find(':') {
                let host_part = PathBuf::from(&without_verbatim[..2 + colon_rel]);
                let stream_part = &without_verbatim[2 + colon_rel + 1..];
                if !stream_part.is_empty() {
                    return self.quarantine_ntfs_stream(
                        &host_part,
                        stream_part,
                        threat_name,
                        threat_score,
                    );
                }
            }
        }

        let mut raw_bytes = Vec::new();
        {
            let mut file = File::open(file_path)
                .map_err(|e| format!("Failed to open source file for quarantine: {e}"))?;
            file.read_to_end(&mut raw_bytes)
                .map_err(|e| format!("Failed reading file for quarantine: {e}"))?;
        }

        let entry = self.seal_bytes_into_vault(
            &raw_bytes,
            &file_path.to_string_lossy(),
            threat_name,
            threat_score,
        );
        zeroize_slice(&mut raw_bytes);
        let entry = entry?;

        // Invariant I4 (Master Plan v2 §1.1 & §5 `invariant_i4`):
        // Read the vault entry back from disk and verify its AEAD authentication tag and SHA-256
        // BEFORE removing/shredding the source file. If verification fails, abort and leave source intact.
        self.verify_entry(&entry.entry_id)?;

        // Shred the original plaintext carrier from the source volume after verifying `.quar` (`BUG-CLI-01` #2)
        // Propagate errors with `?` — never ignore shred errors!
        SecureShredder::shred_file_with_shared_ledger(
            file_path,
            ShredMethod::ClearMultiPass { passes: 3 },
            self.shared_ledger.as_ref(),
        )?;

        self.append_ledger_event(
            "QUARANTINE_CREATED",
            &format!(
                "entry_id={} path={} sha256={} threat={} score={}",
                entry.entry_id,
                entry.original_path,
                entry.original_sha256,
                threat_name,
                threat_score
            ),
        )?;

        Ok(entry)
    }

    /// Fault-injectable variant of `quarantine_file` for testing Invariant I4 (`T14`, `Row 203`):
    /// when `inject_fault_before_removal` is `true`, simulates a disk/storage corruption between
    /// `.quar` envelope creation and `verify_entry` so `verify_entry` fails closed BEFORE
    /// `SecureShredder::shred_file` is ever called, leaving `file_path` intact on disk.
    pub fn quarantine_file_with_fault_injection(
        &self,
        file_path: &Path,
        threat_name: &str,
        inject_fault_before_removal: bool,
    ) -> Result<QuarantineEntry, String> {
        if !inject_fault_before_removal {
            return self.quarantine_file(file_path, threat_name);
        }
        self.check_healthy()?;

        let mut raw_bytes = Vec::new();
        {
            let mut file = File::open(file_path)
                .map_err(|e| format!("Failed to open source file for quarantine: {e}"))?;
            file.read_to_end(&mut raw_bytes)
                .map_err(|e| format!("Failed reading file for quarantine: {e}"))?;
        }

        let entry =
            self.seal_bytes_into_vault(&raw_bytes, &file_path.to_string_lossy(), threat_name, 95);
        zeroize_slice(&mut raw_bytes);
        let entry = entry?;

        // Simulate disk fault / bit-flip in `.quar` before verification completes (`Invariant I4`)
        let quar_path = Path::new(&entry.vault_file_path);
        if let Ok(mut disk_bytes) = fs::read(quar_path) {
            if let Some(last) = disk_bytes.last_mut() {
                *last ^= 0xFF;
            }
            let _ = fs::write(quar_path, &disk_bytes);
        }

        // `verify_entry` MUST fail closed here, and cleanup the broken `.quar`/`.dek` while
        // NEVER calling `SecureShredder::shred_file(file_path, ...)`!
        if let Err(verify_err) = self.verify_entry(&entry.entry_id) {
            let _ = fs::remove_file(quar_path);
            let _ = fs::remove_file(self.vault_dir.join(format!("{}.dek", entry.entry_id)));
            return Err(format!(
                "INVARIANT_I4_ABORT: Vault verification failed before source removal ({verify_err}); source file preserved intact"
            ));
        }

        SecureShredder::shred_file_with_shared_ledger(
            file_path,
            ShredMethod::ClearMultiPass { passes: 3 },
            self.shared_ledger.as_ref(),
        )?;
        Ok(entry)
    }

    /// Surgically quarantines an NTFS Alternate Data Stream (`host_path:stream_name`) into an
    /// authenticated `.quar` envelope, verifies the `.quar` entry on disk (Invariant I4),
    /// and then calls `SecureShredder::shred_ntfs_stream(host_path, stream_name)` so the
    /// host file is preserved intact (`High #10`, `Rows 50, 64`, `BUG-CLI-01`).
    pub fn quarantine_ntfs_stream(
        &self,
        host_path: &Path,
        stream_name: &str,
        threat_name: &str,
        threat_score: u8,
    ) -> Result<QuarantineEntry, String> {
        self.check_healthy()?;

        let clean_stream = stream_name
            .trim_matches(':')
            .trim_end_matches(":$DATA")
            .trim_end_matches(":$data")
            .trim_matches(':');
        if clean_stream.is_empty() {
            return Err("Invalid empty NTFS Alternate Data Stream name".to_string());
        }

        let verbatim_host = to_verbatim_path(host_path);
        let stream_full_path = format!("{}:{}", verbatim_host.display(), clean_stream);
        let logical_display_path = format!("{}:{}", host_path.display(), clean_stream);

        let mut raw_bytes = Vec::new();
        {
            let mut file = File::open(&stream_full_path).map_err(|e| {
                format!(
                    "Failed opening NTFS Alternate Data Stream '{logical_display_path}' for quarantine: {e}"
                )
            })?;
            file.read_to_end(&mut raw_bytes).map_err(|e| {
                format!(
                    "Failed reading NTFS Alternate Data Stream '{logical_display_path}' for quarantine: {e}"
                )
            })?;
        }

        let entry = self.seal_bytes_into_vault(
            &raw_bytes,
            &logical_display_path,
            threat_name,
            threat_score,
        );
        zeroize_slice(&mut raw_bytes);
        let entry = entry?;

        // Invariant I4: Verify the `.quar` copy on disk before touching the source ADS stream
        self.verify_entry(&entry.entry_id)?;

        // Surgically Clear and delete ONLY the NTFS Alternate Data Stream, preserving `host_path`
        SecureShredder::shred_ntfs_stream_with_shared_ledger(
            host_path,
            clean_stream,
            self.shared_ledger.as_ref(),
        )?;

        self.append_ledger_event(
            "QUARANTINE_ADS_CREATED",
            &format!(
                "entry_id={} ads={} sha256={} threat={} score={}",
                entry.entry_id,
                logical_display_path,
                entry.original_sha256,
                threat_name,
                threat_score
            ),
        )?;

        Ok(entry)
    }

    fn seal_bytes_into_vault(
        &self,
        raw_bytes: &[u8],
        original_path_str: &str,
        threat_name: &str,
        threat_score: u8,
    ) -> Result<QuarantineEntry, String> {
        let mut hasher = Sha256::new();
        hasher.update(raw_bytes);
        let sha256_plaintext = hex::encode(hasher.finalize());
        let original_size = raw_bytes.len() as u64;

        let entry_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let quarantined_at_utc = now.to_rfc3339();
        let quarantined_at_unix = now.timestamp().max(0) as u64;

        let mut file_salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        let mut raw_entry_dek = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut file_salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        rand::rngs::OsRng.fill_bytes(&mut raw_entry_dek);

        let entry_dek = ZeroizingBytes::new(raw_entry_dek);
        zeroize_slice(&mut raw_entry_dek);

        // Persist wrapped DEK (`<entry_id>.dek`) under `HKDF-SHA256(KEK, file_salt, "OMNICONNECT_SENTINEL_QUARANTINE_V2")`
        self.write_wrapped_entry_dek(&entry_id, &file_salt, &entry_dek)?;

        let header = QuarantineEnvelopeHeader {
            magic: *ENVELOPE_MAGIC_V2_FULL,
            version: ENVELOPE_VERSION,
            kek_id: self.kek_id.clone(),
            file_salt,
            nonce,
            original_path: original_path_str.to_string(),
            original_size,
            sha256_plaintext: sha256_plaintext.clone(),
            threat_name: threat_name.to_string(),
            threat_score,
            quarantined_at_unix,
            entry_id: entry_id.clone(),
            quarantined_at_utc: quarantined_at_utc.clone(),
            recovery_status: "RECOVERABLE".to_string(),
        };

        let header_json = serde_json::to_vec(&header)
            .map_err(|e| format!("Failed serializing quarantine header: {e}"))?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(entry_dek.as_slice()));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: raw_bytes,
                    aad: &header_json,
                },
            )
            .map_err(|e| format!("AES-256-GCM AEAD encryption failure: {e}"))?;

        let vault_file_name = format!("{entry_id}.quar");
        let vault_file_path = self.vault_dir.join(&vault_file_name);
        let tmp_file_path = self.vault_dir.join(format!("{entry_id}.quar.tmp"));

        // Exact layout (`Plan v2 §1.1 #4`): `[header_len: u32 LE][header JSON][ciphertext]`
        {
            let mut vault_file =
                create_restricted_file_handle_atomic(&tmp_file_path).map_err(|e| {
                    format!("Failed creating atomic restricted temporary vault file: {e}")
                })?;
            let header_len = header_json.len() as u32;
            vault_file
                .write_all(&header_len.to_le_bytes())
                .map_err(|e| e.to_string())?;
            vault_file
                .write_all(&header_json)
                .map_err(|e| e.to_string())?;
            vault_file
                .write_all(&ciphertext)
                .map_err(|e| e.to_string())?;
            vault_file.sync_all().map_err(|e| e.to_string())?;
        }

        fs::rename(&tmp_file_path, &vault_file_path)
            .map_err(|e| format!("Atomic rename into quarantine vault failed: {e}"))?;
        sync_directory(&self.vault_dir)
            .map_err(|e| format!("Failed syncing quarantine vault directory: {e}"))?;

        info!(
            "Artifact quarantined into {} (ID: {}, SHA256: {})",
            vault_file_path.display(),
            entry_id,
            sha256_plaintext
        );

        Ok(QuarantineEntry {
            entry_id,
            kek_id: self.kek_id.clone(),
            original_path: header.original_path,
            original_sha256: sha256_plaintext,
            original_size_bytes: original_size,
            vault_file_path: vault_file_path.to_string_lossy().to_string(),
            threat_reason: threat_name.to_string(),
            threat_score,
            quarantined_at_utc,
            quarantined_at_unix,
            encryption_algorithm: "AES-256-GCM-HKDF-SHA256-V2".to_string(),
            nonce_hex: hex::encode(nonce),
            recovery_status: "RECOVERABLE".to_string(),
        })
    }

    /// Decrypts, authenticates (AEAD + AAD + SHA-256), and atomically restores a quarantined file (`BUG-CORE-02`).
    pub fn restore_file(&self, entry_id: &str, destination_path: &Path) -> Result<PathBuf, String> {
        self.check_healthy()?;

        if entry_id.contains('/') || entry_id.contains('\\') || entry_id.contains("..") {
            return Err("Invalid quarantine entry ID".to_string());
        }

        let vault_file_path = self.vault_dir.join(format!("{entry_id}.quar"));
        let envelope_bytes = fs::read(&vault_file_path).map_err(|e| {
            format!(
                "VAULT_INTEGRITY_FAIL: Failed reading quarantine envelope {}: {}",
                vault_file_path.display(),
                e
            )
        })?;

        let (header, header_json, ciphertext) = Self::parse_envelope(&envelope_bytes)?;

        if !header.entry_id.is_empty() && header.entry_id != entry_id {
            return Err("VAULT_INTEGRITY_FAIL: Envelope entry_id mismatch".to_string());
        }

        let entry_dek = self.unwrap_entry_dek(entry_id, &header.file_salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(entry_dek.as_slice()));
        let nonce = Nonce::from_slice(&header.nonce);
        let mut plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: header_json,
                },
            )
            .map_err(|_| {
                "VAULT_INTEGRITY_FAIL: AEAD authentication failed — envelope header or ciphertext was tampered with"
                    .to_string()
            })?;

        // Verify original SHA-256 and size integrity
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let actual_sha256 = hex::encode(hasher.finalize());
        if actual_sha256 != header.sha256_plaintext
            || (plaintext.len() as u64) != header.original_size
        {
            zeroize_slice(&mut plaintext);
            return Err(format!(
                "VAULT_INTEGRITY_FAIL: Restored plaintext SHA-256 or size mismatch (expected {}, got {})",
                header.sha256_plaintext, actual_sha256
            ));
        }

        if let Some(parent) = destination_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "Failed creating restore parent directory {}: {}",
                        parent.display(),
                        e
                    )
                })?;
            }
        }

        let tmp_restore = destination_path.with_extension("restore.tmp");
        {
            let mut out = File::create(&tmp_restore).map_err(|e| {
                zeroize_slice(&mut plaintext);
                format!("Failed creating restore target: {e}")
            })?;
            if let Err(e) = out.write_all(&plaintext).and_then(|_| out.sync_all()) {
                zeroize_slice(&mut plaintext);
                return Err(format!("Failed writing restored file: {e}"));
            }
        }
        zeroize_slice(&mut plaintext);

        fs::rename(&tmp_restore, destination_path)
            .map_err(|e| format!("Failed finalizing restored file: {e}"))?;
        if let Some(parent) = destination_path.parent() {
            if !parent.as_os_str().is_empty() {
                sync_directory(parent)
                    .map_err(|e| format!("Failed syncing restore parent directory: {e}"))?;
            }
        }

        self.append_ledger_event(
            "QUARANTINE_RESTORED",
            &format!(
                "entry_id={} destination={} sha256={}",
                entry_id,
                destination_path.display(),
                actual_sha256
            ),
        )?;

        info!(
            "Successfully restored quarantine entry '{}' to {}",
            entry_id,
            destination_path.display()
        );
        Ok(destination_path.to_path_buf())
    }

    /// Reads a `.quar` envelope and its wrapped `.dek` back from disk and verifies its AEAD tag
    /// and SHA-256 digest in memory without writing plaintext to disk (enforces Master Plan v2 Invariant I4).
    pub fn verify_entry(&self, entry_id: &str) -> Result<bool, String> {
        self.check_healthy()?;

        if entry_id.contains('/') || entry_id.contains('\\') || entry_id.contains("..") {
            return Err("Invalid quarantine entry ID".to_string());
        }
        let vault_file_path = self.vault_dir.join(format!("{entry_id}.quar"));
        let envelope_bytes = fs::read(&vault_file_path).map_err(|e| {
            format!(
                "VAULT_INTEGRITY_FAIL: Failed reading quarantine envelope {}: {}",
                vault_file_path.display(),
                e
            )
        })?;
        let (header, header_json, ciphertext) = Self::parse_envelope(&envelope_bytes)?;
        let entry_dek = self.unwrap_entry_dek(entry_id, &header.file_salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(entry_dek.as_slice()));
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(&header.nonce),
                Payload {
                    msg: ciphertext,
                    aad: header_json,
                },
            )
            .map_err(|_| {
                "VAULT_INTEGRITY_FAIL: AEAD authentication failed on verification read".to_string()
            })?;
        let actual_sha256 = hex::encode(Sha256::digest(&plaintext));
        let actual_len = plaintext.len() as u64;
        zeroize_slice(&mut plaintext);

        if actual_sha256 != header.sha256_plaintext || actual_len != header.original_size {
            return Err("VAULT_INTEGRITY_FAIL: Plaintext SHA-256 or size mismatch".to_string());
        }
        Ok(true)
    }

    /// Performs true cryptographic erasure (`Master Plan v2 §1.1 #5`, `ADR-011`) by first
    /// overwriting and destroying the entry's wrapped DEK file (`<entry_id>.dek`) so the
    /// ciphertext is immediately unrecoverable, and then running NIST 800-88 Clear on `<entry_id>.quar`.
    pub fn purge(&self, entry_id: &str) -> Result<(), String> {
        self.check_healthy()?;

        if entry_id.contains('/') || entry_id.contains('\\') || entry_id.contains("..") {
            return Err("Invalid quarantine entry ID".to_string());
        }
        let vault_file_path = self.vault_dir.join(format!("{entry_id}.quar"));
        if !vault_file_path.exists() {
            return Err(format!("Quarantine entry '{entry_id}' not found"));
        }

        // Step 1: True Cryptographic Erasure — overwrite and destroy the wrapped per-entry DEK (`<entry_id>.dek`)
        let dek_path = self.vault_dir.join(format!("{entry_id}.dek"));
        if dek_path.exists() {
            SecureShredder::shred_file_with_shared_ledger(
                &dek_path,
                ShredMethod::ClearMultiPass { passes: 3 },
                self.shared_ledger.as_ref(),
            )?;
        }

        // Step 2: Overwrite and unlink the `.quar` ciphertext envelope and sync the directory
        SecureShredder::shred_file_with_shared_ledger(
            &vault_file_path,
            ShredMethod::CryptoErase,
            self.shared_ledger.as_ref(),
        )?;
        sync_directory(&self.vault_dir)
            .map_err(|e| format!("Failed syncing quarantine directory after purge: {e}"))?;

        self.append_ledger_event(
            "QUARANTINE_PURGED",
            &format!("Crypto-erased DEK and shredded quarantine entry '{entry_id}'"),
        )?;

        Ok(())
    }

    /// Lists all entries in the Quarantine Vault (`Master Plan v2 §1.1 #5`).
    pub fn list(&self) -> Result<Vec<QuarantineEntry>, String> {
        self.list_entries()
    }

    pub fn list_entries(&self) -> Result<Vec<QuarantineEntry>, String> {
        self.check_healthy()?;

        let mut entries = Vec::new();
        let read_dir = fs::read_dir(&self.vault_dir).map_err(|e| e.to_string())?;

        for dir_entry in read_dir.flatten() {
            let path = dir_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("quar") {
                continue;
            }
            let file_stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            if let Ok(bytes) = fs::read(&path) {
                if let Ok((header, _, _)) = Self::parse_envelope(&bytes) {
                    let entry_id = if header.entry_id.is_empty() {
                        file_stem
                    } else {
                        header.entry_id
                    };
                    entries.push(QuarantineEntry {
                        entry_id,
                        kek_id: header.kek_id,
                        original_path: header.original_path,
                        original_sha256: header.sha256_plaintext,
                        original_size_bytes: header.original_size,
                        vault_file_path: path.to_string_lossy().to_string(),
                        threat_reason: header.threat_name,
                        threat_score: header.threat_score,
                        quarantined_at_utc: header.quarantined_at_utc,
                        quarantined_at_unix: header.quarantined_at_unix,
                        encryption_algorithm: "AES-256-GCM-HKDF-SHA256-V2".to_string(),
                        nonce_hex: hex::encode(header.nonce),
                        recovery_status: header.recovery_status,
                    });
                } else {
                    // Legacy v1 key-less `.quar` file (with or without `.json` sidecar)
                    entries.push(QuarantineEntry {
                        entry_id: file_stem,
                        kek_id: "LEGACY-NONE".to_string(),
                        original_path: path.to_string_lossy().to_string(),
                        original_sha256: "UNRECOVERABLE_LEGACY".to_string(),
                        original_size_bytes: bytes.len() as u64,
                        vault_file_path: path.to_string_lossy().to_string(),
                        threat_reason: "Legacy v1 quarantine artifact (key never persisted)"
                            .to_string(),
                        threat_score: 0,
                        quarantined_at_utc: "LEGACY".to_string(),
                        quarantined_at_unix: 0,
                        encryption_algorithm: "LEGACY-V1-KEYLESS".to_string(),
                        nonce_hex: String::new(),
                        recovery_status: "UNRECOVERABLE_LEGACY".to_string(),
                    });
                }
            }
        }
        Ok(entries)
    }

    /// Explicitly migrates legacy v1 `.quar` entries (with or without `.json` sidecars) that lack
    /// a v2 authenticated envelope, recording each as `UNRECOVERABLE_LEGACY` in the signed audit
    /// ledger and executing the administrator's choice (`Keep` as inert ciphertext vs `Delete`)
    /// (`Master Plan v2 §1.1 #4`, `Row 46`, `vault_migrate_legacy`).
    pub fn migrate_legacy_entries(&self) -> Result<usize, String> {
        let migrated = self.migrate_legacy_entries_with_action(LegacyMigrationAction::Keep)?;
        Ok(migrated.len())
    }

    pub fn migrate_legacy_entries_with_action(
        &self,
        action: LegacyMigrationAction,
    ) -> Result<Vec<String>, String> {
        self.check_healthy()?;

        let mut migrated_ids = Vec::new();
        let read_dir = fs::read_dir(&self.vault_dir)
            .map_err(|e| format!("Failed reading vault directory for migration: {e}"))?;

        for dir_entry in read_dir.flatten() {
            let path = dir_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("quar") {
                continue;
            }
            let bytes = fs::read(&path).map_err(|e| {
                format!("Failed reading {} during migration: {}", path.display(), e)
            })?;

            if Self::parse_envelope(&bytes).is_err() {
                let entry_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("legacy_entry")
                    .to_string();

                let json_sidecar = path.with_extension("json");
                match action {
                    LegacyMigrationAction::Keep => {
                        let marker = serde_json::json!({
                            "entry_id": entry_name,
                            "vault_file_path": path.to_string_lossy(),
                            "recovery_status": "UNRECOVERABLE_LEGACY",
                            "migration_action": "KEEP_INERT_CIPHERTEXT"
                        });
                        let serialized = serde_json::to_vec_pretty(&marker)
                            .map_err(|e| format!("Failed serializing legacy marker: {e}"))?;
                        write_protected_key_file(&json_sidecar, &serialized).map_err(|e| {
                            format!(
                                "Failed writing legacy marker {}: {}",
                                json_sidecar.display(),
                                e
                            )
                        })?;
                    }
                    LegacyMigrationAction::Delete => {
                        SecureShredder::shred_file_with_shared_ledger(
                            &path,
                            ShredMethod::ClearMultiPass { passes: 3 },
                            self.shared_ledger.as_ref(),
                        )?;
                        if json_sidecar.exists() {
                            SecureShredder::shred_file_with_shared_ledger(
                                &json_sidecar,
                                ShredMethod::ClearMultiPass { passes: 3 },
                                self.shared_ledger.as_ref(),
                            )?;
                        }
                    }
                }

                self.append_ledger_event(
                    "UNRECOVERABLE_LEGACY",
                    &format!(
                        "entry_id={} path={} status=UNRECOVERABLE_LEGACY action={:?}",
                        entry_name,
                        path.display(),
                        action
                    ),
                )?;

                warn!(
                    "Migrated legacy key-less quarantine entry {} as UNRECOVERABLE_LEGACY (action={:?})",
                    path.display(),
                    action
                );
                migrated_ids.push(entry_name);
            }
        }
        Ok(migrated_ids)
    }

    pub fn parse_envelope(
        bytes: &[u8],
    ) -> Result<(QuarantineEnvelopeHeader, &[u8], &[u8]), String> {
        if bytes.len() < 4 {
            return Err(
                "VAULT_INTEGRITY_FAIL: Quarantine entry is truncated (<4 bytes) (UNRECOVERABLE_LEGACY)"
                    .to_string(),
            );
        }
        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(&bytes[0..4]);
        let header_len = u32::from_le_bytes(len_buf) as usize;
        if header_len == 0 || header_len > 1024 * 1024 || bytes.len() < 4 + header_len {
            return Err(
                "VAULT_INTEGRITY_FAIL: Quarantine entry is not a v2 authenticated envelope (UNRECOVERABLE_LEGACY)"
                    .to_string(),
            );
        }
        let header_json = &bytes[4..4 + header_len];
        let ciphertext = &bytes[4 + header_len..];
        let header: QuarantineEnvelopeHeader = serde_json::from_slice(header_json).map_err(|e| {
            format!(
                "VAULT_INTEGRITY_FAIL: Malformed quarantine envelope header JSON (UNRECOVERABLE_LEGACY): {e}"
            )
        })?;
        if &header.magic != ENVELOPE_MAGIC_V2_FULL || header.version != ENVELOPE_VERSION {
            return Err(
                "VAULT_INTEGRITY_FAIL: Invalid envelope magic or version (UNRECOVERABLE_LEGACY)"
                    .to_string(),
            );
        }
        Ok((header, header_json, ciphertext))
    }
}
