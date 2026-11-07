use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use tracing::warn;

use sentinel_sys::{
    apply_system_admin_dacl, create_sealed_ecdsa_p256_keypair, sign_with_sealed_ecdsa_p256,
    sync_directory, verify_ecdsa_p256_digest, write_protected_key_file, KeyProtectionPosture,
    SealedEcdsaKeyPair,
};

const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append-only Audit Ledger JSONL Record (`Master Plan v2 §4.2`, Invariant I5).
///
/// Exact JSON schema: `{seq, ts, event, data, prev_hash, hash}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerRecord {
    pub seq: u64,
    #[serde(alias = "timestamp_utc")]
    pub ts: String,
    #[serde(alias = "event_type")]
    pub event: String,
    #[serde(alias = "details")]
    pub data: String,
    pub prev_hash: String,
    #[serde(alias = "record_hash")]
    pub hash: String,
}

/// Asymmetric ECDSA P-256 Signed Chain-Head Checkpoint (`<ledger>.head.sig`, `Master Plan v2 §4.2`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedChainHead {
    pub head_seq: u64,
    pub head_hash: String,
    pub algorithm: String,
    pub key_posture: KeyProtectionPosture,
    pub public_key_blob_hex: String,
    pub ecdsa_p256_signature_hex: String,
    pub signed_at_utc: String,
}

/// Tamper-Evident Hash-Chained Audit Ledger (`Phase 4.2`, Invariant I5, NIST AU-9 / AU-10, CERT-In 180-Day Retention)
///
/// - Each JSONL record (`{seq, ts, event, data, prev_hash, hash}`) links `prev_hash` -> `hash` (`SHA-256`).
/// - Signs the chain head (`seq|hash`) using an asymmetric **ECDSA P-256** keypair (TPM 2.0 PCP
///   `NCryptSignHash` when available, or DPAPI `CRYPTPROTECT_LOCAL_MACHINE` sealed `BCRYPT_ECDSA_P256_ALGORITHM`
///   protected by a SYSTEM/Admin DACL).
/// - Persists the signed head checkpoint (`<ledger>.head.sig`) so `verify_chain()` detects record
///   modification, insertion, reordering, AND tail truncation using the public key.
/// - Fails closed (`Err`) if an existing `.ledger_key.sealed` cannot be unsealed — never silently
///   regenerating or overwriting the signing key.
pub struct AuditLedger {
    ledger_path: PathBuf,
    ecdsa_keypair: Option<SealedEcdsaKeyPair>,
    init_error: Option<String>,
    next_seq: u64,
    last_hash: String,
}

impl AuditLedger {
    /// Opens or initializes the Audit Ledger, returning `Err` if directory creation, DACL hardening,
    /// or existing ECDSA P-256 signing key unsealing fails.
    pub fn open_result(ledger_path: impl Into<PathBuf>) -> Result<Self, String> {
        let ledger_path = ledger_path.into();
        if let Some(parent) = ledger_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "Failed creating audit ledger directory {}: {}",
                        parent.display(),
                        e
                    )
                })?;
                apply_system_admin_dacl(parent).map_err(|e| {
                    format!(
                        "Failed applying SYSTEM/Admin DACL to audit ledger directory {}: {}",
                        parent.display(),
                        e
                    )
                })?;
            }
        }

        let ecdsa_keypair = Self::load_or_init_ecdsa_key(&ledger_path)?;
        let (next_seq, last_hash) = Self::scan_tail(&ledger_path)?;

        Ok(Self {
            ledger_path,
            ecdsa_keypair: Some(ecdsa_keypair),
            init_error: None,
            next_seq,
            last_hash,
        })
    }

    /// Opens the Audit Ledger, latching `init_error` if an existing key file is corrupted or
    /// unreadable so all subsequent `append_event` / `verify_chain` calls fail closed without
    /// overwriting the existing key file.
    pub fn open(ledger_path: impl Into<PathBuf>) -> Self {
        let ledger_path = ledger_path.into();
        match Self::open_result(ledger_path.clone()) {
            Ok(ledger) => ledger,
            Err(err) => {
                warn!("AuditLedger initialization failed closed: {}", err);
                Self {
                    ledger_path,
                    ecdsa_keypair: None,
                    init_error: Some(err),
                    next_seq: 1,
                    last_hash: GENESIS_PREV_HASH.to_string(),
                }
            }
        }
    }

    pub fn key_posture(&self) -> Option<KeyProtectionPosture> {
        self.ecdsa_keypair.as_ref().map(|k| k.posture)
    }

    pub fn public_key_blob(&self) -> Option<&[u8]> {
        self.ecdsa_keypair
            .as_ref()
            .map(|k| k.public_key_blob.as_slice())
    }

    fn check_healthy(&self) -> Result<&SealedEcdsaKeyPair, String> {
        if let Some(err) = &self.init_error {
            return Err(err.clone());
        }
        self.ecdsa_keypair.as_ref().ok_or_else(|| {
            "LEDGER_KEY_INTEGRITY_FAIL: ECDSA P-256 signing key unavailable".to_string()
        })
    }

    fn key_file_path(ledger_path: &Path) -> PathBuf {
        ledger_path.with_extension("ledger_key.sealed")
    }

    fn head_sig_path(ledger_path: &Path) -> PathBuf {
        ledger_path.with_extension("head.sig")
    }

    fn context_string(ledger_path: &Path) -> String {
        format!(
            "OmniConnect-Sentinel-Ledger-ECDSA-P256:{}",
            ledger_path.display()
        )
    }

    fn load_or_init_ecdsa_key(ledger_path: &Path) -> Result<SealedEcdsaKeyPair, String> {
        let key_path = Self::key_file_path(ledger_path);
        let context = Self::context_string(ledger_path);

        // CRITICAL (#7, Row 167): If `.ledger_key.sealed` already exists on disk, NEVER overwrite
        // or regenerate it if reading, parsing, or unsealing fails!
        if key_path.exists() {
            let raw = fs::read(&key_path).map_err(|e| {
                format!(
                    "LEDGER_KEY_INTEGRITY_FAIL: Failed reading existing ledger key {}: {}",
                    key_path.display(),
                    e
                )
            })?;
            let keypair: SealedEcdsaKeyPair = serde_json::from_slice(&raw).map_err(|e| {
                format!(
                    "LEDGER_KEY_INTEGRITY_FAIL: Corrupted JSON in existing ledger key {}: {}",
                    key_path.display(),
                    e
                )
            })?;

            // Verify that the sealed keypair can actually sign and verify a probe digest
            let probe_digest = [0x5Au8; 32];
            let probe_sig = sign_with_sealed_ecdsa_p256(&keypair, context.as_bytes(), &probe_digest)
                .map_err(|e| {
                    format!(
                        "LEDGER_KEY_INTEGRITY_FAIL: Failed unsealing/using existing ledger ECDSA P-256 key {}: {}",
                        key_path.display(),
                        e
                    )
                })?;
            let valid = verify_ecdsa_p256_digest(&keypair.public_key_blob, &probe_digest, &probe_sig)
                .map_err(|e| {
                    format!(
                        "LEDGER_KEY_INTEGRITY_FAIL: Existing ledger ECDSA P-256 public key verification failed: {e}"
                    )
                })?;
            if !valid {
                return Err(
                    "LEDGER_KEY_INTEGRITY_FAIL: Existing ledger ECDSA P-256 keypair self-test failed"
                        .to_string(),
                );
            }
            return Ok(keypair);
        }

        // First-time provisioning of the ledger's asymmetric ECDSA P-256 keypair
        let unique_key_id = format!(
            "LEDGER-ECDSA-P256-{}",
            hex::encode(Sha256::digest(context.as_bytes()))[..16].to_ascii_uppercase()
        );
        let keypair = create_sealed_ecdsa_p256_keypair(context.as_bytes(), &unique_key_id)
            .map_err(|e| format!("Failed creating ledger ECDSA P-256 keypair: {e}"))?;
        let json = serde_json::to_vec_pretty(&keypair)
            .map_err(|e| format!("Failed serializing ledger ECDSA P-256 keypair: {e}"))?;
        write_protected_key_file(&key_path, &json).map_err(|e| {
            format!(
                "Failed persisting protected ledger key file {}: {}",
                key_path.display(),
                e
            )
        })?;
        Ok(keypair)
    }

    fn scan_tail(ledger_path: &Path) -> Result<(u64, String), String> {
        if !ledger_path.exists() {
            return Ok((1, GENESIS_PREV_HASH.to_string()));
        }
        let file = fs::File::open(ledger_path)
            .map_err(|e| format!("Failed opening ledger {}: {}", ledger_path.display(), e))?;
        let reader = BufReader::new(file);
        let mut last_seq = 0u64;
        let mut last_hash = GENESIS_PREV_HASH.to_string();

        for (idx, line_res) in reader.lines().enumerate() {
            let line =
                line_res.map_err(|e| format!("Failed reading ledger line {}: {}", idx + 1, e))?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: LedgerRecord = serde_json::from_str(&line).map_err(|e| {
                format!(
                    "Corrupted ledger JSON during tail scan at line {}: {}",
                    idx + 1,
                    e
                )
            })?;
            last_seq = rec.seq;
            last_hash = rec.hash;
        }

        Ok((last_seq + 1, last_hash))
    }

    /// Appends a hash-chained JSONL record (`{seq, ts, event, data, prev_hash, hash}`) and
    /// signs the updated chain head with ECDSA P-256 (`<ledger>.head.sig`).
    pub fn append_event(
        &mut self,
        event: &str,
        data: impl std::fmt::Display,
    ) -> Result<LedgerRecord, String> {
        let _ = self.check_healthy()?;

        let data_str = data.to_string();
        let seq = self.next_seq;
        let ts = Utc::now().to_rfc3339();
        let prev_hash = self.last_hash.clone();
        let hash = Self::compute_record_hash(seq, &ts, event, &data_str, &prev_hash);

        let record = LedgerRecord {
            seq,
            ts,
            event: event.to_string(),
            data: data_str,
            prev_hash,
            hash: hash.clone(),
        };

        let mut line = serde_json::to_string(&record).map_err(|e| e.to_string())?;
        line.push('\n');

        let is_new_file = !self.ledger_path.exists();
        {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.ledger_path)
                .map_err(|e| format!("Failed opening audit ledger: {e}"))?;
            file.write_all(line.as_bytes())
                .map_err(|e| format!("Failed appending to audit ledger: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("Failed syncing audit ledger: {e}"))?;
        }
        if is_new_file {
            apply_system_admin_dacl(&self.ledger_path).map_err(|e| {
                format!(
                    "Failed applying SYSTEM/Admin DACL to audit ledger {}: {}",
                    self.ledger_path.display(),
                    e
                )
            })?;
            if let Some(parent) = self.ledger_path.parent() {
                if !parent.as_os_str().is_empty() {
                    sync_directory(parent)
                        .map_err(|e| format!("Failed syncing ledger parent directory: {e}"))?;
                }
            }
        }

        self.next_seq = seq + 1;
        self.last_hash = hash;

        // Sign the updated chain head with ECDSA P-256 and persist `<ledger>.head.sig`
        self.sign_chain_head()?;

        Ok(record)
    }

    /// Explicitly signs the current chain head (`head_seq|head_hash`) with the asymmetric
    /// ECDSA P-256 private key and writes `<ledger>.head.sig` atomically (`Master Plan v2 §4.2`).
    pub fn sign_chain_head(&self) -> Result<SignedChainHead, String> {
        let keypair = self.check_healthy()?;
        if self.next_seq <= 1 {
            return Err("Cannot sign chain head of an empty ledger".to_string());
        }
        let head_seq = self.next_seq - 1;
        let head_hash = self.last_hash.clone();
        let digest = Self::compute_head_digest(head_seq, &head_hash);
        let context = Self::context_string(&self.ledger_path);

        let sig_bytes = sign_with_sealed_ecdsa_p256(keypair, context.as_bytes(), &digest)
            .map_err(|e| format!("ECDSA P-256 chain-head signing failed: {e}"))?;

        let signed_head = SignedChainHead {
            head_seq,
            head_hash,
            algorithm: "ECDSA-P256-SHA256".to_string(),
            key_posture: keypair.posture,
            public_key_blob_hex: hex::encode(&keypair.public_key_blob),
            ecdsa_p256_signature_hex: hex::encode(&sig_bytes),
            signed_at_utc: Utc::now().to_rfc3339(),
        };

        let head_path = Self::head_sig_path(&self.ledger_path);
        let head_json = serde_json::to_vec_pretty(&signed_head)
            .map_err(|e| format!("Failed serializing signed chain head: {e}"))?;
        write_protected_key_file(&head_path, &head_json).map_err(|e| {
            format!(
                "Failed writing signed chain head {}: {}",
                head_path.display(),
                e
            )
        })?;

        Ok(signed_head)
    }

    /// Verifies the cryptographic integrity of every record and hash link in the ledger,
    /// verifies the asymmetric ECDSA P-256 signature on `<ledger>.head.sig`, AND verifies
    /// that the final record matches `head_seq` and `head_hash` (detecting tail truncation).
    pub fn verify_chain(&self) -> Result<usize, String> {
        let keypair = self.check_healthy()?;

        if !self.ledger_path.exists() {
            let head_path = Self::head_sig_path(&self.ledger_path);
            if head_path.exists() {
                return Err(
                    "Ledger file was deleted while signed chain-head checkpoint exists".to_string(),
                );
            }
            return Ok(0);
        }

        let file = fs::File::open(&self.ledger_path).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);
        let mut expected_seq = 1u64;
        let mut expected_prev_hash = GENESIS_PREV_HASH.to_string();
        let mut count = 0usize;

        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res.map_err(|e| e.to_string())?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: LedgerRecord = serde_json::from_str(&line)
                .map_err(|e| format!("Corrupted ledger JSON at line {}: {}", idx + 1, e))?;

            if rec.seq != expected_seq {
                return Err(format!(
                    "Ledger sequence break at line {}: expected seq {}, found {}",
                    idx + 1,
                    expected_seq,
                    rec.seq
                ));
            }

            if rec.prev_hash != expected_prev_hash {
                return Err(format!(
                    "Ledger hash-chain break at seq {}: prev_hash mismatch",
                    rec.seq
                ));
            }

            let recomputed_hash =
                Self::compute_record_hash(rec.seq, &rec.ts, &rec.event, &rec.data, &rec.prev_hash);
            if rec.hash != recomputed_hash {
                return Err(format!(
                    "Ledger content tampered at seq {}: hash mismatch",
                    rec.seq
                ));
            }

            expected_seq += 1;
            expected_prev_hash = rec.hash;
            count += 1;
        }

        if count == 0 {
            return Ok(0);
        }

        let final_seq = expected_seq - 1;
        let final_hash = expected_prev_hash;

        // Verify `<ledger>.head.sig` ECDSA P-256 signature and tail-truncation protection
        let head_path = Self::head_sig_path(&self.ledger_path);
        let raw_head = fs::read(&head_path).map_err(|e| {
            format!(
                "Ledger signed chain-head checkpoint {} missing or unreadable: {}",
                head_path.display(),
                e
            )
        })?;
        let signed_head: SignedChainHead = serde_json::from_slice(&raw_head)
            .map_err(|e| format!("Corrupted signed chain-head JSON: {e}"))?;

        if signed_head.head_seq != final_seq || signed_head.head_hash != final_hash {
            return Err(format!(
                "LEDGER_CHAIN_BROKEN: Ledger tail-truncation or head mismatch detected: expected seq={} hash={}, found seq={} hash={}",
                signed_head.head_seq, signed_head.head_hash, final_seq, final_hash
            ));
        }

        let pub_bytes = hex::decode(&signed_head.public_key_blob_hex)
            .map_err(|e| format!("Invalid public key hex in signed chain head: {e}"))?;
        if pub_bytes != keypair.public_key_blob {
            return Err(
                "Ledger public key mismatch between signed head and sealed keypair".to_string(),
            );
        }

        let sig_bytes = hex::decode(&signed_head.ecdsa_p256_signature_hex)
            .map_err(|e| format!("Invalid ECDSA signature hex in signed chain head: {e}"))?;
        let digest = Self::compute_head_digest(signed_head.head_seq, &signed_head.head_hash);

        let sig_valid = verify_ecdsa_p256_digest(&pub_bytes, &digest, &sig_bytes)
            .map_err(|e| format!("ECDSA P-256 verification error: {e}"))?;
        if !sig_valid {
            return Err(
                "Ledger ECDSA P-256 chain-head signature verification failed (signature forged or tampered)"
                    .to_string(),
            );
        }

        Ok(count)
    }

    fn compute_record_hash(seq: u64, ts: &str, event: &str, data: &str, prev_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{seq}|{ts}|{event}|{data}|{prev_hash}"));
        hex::encode(hasher.finalize())
    }

    fn compute_head_digest(head_seq: u64, head_hash: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(format!("SENTINEL-LEDGER-HEAD-V2:{head_seq}|{head_hash}"));
        let final_hash = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&final_hash);
        out
    }
}

impl Drop for AuditLedger {
    fn drop(&mut self) {
        if self.init_error.is_none() && self.next_seq > 1 {
            let _ = self.sign_chain_head();
        }
    }
}
