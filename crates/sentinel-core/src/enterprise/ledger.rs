use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tracing::warn;

use sentinel_sys::{
    create_restricted_dir_atomic, create_restricted_file_handle_atomic,
    create_sealed_ecdsa_p256_keypair, ensure_not_symlink_or_reparse_point, query_ntp_sync_status,
    seal_key_bytes, sign_with_sealed_ecdsa_p256, sync_directory, unseal_key_bytes,
    verify_ecdsa_p256_digest, write_protected_key_file, zeroize_slice, KeyProtectionPosture,
    NtpSyncStatus, SealedEcdsaKeyPair, SealedKeyBlob, ZeroizingBytes,
};

const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Process-wide serialization lock synchronizing on-disk JSONL tail scans, record appends,
/// and `<ledger>.head.sig` checkpoint writes across both `SharedAuditLedger` and path-based
/// `AuditLedger` handles (`CSE-13`, `CSE-14`).
static LEDGER_IO_LOCK: Mutex<()> = Mutex::new(());

/// Subsystem classification for the unified single-root Audit Ledger (`Master Plan v2 §4.2`, `CSE-13`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditSubsystem {
    Quarantine,
    VfsShadow,
    Tier3Sandbox,
    SiemFalcon,
    SecureShredder,
    Intune,
    Kiosk,
    System,
}

impl std::fmt::Display for AuditSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quarantine => write!(f, "Quarantine"),
            Self::VfsShadow => write!(f, "VfsShadow"),
            Self::Tier3Sandbox => write!(f, "Tier3Sandbox"),
            Self::SiemFalcon => write!(f, "SiemFalcon"),
            Self::SecureShredder => write!(f, "SecureShredder"),
            Self::Intune => write!(f, "Intune"),
            Self::Kiosk => write!(f, "Kiosk"),
            Self::System => write!(f, "System"),
        }
    }
}

/// Thread-safe shared handle to the unified Audit Ledger (`Master Plan v2 §4.2`, `CSE-13`).
pub type SharedAuditLedger = Arc<Mutex<AuditLedger>>;

static GLOBAL_UNIFIED_LEDGER: OnceLock<SharedAuditLedger> = OnceLock::new();

/// Verifies that `dir` can be created/validated as a non-reparse restricted directory AND that
/// the current process actually has read/write capability on `dir` and any pre-existing ledger/key/head files.
pub fn is_restricted_ledger_dir_writable(dir: &Path, ledger_filename: &str) -> bool {
    if create_restricted_dir_atomic(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(
        ".sentinel_write_probe_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    match create_restricted_file_handle_atomic(&probe) {
        Ok(f) => {
            drop(f);
            let _ = fs::remove_file(&probe);
        }
        Err(_) => return false,
    }

    let ledger_file = dir.join(ledger_filename);
    if ledger_file.exists()
        && OpenOptions::new()
            .read(true)
            .append(true)
            .open(&ledger_file)
            .is_err()
    {
        return false;
    }
    let key_file = ledger_file.with_extension("ledger_key.sealed");
    if key_file.exists() && fs::read(&key_file).is_err() {
        return false;
    }
    let hmac_file = ledger_file.with_extension("privacy_hmac.sealed");
    if hmac_file.exists() && fs::read(&hmac_file).is_err() {
        return false;
    }
    let head_file = ledger_file.with_extension("head.sig");
    if head_file.exists()
        && OpenOptions::new()
            .read(true)
            .write(true)
            .open(&head_file)
            .is_err()
    {
        return false;
    }
    true
}

/// Resolves the default path for the unified single-root Audit Ledger.
pub fn default_unified_ledger_path() -> PathBuf {
    if let Ok(custom) = std::env::var("SENTINEL_UNIFIED_AUDIT_LEDGER") {
        return PathBuf::from(custom);
    }
    if let Ok(custom) = std::env::var("SENTINEL_AUDIT_LEDGER_PATH") {
        return PathBuf::from(custom);
    }

    const LEDGER_NAME: &str = "sentinel_unified_audit.jsonl";

    #[cfg(windows)]
    {
        if let Ok(pd) = std::env::var("ProgramData") {
            let dir = PathBuf::from(pd).join("OmniConnect").join("AuditLedger");
            if is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
                return dir.join(LEDGER_NAME);
            }
        }
        if let Ok(lad) = std::env::var("LOCALAPPDATA") {
            let dir = PathBuf::from(lad).join("OmniConnect").join("AuditLedger");
            if is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
                return dir.join(LEDGER_NAME);
            }
        }
    }
    #[cfg(not(windows))]
    {
        let dir = PathBuf::from("/var/lib/omniconnect/audit_ledger");
        if is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
            return dir.join(LEDGER_NAME);
        }
        if let Ok(home) = std::env::var("HOME") {
            let dir = PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("omniconnect")
                .join("audit_ledger");
            if is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
                return dir.join(LEDGER_NAME);
            }
        }
    }

    #[cfg(test)]
    {
        std::env::temp_dir()
            .join(format!("sentinel_unified_ledger_{}", std::process::id()))
            .join(LEDGER_NAME)
    }
    #[cfg(not(test))]
    {
        if let Ok(cwd) = std::env::current_dir() {
            let dir = cwd.join(".sentinel_audit");
            if is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
                return dir.join(LEDGER_NAME);
            }
        }
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\ProgramData\OmniConnect\AuditLedger\sentinel_unified_audit.jsonl")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/var/lib/omniconnect/audit_ledger/sentinel_unified_audit.jsonl")
        }
    }
}

/// Creates a new thread-safe `SharedAuditLedger` wrapping an `AuditLedger` at the given path.
pub fn create_shared_audit_ledger(
    ledger_path: impl Into<PathBuf>,
) -> Result<SharedAuditLedger, String> {
    let ledger = AuditLedger::open_result(ledger_path)?;
    Ok(Arc::new(Mutex::new(ledger)))
}

/// Returns or initializes the global unified `SharedAuditLedger` singleton.
pub fn get_or_init_global_shared_ledger(explicit_path: Option<PathBuf>) -> SharedAuditLedger {
    GLOBAL_UNIFIED_LEDGER
        .get_or_init(|| {
            let path = explicit_path.unwrap_or_else(default_unified_ledger_path);
            let ledger = AuditLedger::open(path);
            Arc::new(Mutex::new(ledger))
        })
        .clone()
}

/// Computes an HMAC-SHA256 pseudonymized token for sensitive file paths (GDPR/DPDP compliance, `Master Plan v2 §4.2`).
pub fn tokenize_path_for_privacy(hmac_key: &[u8], raw_path: &Path) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = match HmacSha256::new_from_slice(hmac_key) {
        Ok(m) => m,
        Err(_) => {
            let digest = Sha256::digest(hmac_key);
            match HmacSha256::new_from_slice(&digest) {
                Ok(m) => m,
                Err(_) => {
                    let mut fallback = Sha256::new();
                    fallback.update(hmac_key);
                    fallback.update(raw_path.to_string_lossy().as_bytes());
                    return hex::encode(fallback.finalize());
                }
            }
        }
    };
    mac.update(raw_path.to_string_lossy().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Computes a pseudonymized HMAC-SHA256 path token using the unified `SharedAuditLedger` if
/// present, or the fallback path ledger's OS-sealed privacy HMAC key (`CEA-DEFECT-06`).
pub fn tokenize_path_for_ledger(
    shared_ledger: Option<&SharedAuditLedger>,
    fallback_ledger_path: &Path,
    raw_path: &Path,
) -> Result<String, String> {
    if let Some(shared) = shared_ledger {
        let guard = shared.lock().map_err(|e| {
            format!("SharedAuditLedger lock poisoned during path tokenization: {e}")
        })?;
        return guard.tokenize_path(raw_path);
    }
    let ledger = AuditLedger::open_result(fallback_ledger_path)?;
    ledger.tokenize_path(raw_path)
}

/// Append-only Audit Ledger JSONL Record (`Master Plan v2 §4.2`, Invariant I5, `CERT-In Apr 2022` NTP telemetry).
///
/// Exact JSON schema: `{seq, ts, event, data, ntp_synchronized, clock_source, ntp_max_error_us, prev_hash, hash}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerRecord {
    pub seq: u64,
    #[serde(alias = "timestamp_utc")]
    pub ts: String,
    #[serde(alias = "event_type")]
    pub event: String,
    #[serde(alias = "details")]
    pub data: String,
    #[serde(default)]
    pub ntp_synchronized: bool,
    #[serde(default)]
    pub clock_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntp_max_error_us: Option<u64>,
    pub prev_hash: String,
    #[serde(alias = "record_hash")]
    pub hash: String,
}

/// Alias matching regulatory schema nomenclature (`Master Plan v2 Sub-Phase 2.2`, `CSE-14`).
pub type AuditEntry = LedgerRecord;

/// Asymmetric ECDSA P-256 Signed Chain-Head Checkpoint (`<ledger>.head.sig`, `Master Plan v2 §4.2`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    privacy_hmac_key: Option<ZeroizingBytes<32>>,
    init_error: Option<String>,
    next_seq: u64,
    last_hash: String,
}

impl AuditLedger {
    /// Opens or initializes the Audit Ledger, returning `Err` if directory creation, DACL hardening,
    /// existing ECDSA P-256 signing key unsealing, or sealed privacy HMAC key loading fails.
    pub fn open_result(ledger_path: impl Into<PathBuf>) -> Result<Self, String> {
        let ledger_path = ledger_path.into();
        if let Some(parent) = ledger_path.parent() {
            if !parent.as_os_str().is_empty() {
                create_restricted_dir_atomic(parent).map_err(|e| {
                    format!(
                        "Failed creating atomic restricted audit ledger directory {}: {}",
                        parent.display(),
                        e
                    )
                })?;
            }
        }

        let ecdsa_keypair = Self::load_or_init_ecdsa_key(&ledger_path)?;
        let privacy_hmac_key = Self::load_or_init_privacy_hmac_key(&ledger_path)?;
        let (next_seq, last_hash) = Self::scan_tail(&ledger_path)?;

        Ok(Self {
            ledger_path,
            ecdsa_keypair: Some(ecdsa_keypair),
            privacy_hmac_key: Some(privacy_hmac_key),
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
                    privacy_hmac_key: None,
                    init_error: Some(err),
                    next_seq: 1,
                    last_hash: GENESIS_PREV_HASH.to_string(),
                }
            }
        }
    }

    /// Tokenizes a sensitive filesystem/device path using this ledger's OS-sealed per-device
    /// 32-byte CSPRNG HMAC-SHA256 key (`privacy_hmac.sealed`, `GDPR`/`DPDP Act` / `CEA-DEFECT-06`).
    pub fn tokenize_path(&self, raw_path: &Path) -> Result<String, String> {
        let _ = self.check_healthy()?;
        let hmac_key = self.privacy_hmac_key.as_ref().ok_or_else(|| {
            "LEDGER_PRIVACY_KEY_FAIL: Per-device privacy HMAC key unavailable".to_string()
        })?;
        Ok(tokenize_path_for_privacy(hmac_key.as_slice(), raw_path))
    }

    pub fn path(&self) -> &Path {
        &self.ledger_path
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

    fn privacy_hmac_file_path(ledger_path: &Path) -> PathBuf {
        ledger_path.with_extension("privacy_hmac.sealed")
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

    fn privacy_hmac_context_string(ledger_path: &Path) -> String {
        format!(
            "OmniConnect-Sentinel-Ledger-Privacy-HMAC:{}",
            ledger_path.display()
        )
    }

    fn load_or_init_privacy_hmac_key(ledger_path: &Path) -> Result<ZeroizingBytes<32>, String> {
        static PRIVACY_HMAC_INIT_LOCK: Mutex<()> = Mutex::new(());
        let _guard = PRIVACY_HMAC_INIT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let hmac_path = Self::privacy_hmac_file_path(ledger_path);
        let context = Self::privacy_hmac_context_string(ledger_path);

        if hmac_path.exists() {
            let raw = fs::read(&hmac_path).map_err(|e| {
                format!(
                    "LEDGER_PRIVACY_KEY_FAIL: Failed reading existing privacy HMAC key {}: {}",
                    hmac_path.display(),
                    e
                )
            })?;
            let sealed: SealedKeyBlob = serde_json::from_slice(&raw).map_err(|e| {
                format!(
                    "LEDGER_PRIVACY_KEY_FAIL: Corrupted JSON in existing privacy HMAC key {}: {}",
                    hmac_path.display(),
                    e
                )
            })?;
            let mut unsealed = unseal_key_bytes(&sealed, context.as_bytes()).map_err(|e| {
                format!(
                    "LEDGER_PRIVACY_KEY_FAIL: Failed unsealing privacy HMAC key {}: {}",
                    hmac_path.display(),
                    e
                )
            })?;
            if unsealed.len() != 32 {
                zeroize_slice(&mut unsealed);
                return Err(format!(
                    "LEDGER_PRIVACY_KEY_FAIL: Unexpected privacy HMAC key length {} in {}",
                    unsealed.len(),
                    hmac_path.display()
                ));
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&unsealed);
            zeroize_slice(&mut unsealed);
            let secret = ZeroizingBytes::new(key_arr);
            zeroize_slice(&mut key_arr);
            return Ok(secret);
        }

        let mut raw_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_key);
        let secret = ZeroizingBytes::new(raw_key);
        zeroize_slice(&mut raw_key);

        let key_id = format!(
            "LEDGER-PRIVACY-HMAC-{}",
            hex::encode(Sha256::digest(context.as_bytes()))[..16].to_ascii_uppercase()
        );
        let sealed = seal_key_bytes(secret.as_slice(), context.as_bytes(), &key_id)
            .map_err(|e| format!("Failed sealing privacy HMAC key: {e}"))?;
        let json = serde_json::to_vec_pretty(&sealed)
            .map_err(|e| format!("Failed serializing privacy HMAC key: {e}"))?;
        write_protected_key_file(&hmac_path, &json).map_err(|e| {
            format!(
                "Failed persisting protected privacy HMAC key {}: {}",
                hmac_path.display(),
                e
            )
        })?;
        Ok(secret)
    }

    fn load_or_init_ecdsa_key(ledger_path: &Path) -> Result<SealedEcdsaKeyPair, String> {
        static LEDGER_KEY_INIT_LOCK: Mutex<()> = Mutex::new(());
        let _init_guard = LEDGER_KEY_INIT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        ensure_not_symlink_or_reparse_point(ledger_path).map_err(|e| {
            format!(
                "Refusing symlink/reparse ledger {}: {}",
                ledger_path.display(),
                e
            )
        })?;
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
        let _io_guard = LEDGER_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        self.append_event_locked(event, data_str)
    }

    fn append_event_locked(
        &mut self,
        event: &str,
        data_str: String,
    ) -> Result<LedgerRecord, String> {
        let _ = self.check_healthy()?;

        let (disk_next_seq, disk_last_hash) = Self::scan_tail(&self.ledger_path)?;
        self.next_seq = disk_next_seq;
        self.last_hash = disk_last_hash;

        let seq = self.next_seq;
        let ts = Utc::now().to_rfc3339();
        let ntp: NtpSyncStatus = query_ntp_sync_status();
        let prev_hash = self.last_hash.clone();
        let hash = Self::compute_record_hash_v2(
            seq,
            &ts,
            event,
            &data_str,
            (ntp.ntp_synchronized, &ntp.clock_source, ntp.max_error_us),
            &prev_hash,
        );

        let record = LedgerRecord {
            seq,
            ts,
            event: event.to_string(),
            data: data_str,
            ntp_synchronized: ntp.ntp_synchronized,
            clock_source: ntp.clock_source,
            ntp_max_error_us: ntp.max_error_us,
            prev_hash,
            hash: hash.clone(),
        };

        let mut line = serde_json::to_string(&record).map_err(|e| e.to_string())?;
        line.push('\n');

        let is_new_file = !self.ledger_path.exists();
        if is_new_file {
            let mut file = create_restricted_file_handle_atomic(&self.ledger_path)
                .map_err(|e| format!("Failed creating atomic restricted audit ledger: {e}"))?;
            file.write_all(line.as_bytes())
                .map_err(|e| format!("Failed appending to audit ledger: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("Failed syncing audit ledger: {e}"))?;
            if let Some(parent) = self.ledger_path.parent() {
                if !parent.as_os_str().is_empty() {
                    sync_directory(parent)
                        .map_err(|e| format!("Failed syncing ledger parent directory: {e}"))?;
                }
            }
        } else {
            ensure_not_symlink_or_reparse_point(&self.ledger_path).map_err(|e| {
                format!(
                    "Refusing to append to symlink/reparse audit ledger {}: {e}",
                    self.ledger_path.display()
                )
            })?;
            let mut file = OpenOptions::new()
                .append(true)
                .open(&self.ledger_path)
                .map_err(|e| format!("Failed opening audit ledger: {e}"))?;
            file.write_all(line.as_bytes())
                .map_err(|e| format!("Failed appending to audit ledger: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("Failed syncing audit ledger: {e}"))?;
        }

        self.next_seq = seq + 1;
        self.last_hash = hash.clone();

        // Sign the updated chain head with ECDSA P-256 and persist `<ledger>.head.sig`
        self.sign_chain_head_for_tip(seq, &hash)?;

        Ok(record)
    }

    /// Appends a subsystem-tagged JSONL record to the unified Audit Ledger (`CSE-13`).
    pub fn append_subsystem_event(
        &mut self,
        subsystem: AuditSubsystem,
        event: &str,
        event_data: serde_json::Value,
    ) -> Result<LedgerRecord, String> {
        let payload = serde_json::json!({
            "subsystem": subsystem.to_string(),
            "payload": event_data,
        });
        self.append_event(event, payload)
    }

    /// Emits a signed WORM checkpoint to the Audit Ledger (`Master Plan v2 §4.2`, `CSE-13`).
    pub fn emit_worm_checkpoint(&mut self) -> Result<SignedChainHead, String> {
        let _ = self.check_healthy()?;
        let _io_guard = LEDGER_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut disk_next_seq, mut disk_last_hash) = Self::scan_tail(&self.ledger_path)?;
        self.next_seq = disk_next_seq;
        self.last_hash = disk_last_hash.clone();

        if disk_next_seq <= 1 {
            let genesis = self.append_event_locked(
                "LEDGER_GENESIS_INIT",
                serde_json::json!({ "subsystem": "System", "status": "INITIALIZED" }).to_string(),
            )?;
            disk_next_seq = genesis.seq + 1;
            disk_last_hash = genesis.hash;
        }
        let head = self.sign_chain_head_for_tip(disk_next_seq - 1, &disk_last_hash)?;
        let ntp = query_ntp_sync_status();
        let checkpoint_data = serde_json::json!({
            "subsystem": "System",
            "checkpoint_type": "WORM_PERIODIC_60S",
            "head_seq": head.head_seq,
            "head_hash": head.head_hash,
            "signed_at_utc": head.signed_at_utc,
            "ntp_synchronized": ntp.ntp_synchronized,
            "clock_source": ntp.clock_source,
            "ntp_stratum": ntp.stratum,
            "ntp_max_error_us": ntp.max_error_us,
        });
        self.append_event_locked("LEDGER_WORM_CHECKPOINT", checkpoint_data.to_string())?;
        Ok(head)
    }

    /// Signs a domain-separated payload digest using the ledger's hardware/DPAPI/OS-sealed
    /// ECDSA P-256 keypair, returning `(public_key_blob, signature_64_bytes)` (`Sub-Phase 2.2`).
    pub fn sign_domain_payload(
        &self,
        domain_tag: &[u8],
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let keypair = self.check_healthy()?;
        let mut hasher = Sha256::new();
        hasher.update(domain_tag);
        hasher.update(payload);
        let digest_out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&digest_out);
        let context = Self::context_string(&self.ledger_path);
        let sig = sign_with_sealed_ecdsa_p256(keypair, context.as_bytes(), &digest)
            .map_err(|e| format!("ECDSA P-256 domain signing failed: {e}"))?;
        Ok((keypair.public_key_blob.clone(), sig))
    }

    /// Explicitly signs the current chain head (`head_seq|head_hash`) with the asymmetric
    /// ECDSA P-256 private key and writes `<ledger>.head.sig` atomically (`Master Plan v2 §4.2`).
    pub fn sign_chain_head(&self) -> Result<SignedChainHead, String> {
        let _ = self.check_healthy()?;
        let _io_guard = LEDGER_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (disk_next_seq, disk_last_hash) = Self::scan_tail(&self.ledger_path)?;
        if disk_next_seq <= 1 {
            return Err("Cannot sign chain head of an empty ledger".to_string());
        }
        self.sign_chain_head_for_tip(disk_next_seq - 1, &disk_last_hash)
    }

    fn sign_chain_head_for_tip(
        &self,
        head_seq: u64,
        head_hash: &str,
    ) -> Result<SignedChainHead, String> {
        let keypair = self.check_healthy()?;
        let digest = Self::compute_head_digest(head_seq, head_hash);
        let context = Self::context_string(&self.ledger_path);

        let sig_bytes = sign_with_sealed_ecdsa_p256(keypair, context.as_bytes(), &digest)
            .map_err(|e| format!("ECDSA P-256 chain-head signing failed: {e}"))?;

        let signed_head = SignedChainHead {
            head_seq,
            head_hash: head_hash.to_string(),
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
        let _io_guard = LEDGER_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());

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

            let recomputed_hash = if rec.clock_source.is_empty()
                && !rec.ntp_synchronized
                && rec.ntp_max_error_us.is_none()
            {
                Self::compute_record_hash(rec.seq, &rec.ts, &rec.event, &rec.data, &rec.prev_hash)
            } else {
                Self::compute_record_hash_v2(
                    rec.seq,
                    &rec.ts,
                    &rec.event,
                    &rec.data,
                    (
                        rec.ntp_synchronized,
                        &rec.clock_source,
                        rec.ntp_max_error_us,
                    ),
                    &rec.prev_hash,
                )
            };
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
            let head_path = Self::head_sig_path(&self.ledger_path);
            if head_path.exists() {
                return Err(format!(
                    "LEDGER_CHAIN_BROKEN: Ledger file is empty while signed chain-head checkpoint {} exists (total tail-truncation detected)",
                    head_path.display()
                ));
            }
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

    fn compute_record_hash_v2(
        seq: u64,
        ts: &str,
        event: &str,
        data: &str,
        ntp_telemetry: (bool, &str, Option<u64>),
        prev_hash: &str,
    ) -> String {
        let (ntp_synchronized, clock_source, ntp_max_error_us) = ntp_telemetry;
        let mut hasher = Sha256::new();
        hasher.update(b"SENTINEL-LEDGER-RECORD-V2\0");
        hasher.update(seq.to_le_bytes());
        hasher.update((ts.len() as u64).to_le_bytes());
        hasher.update(ts.as_bytes());
        hasher.update((event.len() as u64).to_le_bytes());
        hasher.update(event.as_bytes());
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data.as_bytes());
        hasher.update([u8::from(ntp_synchronized)]);
        hasher.update((clock_source.len() as u64).to_le_bytes());
        hasher.update(clock_source.as_bytes());
        match ntp_max_error_us {
            Some(v) => {
                hasher.update([1u8]);
                hasher.update(v.to_le_bytes());
            }
            None => {
                hasher.update([0u8]);
            }
        }
        hasher.update((prev_hash.len() as u64).to_le_bytes());
        hasher.update(prev_hash.as_bytes());
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
        if self.init_error.is_none()
            && self.ledger_path.exists()
            && !Self::head_sig_path(&self.ledger_path).exists()
        {
            let _ = self.sign_chain_head();
        }
    }
}
