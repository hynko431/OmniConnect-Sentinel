use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use uuid::Uuid;
use walkdir::WalkDir;

use sentinel_sys::{
    create_restricted_dir_atomic, create_restricted_file_atomic,
    ensure_not_symlink_or_reparse_point, enumerate_ntfs_ads, evaluate_strict_kiosk_key_posture,
    is_reparse_point_or_symlink, now_rfc3339_utc, open_untrusted_readonly_nofollow,
    query_ntp_sync_status, validate_p256_uncompressed_point, verify_ecdsa_p256_digest,
    verify_system_posture, zeroize_slice, KeyProtectionPosture, NtpSyncStatus, ZeroizingBytes,
};
pub use sentinel_sys::{HardwareWriteBlockerState, PostureReport};

use crate::enterprise::ledger::{
    tokenize_path_for_ledger, AuditLedger, AuditSubsystem, SharedAuditLedger,
};
use crate::scanner::secure_shredder::{SecureShredder, ShredMethod};

pub const PASSPORT_MANIFEST_FILENAME: &str = ".sentinel-passport.json";
pub const PASSPORT_PUBKEY_FILENAME: &str = ".sentinel-passport.pub.hex";
const PASSPORT_DOMAIN_TAG: &[u8] = b"OMNICONNECT-CDR-PASSPORT-V1:";

/// Individual sanitized file record inside `.sentinel-passport.json` (`Sub-Phase 2.2`, `CSE-14`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassportSanitizedFileEntry {
    pub rel_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub cdr_action: String,
}

/// Canonical unsigned payload serialized deterministically for ECDSA P-256 signing & verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CanonicalPassportSignable<'a> {
    schema_version: &'a str,
    passport_id: &'a str,
    kiosk_id: &'a str,
    session_id: &'a str,
    media_id: &'a str,
    issued_at_utc: &'a str,
    ntp_sync: &'a NtpSyncStatus,
    policy_id: &'a str,
    policy_sequence: u64,
    binary_exe_sha256: &'a str,
    binary_dep_v0_sha256: Option<&'a str>,
    sanitized_files: &'a [PassportSanitizedFileEntry],
    signature_algorithm: &'a str,
    public_key_blob_hex: &'a str,
}

/// Detached ECDSA P-256 Signed CDR Kiosk Sanitization Passport (`.sentinel-passport.json`, `Sub-Phase 2.2`, `CSE-14`, `CSE-17`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KioskSanitizationPassport {
    pub schema_version: String,
    pub passport_id: String,
    pub kiosk_id: String,
    pub session_id: String,
    pub media_id: String,
    pub issued_at_utc: String,
    pub ntp_sync: NtpSyncStatus,
    pub policy_id: String,
    pub policy_sequence: u64,
    /// Full streaming SHA-256 of the running kiosk executable (`ADR-014`, `CSE-17`).
    pub binary_exe_sha256: String,
    /// Exact SHA-256 of the embedded `cargo-auditable` `.dep-v0` PE/ELF section when present,
    /// or `None` when running a non-auditable binary (`ADR-014`, `CSE-17`). Never spoofs the full exe hash.
    pub binary_dep_v0_sha256: Option<String>,
    pub sanitized_files: Vec<PassportSanitizedFileEntry>,
    pub signature_algorithm: String,
    pub public_key_blob_hex: String,
    pub ecdsa_p256_signature_hex: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KioskPathError {
    #[error("Path traversal rejected: path contains '..' or parent-directory components: {0}")]
    PathTraversal(String),
    #[error("Absolute or drive-prefixed path rejected (must be relative): {0}")]
    AbsolutePath(String),
    #[error("Prohibited NTFS alternate data stream (ADS) ':' detected: {0}")]
    AlternateDataStream(String),
    #[error("Prohibited control or null character detected in path: {0}")]
    ControlCharacter(String),
    #[error("Prohibited Unicode directional override or bidi smuggling character detected: {0}")]
    BidiOverride(String),
    #[error("Prohibited DOS legacy device name detected ({0}): {1}")]
    DosDeviceName(String, String),
    #[error("Empty or invalid relative path: {0}")]
    EmptyPath(String),
    #[error("Invalid media_id '{0}': must match ^[A-Za-z0-9_-]{{1,64}}$")]
    InvalidMediaId(String),
}

/// Validates that a media identifier matches strictly `^[A-Za-z0-9_-]{1,64}$` (`T34`).
pub fn is_valid_media_id(media_id: &str) -> bool {
    !media_id.is_empty()
        && media_id.len() <= 64
        && media_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Sanitizes an untrusted kiosk relative path, strictly rejecting traversal (`..`), `.` (`CurDir`),
/// root/prefixes, empty/double-slash segments, NTFS alternate data streams (`:`), non-UTF-8 bytes,
/// control/invisible/Unicode-whitespace characters, leading/trailing component whitespace,
/// Unicode bidi overrides, and DOS device stems (`T34`, `CSE-11`, `CSE-14`).
pub fn sanitize_strict_relative_subpath(raw_path: &Path) -> Result<PathBuf, KioskPathError> {
    use std::path::Component;

    let path_str = raw_path.to_str().ok_or_else(|| {
        KioskPathError::ControlCharacter(format!(
            "Invalid non-UTF-8 bytes prohibited in path: {}",
            raw_path.display()
        ))
    })?;

    // Check for NUL, ASCII C0/DEL control chars (< 0x20, 0x7F), C1 control chars (U+0080..=U+009F),
    // zero-width/invisible format chars, and non-ASCII Unicode whitespace (e.g. U+00A0 NBSP)
    // BEFORE `.trim().is_empty()` so `" \t \n "` triggers ControlCharacter while `"   "` triggers EmptyPath.
    for ch in path_str.chars() {
        let cp = ch as u32;
        if cp < 0x20
            || cp == 0x7F
            || (0x0080..=0x009F).contains(&cp)
            || matches!(
                ch,
                '\u{00AD}' | '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
            )
            || (ch.is_whitespace() && ch != ' ')
        {
            return Err(KioskPathError::ControlCharacter(format!(
                "Codepoint U+{cp:04X} prohibited in path: {path_str}"
            )));
        }
    }

    if path_str.trim().is_empty() {
        return Err(KioskPathError::EmptyPath("Path is empty".to_string()));
    }

    // Check for Unicode Bidi directional overrides & isolates
    for ch in path_str.chars() {
        match ch {
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}' | '\u{202B}' | '\u{202C}'
            | '\u{202D}' | '\u{202E}' | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}' => {
                return Err(KioskPathError::BidiOverride(format!(
                    "Unicode directional character U+{:04X} prohibited in path: {}",
                    ch as u32, path_str
                )));
            }
            _ => {}
        }
    }

    // Check for NTFS Alternate Data Streams (ADS) ':'
    if path_str.contains(':') {
        return Err(KioskPathError::AlternateDataStream(format!(
            "NTFS ADS separator ':' prohibited in path: {path_str}"
        )));
    }

    // Reject leading separators as absolute paths and trailing/repeated/dot segments
    // BEFORE `raw_path.components()` (since Rust `Path::components()` silently strips intermediate `/./`!)
    if path_str.starts_with('/') || path_str.starts_with('\\') {
        return Err(KioskPathError::AbsolutePath(format!(
            "Leading separator prohibited in relative path: {path_str}"
        )));
    }
    for raw_seg in path_str.split(['/', '\\']) {
        if raw_seg.is_empty() || raw_seg == "." || raw_seg == ".." {
            return Err(KioskPathError::PathTraversal(format!(
                "Empty, '.', or '..' segment '{raw_seg}' prohibited in strict relative path: {path_str}"
            )));
        }
    }

    const DOS_DEVICE_NAMES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    let mut sanitized = PathBuf::new();
    let mut component_count = 0;

    for comp in raw_path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                return Err(KioskPathError::AbsolutePath(format!(
                    "Absolute or drive-prefixed path prohibited: {}",
                    raw_path.display()
                )));
            }
            Component::ParentDir => {
                return Err(KioskPathError::PathTraversal(format!(
                    "Parent directory traversal '..' prohibited: {}",
                    raw_path.display()
                )));
            }
            Component::CurDir => {
                return Err(KioskPathError::PathTraversal(format!(
                    "Current-directory '.' component prohibited in strict relative path: {}",
                    raw_path.display()
                )));
            }
            Component::Normal(os_name) => {
                let name = os_name.to_str().ok_or_else(|| {
                    KioskPathError::ControlCharacter(format!(
                        "Non-UTF-8 path component prohibited: {}",
                        raw_path.display()
                    ))
                })?;
                if name.is_empty() {
                    return Err(KioskPathError::PathTraversal(format!(
                        "Empty path component prohibited: {}",
                        raw_path.display()
                    )));
                }

                // Strictly reject leading or trailing whitespace (`safe/ report.pdf`, `safe/report.pdf `)
                // instead of silently mutating or skipping components (`[CEA-DEFECT-01]`).
                if name != name.trim() {
                    return Err(KioskPathError::PathTraversal(format!(
                        "Leading or trailing whitespace prohibited in path component '{name}': {}",
                        raw_path.display()
                    )));
                }

                // Reject dot-only sequences (e.g., '...', '....') and trailing dots
                if name.chars().all(|c| c == '.') {
                    return Err(KioskPathError::PathTraversal(format!(
                        "Dot-only sequence '{name}' prohibited: {}",
                        raw_path.display()
                    )));
                }
                if name.ends_with('.') {
                    return Err(KioskPathError::PathTraversal(format!(
                        "Trailing dot prohibited in component '{name}': {}",
                        raw_path.display()
                    )));
                }

                // Extract base stem before any dot
                let stem = name.split('.').next().unwrap_or("").trim();
                for &dos_name in DOS_DEVICE_NAMES {
                    if stem.eq_ignore_ascii_case(dos_name) {
                        return Err(KioskPathError::DosDeviceName(
                            dos_name.to_string(),
                            format!("Component '{name}' in path '{}'", raw_path.display()),
                        ));
                    }
                }

                sanitized.push(name);
                component_count += 1;
            }
        }
    }

    if component_count == 0 {
        return Err(KioskPathError::EmptyPath(format!(
            "Normalized path is empty: {}",
            raw_path.display()
        )));
    }

    Ok(sanitized)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KioskConfig {
    pub kiosk_id: String,
    pub max_session_minutes: u32,
    pub wipe_cache_on_unplug: bool,
    pub block_executable_extensions: bool,
}

impl Default for KioskConfig {
    fn default() -> Self {
        Self {
            kiosk_id: "KIOSK-TERMINAL-001".to_string(),
            max_session_minutes: 15,
            wipe_cache_on_unplug: true,
            block_executable_extensions: true,
        }
    }
}

/// Public Kiosk Isolation & Ephemeral Session Controller (`BUG-CORE-07`, `BUG-CORE-13`, `Rows 23, 168`, Phase 4.1 & 4.2)
///
/// Combines recursive bottom-up streaming file sanitization (`WalkDir::contents_first(true)` +
/// `SecureShredder::shred_file` with 64 KB chunks, zero whole-file allocation), per-session
/// cryptographic key destruction (`ZeroizingBytes<32>`), and tamper-evident `AuditLedger` logging.
pub struct KioskEnforcer {
    config: KioskConfig,
    session_dir: PathBuf,
    ledger_path: PathBuf,
    shared_ledger: Option<SharedAuditLedger>,
    active_session_id: Option<String>,
    active_session_key: Option<ZeroizingBytes<32>>,
}

pub type AirGappedKioskManager = KioskEnforcer;

impl KioskEnforcer {
    pub fn new(config: KioskConfig, session_dir: PathBuf) -> Self {
        let _ = create_restricted_dir_atomic(&session_dir);
        let ledger_path = default_kiosk_ledger_path(&session_dir);
        Self {
            config,
            session_dir,
            ledger_path,
            shared_ledger: None,
            active_session_id: None,
            active_session_key: None,
        }
    }

    pub fn from_terminal_id(kiosk_id: String, session_dir: PathBuf) -> Self {
        Self::new(
            KioskConfig {
                kiosk_id,
                ..KioskConfig::default()
            },
            session_dir,
        )
    }

    pub fn with_ledger_path(mut self, ledger_path: PathBuf) -> Self {
        self.ledger_path = ledger_path;
        self.shared_ledger = None;
        self
    }

    pub fn with_shared_ledger(mut self, shared_ledger: SharedAuditLedger) -> Self {
        if let Ok(guard) = shared_ledger.lock() {
            self.ledger_path = guard.path().to_path_buf();
        }
        self.shared_ledger = Some(shared_ledger);
        self
    }

    pub fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    fn tokenize_kiosk_path(&self, raw_path: &Path) -> String {
        tokenize_path_for_ledger(self.shared_ledger.as_ref(), &self.ledger_path, raw_path)
            .unwrap_or_else(|_| "TOKENIZE_ERR".to_string())
    }

    fn append_kiosk_event(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        if let Some(ref shared) = self.shared_ledger {
            let mut guard = shared
                .lock()
                .map_err(|e| format!("Kiosk shared ledger mutex poisoned: {e}"))?;
            guard.append_subsystem_event(AuditSubsystem::Kiosk, event, data)?;
            return Ok(());
        }
        let mut ledger = AuditLedger::open_result(&self.ledger_path)?;
        ledger.append_subsystem_event(AuditSubsystem::Kiosk, event, data)?;
        Ok(())
    }

    /// Formats an honest Pivot A hardware write-blocker posture banner for Kiosk UI/CLI output (`CSE-27`).
    pub fn format_hardware_write_blocker_banner(state: &HardwareWriteBlockerState) -> String {
        match state {
            HardwareWriteBlockerState::NotDetected => {
                "HW-WRITE-BLOCKER: NOT_DETECTED (software OS write-protect only)".to_string()
            }
            HardwareWriteBlockerState::Bay1RoOnly {
                bay1_device,
                bay1_readonly_verified,
            } => format!(
                "HW-WRITE-BLOCKER: BAY1_RO_VERIFIED (bay1={bay1_device}, readonly={bay1_readonly_verified})"
            ),
            HardwareWriteBlockerState::DualBayVerified {
                bay1_ro_device,
                bay2_rw_device,
            } => format!(
                "HW-WRITE-BLOCKER: DUAL_BAY_VERIFIED (bay1_ro={bay1_ro_device}, bay2_rw={bay2_rw_device})"
            ),
            HardwareWriteBlockerState::Faulted { reason } => {
                format!("HW-WRITE-BLOCKER: FAULTED ({reason})")
            }
        }
    }

    pub fn verify_posture(&self) -> PostureReport {
        let report = verify_system_posture();
        let _ = self.append_kiosk_event(
            "KIOSK_POSTURE_VERIFIED",
            serde_json::json!({
                "kiosk_id": self.config.kiosk_id,
                "compliant": report.is_compliant(),
                "automount_disabled": report.automount_disabled,
                "user_deny_policy_present": report.user_deny_policy_present,
                "install_restrictions_active": report.install_restrictions_active,
                "write_protect_active": report.write_protect_active,
                "hardware_write_blocker": report.hardware_write_blocker,
            }),
        );
        report
    }

    /// Queries the live OS registry StorageDevicePolicies WriteProtect posture (`BUG-CORE-13`).
    pub fn verify_write_blocking_active(&self) -> bool {
        self.verify_posture().write_protect_active
    }

    /// Enforces `PostureReport::is_compliant()` and strict key protection posture (refusing
    /// file-backed `KeyProtectionPosture::UnixLocalKeyring` fallback on Linux with `POSTURE_REDUCED_NO_TPM`,
    /// `CSE-28`) before starting a strict kiosk session, recording the decision in `AuditLedger`.
    ///
    /// Resolves key posture fail-closed from either `self.shared_ledger` or
    /// `AuditLedger::open_result(&self.ledger_path)?` so callers without a shared ledger cannot
    /// bypass `evaluate_strict_kiosk_key_posture`.
    pub fn begin_kiosk_session_with_posture(
        &mut self,
        posture: &PostureReport,
    ) -> Result<String, String> {
        let resolved_key_posture = if let Some(ref shared) = self.shared_ledger {
            let guard = shared
                .lock()
                .map_err(|e| format!("Kiosk shared ledger mutex poisoned: {e}"))?;
            guard.key_posture().ok_or_else(|| {
                "POSTURE_REDUCED_NO_TPM: Refusing strict kiosk session because attached AuditLedger signing key posture is unavailable"
                    .to_string()
            })?
        } else {
            let ledger = AuditLedger::open_result(&self.ledger_path)?;
            ledger.key_posture().ok_or_else(|| {
                "POSTURE_REDUCED_NO_TPM: Refusing strict kiosk session because AuditLedger signing key posture is unavailable"
                    .to_string()
            })?
        };
        self.begin_kiosk_session_with_posture_and_key_posture(posture, resolved_key_posture)
    }

    /// Enforces both `PostureReport::is_compliant()` AND `evaluate_strict_kiosk_key_posture(key_posture)`
    /// (`CSE-28`): refuses strict kiosk startup fail-closed if the host fell back to plaintext file-backed
    /// `KeyProtectionPosture::UnixLocalKeyring` (`master.seed`), logging `KIOSK_POSTURE_BLOCKED` +
    /// `POSTURE_REDUCED_NO_TPM` in the tamper-evident `AuditLedger`.
    pub fn begin_kiosk_session_with_posture_and_key_posture(
        &mut self,
        posture: &PostureReport,
        key_posture: KeyProtectionPosture,
    ) -> Result<String, String> {
        if !posture.is_compliant() {
            self.append_kiosk_event(
                "KIOSK_POSTURE_BLOCKED",
                serde_json::json!({
                    "status": "KIOSK_SESSION_REJECTED",
                    "kiosk_id": self.config.kiosk_id,
                    "automount_disabled": posture.automount_disabled,
                    "user_deny_policy_present": posture.user_deny_policy_present,
                    "install_restrictions_active": posture.install_restrictions_active,
                    "write_protect_active": posture.write_protect_active,
                    "hardware_write_blocker": posture.hardware_write_blocker,
                    "key_protection_posture": key_posture,
                }),
            )?;
            return Err(format!(
                "Refusing to start strict kiosk session: system posture non-compliant (automount_disabled={}, user_deny_policy_present={}, install_restrictions_active={}, write_protect_active={}, hardware_write_blocker={:?})",
                posture.automount_disabled,
                posture.user_deny_policy_present,
                posture.install_restrictions_active,
                posture.write_protect_active,
                posture.hardware_write_blocker
            ));
        }

        if let Err(reason) = evaluate_strict_kiosk_key_posture(key_posture) {
            self.append_kiosk_event(
                "KIOSK_POSTURE_BLOCKED",
                serde_json::json!({
                    "status": "KIOSK_SESSION_REJECTED",
                    "kiosk_id": self.config.kiosk_id,
                    "reduced_posture_event": "POSTURE_REDUCED_NO_TPM",
                    "key_protection_posture": key_posture,
                    "reason": "FILE_BACKED_KEY_FALLBACK_REFUSED_IN_STRICT_KIOSK",
                }),
            )?;
            return Err(reason);
        }

        let session_id = self.begin_kiosk_session();
        self.append_kiosk_event(
            "KIOSK_SESSION_STARTED",
            serde_json::json!({
                "kiosk_id": self.config.kiosk_id,
                "session_id": session_id,
                "session_dir_token": self.tokenize_kiosk_path(&self.session_dir),
                "posture_verified": true,
                "key_protection_posture": key_posture,
            }),
        )?;
        Ok(session_id)
    }

    pub fn begin_kiosk_session(&mut self) -> String {
        let session_id = format!("KSESS-{}", Uuid::new_v4());
        let mut raw_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_key);

        let _ = create_restricted_dir_atomic(&self.session_dir);
        self.active_session_id = Some(session_id.clone());
        self.active_session_key = Some(ZeroizingBytes::new(raw_key));
        zeroize_slice(&mut raw_key);

        let _ = self.append_kiosk_event(
            "KIOSK_SESSION_STARTED",
            serde_json::json!({
                "kiosk_id": self.config.kiosk_id,
                "session_id": session_id,
                "session_dir_token": self.tokenize_kiosk_path(&self.session_dir),
            }),
        );

        info!(
            "Kiosk session '{}' started on terminal '{}' (dir: {})",
            session_id,
            self.config.kiosk_id,
            self.session_dir.display()
        );
        session_id
    }

    pub fn start_kiosk_session(
        &mut self,
        media_id: &str,
    ) -> Result<(String, PathBuf), KioskPathError> {
        if !is_valid_media_id(media_id) {
            return Err(KioskPathError::InvalidMediaId(media_id.to_string()));
        }
        let session_id = format!("KSESS-{}-{}", media_id, Uuid::new_v4());
        let session_subdir = self.session_dir.join(&session_id);
        create_restricted_dir_atomic(&session_subdir).map_err(|e| {
            KioskPathError::PathTraversal(format!(
                "Failed creating restricted kiosk session subdir '{}': {e}",
                session_subdir.display()
            ))
        })?;

        let mut raw_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_key);

        self.active_session_id = Some(session_id.clone());
        self.active_session_key = Some(ZeroizingBytes::new(raw_key));
        zeroize_slice(&mut raw_key);

        // Encrypt an initial session state envelope under the per-session AES-256-GCM key (`Row 65`)
        let rel_manifest = PathBuf::from(&session_id).join(".session_envelope.enc");
        let _ = self.write_encrypted_session_file(&rel_manifest, session_id.as_bytes());

        let _ = self.append_kiosk_event(
            "KIOSK_SESSION_STARTED",
            serde_json::json!({
                "kiosk_id": self.config.kiosk_id,
                "session_id": session_id,
                "media_id": media_id,
                "session_subdir_token": self.tokenize_kiosk_path(&session_subdir),
            }),
        );

        Ok((session_id, session_subdir))
    }

    /// Encrypts `plaintext` with AES-256-GCM using the active session's `ZeroizingBytes<32>` key
    /// (`self.active_session_key`) and writes `[12-byte nonce][ciphertext]` into `self.session_dir` (`Row 65`).
    pub fn write_encrypted_session_file(
        &self,
        relative_path: &Path,
        plaintext: &[u8],
    ) -> Result<PathBuf, String> {
        let clean_rel = sanitize_strict_relative_subpath(relative_path)
            .map_err(|e| format!("Kiosk path validation failed: {e}"))?;

        let session_key = self
            .active_session_key
            .as_ref()
            .ok_or_else(|| "Cannot encrypt kiosk file: no active kiosk session key".to_string())?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key.as_slice()));
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let rel_str = clean_rel.to_string_lossy();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: rel_str.as_bytes(),
                },
            )
            .map_err(|e| format!("Kiosk AES-256-GCM encryption failed: {e}"))?;

        let out_path = self.session_dir.join(&clean_rel);
        if let Some(parent) = out_path.parent() {
            create_restricted_dir_atomic(parent).map_err(|e| {
                format!(
                    "Failed creating restricted kiosk session subdirectory '{}': {}",
                    parent.display(),
                    e
                )
            })?;
        }

        let mut payload = Vec::with_capacity(12 + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);

        create_restricted_file_atomic(&out_path, &payload).map_err(|e| {
            format!(
                "Failed creating atomic restricted encrypted kiosk session file '{}': {}",
                out_path.display(),
                e
            )
        })?;

        Ok(out_path)
    }

    /// Decrypts a kiosk session file written by `write_encrypted_session_file` using the active
    /// session's `ZeroizingBytes<32>` AES-256-GCM key (`Row 65`).
    pub fn read_encrypted_session_file(&self, relative_path: &Path) -> Result<Vec<u8>, String> {
        let clean_rel = sanitize_strict_relative_subpath(relative_path)
            .map_err(|e| format!("Kiosk path validation failed: {e}"))?;

        let session_key = self.active_session_key.as_ref().ok_or_else(|| {
            "Cannot decrypt kiosk file: session key has been destroyed or no active session"
                .to_string()
        })?;

        let in_path = self.session_dir.join(&clean_rel);
        let payload = fs::read(&in_path).map_err(|e| {
            format!(
                "Failed reading encrypted kiosk session file '{}': {}",
                in_path.display(),
                e
            )
        })?;
        if payload.len() < 12 + 16 {
            return Err(format!(
                "Encrypted kiosk file '{}' is truncated ({} bytes)",
                in_path.display(),
                payload.len()
            ));
        }

        let (nonce_bytes, ciphertext) = payload.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key.as_slice()));
        let rel_str = clean_rel.to_string_lossy();
        cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: rel_str.as_bytes(),
                },
            )
            .map_err(|_| {
                format!(
                    "AES-256-GCM authentication tag verification failed for kiosk file '{}'",
                    in_path.display()
                )
            })
    }

    /// Alias for `end_kiosk_session` (`Sub-Phase 3.1`).
    pub fn end_session_and_shred(&mut self) -> Result<u64, String> {
        self.end_kiosk_session()
    }

    /// Recursively shreds all files and subdirectories inside `self.session_dir`
    /// using bounded 64 KB streaming chunks (`SecureShredder::shred_file`),
    /// destroys the in-memory session key (`BUG-CORE-07`, `Row 65`), and records the outcome
    /// in the tamper-evident `AuditLedger` (`Rows 23, 168`).
    pub fn end_kiosk_session(&mut self) -> Result<u64, String> {
        let session_id = self
            .active_session_id
            .take()
            .unwrap_or_else(|| "UNTRACKED-SESSION".to_string());

        // Destroy per-session key in memory immediately (ZeroizingBytes<32>::drop)
        if let Some(dropped_key) = self.active_session_key.take() {
            drop(dropped_key);
        }

        if !self.config.wipe_cache_on_unplug || !self.session_dir.exists() {
            self.append_kiosk_event(
                "KIOSK_SESSION_ENDED",
                serde_json::json!({
                    "kiosk_id": self.config.kiosk_id,
                    "session_id": session_id,
                    "wiped_files_count": 0,
                    "key_destroyed": true,
                }),
            )?;
            return Ok(0);
        }

        let mut wiped_files_count: u64 = 0;
        let mut wipe_errors: Vec<String> = Vec::new();
        let mut redacted_wipe_errors: Vec<String> = Vec::new();

        // Bottom-up walk (`contents_first(true)`) so nested files are shredded before their parent directories
        for entry_res in WalkDir::new(&self.session_dir)
            .contents_first(true)
            .follow_links(false)
        {
            let entry = match entry_res {
                Ok(e) => e,
                Err(err) => {
                    warn!("Kiosk session walk error: {}", err);
                    wipe_errors.push(format!("Walk error: {err}"));
                    redacted_wipe_errors.push("Walk error (path redacted)".to_string());
                    continue;
                }
            };

            let path = entry.path();
            if path == self.session_dir {
                continue;
            }

            let is_link_or_reparse = entry.path_is_symlink()
                || fs::symlink_metadata(path)
                    .map(|m| is_reparse_point_or_symlink(&m))
                    .unwrap_or(true);

            if is_link_or_reparse {
                // CRITICAL (#1, Row 67, BUG-CORE-07): Never pass symlinks or NTFS junctions to
                // `SecureShredder::shred_file`. Remove the link itself without touching its target.
                if let Err(e) = fs::remove_file(path).or_else(|_| fs::remove_dir(path)) {
                    warn!(
                        "Failed removing symlink/reparse point '{}' in kiosk session: {}",
                        path.display(),
                        e
                    );
                    wipe_errors.push(format!(
                        "Failed unlinking symlink/reparse '{}': {}",
                        path.display(),
                        e
                    ));
                    redacted_wipe_errors.push(format!(
                        "Failed unlinking symlink/reparse token '{}'",
                        self.tokenize_kiosk_path(path)
                    ));
                }
                continue;
            }

            if entry.file_type().is_file() {
                let shred_res = if let Some(ref shared) = self.shared_ledger {
                    SecureShredder::shred_file_with_shared_ledger(
                        path,
                        ShredMethod::ClearMultiPass { passes: 3 },
                        Some(shared),
                    )
                } else {
                    SecureShredder::shred_file_with_ledger(
                        path,
                        ShredMethod::ClearMultiPass { passes: 3 },
                        &self.ledger_path,
                    )
                };
                match shred_res {
                    Ok(_) => {
                        wiped_files_count += 1;
                    }
                    Err(e) => {
                        warn!("Kiosk SecureShredder error for '{}': {}", path.display(), e);
                        wipe_errors.push(format!("Shred failed for '{}': {}", path.display(), e));
                        redacted_wipe_errors.push(format!(
                            "Shred failed for token '{}'",
                            self.tokenize_kiosk_path(path)
                        ));
                    }
                }
            } else if entry.file_type().is_dir() {
                if let Err(e) = fs::remove_dir(path) {
                    warn!(
                        "Failed removing kiosk session directory '{}': {}",
                        path.display(),
                        e
                    );
                    wipe_errors.push(format!(
                        "Directory remove failed for '{}': {}",
                        path.display(),
                        e
                    ));
                    redacted_wipe_errors.push(format!(
                        "Directory remove failed for token '{}'",
                        self.tokenize_kiosk_path(path)
                    ));
                }
            }
        }

        if !wipe_errors.is_empty() {
            let _ = self.append_kiosk_event(
                "KIOSK_SESSION_WIPE_ERROR",
                serde_json::json!({
                    "kiosk_id": self.config.kiosk_id,
                    "session_id": session_id,
                    "wiped_files_count": wiped_files_count,
                    "errors": redacted_wipe_errors,
                }),
            );
            return Err(format!(
                "Kiosk session '{}' wipe encountered {} error(s): {}",
                session_id,
                wipe_errors.len(),
                wipe_errors.join("; ")
            ));
        }

        self.append_kiosk_event(
            "KIOSK_SESSION_ENDED",
            serde_json::json!({
                "kiosk_id": self.config.kiosk_id,
                "session_id": session_id,
                "wiped_files_count": wiped_files_count,
                "key_destroyed": true,
            }),
        )?;

        info!(
            "Kiosk session '{}' terminated. Recursively shredded {} files in {}",
            session_id,
            wiped_files_count,
            self.session_dir.display()
        );
        Ok(wiped_files_count)
    }

    /// Exports a batch of sanitized files `(relative_path, clean_bytes, cdr_action)` into `export_dir`
    /// and writes a detached ECDSA P-256 signed `.sentinel-passport.json` manifest (`Sub-Phase 2.2`, `CSE-14`).
    pub fn export_sanitized_batch_with_passport(
        &self,
        export_dir: &Path,
        media_id: &str,
        policy_id: &str,
        policy_sequence: u64,
        sanitized_batch: &[(PathBuf, Vec<u8>, String)],
    ) -> Result<KioskSanitizationPassport, String> {
        if !is_valid_media_id(media_id) {
            return Err(format!(
                "Invalid media_id '{media_id}': must match ^[A-Za-z0-9_-]{{1,64}}$"
            ));
        }
        ensure_not_symlink_or_reparse_point(export_dir).map_err(|e| {
            format!(
                "Refusing kiosk export to symlink/reparse directory '{}': {e}",
                export_dir.display()
            )
        })?;
        match fs::symlink_metadata(export_dir) {
            Ok(meta) => {
                if is_reparse_point_or_symlink(&meta) || !meta.is_dir() {
                    return Err(format!(
                        "Refusing kiosk export: '{}' is a symlink, reparse point, or non-directory",
                        export_dir.display()
                    ));
                }
            }
            Err(_) => {
                if let Some(parent) = export_dir.parent() {
                    if !parent.as_os_str().is_empty() {
                        ensure_not_symlink_or_reparse_point(parent).map_err(|e| {
                            format!(
                                "Refusing kiosk export: parent '{}' is a symlink/reparse point: {e}",
                                parent.display()
                            )
                        })?;
                    }
                }
                fs::create_dir_all(export_dir).map_err(|e| {
                    format!(
                        "Failed creating kiosk export directory '{}': {e}",
                        export_dir.display()
                    )
                })?;
                ensure_not_symlink_or_reparse_point(export_dir).map_err(|e| {
                    format!(
                        "Created kiosk export directory '{}' failed symlink/reparse check: {e}",
                        export_dir.display()
                    )
                })?;
            }
        }

        let mut action_overrides = std::collections::HashMap::new();
        for (rel_path, clean_bytes, cdr_action) in sanitized_batch {
            let clean_rel = sanitize_strict_relative_subpath(rel_path)
                .map_err(|e| format!("Export path rejected: {e}"))?;
            let norm_rel = normalize_forward_slash_path(&clean_rel);
            if norm_rel == PASSPORT_MANIFEST_FILENAME || norm_rel == PASSPORT_PUBKEY_FILENAME {
                return Err(format!("Reserved passport filename prohibited: {norm_rel}"));
            }
            let components: Vec<_> = clean_rel.components().collect();
            let mut cur_dir = export_dir.to_path_buf();
            for comp in components.iter().take(components.len().saturating_sub(1)) {
                cur_dir.push(comp);
                ensure_not_symlink_or_reparse_point(&cur_dir).map_err(|e| {
                    format!(
                        "Export subdirectory '{}' is a symlink/reparse point: {e}",
                        cur_dir.display()
                    )
                })?;
                if fs::symlink_metadata(&cur_dir).is_err() {
                    fs::create_dir(&cur_dir).map_err(|e| {
                        format!(
                            "Failed creating export subdirectory '{}': {e}",
                            cur_dir.display()
                        )
                    })?;
                }
                let sub_meta = fs::symlink_metadata(&cur_dir).map_err(|e| {
                    format!(
                        "Failed verifying export subdirectory '{}': {e}",
                        cur_dir.display()
                    )
                })?;
                if is_reparse_point_or_symlink(&sub_meta) || !sub_meta.is_dir() {
                    return Err(format!(
                        "Export subdirectory '{}' is a symlink/reparse point or non-directory",
                        cur_dir.display()
                    ));
                }
            }
            let dest = export_dir.join(&clean_rel);
            ensure_not_symlink_or_reparse_point(&dest).map_err(|e| {
                format!(
                    "Destination '{}' is a symlink/reparse point: {e}",
                    dest.display()
                )
            })?;
            fs::write(&dest, clean_bytes).map_err(|e| {
                format!("Failed writing sanitized export '{}': {e}", dest.display())
            })?;
            action_overrides.insert(norm_rel, cdr_action.clone());
        }

        self.generate_passport_for_directory_with_actions(
            export_dir,
            media_id,
            policy_id,
            policy_sequence,
            &action_overrides,
            "DEEP_CDR_SANITIZED",
        )
    }

    /// Generates and signs `.sentinel-passport.json` across all sanitized files in `export_dir`
    /// using bounded 64 KiB `O_NOFOLLOW` streaming SHA-256 reads (`Sub-Phase 2.2`, `CSE-14`).
    pub fn generate_passport_for_directory(
        &self,
        export_dir: &Path,
        media_id: &str,
        policy_id: &str,
        policy_sequence: u64,
        default_cdr_action: &str,
    ) -> Result<KioskSanitizationPassport, String> {
        let empty = std::collections::HashMap::new();
        self.generate_passport_for_directory_with_actions(
            export_dir,
            media_id,
            policy_id,
            policy_sequence,
            &empty,
            default_cdr_action,
        )
    }

    fn generate_passport_for_directory_with_actions(
        &self,
        export_dir: &Path,
        media_id: &str,
        policy_id: &str,
        policy_sequence: u64,
        action_overrides: &std::collections::HashMap<String, String>,
        default_cdr_action: &str,
    ) -> Result<KioskSanitizationPassport, String> {
        if !is_valid_media_id(media_id) {
            return Err(format!(
                "Invalid media_id '{media_id}': must match ^[A-Za-z0-9_-]{{1,64}}$"
            ));
        }
        if policy_id.trim().is_empty() {
            return Err("Passport policy_id must not be empty".to_string());
        }
        ensure_not_symlink_or_reparse_point(export_dir).map_err(|e| {
            format!(
                "Export directory '{}' failed symlink/reparse check: {e}",
                export_dir.display()
            )
        })?;
        let export_meta = fs::symlink_metadata(export_dir).map_err(|e| {
            format!(
                "Export directory '{}' metadata error: {e}",
                export_dir.display()
            )
        })?;
        if is_reparse_point_or_symlink(&export_meta) || !export_meta.is_dir() {
            return Err(format!(
                "Export directory '{}' is a symlink, reparse point, or non-directory",
                export_dir.display()
            ));
        }
        ensure_no_ntfs_ads(export_dir, "Refusing to issue CDR passport")?;

        let mut entries = Vec::new();
        let mut seen_dirs = Vec::new();
        for item_res in WalkDir::new(export_dir).follow_links(false) {
            let item = item_res.map_err(|e| format!("Export directory walk error: {e}"))?;
            let path = item.path();
            if path == export_dir {
                continue;
            }
            let sym_meta = fs::symlink_metadata(path)
                .map_err(|e| format!("Failed reading metadata for '{}': {e}", path.display()))?;
            if item.path_is_symlink() || is_reparse_point_or_symlink(&sym_meta) {
                return Err(format!(
                    "Refusing to issue CDR passport: symlink or reparse point detected at '{}'",
                    path.display()
                ));
            }
            ensure_no_ntfs_ads(path, "Refusing to issue CDR passport")?;
            if !sym_meta.is_file() && !sym_meta.is_dir() {
                return Err(format!(
                    "Refusing to issue CDR passport: non-regular special file detected at '{}'",
                    path.display()
                ));
            }
            let rel = path
                .strip_prefix(export_dir)
                .map_err(|e| format!("Failed computing relative path: {e}"))?;
            if sym_meta.is_dir() {
                let clean_dir = sanitize_strict_relative_subpath(rel).map_err(|e| {
                    format!("Refusing to issue CDR passport: invalid directory path: {e}")
                })?;
                seen_dirs.push(normalize_forward_slash_path(&clean_dir));
                continue;
            }
            let file_name = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if rel.components().count() == 1
                && (file_name == PASSPORT_MANIFEST_FILENAME
                    || file_name == PASSPORT_PUBKEY_FILENAME)
            {
                continue;
            }
            let clean_rel = sanitize_strict_relative_subpath(rel)
                .map_err(|e| format!("Exported file failed strict relative path check: {e}"))?;
            let norm_rel = normalize_forward_slash_path(&clean_rel);
            let (size_bytes, sha256) = hash_file_streaming_64k(path)?;
            let cdr_action = action_overrides
                .get(&norm_rel)
                .cloned()
                .unwrap_or_else(|| default_cdr_action.to_string());

            entries.push(PassportSanitizedFileEntry {
                rel_path: norm_rel,
                size_bytes,
                sha256,
                cdr_action,
            });
        }

        let mut referenced_ancestor_dirs = HashSet::new();
        for entry in &entries {
            let p = Path::new(&entry.rel_path);
            let mut cur = PathBuf::new();
            let comps: Vec<_> = p.components().collect();
            for comp in comps.iter().take(comps.len().saturating_sub(1)) {
                cur.push(comp);
                referenced_ancestor_dirs.insert(normalize_forward_slash_path(&cur));
            }
        }
        for dir_norm in seen_dirs {
            if !referenced_ancestor_dirs.contains(&dir_norm) {
                return Err(format!(
                    "Refusing to issue CDR passport: empty or unreferenced directory '{dir_norm}' in export directory '{}'",
                    export_dir.display()
                ));
            }
        }

        entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

        let session_id = self
            .active_session_id
            .clone()
            .unwrap_or_else(|| format!("KSESS-EXPORT-{}", Uuid::new_v4()));
        let passport_id = format!("PASS-{}", Uuid::new_v4());
        let issued_at_utc = now_rfc3339_utc();
        let ntp_sync = query_ntp_sync_status();
        let (binary_exe_sha256, binary_dep_v0_sha256) = compute_current_binary_provenance();
        let schema_version = "1.0".to_string();
        let signature_algorithm = "ECDSA-P256-SHA256".to_string();

        let raw_pub_blob = if let Some(ref shared) = self.shared_ledger {
            let guard = shared
                .lock()
                .map_err(|e| format!("Kiosk shared ledger mutex poisoned: {e}"))?;
            guard
                .public_key_blob()
                .ok_or_else(|| "AuditLedger ECDSA P-256 public key is unavailable".to_string())?
                .to_vec()
        } else {
            let ledger = AuditLedger::open_result(&self.ledger_path)?;
            ledger
                .public_key_blob()
                .ok_or_else(|| "AuditLedger ECDSA P-256 public key is unavailable".to_string())?
                .to_vec()
        };
        if raw_pub_blob.len() != 72 || &raw_pub_blob[0..8] != b"ECS1\x20\x00\x00\x00" {
            return Err(format!(
                "Invalid ledger ECDSA P-256 public key blob format ({} bytes; expected 72B canonical ECS1)",
                raw_pub_blob.len()
            ));
        }
        let public_key_blob_hex = hex::encode(&raw_pub_blob);

        let signable = CanonicalPassportSignable {
            schema_version: &schema_version,
            passport_id: &passport_id,
            kiosk_id: &self.config.kiosk_id,
            session_id: &session_id,
            media_id,
            issued_at_utc: &issued_at_utc,
            ntp_sync: &ntp_sync,
            policy_id,
            policy_sequence,
            binary_exe_sha256: &binary_exe_sha256,
            binary_dep_v0_sha256: binary_dep_v0_sha256.as_deref(),
            sanitized_files: &entries,
            signature_algorithm: &signature_algorithm,
            public_key_blob_hex: &public_key_blob_hex,
        };
        let canonical_bytes = serde_json::to_vec(&signable)
            .map_err(|e| format!("Failed serializing canonical passport payload: {e}"))?;

        let (_pub_key_blob, sig_bytes) = if let Some(ref shared) = self.shared_ledger {
            let guard = shared
                .lock()
                .map_err(|e| format!("Kiosk shared ledger mutex poisoned: {e}"))?;
            guard.sign_domain_payload(PASSPORT_DOMAIN_TAG, &canonical_bytes)?
        } else {
            let ledger = AuditLedger::open_result(&self.ledger_path)?;
            ledger.sign_domain_payload(PASSPORT_DOMAIN_TAG, &canonical_bytes)?
        };
        let ecdsa_p256_signature_hex = hex::encode(&sig_bytes);

        let passport = KioskSanitizationPassport {
            schema_version,
            passport_id: passport_id.clone(),
            kiosk_id: self.config.kiosk_id.clone(),
            session_id,
            media_id: media_id.to_string(),
            issued_at_utc,
            ntp_sync: ntp_sync.clone(),
            policy_id: policy_id.to_string(),
            policy_sequence,
            binary_exe_sha256,
            binary_dep_v0_sha256,
            sanitized_files: entries,
            signature_algorithm,
            public_key_blob_hex: public_key_blob_hex.clone(),
            ecdsa_p256_signature_hex,
        };

        let manifest_path = export_dir.join(PASSPORT_MANIFEST_FILENAME);
        ensure_not_symlink_or_reparse_point(&manifest_path).map_err(|e| {
            format!(
                "Passport file '{}' is a symlink/reparse point: {e}",
                manifest_path.display()
            )
        })?;
        let passport_json = serde_json::to_vec_pretty(&passport)
            .map_err(|e| format!("Failed serializing KioskSanitizationPassport: {e}"))?;
        fs::write(&manifest_path, &passport_json).map_err(|e| {
            format!(
                "Failed writing passport manifest '{}': {e}",
                manifest_path.display()
            )
        })?;

        let pub_path = export_dir.join(PASSPORT_PUBKEY_FILENAME);
        ensure_not_symlink_or_reparse_point(&pub_path).map_err(|e| {
            format!(
                "Passport pubkey sidecar '{}' is a symlink/reparse point: {e}",
                pub_path.display()
            )
        })?;
        fs::write(&pub_path, format!("{public_key_blob_hex}\n")).map_err(|e| {
            format!(
                "Failed writing passport public key sidecar '{}': {e}",
                pub_path.display()
            )
        })?;
        ensure_no_ntfs_ads(&manifest_path, "Refusing to issue CDR passport")?;
        ensure_no_ntfs_ads(&pub_path, "Refusing to issue CDR passport")?;

        self.append_kiosk_event(
            "KIOSK_PASSPORT_ISSUED",
            serde_json::json!({
                "passport_id": passport_id,
                "kiosk_id": self.config.kiosk_id,
                "media_id": media_id,
                "policy_id": policy_id,
                "policy_sequence": policy_sequence,
                "files_count": passport.sanitized_files.len(),
                "ntp_synchronized": ntp_sync.ntp_synchronized,
                "clock_source": ntp_sync.clock_source,
            }),
        )?;

        Ok(passport)
    }
}

fn ensure_no_ntfs_ads(path: &Path, err_prefix: &str) -> Result<(), String> {
    let streams = enumerate_ntfs_ads(path);
    if let Some((stream_name, stream_size)) = streams.first() {
        return Err(format!(
            "{err_prefix}: Prohibited NTFS Alternate Data Stream '{}' ({} bytes) detected on '{}'",
            stream_name,
            stream_size,
            path.display()
        ));
    }
    Ok(())
}

fn normalize_forward_slash_path(clean_rel: &Path) -> String {
    clean_rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn hash_file_streaming_64k(path: &Path) -> Result<(u64, String), String> {
    let mut file = open_untrusted_readonly_nofollow(path)
        .map_err(|e| format!("Failed opening '{}' with O_NOFOLLOW: {e}", path.display()))?;
    let mut buf = [0u8; 65536];
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Read error while hashing '{}': {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((total, hex::encode(hasher.finalize())))
}

/// Extracts and hashes the exact payload bytes of an embedded `cargo-auditable` `.dep-v0` section
/// from a PE32/PE32+ or ELF32/ELF64 executable image (`ADR-014`, `CSE-17`).
/// Returns `None` when the binary contains no `.dep-v0` section or is not a valid PE/ELF image.
pub fn extract_dep_v0_section_sha256(bytes: &[u8]) -> Option<String> {
    if bytes.len() >= 0x40 && &bytes[0..2] == b"MZ" {
        return extract_pe_dep_v0_sha256(bytes);
    }
    if bytes.len() >= 52 && &bytes[0..4] == b"\x7fELF" {
        return extract_elf_dep_v0_sha256(bytes);
    }
    None
}

fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let slice = bytes.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u16_endian(bytes: &[u8], off: usize, big: bool) -> Option<u16> {
    let slice = bytes.get(off..off.checked_add(2)?)?;
    let arr = [slice[0], slice[1]];
    Some(if big {
        u16::from_be_bytes(arr)
    } else {
        u16::from_le_bytes(arr)
    })
}

fn read_u32_endian(bytes: &[u8], off: usize, big: bool) -> Option<u32> {
    let slice = bytes.get(off..off.checked_add(4)?)?;
    let arr = [slice[0], slice[1], slice[2], slice[3]];
    Some(if big {
        u32::from_be_bytes(arr)
    } else {
        u32::from_le_bytes(arr)
    })
}

fn read_u64_endian(bytes: &[u8], off: usize, big: bool) -> Option<u64> {
    let slice = bytes.get(off..off.checked_add(8)?)?;
    let arr = [
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ];
    Some(if big {
        u64::from_be_bytes(arr)
    } else {
        u64::from_le_bytes(arr)
    })
}

fn extract_pe_dep_v0_sha256(bytes: &[u8]) -> Option<String> {
    let pe_off = read_u32_le(bytes, 0x3C)? as usize;
    if bytes.get(pe_off..pe_off.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff_off = pe_off.checked_add(4)?;
    let num_sections = read_u16_le(bytes, coff_off.checked_add(2)?)? as usize;
    let opt_hdr_size = read_u16_le(bytes, coff_off.checked_add(16)?)? as usize;
    let sec_table_off = coff_off.checked_add(20)?.checked_add(opt_hdr_size)?;

    for idx in 0..num_sections {
        let entry_off = sec_table_off.checked_add(idx.checked_mul(40)?)?;
        let name_bytes = bytes.get(entry_off..entry_off.checked_add(8)?)?;
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        if &name_bytes[..name_end] == b".dep-v0" {
            let virtual_size = read_u32_le(bytes, entry_off.checked_add(8)?)? as usize;
            let raw_size = read_u32_le(bytes, entry_off.checked_add(16)?)? as usize;
            let raw_ptr = read_u32_le(bytes, entry_off.checked_add(20)?)? as usize;
            let effective_len = if virtual_size > 0 {
                virtual_size.min(raw_size)
            } else {
                raw_size
            };
            if effective_len == 0 {
                return None;
            }
            let payload = bytes.get(raw_ptr..raw_ptr.checked_add(effective_len)?)?;
            return Some(hex::encode(Sha256::digest(payload)));
        }
    }
    None
}

fn extract_elf_dep_v0_sha256(bytes: &[u8]) -> Option<String> {
    let ei_class = *bytes.get(4)?;
    let ei_data = *bytes.get(5)?;
    let big = match ei_data {
        1 => false,
        2 => true,
        _ => return None,
    };

    let (shoff, shentsize, shnum, shstrndx) = match ei_class {
        1 => {
            if bytes.len() < 52 {
                return None;
            }
            (
                read_u32_endian(bytes, 32, big)? as usize,
                read_u16_endian(bytes, 46, big)? as usize,
                read_u16_endian(bytes, 48, big)? as usize,
                read_u16_endian(bytes, 50, big)? as usize,
            )
        }
        2 => {
            if bytes.len() < 64 {
                return None;
            }
            (
                usize::try_from(read_u64_endian(bytes, 40, big)?).ok()?,
                read_u16_endian(bytes, 58, big)? as usize,
                read_u16_endian(bytes, 60, big)? as usize,
                read_u16_endian(bytes, 62, big)? as usize,
            )
        }
        _ => return None,
    };

    if shoff == 0 || shnum == 0 || shstrndx >= shnum {
        return None;
    }
    let min_ent = if ei_class == 2 { 64 } else { 40 };
    if shentsize < min_ent {
        return None;
    }

    let strtab_hdr = shoff.checked_add(shstrndx.checked_mul(shentsize)?)?;
    let (strtab_off, strtab_size) = if ei_class == 2 {
        (
            usize::try_from(read_u64_endian(bytes, strtab_hdr.checked_add(24)?, big)?).ok()?,
            usize::try_from(read_u64_endian(bytes, strtab_hdr.checked_add(32)?, big)?).ok()?,
        )
    } else {
        (
            read_u32_endian(bytes, strtab_hdr.checked_add(16)?, big)? as usize,
            read_u32_endian(bytes, strtab_hdr.checked_add(20)?, big)? as usize,
        )
    };
    let strtab = bytes.get(strtab_off..strtab_off.checked_add(strtab_size)?)?;

    for idx in 0..shnum {
        let hdr = shoff.checked_add(idx.checked_mul(shentsize)?)?;
        let sh_name = read_u32_endian(bytes, hdr, big)? as usize;
        if sh_name >= strtab.len() {
            continue;
        }
        let tail = &strtab[sh_name..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        if &tail[..end] == b".dep-v0" {
            let (sec_off, sec_size) = if ei_class == 2 {
                (
                    usize::try_from(read_u64_endian(bytes, hdr.checked_add(24)?, big)?).ok()?,
                    usize::try_from(read_u64_endian(bytes, hdr.checked_add(32)?, big)?).ok()?,
                )
            } else {
                (
                    read_u32_endian(bytes, hdr.checked_add(16)?, big)? as usize,
                    read_u32_endian(bytes, hdr.checked_add(20)?, big)? as usize,
                )
            };
            if sec_size == 0 {
                return None;
            }
            let payload = bytes.get(sec_off..sec_off.checked_add(sec_size)?)?;
            return Some(hex::encode(Sha256::digest(payload)));
        }
    }
    None
}

/// Computes `(binary_exe_sha256, binary_dep_v0_sha256)` for the currently running binary (`ADR-014`, `CSE-17`).
/// Never substitutes the full executable SHA-256 into `binary_dep_v0_sha256`.
pub fn compute_current_binary_provenance() -> (String, Option<String>) {
    if let Ok(exe_path) = std::env::current_exe() {
        let exe_hash = hash_file_streaming_64k(&exe_path)
            .map(|(_sz, digest)| digest)
            .unwrap_or_else(|_| "UNAVAILABLE_IN_EPHEMERAL_HARNESS".to_string());
        let dep_v0_hash = fs::File::open(&exe_path)
            .ok()
            .and_then(|mut f| {
                sentinel_sys::read_untrusted_to_end_bounded(&mut f, 64 * 1024 * 1024).ok()
            })
            .and_then(|bytes| extract_dep_v0_section_sha256(&bytes));
        return (exe_hash, dep_v0_hash);
    }
    ("UNAVAILABLE_IN_EPHEMERAL_HARNESS".to_string(), None)
}

/// RFC 5480 ASN.1 DER SubjectPublicKeyInfo 26-byte prefix for `id-ecPublicKey` (`1.2.840.10045.2.1`)
/// over NIST P-256 / `secp256r1` (`1.2.840.10045.3.1.7`) with uncompressed BIT STRING (`0x03 0x42 0x00`).
const RFC5480_P256_SPKI_DER_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Extracts and curve-validates normalized 64-byte `(X[32] || Y[32])` P-256 public key coordinates from
/// a canonical 72-byte Windows CNG `ECS1` blob (`ECS1\x20\x00\x00\x00`), 65-byte uncompressed SEC1 (`0x04 || X || Y`),
/// or 91-byte RFC 5480 `secp256r1` SubjectPublicKeyInfo DER.
pub fn extract_p256_xy_coordinates(raw_pub: &[u8]) -> Result<[u8; 64], String> {
    let mut xy = [0u8; 64];
    if raw_pub.len() == 72 && &raw_pub[0..8] == b"ECS1\x20\x00\x00\x00" {
        xy.copy_from_slice(&raw_pub[8..72]);
    } else if raw_pub.len() == 65 && raw_pub[0] == 0x04 {
        xy.copy_from_slice(&raw_pub[1..65]);
    } else if raw_pub.len() == 91
        && raw_pub[0..26] == RFC5480_P256_SPKI_DER_PREFIX
        && raw_pub[26] == 0x04
    {
        xy.copy_from_slice(&raw_pub[27..91]);
    } else {
        return Err(format!(
            "Unsupported or non-canonical ECDSA P-256 public key format ({} bytes; expected 72B canonical ECS1, 65B SEC1, or 91B secp256r1 SPKI DER)",
            raw_pub.len()
        ));
    }

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..65].copy_from_slice(&xy);
    validate_p256_uncompressed_point(&sec1)
        .map_err(|e| format!("Invalid P-256 public key: {e}"))?;
    Ok(xy)
}

/// Parses a trusted ECDSA P-256 public key file (supports hex-encoded `ECS1`/`SEC1`, PEM SPKI, or raw binary).
pub fn parse_passport_public_key_bytes(raw: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim();
        if trimmed.starts_with("-----BEGIN") {
            let lines: Vec<&str> = trimmed
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            if lines.len() < 3
                || lines.first() != Some(&"-----BEGIN PUBLIC KEY-----")
                || lines.last() != Some(&"-----END PUBLIC KEY-----")
            {
                return Err(
                    "Invalid PEM public key framing (expected exact -----BEGIN PUBLIC KEY----- / -----END PUBLIC KEY-----)"
                        .to_string(),
                );
            }
            let body_lines = &lines[1..lines.len() - 1];
            if body_lines.iter().any(|l| l.starts_with("-----")) {
                return Err("Unexpected extra PEM armor boundary inside public key".to_string());
            }
            let b64_body: String = body_lines.concat();
            let der = decode_base64_simple(&b64_body)?;
            let xy = extract_p256_xy_coordinates(&der)?;
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&xy);
            return Ok(sec1);
        }
        let compact_hex: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
        if !compact_hex.is_empty() && compact_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let decoded =
                hex::decode(&compact_hex).map_err(|e| format!("Invalid public key hex: {e}"))?;
            let xy = extract_p256_xy_coordinates(&decoded)?;
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&xy);
            return Ok(sec1);
        }
    }
    let xy = extract_p256_xy_coordinates(raw)?;
    if raw.len() == 72 || raw.len() == 65 {
        Ok(raw.to_vec())
    } else {
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&xy);
        Ok(sec1)
    }
}

fn decode_base64_simple(input: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    if clean.is_empty() || !clean.len().is_multiple_of(4) {
        return Err("Invalid Base64 length in PEM public key".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    let mut pad_count: usize = 0;

    for (idx, &ch) in clean.iter().enumerate() {
        if ch == b'=' {
            pad_count += 1;
            if pad_count > 2 || idx < clean.len() - 2 {
                return Err("Invalid Base64 '=' padding position in PEM public key".to_string());
            }
            continue;
        }
        if pad_count > 0 {
            return Err("Trailing characters after '=' padding in PEM public key".to_string());
        }
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => {
                return Err(format!(
                    "Invalid Base64 character 0x{ch:02X} in PEM public key"
                ))
            }
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    if (pad_count == 1 && bits != 2)
        || (pad_count == 2 && bits != 4)
        || (pad_count == 0 && bits != 0)
    {
        return Err("Malformed Base64 quantum padding in PEM public key".to_string());
    }
    if bits > 0 && (buf & ((1u32 << bits) - 1)) != 0 {
        return Err("Non-zero Base64 padding bits in PEM public key".to_string());
    }
    Ok(out)
}

/// Verifies a `.sentinel-passport.json` manifest offline (`sentinel verify-passport`, `Sub-Phase 2.2`, `CSE-14`).
///
/// Enforces fail-closed verification across:
/// 1. Detached ECDSA P-256 cryptographic signature over canonical passport metadata + file hashes.
/// 2. Optional pinned `--pub-key` constant-time signer key match (`PASSPORT_UNTRUSTED_SIGNER`).
/// 3. Strict relative path containment (`sanitize_strict_relative_subpath`) on every manifest entry.
/// 4. Handle-bound `O_NOFOLLOW` 64 KiB streaming SHA-256 and exact byte-size match for every listed file.
/// 5. Directory completeness check rejecting any unlisted extra file or symlink dropped after signing.
pub fn verify_kiosk_passport(
    target_path: &Path,
    trusted_pubkey_override: Option<&[u8]>,
) -> Result<KioskSanitizationPassport, String> {
    ensure_not_symlink_or_reparse_point(target_path).map_err(|e| {
        format!(
            "PASSPORT_SYMLINK_REJECTED: Target '{}' is a symlink or reparse point: {e}",
            target_path.display()
        )
    })?;

    let (export_dir, manifest_path) = if target_path.is_dir() {
        (
            target_path.to_path_buf(),
            target_path.join(PASSPORT_MANIFEST_FILENAME),
        )
    } else {
        let parent = target_path.parent().ok_or_else(|| {
            format!(
                "PASSPORT_INVALID_PATH: Cannot resolve parent export directory for '{}'",
                target_path.display()
            )
        })?;
        (
            if parent.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                parent.to_path_buf()
            },
            target_path.to_path_buf(),
        )
    };

    ensure_not_symlink_or_reparse_point(&export_dir).map_err(|e| {
        format!(
            "PASSPORT_SYMLINK_REJECTED: Export directory '{}' is a symlink or reparse point: {e}",
            export_dir.display()
        )
    })?;
    let export_meta = fs::symlink_metadata(&export_dir).map_err(|e| {
        format!(
            "PASSPORT_INVALID_PATH: Export directory '{}' metadata error: {e}",
            export_dir.display()
        )
    })?;
    if is_reparse_point_or_symlink(&export_meta) || !export_meta.is_dir() {
        return Err(format!(
            "PASSPORT_SYMLINK_REJECTED: Export directory '{}' is a symlink, reparse point, or non-directory",
            export_dir.display()
        ));
    }
    ensure_no_ntfs_ads(&export_dir, "PASSPORT_UNLISTED_ADS")?;

    ensure_not_symlink_or_reparse_point(&manifest_path).map_err(|e| {
        format!(
            "PASSPORT_SYMLINK_REJECTED: Manifest '{}' is a symlink or reparse point: {e}",
            manifest_path.display()
        )
    })?;
    ensure_no_ntfs_ads(&manifest_path, "PASSPORT_UNLISTED_ADS")?;

    let mut manifest_file = open_untrusted_readonly_nofollow(&manifest_path).map_err(|e| {
        format!(
            "PASSPORT_MISSING: Failed opening passport manifest '{}': {e}",
            manifest_path.display()
        )
    })?;
    let raw_manifest =
        sentinel_sys::read_untrusted_to_end_bounded(&mut manifest_file, 4 * 1024 * 1024).map_err(
            |e| {
                if e.kind() == std::io::ErrorKind::InvalidData {
                    format!(
                        "PASSPORT_MANIFEST_TOO_LARGE: Manifest '{}' exceeds 4 MiB quota: {e}",
                        manifest_path.display()
                    )
                } else {
                    format!("PASSPORT_READ_ERROR: Failed reading manifest: {e}")
                }
            },
        )?;

    let passport: KioskSanitizationPassport = serde_json::from_slice(&raw_manifest)
        .map_err(|e| format!("PASSPORT_CORRUPT_JSON: Invalid passport JSON: {e}"))?;

    if passport.schema_version != "1.0" {
        return Err(format!(
            "PASSPORT_UNSUPPORTED_VERSION: Unsupported schema_version '{}'",
            passport.schema_version
        ));
    }
    if passport.signature_algorithm != "ECDSA-P256-SHA256" {
        return Err(format!(
            "PASSPORT_UNSUPPORTED_ALGORITHM: Expected ECDSA-P256-SHA256, found '{}'",
            passport.signature_algorithm
        ));
    }
    if !is_valid_media_id(&passport.media_id) {
        return Err(format!(
            "PASSPORT_INVALID_MEDIA_ID: Invalid media_id '{}'",
            passport.media_id
        ));
    }

    let embedded_pub = hex::decode(&passport.public_key_blob_hex)
        .map_err(|e| format!("PASSPORT_INVALID_PUBKEY: Invalid public_key_blob_hex: {e}"))?;
    if embedded_pub.len() != 72 || &embedded_pub[0..8] != b"ECS1\x20\x00\x00\x00" {
        return Err(format!(
            "PASSPORT_INVALID_PUBKEY: Manifest public_key_blob_hex must be canonical 72-byte ECS1 format (got {} bytes)",
            embedded_pub.len()
        ));
    }
    let embedded_xy = extract_p256_xy_coordinates(&embedded_pub)
        .map_err(|e| format!("PASSPORT_INVALID_PUBKEY: {e}"))?;

    let verify_key_bytes: Vec<u8> = if let Some(trusted_raw) = trusted_pubkey_override {
        let parsed_trusted = parse_passport_public_key_bytes(trusted_raw)
            .map_err(|e| format!("PASSPORT_INVALID_TRUSTED_KEY: {e}"))?;
        let trusted_xy = extract_p256_xy_coordinates(&parsed_trusted)
            .map_err(|e| format!("PASSPORT_INVALID_TRUSTED_KEY: {e}"))?;
        let matches: bool = embedded_xy.ct_eq(&trusted_xy).into();
        if !matches {
            return Err(
                "PASSPORT_UNTRUSTED_SIGNER: Passport public key does not match pinned trusted kiosk public key"
                    .to_string(),
            );
        }
        parsed_trusted
    } else {
        embedded_pub
    };

    let sig_bytes = hex::decode(&passport.ecdsa_p256_signature_hex)
        .map_err(|e| format!("PASSPORT_SIGNATURE_INVALID: Invalid signature hex: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "PASSPORT_SIGNATURE_INVALID: Expected 64-byte ECDSA P-256 signature, got {} bytes",
            sig_bytes.len()
        ));
    }

    let signable = CanonicalPassportSignable {
        schema_version: &passport.schema_version,
        passport_id: &passport.passport_id,
        kiosk_id: &passport.kiosk_id,
        session_id: &passport.session_id,
        media_id: &passport.media_id,
        issued_at_utc: &passport.issued_at_utc,
        ntp_sync: &passport.ntp_sync,
        policy_id: &passport.policy_id,
        policy_sequence: passport.policy_sequence,
        binary_exe_sha256: &passport.binary_exe_sha256,
        binary_dep_v0_sha256: passport.binary_dep_v0_sha256.as_deref(),
        sanitized_files: &passport.sanitized_files,
        signature_algorithm: &passport.signature_algorithm,
        public_key_blob_hex: &passport.public_key_blob_hex,
    };
    let canonical_bytes =
        serde_json::to_vec(&signable).map_err(|e| format!("PASSPORT_SERIALIZE_ERROR: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(PASSPORT_DOMAIN_TAG);
    hasher.update(&canonical_bytes);
    let digest_arr = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&digest_arr);

    let sig_ok = verify_ecdsa_p256_digest(&verify_key_bytes, &digest, &sig_bytes)
        .map_err(|e| format!("PASSPORT_SIGNATURE_INVALID: ECDSA P-256 verification error: {e}"))?;
    if !sig_ok {
        return Err(
            "PASSPORT_SIGNATURE_INVALID: Detached ECDSA P-256 signature verification failed (manifest forged or modified)"
                .to_string(),
        );
    }

    // Enforce canonical manifest byte-framing + lowercase ASCII hex (blocks whitespace & hex-case covert channels)
    let mut canonical_passport = passport.clone();
    canonical_passport.public_key_blob_hex =
        canonical_passport.public_key_blob_hex.to_ascii_lowercase();
    canonical_passport.ecdsa_p256_signature_hex = canonical_passport
        .ecdsa_p256_signature_hex
        .to_ascii_lowercase();
    if canonical_passport.binary_exe_sha256 != "UNAVAILABLE_IN_EPHEMERAL_HARNESS" {
        canonical_passport.binary_exe_sha256 =
            canonical_passport.binary_exe_sha256.to_ascii_lowercase();
    }
    if let Some(dep_hash) = canonical_passport.binary_dep_v0_sha256.as_mut() {
        *dep_hash = dep_hash.to_ascii_lowercase();
    }
    for f in &mut canonical_passport.sanitized_files {
        f.sha256 = f.sha256.to_ascii_lowercase();
    }
    let canonical_pretty = serde_json::to_vec_pretty(&canonical_passport)
        .map_err(|e| format!("PASSPORT_SERIALIZE_ERROR: {e}"))?;
    let normalized_raw = {
        let mut v = Vec::with_capacity(raw_manifest.len());
        let mut idx = 0usize;
        while idx < raw_manifest.len() {
            if raw_manifest[idx] == b'\r'
                && idx + 1 < raw_manifest.len()
                && raw_manifest[idx + 1] == b'\n'
            {
                v.push(b'\n');
                idx += 2;
            } else {
                v.push(raw_manifest[idx]);
                idx += 1;
            }
        }
        if v.last() == Some(&b'\n') {
            v.pop();
        }
        v
    };
    let framing_len_ok = normalized_raw.len() == canonical_pretty.len();
    let framing_bytes_ok: bool = normalized_raw
        .as_slice()
        .ct_eq(canonical_pretty.as_slice())
        .into();
    if !framing_len_ok || !framing_bytes_ok {
        return Err(format!(
            "PASSPORT_MANIFEST_FRAMING_TAMPERED: Manifest '{}' contains non-canonical byte framing, duplicate keys, or covert whitespace padding",
            manifest_path.display()
        ));
    }

    // Verify every file listed in `sanitized_files` and collect expected ancestor directories
    let mut expected_rel_set = HashSet::with_capacity(passport.sanitized_files.len());
    let mut expected_ancestor_dirs = HashSet::new();
    for entry in &passport.sanitized_files {
        let clean_rel = sanitize_strict_relative_subpath(Path::new(&entry.rel_path))
            .map_err(|e| format!("PASSPORT_PATH_VIOLATION: '{}': {e}", entry.rel_path))?;
        let norm_rel = normalize_forward_slash_path(&clean_rel);
        if entry.rel_path != norm_rel {
            return Err(format!(
                "PASSPORT_PATH_VIOLATION: Non-canonical manifest rel_path '{}' (expected '{norm_rel}')",
                entry.rel_path
            ));
        }
        if !expected_rel_set.insert(norm_rel.clone()) {
            return Err(format!(
                "PASSPORT_DUPLICATE_ENTRY: Duplicate file entry '{norm_rel}' in manifest"
            ));
        }

        let comps: Vec<_> = clean_rel.components().collect();
        let mut cur_sub = export_dir.clone();
        let mut rel_anc = PathBuf::new();
        for comp in comps.iter().take(comps.len().saturating_sub(1)) {
            cur_sub.push(comp);
            rel_anc.push(comp);
            expected_ancestor_dirs.insert(normalize_forward_slash_path(&rel_anc));
            ensure_not_symlink_or_reparse_point(&cur_sub).map_err(|e| {
                format!(
                    "PASSPORT_SYMLINK_REJECTED: Intermediate directory '{}' is a symlink/reparse point: {e}",
                    cur_sub.display()
                )
            })?;
        }
        let disk_path = export_dir.join(&clean_rel);
        ensure_not_symlink_or_reparse_point(&disk_path).map_err(|e| {
            format!(
                "PASSPORT_SYMLINK_REJECTED: Sanitized file '{}' is a symlink/reparse point: {e}",
                disk_path.display()
            )
        })?;
        if !disk_path.exists() {
            return Err(format!(
                "PASSPORT_FILE_MISSING: Expected sanitized file '{}' is missing from '{}'",
                norm_rel,
                export_dir.display()
            ));
        }

        let (actual_size, actual_sha256) = hash_file_streaming_64k(&disk_path)
            .map_err(|e| format!("PASSPORT_FILE_READ_FAIL: {e}"))?;
        if actual_size != entry.size_bytes {
            return Err(format!(
                "PASSPORT_FILE_TAMPERED: Size mismatch for '{}': passport={} bytes, disk={} bytes",
                norm_rel, entry.size_bytes, actual_size
            ));
        }
        let expected_sha_lower = entry.sha256.to_ascii_lowercase();
        let hash_matches: bool = actual_sha256
            .as_bytes()
            .ct_eq(expected_sha_lower.as_bytes())
            .into();
        if !hash_matches {
            return Err(format!(
                "PASSPORT_FILE_TAMPERED: SHA-256 mismatch for '{}': passport={}, disk={}",
                norm_rel, entry.sha256, actual_sha256
            ));
        }
    }

    // Reject unlisted extra files or symlinks injected into `export_dir` after passport signing,
    // enforcing a strict 1-to-1 bijection between raw `OsStr` filesystem components and manifest entries.
    let manifest_file_name = manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(PASSPORT_MANIFEST_FILENAME);
    let mut visited_dirs_set: HashSet<String> = HashSet::new();
    let mut visited_files_set: HashSet<String> = HashSet::new();

    for item_res in WalkDir::new(&export_dir).follow_links(false) {
        let item = item_res.map_err(|e| format!("PASSPORT_DIR_WALK_ERROR: {e}"))?;
        let path = item.path();
        if path == export_dir {
            continue;
        }
        let sym_meta = fs::symlink_metadata(path)
            .map_err(|e| format!("PASSPORT_METADATA_ERROR: '{}': {e}", path.display()))?;
        if item.path_is_symlink() || is_reparse_point_or_symlink(&sym_meta) {
            return Err(format!(
                "PASSPORT_UNLISTED_SYMLINK: Unlisted symlink or reparse point '{}' detected in export directory",
                path.display()
            ));
        }
        ensure_no_ntfs_ads(path, "PASSPORT_UNLISTED_ADS")?;
        if !sym_meta.is_file() && !sym_meta.is_dir() {
            return Err(format!(
                "PASSPORT_UNLISTED_SPECIAL_FILE: Prohibited non-regular special file '{}' detected in export directory",
                path.display()
            ));
        }
        let rel = path
            .strip_prefix(&export_dir)
            .map_err(|e| format!("PASSPORT_STRIP_PREFIX_ERROR: {e}"))?;
        if sym_meta.is_dir() {
            let clean_dir = sanitize_strict_relative_subpath(rel).map_err(|e| {
                format!(
                    "PASSPORT_UNLISTED_INVALID_DIR: Prohibited directory path '{}': {e}",
                    rel.display()
                )
            })?;
            if !rel.components().eq(clean_dir.components()) {
                return Err(format!(
                    "PASSPORT_UNLISTED_INVALID_DIR: Non-canonical directory component '{}' in export directory",
                    rel.display()
                ));
            }
            let norm_dir = normalize_forward_slash_path(&clean_dir);
            if !expected_ancestor_dirs.contains(&norm_dir)
                || !visited_dirs_set.insert(norm_dir.clone())
            {
                return Err(format!(
                    "PASSPORT_UNLISTED_DIRECTORY: Unauthorized unlisted directory '{norm_dir}' found in export directory '{}'",
                    export_dir.display()
                ));
            }
            continue;
        }
        if rel.components().count() == 1 && rel.as_os_str().to_str() == Some(manifest_file_name) {
            continue;
        }
        if rel.components().count() == 1
            && rel.as_os_str().to_str() == Some(PASSPORT_PUBKEY_FILENAME)
        {
            let sidecar_file = open_untrusted_readonly_nofollow(path).map_err(|e| {
                format!(
                    "PASSPORT_PUBKEY_SIDECAR_TAMPERED: Failed opening '{}': {e}",
                    path.display()
                )
            })?;
            let mut raw_sidecar = Vec::with_capacity(257);
            sidecar_file
                .take(257)
                .read_to_end(&mut raw_sidecar)
                .map_err(|e| {
                    format!(
                        "PASSPORT_PUBKEY_SIDECAR_TAMPERED: Failed reading '{}': {e}",
                        path.display()
                    )
                })?;
            if raw_sidecar.len() > 256 {
                return Err(format!(
                    "PASSPORT_PUBKEY_SIDECAR_TAMPERED: '{}' exceeds 256-byte cap (potential payload smuggling)",
                    path.display()
                ));
            }
            let sidecar_str = std::str::from_utf8(&raw_sidecar).map_err(|_| {
                format!(
                    "PASSPORT_PUBKEY_SIDECAR_TAMPERED: '{}' contains non-UTF-8 binary bytes",
                    path.display()
                )
            })?;
            let sidecar_trimmed = sidecar_str.trim();
            let expected_hex_lower = passport.public_key_blob_hex.trim().to_ascii_lowercase();
            let len_eq = sidecar_trimmed.len() == expected_hex_lower.len();
            let bytes_eq: bool = sidecar_trimmed
                .as_bytes()
                .ct_eq(expected_hex_lower.as_bytes())
                .into();
            let canonical_nl = format!("{sidecar_trimmed}\n");
            let canonical_crlf = format!("{sidecar_trimmed}\r\n");
            let exact_framing = sidecar_str == sidecar_trimmed
                || sidecar_str == canonical_nl
                || sidecar_str == canonical_crlf;
            if !len_eq || !bytes_eq || !exact_framing {
                return Err(format!(
                    "PASSPORT_PUBKEY_SIDECAR_TAMPERED: '{}' content does not match canonical lowercase passport public_key_blob_hex",
                    path.display()
                ));
            }
            continue;
        }
        let clean_rel = sanitize_strict_relative_subpath(rel)
            .map_err(|e| format!("PASSPORT_UNLISTED_INVALID_PATH: '{}': {e}", rel.display()))?;
        if !rel.components().eq(clean_rel.components()) {
            return Err(format!(
                "PASSPORT_UNLISTED_INVALID_PATH: Non-canonical file component '{}' in export directory",
                rel.display()
            ));
        }
        let norm_rel = normalize_forward_slash_path(&clean_rel);
        if !expected_rel_set.contains(&norm_rel) || !visited_files_set.insert(norm_rel.clone()) {
            return Err(format!(
                "PASSPORT_UNLISTED_FILE: Unauthorized unlisted file '{norm_rel}' found in export directory '{}'",
                export_dir.display()
            ));
        }
    }

    if visited_files_set.len() != expected_rel_set.len()
        || visited_dirs_set.len() != expected_ancestor_dirs.len()
    {
        return Err(format!(
            "PASSPORT_FILE_MISSING: Export directory '{}' file/directory count mismatch against signed passport",
            export_dir.display()
        ));
    }

    Ok(passport)
}

fn default_kiosk_ledger_path(session_dir: &Path) -> PathBuf {
    if let Some(parent) = session_dir.parent() {
        if !parent.as_os_str().is_empty() {
            let audit_dir = parent.join("kiosk_audit");
            let leaf: String = session_dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "default".to_string())
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            let prefix = if leaf.is_empty() { "default" } else { &leaf };
            let ledger_name = format!("{prefix}_kiosk_audit_ledger_v2.jsonl");
            if crate::enterprise::ledger::is_restricted_ledger_dir_writable(
                &audit_dir,
                &ledger_name,
            ) {
                return audit_dir.join(ledger_name);
            }
        }
    }
    crate::enterprise::ledger::default_unified_ledger_path()
}
