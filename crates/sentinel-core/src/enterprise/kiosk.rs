use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;
use walkdir::WalkDir;

pub use sentinel_sys::PostureReport;
use sentinel_sys::{
    apply_system_admin_dacl, is_reparse_point_or_symlink, verify_system_posture, zeroize_slice,
    ZeroizingBytes,
};

use crate::enterprise::ledger::AuditLedger;
use crate::scanner::secure_shredder::{SecureShredder, ShredMethod};

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
    active_session_id: Option<String>,
    active_session_key: Option<ZeroizingBytes<32>>,
}

pub type AirGappedKioskManager = KioskEnforcer;

impl KioskEnforcer {
    pub fn new(config: KioskConfig, session_dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&session_dir);
        let ledger_path = default_kiosk_ledger_path(&session_dir);
        Self {
            config,
            session_dir,
            ledger_path,
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
        self
    }

    pub fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    pub fn verify_posture(&self) -> PostureReport {
        let report = verify_system_posture();
        let mut ledger = AuditLedger::open(&self.ledger_path);
        let _ = ledger.append_event(
            "KIOSK_POSTURE_VERIFIED",
            serde_json::json!({
                "kiosk_id": self.config.kiosk_id,
                "compliant": report.is_compliant(),
                "automount_disabled": report.automount_disabled,
                "user_deny_policy_present": report.user_deny_policy_present,
                "install_restrictions_active": report.install_restrictions_active,
                "write_protect_active": report.write_protect_active,
            }),
        );
        report
    }

    /// Queries the live OS registry StorageDevicePolicies WriteProtect posture (`BUG-CORE-13`).
    pub fn verify_write_blocking_active(&self) -> bool {
        self.verify_posture().write_protect_active
    }

    /// Enforces `PostureReport::is_compliant()` before starting a strict kiosk session
    /// (Master Plan v2 §0.1 & §5 `kiosk_posture_blocks_session`), recording the decision
    /// in the tamper-evident `AuditLedger` (`Rows 23, 168`).
    pub fn begin_kiosk_session_with_posture(
        &mut self,
        posture: &PostureReport,
    ) -> Result<String, String> {
        let mut ledger = AuditLedger::open(&self.ledger_path);
        if !posture.is_compliant() {
            ledger.append_event(
                "KIOSK_POSTURE_BLOCKED",
                serde_json::json!({
                    "status": "KIOSK_SESSION_REJECTED",
                    "kiosk_id": self.config.kiosk_id,
                    "automount_disabled": posture.automount_disabled,
                    "user_deny_policy_present": posture.user_deny_policy_present,
                    "install_restrictions_active": posture.install_restrictions_active,
                    "write_protect_active": posture.write_protect_active,
                }),
            )?;
            return Err(format!(
                "Refusing to start strict kiosk session: system posture non-compliant (automount_disabled={}, user_deny_policy_present={}, install_restrictions_active={}, write_protect_active={})",
                posture.automount_disabled,
                posture.user_deny_policy_present,
                posture.install_restrictions_active,
                posture.write_protect_active
            ));
        }
        let session_id = self.begin_kiosk_session();
        ledger.append_event(
            "KIOSK_SESSION_STARTED",
            serde_json::json!({
                "kiosk_id": self.config.kiosk_id,
                "session_id": session_id,
                "session_dir": self.session_dir.to_string_lossy(),
                "posture_verified": true,
            }),
        )?;
        Ok(session_id)
    }

    pub fn begin_kiosk_session(&mut self) -> String {
        let session_id = format!("KSESS-{}", Uuid::new_v4());
        let mut raw_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_key);

        let _ = fs::create_dir_all(&self.session_dir);
        self.active_session_id = Some(session_id.clone());
        self.active_session_key = Some(ZeroizingBytes::new(raw_key));
        zeroize_slice(&mut raw_key);

        let mut ledger = AuditLedger::open(&self.ledger_path);
        let _ = ledger.append_event(
            "KIOSK_SESSION_STARTED",
            serde_json::json!({
                "kiosk_id": self.config.kiosk_id,
                "session_id": session_id,
                "session_dir": self.session_dir.to_string_lossy(),
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

    pub fn start_kiosk_session(&mut self, media_id: &str) -> (String, PathBuf) {
        let session_id = format!("KSESS-{}-{}", media_id, Uuid::new_v4());
        let session_subdir = self.session_dir.join(&session_id);
        let _ = fs::create_dir_all(&session_subdir);

        let mut raw_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_key);

        self.active_session_id = Some(session_id.clone());
        self.active_session_key = Some(ZeroizingBytes::new(raw_key));
        zeroize_slice(&mut raw_key);

        // Encrypt an initial session state envelope under the per-session AES-256-GCM key (`Row 65`)
        let rel_manifest = PathBuf::from(&session_id).join(".session_envelope.enc");
        let _ = self.write_encrypted_session_file(&rel_manifest, session_id.as_bytes());

        let mut ledger = AuditLedger::open(&self.ledger_path);
        let _ = ledger.append_event(
            "KIOSK_SESSION_STARTED",
            serde_json::json!({
                "kiosk_id": self.config.kiosk_id,
                "session_id": session_id,
                "media_id": media_id,
                "session_subdir": session_subdir.to_string_lossy(),
            }),
        );

        (session_id, session_subdir)
    }

    /// Encrypts `plaintext` with AES-256-GCM using the active session's `ZeroizingBytes<32>` key
    /// (`self.active_session_key`) and writes `[12-byte nonce][ciphertext]` into `self.session_dir` (`Row 65`).
    pub fn write_encrypted_session_file(
        &self,
        relative_path: &Path,
        plaintext: &[u8],
    ) -> Result<PathBuf, String> {
        let session_key = self
            .active_session_key
            .as_ref()
            .ok_or_else(|| "Cannot encrypt kiosk file: no active kiosk session key".to_string())?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key.as_slice()));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let rel_str = relative_path.to_string_lossy();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: rel_str.as_bytes(),
                },
            )
            .map_err(|e| format!("Kiosk AES-256-GCM encryption failed: {}", e))?;

        let out_path = self.session_dir.join(relative_path);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Failed creating kiosk session subdirectory '{}': {}",
                    parent.display(),
                    e
                )
            })?;
        }

        let mut payload = Vec::with_capacity(12 + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);

        {
            let mut f = File::create(&out_path).map_err(|e| {
                format!(
                    "Failed creating encrypted kiosk session file '{}': {}",
                    out_path.display(),
                    e
                )
            })?;
            f.write_all(&payload).map_err(|e| {
                format!(
                    "Failed writing encrypted kiosk session file '{}': {}",
                    out_path.display(),
                    e
                )
            })?;
            f.sync_all().map_err(|e| {
                format!(
                    "Failed syncing encrypted kiosk session file '{}': {}",
                    out_path.display(),
                    e
                )
            })?;
        }
        apply_system_admin_dacl(&out_path).map_err(|e| {
            format!(
                "Failed applying SYSTEM/Administrators DACL to '{}': {}",
                out_path.display(),
                e
            )
        })?;

        Ok(out_path)
    }

    /// Decrypts a kiosk session file written by `write_encrypted_session_file` using the active
    /// session's `ZeroizingBytes<32>` AES-256-GCM key (`Row 65`).
    pub fn read_encrypted_session_file(&self, relative_path: &Path) -> Result<Vec<u8>, String> {
        let session_key = self
            .active_session_key
            .as_ref()
            .ok_or_else(|| "Cannot decrypt kiosk file: session key has been destroyed or no active session".to_string())?;

        let in_path = self.session_dir.join(relative_path);
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
        let rel_str = relative_path.to_string_lossy();
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
            let mut ledger = AuditLedger::open(&self.ledger_path);
            ledger.append_event(
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

        // Bottom-up walk (`contents_first(true)`) so nested files are shredded before their parent directories
        for entry_res in WalkDir::new(&self.session_dir)
            .contents_first(true)
            .follow_links(false)
        {
            let entry = match entry_res {
                Ok(e) => e,
                Err(err) => {
                    warn!("Kiosk session walk error: {}", err);
                    wipe_errors.push(format!("Walk error: {}", err));
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
                }
                continue;
            }

            if entry.file_type().is_file() {
                match SecureShredder::shred_file(path, ShredMethod::ClearMultiPass { passes: 3 }) {
                    Ok(_) => {
                        wiped_files_count += 1;
                    }
                    Err(e) => {
                        warn!(
                            "Kiosk SecureShredder error for '{}': {}",
                            path.display(),
                            e
                        );
                        wipe_errors.push(format!("Shred failed for '{}': {}", path.display(), e));
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
                }
            }
        }

        if !wipe_errors.is_empty() {
            let mut ledger = AuditLedger::open(&self.ledger_path);
            let _ = ledger.append_event(
                "KIOSK_SESSION_WIPE_ERROR",
                serde_json::json!({
                    "kiosk_id": self.config.kiosk_id,
                    "session_id": session_id,
                    "wiped_files_count": wiped_files_count,
                    "errors": wipe_errors,
                }),
            );
            return Err(format!(
                "Kiosk session '{}' wipe encountered {} error(s): {}",
                session_id,
                wipe_errors.len(),
                wipe_errors.join("; ")
            ));
        }

        let mut ledger = AuditLedger::open(&self.ledger_path);
        ledger.append_event(
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
}

fn default_kiosk_ledger_path(session_dir: &Path) -> PathBuf {
    if let Some(parent) = session_dir.parent() {
        if !parent.as_os_str().is_empty() {
            let audit_dir = parent.join("kiosk_audit");
            if fs::create_dir_all(&audit_dir).is_ok() {
                return audit_dir.join("kiosk_audit_ledger_v2.jsonl");
            }
        }
    }
    std::env::temp_dir()
        .join(format!(
            "omniconnect_sentinel_kiosk_ledger_{}",
            std::process::id()
        ))
        .join("kiosk_audit_ledger_v2.jsonl")
}
