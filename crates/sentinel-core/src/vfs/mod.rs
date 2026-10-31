pub mod fuse;
pub mod projfs;
#[cfg(feature = "vfs-winfsp")]
pub mod winfsp;

pub use fuse::FuseVfsProvider as FuseProvider;
pub use projfs::ProjFsProvider;
pub type VfsProvider = dyn VirtualFileSystemProvider;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use async_trait::async_trait;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;
use walkdir::WalkDir;

use sentinel_cdr::{SanitizationPolicy, WorkerLauncher, WorkerRequest};
use sentinel_sys::{
    apply_system_admin_dacl, is_projfs_available, is_reparse_point_or_symlink,
    normalize_file_attributes, set_volume_offline, set_volume_online_readonly,
    write_mark_of_the_web, ZeroizingBytes,
};

use crate::enterprise::ledger::AuditLedger;
use crate::error::{DegradationEvent, SentinelError};
use crate::scanner::secure_shredder::{SecureShredder, ShredMethod};
use crate::scanner::universal_scanner::{UniversalScanner, UniversalThreat};

pub const DEFAULT_MAX_SHADOW_CACHE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
pub const DEFAULT_MAX_SHADOW_CACHE_FILES: usize = 10_000;

#[derive(Debug, Clone)]
pub struct VirtualFileEntry {
    pub relative_path: PathBuf,
    pub original_size: u64,
    pub sanitized_size: u64,
    pub source_sha256: String,
    pub sanitized_sha256: String,
    pub is_directory: bool,
    pub is_sanitized: bool,
    pub encrypted_cache_path: Option<PathBuf>,
    pub cached_clean_path: Option<PathBuf>,
}

#[async_trait]
pub trait VirtualFileSystemProvider: Send + Sync {
    fn provider_name(&self) -> &'static str {
        "ProjFS + Read-Once ShadowCache"
    }

    async fn mount_sanitized_volume(
        &self,
        raw_volume_path: &Path,
        virtual_mount_point: &Path,
    ) -> Result<(), String>;

    #[allow(non_snake_case)]
    async fn on_file_First_open(&self, relative_path: &Path) -> Result<PathBuf, String>;

    async fn unmount_volume(&self, virtual_mount_point: &Path) -> Result<(), String>;

    fn take_withheld_threats(&self, _virtual_mount_point: &Path) -> Vec<UniversalThreat> {
        Vec::new()
    }
}

/// Per-Session Read-Once Encrypted Shadow Cache (`BUG-CORE-13`, `Invariant I2`, `ADR-010`, Phase 3.2)
///
/// Defends against hardware TOCTOU attacks (BadUSB storage controllers returning
/// benign bytes on scan read #1 and malicious bytes on Explorer read #2) by:
/// 1. Reading each file from the USB volume **at most once** during the read-only window,
///    computing `source_sha256`, and returning the raw USB volume offline immediately afterward.
/// 2. Running `UniversalScanner::scan_bytes_single_read` (over an in-memory `Cursor`) and
///    `WorkerLauncher::sanitize_isolated` (sandboxed child process, `Invariant I3`) against
///    that single-read buffer without ever re-opening the file on the USB device.
/// 3. Failing closed (`!complete`) if any walk error, metadata error, file read error,
///    or file-count limit occurs (`Row 85`).
/// 4. Storing sanitized files inside `C:\ProgramData\OmniConnect\ShadowCache\<session_id>`
///    (protected by `apply_system_admin_dacl`) **exclusively as AES-256-GCM `.enc` ciphertexts**
///    under a per-session `ZeroizingBytes<32>` key (`Rows 146, 147, 223`).
/// 5. Enforcing a configurable byte quota (`max_cache_bytes`), emitting `CACHE_QUOTA_EXCEEDED`
///    on overflow (`Row 195`).
/// 6. Decrypting and verifying `sanitized_sha256` on demand when serving files, attaching
///    Mark-of-the-Web (`ZoneId=3`), and destroying the session key + shredding cache directories on unplug.
pub struct ShadowCacheManager {
    sessions: Arc<Mutex<HashMap<PathBuf, ShadowSessionState>>>,
    cache_root_override: Option<PathBuf>,
    max_cache_bytes: u64,
    max_files: usize,
    ledger_path: PathBuf,
}

struct ShadowSessionState {
    session_id: String,
    session_key: ZeroizingBytes<32>,
    entries: HashMap<PathBuf, VirtualFileEntry>,
    projection_root: PathBuf,
    shadow_cipher_dir: PathBuf,
    total_cached_bytes: u64,
    withheld_threats: Vec<UniversalThreat>,
}

impl Default for ShadowCacheManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowCacheManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            cache_root_override: None,
            max_cache_bytes: DEFAULT_MAX_SHADOW_CACHE_BYTES,
            max_files: DEFAULT_MAX_SHADOW_CACHE_FILES,
            ledger_path: Self::default_ledger_path(),
        }
    }

    pub fn with_cache_root_and_quota(cache_root: PathBuf, max_cache_bytes: u64) -> Self {
        let ledger_path = cache_root.join("shadow_cache_audit.jsonl");
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            cache_root_override: Some(cache_root),
            max_cache_bytes,
            max_files: DEFAULT_MAX_SHADOW_CACHE_FILES,
            ledger_path,
        }
    }

    pub fn with_max_cache_bytes(mut self, max_cache_bytes: u64) -> Self {
        self.max_cache_bytes = max_cache_bytes;
        self
    }

    pub fn with_max_files(mut self, max_files: usize) -> Self {
        self.max_files = max_files;
        self
    }

    pub fn with_ledger_path(mut self, ledger_path: PathBuf) -> Self {
        self.ledger_path = ledger_path;
        self
    }

    fn default_ledger_path() -> PathBuf {
        #[cfg(windows)]
        {
            let p = PathBuf::from(r"C:\ProgramData\OmniConnect\AuditLedger\shadow_cache_audit.jsonl");
            if let Some(parent) = p.parent() {
                if fs::create_dir_all(parent).is_ok() {
                    return p;
                }
            }
        }
        std::env::temp_dir()
            .join(format!("OmniConnect_ShadowCache_{}", std::process::id()))
            .join("shadow_cache_audit.jsonl")
    }

    fn resolve_session_cipher_dir(&self, session_id: &str) -> Result<PathBuf, String> {
        let base_dir = if let Some(ref custom_root) = self.cache_root_override {
            custom_root.clone()
        } else {
            #[cfg(windows)]
            {
                let prog_data = PathBuf::from(r"C:\ProgramData\OmniConnect\ShadowCache");
                if fs::create_dir_all(&prog_data).is_ok() {
                    prog_data
                } else {
                    std::env::temp_dir()
                        .join("OmniConnect")
                        .join("ShadowCache")
                }
            }
            #[cfg(not(windows))]
            {
                let var_lib = PathBuf::from("/var/lib/omniconnect/shadow_cache");
                if fs::create_dir_all(&var_lib).is_ok() {
                    var_lib
                } else {
                    std::env::temp_dir()
                        .join("omniconnect")
                        .join("shadow_cache")
                }
            }
        };

        let session_dir = base_dir.join(session_id);
        fs::create_dir_all(&session_dir).map_err(|e| {
            format!(
                "Failed creating encrypted shadow cache directory '{}': {}",
                session_dir.display(),
                e
            )
        })?;
        apply_system_admin_dacl(&session_dir).map_err(|e| {
            format!(
                "Failed applying SYSTEM/Administrators DACL to shadow cache directory '{}': {}",
                session_dir.display(),
                e
            )
        })?;
        Ok(session_dir)
    }

    fn append_ledger(&self, event: &str, details: &str) {
        let mut ledger = AuditLedger::open(&self.ledger_path);
        let _ = ledger.append_event(event, details);
    }

    fn cleanup_cipher_dir(dir: &Path) {
        if !dir.exists() {
            return;
        }
        for entry in WalkDir::new(dir)
            .contents_first(true)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            let p = entry.path();
            if entry.file_type().is_file() {
                let _ = normalize_file_attributes(p);
                let _ = SecureShredder::shred_file(p, ShredMethod::ClearMultiPass { passes: 3 });
            } else if entry.file_type().is_dir() && p != dir {
                let _ = fs::remove_dir(p);
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    /// Alias for `ingest_volume_read_once` (`Sub-Phase 3.1`).
    pub fn ingest_usb_volume(
        &self,
        raw_volume_path: &Path,
        virtual_mount_point: &Path,
    ) -> Result<usize, String> {
        self.ingest_volume_read_once(raw_volume_path, virtual_mount_point)
    }

    /// Reads each regular file on `raw_volume_path` **at most once**, hashes it (`source_sha256`),
    /// scans the single-read copy with `UniversalScanner::scan_bytes_single_read`, disarms it in
    /// the isolated `sentinel-cdr-worker` process, and stores **only AES-256-GCM `.enc` ciphertexts**
    /// inside `%ProgramData%\OmniConnect\ShadowCache\<session_id>` (`Rows 7, 70, 85, 146, 147, 195`).
    pub fn ingest_volume_read_once(
        &self,
        raw_volume_path: &Path,
        virtual_mount_point: &Path,
    ) -> Result<usize, String> {
        if !raw_volume_path.exists() {
            let msg = SentinelError::WalkAccessDenied(format!(
                "Raw USB volume path '{}' does not exist or is inaccessible",
                raw_volume_path.display()
            ))
            .to_string();
            self.append_ledger("SHADOW_CACHE_INGEST_INCOMPLETE", &msg);
            return Err(msg);
        }

        fs::create_dir_all(virtual_mount_point).map_err(|e| {
            format!(
                "Failed creating virtual projection root '{}': {}",
                virtual_mount_point.display(),
                e
            )
        })?;

        let session_id = Uuid::new_v4().to_string();
        let shadow_cipher_dir = self.resolve_session_cipher_dir(&session_id)?;

        // If `raw_volume_path` is a volume device path, open the controlled read-only window (`Row 16, 146`)
        let raw_str = raw_volume_path.to_string_lossy();
        let is_volume_device = raw_str.starts_with(r"\\?\Volume{")
            || (raw_str.len() <= 3 && raw_str.ends_with('\\'));
        if is_volume_device {
            let _ = set_volume_online_readonly(raw_volume_path, true);
        }

        let mut raw_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_key);
        let session_key = ZeroizingBytes::new(raw_key);
        sentinel_sys::zeroize_slice(&mut raw_key);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key.as_slice()));

        let worker_launcher = WorkerLauncher::new();
        let default_policy = SanitizationPolicy::default();
        let mut entries = HashMap::new();
        let mut withheld_threats = Vec::new();
        let mut projected_count = 0usize;
        let mut files_scanned = 0usize;
        let mut total_cached_bytes = 0u64;

        for entry_res in WalkDir::new(raw_volume_path)
            .follow_links(false)
            .same_file_system(true)
        {
            // Row 85: Fail closed on any walk error
            let entry = match entry_res {
                Ok(e) => e,
                Err(walk_err) => {
                    Self::cleanup_cipher_dir(&shadow_cipher_dir);
                    if is_volume_device {
                        let _ = set_volume_offline(raw_volume_path, true);
                    }
                    let msg = SentinelError::WalkAccessDenied(format!(
                        "ShadowCache directory walk failed inside '{}': {}",
                        raw_volume_path.display(),
                        walk_err
                    ))
                    .to_string();
                    self.append_ledger("SHADOW_CACHE_INGEST_INCOMPLETE", &msg);
                    return Err(msg);
                }
            };

            let path = entry.path();
            if path == raw_volume_path {
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(meta_err) => {
                    Self::cleanup_cipher_dir(&shadow_cipher_dir);
                    if is_volume_device {
                        let _ = set_volume_offline(raw_volume_path, true);
                    }
                    let msg = SentinelError::WalkAccessDenied(format!(
                        "ShadowCache metadata query failed for '{}': {}",
                        path.display(),
                        meta_err
                    ))
                    .to_string();
                    self.append_ledger("SHADOW_CACHE_INGEST_INCOMPLETE", &msg);
                    return Err(msg);
                }
            };

            if entry.path_is_symlink() || is_reparse_point_or_symlink(&meta) {
                warn!(
                    "ShadowCache skipping symlink/reparse point on removable media: {}",
                    path.display()
                );
                continue;
            }

            let rel_path = match path.strip_prefix(raw_volume_path) {
                Ok(r) => r.to_path_buf(),
                Err(_) => continue,
            };

            if entry.file_type().is_dir() {
                entries.insert(
                    rel_path.clone(),
                    VirtualFileEntry {
                        relative_path: rel_path,
                        original_size: 0,
                        sanitized_size: 0,
                        source_sha256: String::new(),
                        sanitized_sha256: String::new(),
                        is_directory: true,
                        is_sanitized: true,
                        encrypted_cache_path: None,
                        cached_clean_path: None,
                    },
                );
                continue;
            }

            if !entry.file_type().is_file() {
                continue;
            }

            files_scanned += 1;
            if files_scanned > self.max_files {
                Self::cleanup_cipher_dir(&shadow_cipher_dir);
                if is_volume_device {
                    let _ = set_volume_offline(raw_volume_path, true);
                }
                let msg = SentinelError::WalkAccessDenied(format!(
                    "ShadowCache file count exceeded max_files limit ({}) on '{}'",
                    self.max_files,
                    raw_volume_path.display()
                ))
                .to_string();
                self.append_ledger("SHADOW_CACHE_INGEST_INCOMPLETE", &msg);
                return Err(msg);
            }

            // Read file from USB device ONCE into memory (`Invariant I2`, `Row 7, 70` TOCTOU defense)
            let raw_bytes = match fs::read(path) {
                Ok(b) => b,
                Err(read_err) => {
                    Self::cleanup_cipher_dir(&shadow_cipher_dir);
                    if is_volume_device {
                        let _ = set_volume_offline(raw_volume_path, true);
                    }
                    let msg = SentinelError::WalkAccessDenied(format!(
                        "ShadowCache single-read failed for '{}': {}",
                        path.display(),
                        read_err
                    ))
                    .to_string();
                    self.append_ledger("SHADOW_CACHE_INGEST_INCOMPLETE", &msg);
                    return Err(msg);
                }
            };

            let original_size = raw_bytes.len() as u64;
            let source_sha256 = hex::encode(Sha256::digest(&raw_bytes));
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();

            // Run UniversalScanner on the single-read byte slice without re-opening the USB file (`Row 7, 70`)
            let threats = UniversalScanner::scan_bytes_single_read(path, &raw_bytes);
            if threats
                .iter()
                .any(|t| !t.can_disarm_via_cdr || t.stream_name.is_some())
            {
                withheld_threats.extend(threats);
                warn!(
                    "ShadowCache blocked non-disarmable threat-flagged file '{}' (source_sha256={})",
                    path.display(),
                    source_sha256
                );
                self.append_ledger(
                    "SHADOW_CACHE_THREAT_WITHHELD",
                    &format!("path={} sha256={}", path.display(), source_sha256),
                );
                continue;
            }

            // Dispatch to isolated sandboxed CDR worker (`Invariant I3` — zero in-process CdrEngine calls)
            let release_bytes = match worker_launcher.sanitize_isolated(WorkerRequest {
                file_name,
                policy: default_policy.clone(),
                raw_bytes,
            }) {
                Ok(outcome) => outcome.clean_bytes,
                Err(e) => {
                    warn!(
                        "ShadowCache withheld file '{}' rejected by sandboxed CDR worker: {}",
                        path.display(),
                        e
                    );
                    self.append_ledger(
                        "SHADOW_CACHE_CDR_WITHHELD",
                        &format!(
                            "path={} sha256={} reason={}",
                            path.display(),
                            source_sha256,
                            e
                        ),
                    );
                    continue;
                }
            };

            let sanitized_size = release_bytes.len() as u64;
            total_cached_bytes = total_cached_bytes.saturating_add(sanitized_size);
            if total_cached_bytes > self.max_cache_bytes {
                Self::cleanup_cipher_dir(&shadow_cipher_dir);
                if is_volume_device {
                    let _ = set_volume_offline(raw_volume_path, true);
                }
                let msg = SentinelError::CacheQuotaExceeded(format!(
                    "ShadowCache quota exceeded ({} > {} bytes) while caching '{}'",
                    total_cached_bytes,
                    self.max_cache_bytes,
                    path.display()
                ))
                .to_string();
                self.append_ledger(DegradationEvent::CacheQuotaExceeded.event_code(), &msg);
                return Err(msg);
            }

            let sanitized_sha256 = hex::encode(Sha256::digest(&release_bytes));
            let rel_str = rel_path.to_string_lossy();

            // Encrypt sanitized output with AES-256-GCM bound to relative_path AAD (`Row 147, 223`)
            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: release_bytes.as_slice(),
                        aad: rel_str.as_bytes(),
                    },
                )
                .map_err(|e| format!("ShadowCache AES-256-GCM encryption failed: {}", e))?;

            let entry_id_hash = hex::encode(Sha256::digest(rel_str.as_bytes()));
            let enc_path = shadow_cipher_dir.join(format!("{}.enc", &entry_id_hash[..32]));
            let mut enc_payload = Vec::with_capacity(12 + ciphertext.len());
            enc_payload.extend_from_slice(&nonce_bytes);
            enc_payload.extend_from_slice(&ciphertext);

            {
                let mut enc_f = File::create(&enc_path).map_err(|e| {
                    format!(
                        "ShadowCache failed creating encrypted entry '{}': {}",
                        enc_path.display(),
                        e
                    )
                })?;
                enc_f.write_all(&enc_payload).map_err(|e| {
                    format!(
                        "ShadowCache failed writing encrypted entry '{}': {}",
                        enc_path.display(),
                        e
                    )
                })?;
                enc_f.sync_all().map_err(|e| {
                    format!(
                        "ShadowCache failed syncing encrypted entry '{}': {}",
                        enc_path.display(),
                        e
                    )
                })?;
            }
            apply_system_admin_dacl(&enc_path).map_err(|e| {
                format!(
                    "ShadowCache failed applying DACL to encrypted entry '{}': {}",
                    enc_path.display(),
                    e
                )
            })?;

            projected_count += 1;
            entries.insert(
                rel_path.clone(),
                VirtualFileEntry {
                    relative_path: rel_path,
                    original_size,
                    sanitized_size,
                    source_sha256,
                    sanitized_sha256,
                    is_directory: false,
                    is_sanitized: true,
                    encrypted_cache_path: Some(enc_path),
                    cached_clean_path: None,
                },
            );
        }

        // Return raw USB volume offline immediately after single-read ingestion (`Row 146`)
        if is_volume_device {
            let _ = set_volume_offline(raw_volume_path, true);
        }

        if let Ok(mut guard) = self.sessions.lock() {
            guard.insert(
                virtual_mount_point.to_path_buf(),
                ShadowSessionState {
                    session_id: session_id.clone(),
                    session_key,
                    entries,
                    projection_root: virtual_mount_point.to_path_buf(),
                    shadow_cipher_dir: shadow_cipher_dir.clone(),
                    total_cached_bytes,
                    withheld_threats,
                },
            );
        }

        self.append_ledger(
            "SHADOW_CACHE_INGEST_COMPLETE",
            &format!(
                "session={} files={} bytes={} cipher_dir={}",
                session_id,
                projected_count,
                total_cached_bytes,
                shadow_cipher_dir.display()
            ),
        );

        info!(
            "ShadowCache ingested {} verified files ({} bytes encrypted at {}) for virtualization root {}",
            projected_count,
            total_cached_bytes,
            shadow_cipher_dir.display(),
            virtual_mount_point.display()
        );
        Ok(projected_count)
    }

    /// Decrypts a `.enc` entry from `%ProgramData%\OmniConnect\ShadowCache\<session_id>` using
    /// the session's `ZeroizingBytes<32>` key and verifies its SHA-256 against `sanitized_sha256` (`Row 148`).
    pub fn read_projected_file(
        &self,
        virtual_mount_point: &Path,
        relative_path: &Path,
    ) -> Result<Vec<u8>, String> {
        let guard = self.sessions.lock().map_err(|e| e.to_string())?;
        let session = guard.get(virtual_mount_point).ok_or_else(|| {
            format!(
                "No active ShadowCache session for mount '{}'",
                virtual_mount_point.display()
            )
        })?;
        let entry = session.entries.get(relative_path).ok_or_else(|| {
            format!(
                "Projected file '{}' not found in shadow cache",
                relative_path.display()
            )
        })?;
        if entry.is_directory {
            return Err(format!(
                "Projected entry '{}' is a directory",
                relative_path.display()
            ));
        }
        let enc_path = entry.encrypted_cache_path.as_ref().ok_or_else(|| {
            format!(
                "Projected file '{}' has no encrypted cache backing",
                relative_path.display()
            )
        })?;

        let enc_payload = fs::read(enc_path).map_err(|e| {
            format!(
                "Failed reading encrypted shadow cache entry '{}': {}",
                enc_path.display(),
                e
            )
        })?;
        if enc_payload.len() < 12 + 16 {
            return Err(format!(
                "SHADOW_CACHE_INTEGRITY_FAILURE: Truncated ciphertext in '{}'",
                enc_path.display()
            ));
        }

        let (nonce_bytes, ciphertext) = enc_payload.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session.session_key.as_slice()));
        let rel_str = relative_path.to_string_lossy();
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: rel_str.as_bytes(),
                },
            )
            .map_err(|_| {
                format!(
                    "SHADOW_CACHE_INTEGRITY_FAILURE: AES-256-GCM authentication tag verification failed for '{}'",
                    relative_path.display()
                )
            })?;

        let actual_sha256 = hex::encode(Sha256::digest(&plaintext));
        if actual_sha256 != entry.sanitized_sha256 {
            return Err(format!(
                "SHADOW_CACHE_INTEGRITY_FAILURE: SHA-256 mismatch for '{}' (expected {}, got {})",
                relative_path.display(),
                entry.sanitized_sha256,
                actual_sha256
            ));
        }

        Ok(plaintext)
    }

    /// Returns the recorded `(source_sha256, sanitized_sha256)` for a cached file entry.
    pub fn get_entry_hashes(
        &self,
        virtual_mount_point: &Path,
        relative_path: &Path,
    ) -> Result<(String, String), String> {
        let guard = self.sessions.lock().map_err(|e| e.to_string())?;
        let session = guard.get(virtual_mount_point).ok_or_else(|| {
            format!(
                "No active ShadowCache session for mount '{}'",
                virtual_mount_point.display()
            )
        })?;
        let entry = session.entries.get(relative_path).ok_or_else(|| {
            format!(
                "Projected file '{}' not found in shadow cache",
                relative_path.display()
            )
        })?;
        Ok((entry.source_sha256.clone(), entry.sanitized_sha256.clone()))
    }

    /// Alias for `read_projected_file` that decrypts the `.enc` shadow cache file and verifies `sanitized_sha256` (`Invariant I2`, `Row 148`).
    pub fn read_and_verify(
        &self,
        virtual_mount_point: &Path,
        relative_path: &Path,
    ) -> Result<Vec<u8>, String> {
        self.read_projected_file(virtual_mount_point, relative_path)
    }

    /// Returns the on-disk `.enc` ciphertext path for a cached file entry (`Row 147`).
    pub fn get_encrypted_cache_path(
        &self,
        virtual_mount_point: &Path,
        relative_path: &Path,
    ) -> Result<PathBuf, String> {
        let guard = self.sessions.lock().map_err(|e| e.to_string())?;
        let session = guard.get(virtual_mount_point).ok_or_else(|| {
            format!(
                "No active ShadowCache session for mount '{}'",
                virtual_mount_point.display()
            )
        })?;
        let entry = session.entries.get(relative_path).ok_or_else(|| {
            format!(
                "Projected file '{}' not found in shadow cache",
                relative_path.display()
            )
        })?;
        entry.encrypted_cache_path.clone().ok_or_else(|| {
            format!(
                "Projected file '{}' has no encrypted cache path",
                relative_path.display()
            )
        })
    }

    /// Ingests a single stream from `reader` **at most once** (`Invariant I2` TOCTOU rig test helper),
    /// scans the single-read copy, disarms it via the isolated `sentinel-cdr-worker` (`Invariant I3`),
    /// and stores only AES-256-GCM `.enc` ciphertext on disk (`Rows 7, 70, 146, 147, 203`).
    pub fn ingest_stream_from_reader<R: std::io::Read>(
        &self,
        virtual_mount_point: &Path,
        relative_path: &Path,
        mut reader: R,
    ) -> Result<VirtualFileEntry, String> {
        fs::create_dir_all(virtual_mount_point).map_err(|e| {
            format!(
                "Failed creating virtual projection root '{}': {}",
                virtual_mount_point.display(),
                e
            )
        })?;

        let session_id = Uuid::new_v4().to_string();
        let shadow_cipher_dir = self.resolve_session_cipher_dir(&session_id)?;

        // Read stream ONCE into memory (`Invariant I2`)
        let mut raw_bytes = Vec::new();
        if let Err(read_err) = reader.read_to_end(&mut raw_bytes) {
            Self::cleanup_cipher_dir(&shadow_cipher_dir);
            let msg = SentinelError::WalkAccessDenied(format!(
                "ShadowCache single-read stream failed for '{}': {}",
                relative_path.display(),
                read_err
            ))
            .to_string();
            self.append_ledger("SHADOW_CACHE_INGEST_INCOMPLETE", &msg);
            return Err(msg);
        }

        let original_size = raw_bytes.len() as u64;
        let source_sha256 = hex::encode(Sha256::digest(&raw_bytes));
        let file_name = relative_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("stream.bin")
            .to_string();

        let threats = UniversalScanner::scan_bytes_single_read(relative_path, &raw_bytes);
        if threats
            .iter()
            .any(|t| !t.can_disarm_via_cdr || t.stream_name.is_some())
        {
            Self::cleanup_cipher_dir(&shadow_cipher_dir);
            let msg = format!(
                "ShadowCache blocked non-disarmable threat in stream '{}' (source_sha256={})",
                relative_path.display(),
                source_sha256
            );
            self.append_ledger("SHADOW_CACHE_THREAT_WITHHELD", &msg);
            return Err(msg);
        }

        let worker_launcher = WorkerLauncher::new();
        let outcome = worker_launcher
            .sanitize_isolated(WorkerRequest {
                file_name,
                policy: SanitizationPolicy::default(),
                raw_bytes,
            })
            .map_err(|e| {
                Self::cleanup_cipher_dir(&shadow_cipher_dir);
                let msg = format!("CDR_WORKER_FAILED: {}", e);
                self.append_ledger("CDR_WORKER_FAILED", &msg);
                msg
            })?;

        let release_bytes = outcome.clean_bytes;
        let sanitized_size = release_bytes.len() as u64;
        if sanitized_size > self.max_cache_bytes {
            Self::cleanup_cipher_dir(&shadow_cipher_dir);
            let msg = SentinelError::CacheQuotaExceeded(format!(
                "ShadowCache quota exceeded ({} > {} bytes)",
                sanitized_size, self.max_cache_bytes
            ))
            .to_string();
            self.append_ledger(DegradationEvent::CacheQuotaExceeded.event_code(), &msg);
            return Err(msg);
        }

        let sanitized_sha256 = hex::encode(Sha256::digest(&release_bytes));
        let rel_str = relative_path.to_string_lossy();

        let mut raw_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_key);
        let session_key = ZeroizingBytes::new(raw_key);
        sentinel_sys::zeroize_slice(&mut raw_key);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key.as_slice()));

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: release_bytes.as_slice(),
                    aad: rel_str.as_bytes(),
                },
            )
            .map_err(|e| format!("ShadowCache AES-256-GCM encryption failed: {}", e))?;

        let entry_id_hash = hex::encode(Sha256::digest(rel_str.as_bytes()));
        let enc_path = shadow_cipher_dir.join(format!("{}.enc", &entry_id_hash[..32]));
        let mut enc_payload = Vec::with_capacity(12 + ciphertext.len());
        enc_payload.extend_from_slice(&nonce_bytes);
        enc_payload.extend_from_slice(&ciphertext);

        {
            let mut enc_f = File::create(&enc_path).map_err(|e| e.to_string())?;
            enc_f.write_all(&enc_payload).map_err(|e| e.to_string())?;
            enc_f.sync_all().map_err(|e| e.to_string())?;
        }
        apply_system_admin_dacl(&enc_path).map_err(|e| e.to_string())?;

        let v_entry = VirtualFileEntry {
            relative_path: relative_path.to_path_buf(),
            original_size,
            sanitized_size,
            source_sha256,
            sanitized_sha256,
            is_directory: false,
            is_sanitized: true,
            encrypted_cache_path: Some(enc_path),
            cached_clean_path: None,
        };

        let mut entries = HashMap::new();
        entries.insert(relative_path.to_path_buf(), v_entry.clone());

        if let Ok(mut guard) = self.sessions.lock() {
            guard.insert(
                virtual_mount_point.to_path_buf(),
                ShadowSessionState {
                    session_id,
                    session_key,
                    entries,
                    projection_root: virtual_mount_point.to_path_buf(),
                    shadow_cipher_dir,
                    total_cached_bytes: sanitized_size,
                    withheld_threats: Vec::new(),
                },
            );
        }

        Ok(v_entry)
    }

    /// Decrypts and verifies the `.enc` entry via `read_projected_file`, then hydrates a
    /// read-only file with Mark-of-the-Web (`ZoneId=3`) at `virtual_mount_point/relative_path`.
    pub fn resolve_projected_file(
        &self,
        virtual_mount_point: &Path,
        relative_path: &Path,
    ) -> Result<PathBuf, String> {
        let verified_bytes = self.read_projected_file(virtual_mount_point, relative_path)?;
        let projected_path = virtual_mount_point.join(relative_path);
        if let Some(parent) = projected_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Failed creating parent directory for projected file '{}': {}",
                    projected_path.display(),
                    e
                )
            })?;
        }
        if projected_path.exists() {
            let _ = normalize_file_attributes(&projected_path);
        }
        {
            let mut out_f = File::create(&projected_path).map_err(|e| {
                format!(
                    "Failed creating hydrated file '{}': {}",
                    projected_path.display(),
                    e
                )
            })?;
            out_f.write_all(&verified_bytes).map_err(|e| {
                format!(
                    "Failed writing hydrated file '{}': {}",
                    projected_path.display(),
                    e
                )
            })?;
            out_f.sync_all().map_err(|e| {
                format!(
                    "Failed syncing hydrated file '{}': {}",
                    projected_path.display(),
                    e
                )
            })?;
        }

        // Propagate Mark-of-the-Web (`ZoneId=3`) errors (`Row 136`)
        write_mark_of_the_web(&projected_path, 3).map_err(|e| {
            format!(
                "Failed attaching Mark-of-the-Web (ZoneId=3) to '{}': {}",
                projected_path.display(),
                e
            )
        })?;

        // Set hydrated file to read-only for interactive users (`Row 148, 151`)
        if let Ok(meta) = fs::metadata(&projected_path) {
            let mut perms = meta.permissions();
            perms.set_readonly(true);
            let _ = fs::set_permissions(&projected_path, perms);
        }

        if let Ok(mut guard) = self.sessions.lock() {
            if let Some(session) = guard.get_mut(virtual_mount_point) {
                if let Some(entry) = session.entries.get_mut(relative_path) {
                    entry.cached_clean_path = Some(projected_path.clone());
                }
            }
        }

        Ok(projected_path)
    }

    /// Materializes all released files into a read-only staging folder with Mark-of-the-Web (`ZoneId=3`)
    /// when `StagingFolderProvider` fallback is active (`Row 151`).
    pub fn materialize_all_readonly_staging(
        &self,
        virtual_mount_point: &Path,
    ) -> Result<usize, String> {
        let rel_paths: Vec<PathBuf> = {
            let guard = self.sessions.lock().map_err(|e| e.to_string())?;
            let session = guard.get(virtual_mount_point).ok_or_else(|| {
                format!(
                    "No active ShadowCache session for mount '{}'",
                    virtual_mount_point.display()
                )
            })?;
            session
                .entries
                .values()
                .filter(|e| !e.is_directory)
                .map(|e| e.relative_path.clone())
                .collect()
        };

        let mut count = 0usize;
        for rel in rel_paths {
            self.resolve_projected_file(virtual_mount_point, &rel)?;
            count += 1;
        }
        Ok(count)
    }

    /// Returns and clears any threats withheld during single-read ingestion of `virtual_mount_point`.
    pub fn take_withheld_threats(&self, virtual_mount_point: &Path) -> Vec<UniversalThreat> {
        if let Ok(mut guard) = self.sessions.lock() {
            if let Some(session) = guard.get_mut(virtual_mount_point) {
                return std::mem::take(&mut session.withheld_threats);
            }
        }
        Vec::new()
    }

    /// Destroys the per-session `ZeroizingBytes<32>` key (`CryptoErase`) and shreds both the
    /// `%ProgramData%\OmniConnect\ShadowCache\<session_id>` ciphertext directory and any
    /// hydrated files in the projection root (`Row 149`).
    pub fn teardown_session(&self, virtual_mount_point: &Path) -> Result<(), String> {
        let removed_session = self
            .sessions
            .lock()
            .map_err(|e| e.to_string())?
            .remove(virtual_mount_point);

        if let Some(session) = removed_session {
            let session_id = session.session_id.clone();
            let cipher_dir = session.shadow_cipher_dir.clone();
            let proj_root = session.projection_root.clone();
            let cached_bytes = session.total_cached_bytes;

            // Explicitly drop `session` first so `session.session_key: ZeroizingBytes<32>`
            // is volatile-zeroed and unlocked in RAM before disk cleanup (`Row 149`).
            drop(session);

            Self::cleanup_cipher_dir(&cipher_dir);
            Self::cleanup_cipher_dir(&proj_root);

            self.append_ledger(
                "SHADOW_CACHE_SESSION_TEARDOWN",
                &format!(
                    "session={} bytes={} cipher_dir={} projection_root={}",
                    session_id,
                    cached_bytes,
                    cipher_dir.display(),
                    proj_root.display()
                ),
            );
        }

        Ok(())
    }
}

/// Read-Only Staging Folder VFS Fallback (`POSTURE_REDUCED_NO_PROJFS`, Phase 3.2 & 5.1)
///
/// Used when Windows ProjFS is not enabled on the endpoint. Decrypts and verifies released
/// files from the Read-Once Encrypted Shadow Cache into a read-only staging folder with
/// Mark-of-the-Web (`ZoneId=3`) and records `DegradationEvent::PostureReducedNoProjfs`.
pub struct StagingFolderProvider {
    shadow_cache: ShadowCacheManager,
    active_mount: Mutex<Option<PathBuf>>,
}

impl Default for StagingFolderProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl StagingFolderProvider {
    pub fn new() -> Self {
        Self {
            shadow_cache: ShadowCacheManager::new(),
            active_mount: Mutex::new(None),
        }
    }
}

#[async_trait]
impl VirtualFileSystemProvider for StagingFolderProvider {
    fn provider_name(&self) -> &'static str {
        "Read-Only Staging Folder Fallback (POSTURE_REDUCED_NO_PROJFS)"
    }

    async fn mount_sanitized_volume(
        &self,
        raw_volume_path: &Path,
        virtual_mount_point: &Path,
    ) -> Result<(), String> {
        let event_code = DegradationEvent::PostureReducedNoProjfs.event_code();
        warn!(
            "[{}] ProjFS unavailable; falling back to read-only staging folder at {}",
            event_code,
            virtual_mount_point.display()
        );
        self.shadow_cache.append_ledger(
            event_code,
            &format!(
                "ProjFS unavailable; using StagingFolderProvider for {}",
                virtual_mount_point.display()
            ),
        );
        self.shadow_cache
            .ingest_volume_read_once(raw_volume_path, virtual_mount_point)?;
        self.shadow_cache
            .materialize_all_readonly_staging(virtual_mount_point)?;
        if let Ok(mut guard) = self.active_mount.lock() {
            *guard = Some(virtual_mount_point.to_path_buf());
        }
        Ok(())
    }

    async fn on_file_First_open(&self, relative_path: &Path) -> Result<PathBuf, String> {
        let mount_root = self
            .active_mount
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "StagingFolderProvider has no active mounted volume".to_string())?;
        self.shadow_cache
            .resolve_projected_file(&mount_root, relative_path)
    }

    async fn unmount_volume(&self, virtual_mount_point: &Path) -> Result<(), String> {
        if let Ok(mut guard) = self.active_mount.lock() {
            *guard = None;
        }
        self.shadow_cache.teardown_session(virtual_mount_point)
    }
}

/// Resolves the inbox OS userspace VFS provider (Hardened Option B, `Rows 148–153, 193`):
/// - Windows: Probes `is_projfs_available()`; selects `ProjFsProvider` when `ProjectedFSLib.dll` is present,
///   otherwise records `POSTURE_REDUCED_NO_PROJFS` and selects `StagingFolderProvider`.
/// - Linux: `FuseVfsProvider` (Linux FUSE3 userspace mount)
pub fn resolve_best_vfs_provider() -> Box<dyn VirtualFileSystemProvider> {
    #[cfg(target_os = "windows")]
    {
        if is_projfs_available() {
            info!("Selected VFS Backend: Windows Projected File System (ProjFS + Read-Once ShadowCache)");
            Box::new(projfs::ProjFsProvider::new())
        } else {
            warn!(
                "[{}] ProjectedFSLib.dll not enabled; selecting Read-Only StagingFolderProvider fallback",
                DegradationEvent::PostureReducedNoProjfs.event_code()
            );
            Box::new(StagingFolderProvider::new())
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        info!("Selected VFS Backend: Linux FUSE3 Userspace Mount (+ Read-Once ShadowCache)");
        Box::new(fuse::FuseVfsProvider::new())
    }
}
