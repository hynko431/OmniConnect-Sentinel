pub mod chunked_cache;
pub mod fuse;
pub mod projfs;
#[cfg(feature = "vfs-winfsp")]
pub mod winfsp;

pub use chunked_cache::{decrypt_chunked_stream, encrypt_chunked_stream, ChunkedCacheError};
pub use fuse::FuseVfsProvider as FuseProvider;
pub use projfs::ProjFsProvider;
pub type VfsProvider = dyn VirtualFileSystemProvider;

use async_trait::async_trait;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;
use walkdir::WalkDir;

use sentinel_cdr::{SanitizationPolicy, WorkerLauncher, WorkerRequest};
use sentinel_sys::{
    create_restricted_dir_atomic, create_restricted_file_atomic, is_projfs_reparse_point,
    is_reparse_point_or_symlink, normalize_file_attributes, open_untrusted_readonly_nofollow,
    read_untrusted_to_end_bounded, set_volume_offline, set_volume_online_readonly,
    write_mark_of_the_web, ZeroizingBytes,
};

use crate::enterprise::ledger::{
    tokenize_path_for_ledger, AuditLedger, AuditSubsystem, SharedAuditLedger,
};
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

    async fn on_file_first_open(&self, relative_path: &Path) -> Result<PathBuf, String>;

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
    shared_ledger: Option<SharedAuditLedger>,
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
            shared_ledger: None,
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
            shared_ledger: None,
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

    fn default_ledger_path() -> PathBuf {
        const LEDGER_NAME: &str = "shadow_cache_audit.jsonl";
        #[cfg(windows)]
        {
            if let Ok(pd) = std::env::var("ProgramData") {
                let dir = PathBuf::from(pd).join("OmniConnect").join("AuditLedger");
                if crate::enterprise::ledger::is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
                    return dir.join(LEDGER_NAME);
                }
            }
            if let Ok(lad) = std::env::var("LOCALAPPDATA") {
                let dir = PathBuf::from(lad).join("OmniConnect").join("AuditLedger");
                if crate::enterprise::ledger::is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
                    return dir.join(LEDGER_NAME);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let dir = PathBuf::from("/var/lib/omniconnect/audit_ledger");
            if crate::enterprise::ledger::is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
                return dir.join(LEDGER_NAME);
            }
            if let Ok(home) = std::env::var("HOME") {
                let dir = PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("omniconnect")
                    .join("audit_ledger");
                if crate::enterprise::ledger::is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
                    return dir.join(LEDGER_NAME);
                }
            }
        }
        #[cfg(test)]
        {
            std::env::temp_dir()
                .join(format!("OmniConnect_ShadowCache_{}", std::process::id()))
                .join(LEDGER_NAME)
        }
        #[cfg(not(test))]
        {
            if let Ok(cwd) = std::env::current_dir() {
                let dir = cwd.join(".sentinel_audit");
                if crate::enterprise::ledger::is_restricted_ledger_dir_writable(&dir, LEDGER_NAME) {
                    return dir.join(LEDGER_NAME);
                }
            }
            #[cfg(windows)]
            {
                PathBuf::from(r"C:\ProgramData\OmniConnect\AuditLedger\shadow_cache_audit.jsonl")
            }
            #[cfg(not(windows))]
            {
                PathBuf::from("/var/lib/omniconnect/audit_ledger/shadow_cache_audit.jsonl")
            }
        }
    }

    fn is_shadow_cache_root_writable(dir: &Path) -> bool {
        if create_restricted_dir_atomic(dir).is_err() {
            return false;
        }
        let probe = dir.join(format!(
            ".shadow_write_probe_{}_{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        if create_restricted_file_atomic(&probe, b"ok").is_ok() {
            let _ = fs::remove_file(&probe);
            true
        } else {
            false
        }
    }

    fn resolve_session_cipher_dir(&self, session_id: &str) -> Result<PathBuf, String> {
        let base_dir = if let Some(ref custom_root) = self.cache_root_override {
            custom_root.clone()
        } else {
            #[cfg(windows)]
            {
                let prog_data = PathBuf::from(r"C:\ProgramData\OmniConnect\ShadowCache");
                if Self::is_shadow_cache_root_writable(&prog_data) {
                    prog_data
                } else {
                    #[cfg(test)]
                    {
                        std::env::temp_dir().join("OmniConnect").join("ShadowCache")
                    }
                    #[cfg(not(test))]
                    {
                        if let Ok(lad) = std::env::var("LOCALAPPDATA") {
                            let lad_dir =
                                PathBuf::from(lad).join("OmniConnect").join("ShadowCache");
                            if Self::is_shadow_cache_root_writable(&lad_dir) {
                                lad_dir
                            } else if let Ok(cwd) = std::env::current_dir() {
                                let cwd_dir = cwd.join(".sentinel_shadow_cache");
                                if Self::is_shadow_cache_root_writable(&cwd_dir) {
                                    cwd_dir
                                } else {
                                    return Err(
                                        "Production shadow cache path 'C:\\ProgramData\\OmniConnect\\ShadowCache' is inaccessible"
                                            .to_string(),
                                    );
                                }
                            } else {
                                return Err(
                                    "Production shadow cache path 'C:\\ProgramData\\OmniConnect\\ShadowCache' is inaccessible"
                                        .to_string(),
                                );
                            }
                        } else if let Ok(cwd) = std::env::current_dir() {
                            let cwd_dir = cwd.join(".sentinel_shadow_cache");
                            if Self::is_shadow_cache_root_writable(&cwd_dir) {
                                cwd_dir
                            } else {
                                return Err(
                                    "Production shadow cache path 'C:\\ProgramData\\OmniConnect\\ShadowCache' is inaccessible"
                                        .to_string(),
                                );
                            }
                        } else {
                            return Err(
                                "Production shadow cache path 'C:\\ProgramData\\OmniConnect\\ShadowCache' is inaccessible"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
            #[cfg(not(windows))]
            {
                let var_lib = PathBuf::from("/var/lib/omniconnect/shadow_cache");
                if Self::is_shadow_cache_root_writable(&var_lib) {
                    var_lib
                } else {
                    #[cfg(test)]
                    {
                        std::env::temp_dir()
                            .join("omniconnect")
                            .join("shadow_cache")
                    }
                    #[cfg(not(test))]
                    {
                        if let Ok(home) = std::env::var("HOME") {
                            let home_dir = PathBuf::from(home)
                                .join(".local")
                                .join("share")
                                .join("omniconnect")
                                .join("shadow_cache");
                            if Self::is_shadow_cache_root_writable(&home_dir) {
                                home_dir
                            } else {
                                return Err(
                                    "Production shadow cache path '/var/lib/omniconnect/shadow_cache' is inaccessible"
                                        .to_string(),
                                );
                            }
                        } else {
                            return Err(
                                "Production shadow cache path '/var/lib/omniconnect/shadow_cache' is inaccessible"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        };

        let session_dir = base_dir.join(session_id);
        create_restricted_dir_atomic(&session_dir).map_err(|e| {
            format!(
                "Failed creating atomic restricted shadow cache directory '{}': {}",
                session_dir.display(),
                e
            )
        })?;
        Ok(session_dir)
    }

    pub(crate) fn tokenize_path_for_audit(&self, raw_path: &Path) -> String {
        tokenize_path_for_ledger(self.shared_ledger.as_ref(), &self.ledger_path, raw_path)
            .unwrap_or_else(|_| "TOKENIZATION_UNAVAILABLE".to_string())
    }

    fn append_ledger(&self, event: &str, details: &str) {
        if let Some(ref shared) = self.shared_ledger {
            if let Ok(mut guard) = shared.lock() {
                let _ = guard.append_subsystem_event(
                    AuditSubsystem::VfsShadow,
                    event,
                    serde_json::Value::String(details.to_string()),
                );
            }
            return;
        }
        let mut ledger = AuditLedger::open(&self.ledger_path);
        let _ = ledger.append_subsystem_event(
            AuditSubsystem::VfsShadow,
            event,
            serde_json::Value::String(details.to_string()),
        );
    }

    fn cleanup_cipher_dir(&self, dir: &Path) {
        let _ = Self::cleanup_dir_with_method(
            dir,
            ShredMethod::ClearMultiPass { passes: 3 },
            Some(&self.ledger_path),
            self.shared_ledger.as_ref(),
        );
    }

    fn cleanup_inception_encrypted_cipher_dir(&self, dir: &Path) -> Result<(), String> {
        Self::cleanup_dir_with_method(
            dir,
            ShredMethod::CryptoErase,
            Some(&self.ledger_path),
            self.shared_ledger.as_ref(),
        )
    }

    fn cleanup_dir_with_method(
        dir: &Path,
        method: ShredMethod,
        ledger_path: Option<&Path>,
        shared_ledger: Option<&SharedAuditLedger>,
    ) -> Result<(), String> {
        match fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(format!(
                    "ShadowCache cleanup failed inspecting directory '{}': {e}",
                    dir.display()
                ))
            }
            Ok(meta) if is_reparse_point_or_symlink(&meta) && !is_projfs_reparse_point(dir) => {
                return fs::remove_file(dir)
                    .or_else(|_| fs::remove_dir(dir))
                    .map_err(|e| {
                        format!(
                            "ShadowCache cleanup failed unlinking symlink/reparse root '{}': {e}",
                            dir.display()
                        )
                    });
            }
            Ok(_) => {}
        }

        let mut shred_errors = Vec::new();
        for entry_res in WalkDir::new(dir).contents_first(true).follow_links(false) {
            let entry = match entry_res {
                Ok(e) => e,
                Err(walk_err) => {
                    warn!(
                        "ShadowCache WalkDir error under '{}': {walk_err}",
                        dir.display()
                    );
                    shred_errors.push(format!("Walk error: {walk_err}"));
                    continue;
                }
            };

            let p = entry.path();
            let is_link_or_reparse = entry.path_is_symlink()
                || match fs::symlink_metadata(p) {
                    Ok(m) => is_reparse_point_or_symlink(&m),
                    Err(e) => {
                        warn!(
                            "ShadowCache symlink_metadata failed for '{}': {e}",
                            p.display()
                        );
                        shred_errors.push(format!("Metadata error for '{}': {e}", p.display()));
                        continue;
                    }
                };

            if is_link_or_reparse {
                if is_projfs_reparse_point(p) {
                    let _ = normalize_file_attributes(p);
                    let rm_res = if entry.file_type().is_dir() {
                        fs::remove_dir(p)
                    } else {
                        fs::remove_file(p)
                    };
                    if let Err(e) = rm_res {
                        warn!(
                            "ShadowCache failed removing ProjFS placeholder '{}': {e}",
                            p.display()
                        );
                        shred_errors.push(format!(
                            "Failed removing ProjFS placeholder '{}': {e}",
                            p.display()
                        ));
                    }
                } else if let Err(e) = fs::remove_file(p).or_else(|_| fs::remove_dir(p)) {
                    warn!(
                        "ShadowCache failed unlinking symlink/reparse '{}': {e}",
                        p.display()
                    );
                    shred_errors.push(format!(
                        "Failed unlinking symlink/reparse '{}': {e}",
                        p.display()
                    ));
                }
                continue;
            }

            if entry.file_type().is_file() {
                let _ = normalize_file_attributes(p);
                let res = if let Some(sl) = shared_ledger {
                    SecureShredder::shred_file_with_shared_ledger(p, method, Some(sl))
                } else if let Some(lp) = ledger_path {
                    SecureShredder::shred_file_with_ledger(p, method, lp)
                } else {
                    SecureShredder::shred_file(p, method)
                };
                if let Err(e) = res {
                    warn!("ShadowCache SecureShredder error on '{}': {e}", p.display());
                    shred_errors.push(format!("{}: {e}", p.display()));
                }
            } else if entry.file_type().is_dir() {
                let _ = normalize_file_attributes(p);
                if let Err(e) = fs::remove_dir(p) {
                    warn!(
                        "ShadowCache directory remove error on '{}': {e}",
                        p.display()
                    );
                    shred_errors.push(format!(
                        "Directory remove failed for '{}': {e}",
                        p.display()
                    ));
                }
            } else if let Err(e) = fs::remove_file(p) {
                shred_errors.push(format!(
                    "Special file remove failed for '{}': {e}",
                    p.display()
                ));
            }
        }

        match fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                shred_errors.push(format!(
                    "Directory '{}' still exists after ShadowCache teardown",
                    dir.display()
                ));
            }
            Err(e) => {
                shred_errors.push(format!(
                    "Post-teardown verification failed for '{}': {e}",
                    dir.display()
                ));
            }
        }

        if shred_errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "ShadowCache cleanup encountered {} shred/teardown error(s): {}",
                shred_errors.len(),
                shred_errors.join("; ")
            ))
        }
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
            let vol_token = self.tokenize_path_for_audit(raw_volume_path);
            self.append_ledger(
                "SHADOW_CACHE_INGEST_INCOMPLETE",
                &format!("reason=volume_inaccessible volume_token={vol_token}"),
            );
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
        let is_volume_device =
            raw_str.starts_with(r"\\?\Volume{") || (raw_str.len() <= 3 && raw_str.ends_with('\\'));
        if is_volume_device {
            let _ = set_volume_online_readonly(raw_volume_path, true);
        }

        let mut raw_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_key);
        let session_key = ZeroizingBytes::new(raw_key);
        sentinel_sys::zeroize_slice(&mut raw_key);

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
                    self.cleanup_cipher_dir(&shadow_cipher_dir);
                    if is_volume_device {
                        let _ = set_volume_offline(raw_volume_path, true);
                    }
                    let msg = SentinelError::WalkAccessDenied(format!(
                        "ShadowCache directory walk failed inside '{}': {}",
                        raw_volume_path.display(),
                        walk_err
                    ))
                    .to_string();
                    let vol_token = self.tokenize_path_for_audit(raw_volume_path);
                    self.append_ledger(
                        "SHADOW_CACHE_INGEST_INCOMPLETE",
                        &format!("reason=walk_failed volume_token={vol_token}"),
                    );
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
                    self.cleanup_cipher_dir(&shadow_cipher_dir);
                    if is_volume_device {
                        let _ = set_volume_offline(raw_volume_path, true);
                    }
                    let msg = SentinelError::WalkAccessDenied(format!(
                        "ShadowCache metadata query failed for '{}': {}",
                        path.display(),
                        meta_err
                    ))
                    .to_string();
                    let path_token = self.tokenize_path_for_audit(path);
                    self.append_ledger(
                        "SHADOW_CACHE_INGEST_INCOMPLETE",
                        &format!("reason=metadata_failed path_token={path_token}"),
                    );
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
                self.cleanup_cipher_dir(&shadow_cipher_dir);
                if is_volume_device {
                    let _ = set_volume_offline(raw_volume_path, true);
                }
                let msg = SentinelError::WalkAccessDenied(format!(
                    "ShadowCache file count exceeded max_files limit ({}) on '{}'",
                    self.max_files,
                    raw_volume_path.display()
                ))
                .to_string();
                let vol_token = self.tokenize_path_for_audit(raw_volume_path);
                self.append_ledger(
                    "SHADOW_CACHE_INGEST_INCOMPLETE",
                    &format!(
                        "reason=max_files_exceeded limit={} volume_token={vol_token}",
                        self.max_files
                    ),
                );
                return Err(msg);
            }

            // Open untrusted file strictly without following symlinks/reparse points, and bounded by quota (`CSE-07`, `CSE-10`)
            let raw_bytes = {
                let mut untrusted_file = match open_untrusted_readonly_nofollow(path) {
                    Ok(f) => f,
                    Err(open_err) => {
                        self.cleanup_cipher_dir(&shadow_cipher_dir);
                        if is_volume_device {
                            let _ = set_volume_offline(raw_volume_path, true);
                        }
                        let msg = SentinelError::WalkAccessDenied(format!(
                            "ShadowCache non-following open failed for '{}': {}",
                            path.display(),
                            open_err
                        ))
                        .to_string();
                        let path_token = self.tokenize_path_for_audit(path);
                        self.append_ledger(
                            "SHADOW_CACHE_INGEST_INCOMPLETE",
                            &format!("reason=open_nofollow_failed path_token={path_token}"),
                        );
                        return Err(msg);
                    }
                };
                match read_untrusted_to_end_bounded(&mut untrusted_file, self.max_cache_bytes) {
                    Ok(b) => b,
                    Err(read_err) => {
                        self.cleanup_cipher_dir(&shadow_cipher_dir);
                        if is_volume_device {
                            let _ = set_volume_offline(raw_volume_path, true);
                        }
                        let detail = format!(
                            "ShadowCache bounded single-read failed for '{}': {}",
                            path.display(),
                            read_err
                        );
                        let msg = if read_err.kind() == std::io::ErrorKind::InvalidData {
                            SentinelError::CacheQuotaExceeded(detail).to_string()
                        } else {
                            SentinelError::WalkAccessDenied(detail).to_string()
                        };
                        let path_token = self.tokenize_path_for_audit(path);
                        self.append_ledger(
                            "SHADOW_CACHE_INGEST_INCOMPLETE",
                            &format!("reason=bounded_read_failed path_token={path_token}"),
                        );
                        return Err(msg);
                    }
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
                let path_token = self.tokenize_path_for_audit(path);
                self.append_ledger(
                    "SHADOW_CACHE_THREAT_WITHHELD",
                    &format!("path_token={path_token} sha256={source_sha256}"),
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
                    let path_token = self.tokenize_path_for_audit(path);
                    self.append_ledger(
                        "SHADOW_CACHE_CDR_WITHHELD",
                        &format!("path_token={path_token} sha256={source_sha256} reason={e}"),
                    );
                    continue;
                }
            };

            let sanitized_size = release_bytes.len() as u64;
            total_cached_bytes = total_cached_bytes.saturating_add(sanitized_size);
            if total_cached_bytes > self.max_cache_bytes {
                self.cleanup_cipher_dir(&shadow_cipher_dir);
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
                let path_token = self.tokenize_path_for_audit(path);
                self.append_ledger(
                    DegradationEvent::CacheQuotaExceeded.event_code(),
                    &format!(
                        "cached_bytes={} max_cache_bytes={} path_token={path_token}",
                        total_cached_bytes, self.max_cache_bytes
                    ),
                );
                return Err(msg);
            }

            let sanitized_sha256 = hex::encode(Sha256::digest(&release_bytes));
            let rel_str = rel_path.to_string_lossy();

            let entry_id_hash = hex::encode(Sha256::digest(rel_str.as_bytes()));
            let mut file_id = [0u8; 16];
            let hash_bytes = Sha256::digest(rel_str.as_bytes());
            file_id.copy_from_slice(&hash_bytes[..16]);

            let enc_path = shadow_cipher_dir.join(format!("{}.enc", &entry_id_hash[..32]));
            encrypt_chunked_stream(
                session_key.as_slice(),
                &file_id,
                release_bytes.as_slice(),
                &enc_path,
            )
            .map_err(|e| format!("ShadowCache 64 KiB chunked streaming encryption failed: {e}"))?;

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

        let cipher_dir_token = self.tokenize_path_for_audit(&shadow_cipher_dir);
        self.append_ledger(
            "SHADOW_CACHE_INGEST_COMPLETE",
            &format!(
                "session={} files={} bytes={} cipher_dir_token={}",
                session_id, projected_count, total_cached_bytes, cipher_dir_token
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

        let rel_str = entry.relative_path.to_string_lossy();
        let mut file_id = [0u8; 16];
        let hash_bytes = Sha256::digest(rel_str.as_bytes());
        file_id.copy_from_slice(&hash_bytes[..16]);

        let mut plaintext = Vec::new();
        decrypt_chunked_stream(
            session.session_key.as_slice(),
            &file_id,
            enc_path,
            &mut plaintext,
        )
        .map_err(|e| format!("SHADOW_CACHE_INTEGRITY_FAILURE: {e}"))?;

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

    fn normalize_relative_components(relative_path: &Path) -> Result<Vec<String>, String> {
        let raw = relative_path
            .to_str()
            .ok_or_else(|| "Projected relative path is not valid UTF-8".to_string())?;
        if raw.is_empty()
            || raw.contains('\0')
            || raw.contains(':')
            || raw.starts_with('/')
            || raw.starts_with('\\')
        {
            return Err(format!(
                "Rejected invalid or non-relative projected path '{}'",
                relative_path.display()
            ));
        }
        let mut parts = Vec::new();
        for seg in raw.split(['/', '\\']) {
            if seg.is_empty() || seg == "." || seg == ".." {
                return Err(format!(
                    "Rejected path traversal or empty segment in '{}'",
                    relative_path.display()
                ));
            }
            parts.push(seg.to_string());
        }
        if parts.is_empty() {
            return Err("Projected relative path cannot be empty".to_string());
        }
        Ok(parts)
    }

    /// Lists all sanitized entries and synthesized intermediate directories for `virtual_mount_point`.
    pub fn list_projected_entries(
        &self,
        virtual_mount_point: &Path,
    ) -> Result<Vec<sentinel_sys::ProjFsProjectedEntry>, String> {
        let guard = self.sessions.lock().map_err(|e| e.to_string())?;
        let session = guard.get(virtual_mount_point).ok_or_else(|| {
            format!(
                "No active ShadowCache session for mount '{}'",
                virtual_mount_point.display()
            )
        })?;

        let mut deduped: HashMap<String, sentinel_sys::ProjFsProjectedEntry> = HashMap::new();

        for entry in session.entries.values() {
            let parts = Self::normalize_relative_components(&entry.relative_path)?;
            for prefix_len in 1..parts.len() {
                let ancestor_parts = &parts[..prefix_len];
                let key = if cfg!(windows) {
                    ancestor_parts.join("/").to_lowercase()
                } else {
                    ancestor_parts.join("/")
                };
                let ancestor_path: PathBuf = ancestor_parts.iter().collect();
                deduped
                    .entry(key)
                    .or_insert(sentinel_sys::ProjFsProjectedEntry {
                        relative_path: ancestor_path,
                        is_directory: true,
                        file_size: 0,
                        content_sha256: [0u8; 32],
                    });
            }

            let canonical_rel: PathBuf = parts.iter().collect();
            let key = if cfg!(windows) {
                parts.join("/").to_lowercase()
            } else {
                parts.join("/")
            };

            if entry.is_directory {
                deduped.insert(
                    key,
                    sentinel_sys::ProjFsProjectedEntry {
                        relative_path: canonical_rel,
                        is_directory: true,
                        file_size: 0,
                        content_sha256: [0u8; 32],
                    },
                );
            } else {
                let decoded = hex::decode(&entry.sanitized_sha256).map_err(|e| {
                    format!(
                        "Invalid sanitized_sha256 hex for '{}': {e}",
                        entry.relative_path.display()
                    )
                })?;
                if decoded.len() != 32 {
                    return Err(format!(
                        "Invalid sanitized_sha256 length ({}) for '{}'",
                        decoded.len(),
                        entry.relative_path.display()
                    ));
                }
                let mut content_sha256 = [0u8; 32];
                content_sha256.copy_from_slice(&decoded);
                deduped.insert(
                    key,
                    sentinel_sys::ProjFsProjectedEntry {
                        relative_path: canonical_rel,
                        is_directory: false,
                        file_size: entry.sanitized_size,
                        content_sha256,
                    },
                );
            }
        }

        let mut list: Vec<sentinel_sys::ProjFsProjectedEntry> = deduped.into_values().collect();
        list.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(list)
    }

    /// Decrypts and SHA-256-verifies `relative_path`, validates `byte_offset`, and returns
    /// the verified slice `[start .. (start + length).min(len)]` (`Row 148`).
    pub fn read_projected_range(
        &self,
        virtual_mount_point: &Path,
        relative_path: &Path,
        byte_offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, String> {
        let req_parts = Self::normalize_relative_components(relative_path)?;

        let matched_key = {
            let guard = self.sessions.lock().map_err(|e| e.to_string())?;
            let session = guard.get(virtual_mount_point).ok_or_else(|| {
                format!(
                    "No active ShadowCache session for mount '{}'",
                    virtual_mount_point.display()
                )
            })?;

            let mut exact_match: Option<PathBuf> = None;
            let mut ci_match: Option<PathBuf> = None;
            for (k, entry) in &session.entries {
                if entry.is_directory {
                    continue;
                }
                let Ok(entry_parts) = Self::normalize_relative_components(&entry.relative_path)
                else {
                    continue;
                };
                if entry_parts == req_parts {
                    exact_match = Some(k.clone());
                    break;
                }
                if cfg!(windows)
                    && ci_match.is_none()
                    && entry_parts.len() == req_parts.len()
                    && entry_parts
                        .iter()
                        .zip(req_parts.iter())
                        .all(|(a, b)| a.to_lowercase() == b.to_lowercase())
                {
                    ci_match = Some(k.clone());
                }
            }

            exact_match.or(ci_match).ok_or_else(|| {
                format!(
                    "Projected file '{}' not found in shadow cache",
                    relative_path.display()
                )
            })?
        };

        let plaintext = self.read_projected_file(virtual_mount_point, &matched_key)?;
        let len = plaintext.len();
        let start = usize::try_from(byte_offset).map_err(|_| {
            format!("Requested byte_offset {byte_offset} exceeds addressable range")
        })?;
        if start > len {
            return Err(format!(
                "Requested byte_offset {byte_offset} exceeds verified file length {len}"
            ));
        }
        let end = start.saturating_add(length).min(len);
        Ok(plaintext[start..end].to_vec())
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
            self.cleanup_cipher_dir(&shadow_cipher_dir);
            let msg = SentinelError::WalkAccessDenied(format!(
                "ShadowCache single-read stream failed for '{}': {}",
                relative_path.display(),
                read_err
            ))
            .to_string();
            let rel_token = self.tokenize_path_for_audit(relative_path);
            self.append_ledger(
                "SHADOW_CACHE_INGEST_INCOMPLETE",
                &format!("reason=stream_read_failed rel_token={rel_token}"),
            );
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
            self.cleanup_cipher_dir(&shadow_cipher_dir);
            let msg = format!(
                "ShadowCache blocked non-disarmable threat in stream '{}' (source_sha256={})",
                relative_path.display(),
                source_sha256
            );
            let rel_token = self.tokenize_path_for_audit(relative_path);
            self.append_ledger(
                "SHADOW_CACHE_THREAT_WITHHELD",
                &format!("rel_token={rel_token} source_sha256={source_sha256}"),
            );
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
                self.cleanup_cipher_dir(&shadow_cipher_dir);
                let msg = format!("CDR_WORKER_FAILED: {e}");
                self.append_ledger("CDR_WORKER_FAILED", &msg);
                msg
            })?;

        let release_bytes = outcome.clean_bytes;
        let sanitized_size = release_bytes.len() as u64;
        if sanitized_size > self.max_cache_bytes {
            self.cleanup_cipher_dir(&shadow_cipher_dir);
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
        rand::rngs::OsRng.fill_bytes(&mut raw_key);
        let session_key = ZeroizingBytes::new(raw_key);
        sentinel_sys::zeroize_slice(&mut raw_key);

        let entry_id_hash = hex::encode(Sha256::digest(rel_str.as_bytes()));
        let mut file_id = [0u8; 16];
        let hash_bytes = Sha256::digest(rel_str.as_bytes());
        file_id.copy_from_slice(&hash_bytes[..16]);

        let enc_path = shadow_cipher_dir.join(format!("{}.enc", &entry_id_hash[..32]));
        encrypt_chunked_stream(
            session_key.as_slice(),
            &file_id,
            release_bytes.as_slice(),
            &enc_path,
        )
        .map_err(|e| format!("ShadowCache 64 KiB chunked streaming encryption failed: {e}"))?;

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
            create_restricted_dir_atomic(parent).map_err(|e| {
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
        create_restricted_file_atomic(&projected_path, &verified_bytes).map_err(|e| {
            format!(
                "Failed creating atomic restricted hydrated file '{}': {}",
                projected_path.display(),
                e
            )
        })?;

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

            let cipher_cleanup_res = self.cleanup_inception_encrypted_cipher_dir(&cipher_dir);
            let proj_cleanup_res = Self::cleanup_dir_with_method(
                &proj_root,
                ShredMethod::ClearMultiPass { passes: 3 },
                Some(&self.ledger_path),
                self.shared_ledger.as_ref(),
            );

            let cipher_failed = cipher_cleanup_res.is_err();
            let proj_failed = proj_cleanup_res.is_err();
            if cipher_failed || proj_failed {
                let mut combined = Vec::new();
                if let Err(e) = cipher_cleanup_res {
                    combined.push(format!("cipher_dir: {e}"));
                }
                if let Err(e) = proj_cleanup_res {
                    combined.push(format!("projection_root: {e}"));
                }
                let err_summary = combined.join(" | ");
                let cipher_token = self.tokenize_path_for_audit(&cipher_dir);
                let proj_token = self.tokenize_path_for_audit(&proj_root);
                self.append_ledger(
                    "SHADOW_CACHE_TEARDOWN_ERROR",
                    &format!(
                        "session={} bytes={} cipher_dir_token={} projection_root_token={} cipher_err={} proj_err={}",
                        session_id,
                        cached_bytes,
                        cipher_token,
                        proj_token,
                        cipher_failed,
                        proj_failed
                    ),
                );
                return Err(format!(
                    "ShadowCache teardown failed closed for session '{}': {}",
                    session_id, err_summary
                ));
            }

            let cipher_token = self.tokenize_path_for_audit(&cipher_dir);
            let proj_token = self.tokenize_path_for_audit(&proj_root);
            self.append_ledger(
                "SHADOW_CACHE_SESSION_TEARDOWN",
                &format!(
                    "session={} bytes={} cipher_dir_token={} projection_root_token={}",
                    session_id, cached_bytes, cipher_token, proj_token
                ),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
impl ShadowCacheManager {
    pub(crate) fn stage_test_encrypted_session_entry(
        &self,
        virtual_mount_point: &Path,
        relative_path: &Path,
        sanitized_payload: &[u8],
    ) -> Result<PathBuf, String> {
        fs::create_dir_all(virtual_mount_point).map_err(|e| {
            format!(
                "Failed creating test virtual projection root '{}': {}",
                virtual_mount_point.display(),
                e
            )
        })?;

        let mut guard = self.sessions.lock().map_err(|e| e.to_string())?;
        if !guard.contains_key(virtual_mount_point) {
            let session_id = Uuid::new_v4().to_string();
            let shadow_cipher_dir = self.resolve_session_cipher_dir(&session_id)?;
            let mut raw_key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut raw_key);
            let session_key = ZeroizingBytes::new(raw_key);
            sentinel_sys::zeroize_slice(&mut raw_key);

            guard.insert(
                virtual_mount_point.to_path_buf(),
                ShadowSessionState {
                    session_id,
                    session_key,
                    entries: HashMap::new(),
                    projection_root: virtual_mount_point.to_path_buf(),
                    shadow_cipher_dir,
                    total_cached_bytes: 0,
                    withheld_threats: Vec::new(),
                },
            );
        }

        let session = guard
            .get_mut(virtual_mount_point)
            .ok_or_else(|| "Failed retrieving staged ShadowCache test session".to_string())?;

        let sanitized_size = sanitized_payload.len() as u64;
        let sanitized_sha256 = hex::encode(Sha256::digest(sanitized_payload));
        let rel_str = relative_path.to_string_lossy();
        let entry_id_hash = hex::encode(Sha256::digest(rel_str.as_bytes()));
        let mut file_id = [0u8; 16];
        let hash_bytes = Sha256::digest(rel_str.as_bytes());
        file_id.copy_from_slice(&hash_bytes[..16]);

        let enc_path = session
            .shadow_cipher_dir
            .join(format!("{}.enc", &entry_id_hash[..32]));
        encrypt_chunked_stream(
            session.session_key.as_slice(),
            &file_id,
            sanitized_payload,
            &enc_path,
        )
        .map_err(|e| format!("Test staged ShadowCache encryption failed: {e}"))?;

        session.total_cached_bytes = session.total_cached_bytes.saturating_add(sanitized_size);
        session.entries.insert(
            relative_path.to_path_buf(),
            VirtualFileEntry {
                relative_path: relative_path.to_path_buf(),
                original_size: sanitized_size,
                sanitized_size,
                source_sha256: sanitized_sha256.clone(),
                sanitized_sha256,
                is_directory: false,
                is_sanitized: true,
                encrypted_cache_path: Some(enc_path.clone()),
                cached_clean_path: None,
            },
        );

        Ok(enc_path)
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

    pub fn with_shared_ledger(mut self, shared_ledger: SharedAuditLedger) -> Self {
        self.shadow_cache = self.shadow_cache.with_shared_ledger(shared_ledger);
        self
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
        let mount_token = self
            .shadow_cache
            .tokenize_path_for_audit(virtual_mount_point);
        self.shadow_cache.append_ledger(
            event_code,
            &format!("ProjFS unavailable; using StagingFolderProvider mount_token={mount_token}"),
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

    async fn on_file_first_open(&self, relative_path: &Path) -> Result<PathBuf, String> {
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
    resolve_best_vfs_provider_with_ledger(None)
}

/// Resolves the inbox OS userspace VFS provider wired to the unified `SharedAuditLedger` (`CEA-DEFECT-06`).
pub fn resolve_best_vfs_provider_with_ledger(
    shared_ledger: Option<SharedAuditLedger>,
) -> Box<dyn VirtualFileSystemProvider> {
    #[cfg(target_os = "windows")]
    {
        if sentinel_sys::is_projfs_available() {
            info!("Selected VFS Backend: Windows Projected File System (ProjFS + Read-Once ShadowCache)");
            let p = projfs::ProjFsProvider::new();
            let p = match shared_ledger {
                Some(sl) => p.with_shared_ledger(sl),
                None => p,
            };
            Box::new(p)
        } else {
            warn!(
                "[{}] ProjectedFSLib.dll not enabled; selecting Read-Only StagingFolderProvider fallback",
                DegradationEvent::PostureReducedNoProjfs.event_code()
            );
            let p = StagingFolderProvider::new();
            let p = match shared_ledger {
                Some(sl) => p.with_shared_ledger(sl),
                None => p,
            };
            Box::new(p)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        info!("Selected VFS Backend: Linux FUSE3 Userspace Mount (+ Read-Once ShadowCache)");
        let p = fuse::FuseVfsProvider::new();
        let p = match shared_ledger {
            Some(sl) => p.with_shared_ledger(sl),
            None => p,
        };
        Box::new(p)
    }
}
