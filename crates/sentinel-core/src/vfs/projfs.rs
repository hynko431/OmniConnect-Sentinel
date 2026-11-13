use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use sentinel_sys::{prj_start_virtualizing_root, prj_write_file_data, ProjFsInstanceHandle};

use crate::enterprise::ledger::AuditLedger;
use crate::error::DegradationEvent;
use crate::vfs::{ShadowCacheManager, VirtualFileSystemProvider};

/// Windows Projected File System (ProjFS) Provider (`BUG-CORE-13`, `Rows 148–151, 193`, Phase 3.2)
///
/// Uses the Read-Once Encrypted Shadow Cache (`ShadowCacheManager`) in
/// `%ProgramData%\OmniConnect\ShadowCache\<session_id>` (storing only `.enc` ciphertexts at rest)
/// and binds Windows `ProjectedFSLib.dll` (`PrjStartVirtualizing` / `PrjWriteFileData` / `PrjStopVirtualizing`).
/// When `Client-ProjFS` is not enabled on the host, records `POSTURE_REDUCED_NO_PROJFS` and
/// decrypts/verifies requested files on demand with Mark-of-the-Web (`ZoneId=3`).
pub struct ProjFsProvider {
    shadow_cache: Arc<ShadowCacheManager>,
    active_root: Arc<Mutex<Option<PathBuf>>>,
    projfs_handle: Arc<Mutex<Option<ProjFsInstanceHandle>>>,
    degraded_no_projfs: Arc<Mutex<bool>>,
}

impl Default for ProjFsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ProjFsProvider {
    pub fn new() -> Self {
        Self {
            shadow_cache: Arc::new(ShadowCacheManager::new()),
            active_root: Arc::new(Mutex::new(None)),
            projfs_handle: Arc::new(Mutex::new(None)),
            degraded_no_projfs: Arc::new(Mutex::new(false)),
        }
    }

    pub fn with_shadow_cache(shadow_cache: ShadowCacheManager) -> Self {
        Self {
            shadow_cache: Arc::new(shadow_cache),
            active_root: Arc::new(Mutex::new(None)),
            projfs_handle: Arc::new(Mutex::new(None)),
            degraded_no_projfs: Arc::new(Mutex::new(false)),
        }
    }

    /// Decrypts the `.enc` shadow cache entry on demand using the session's `ZeroizingBytes<32>` key,
    /// verifies its SHA-256 against `sanitized_sha256`, and streams via `PrjWriteFileData` when an
    /// active ProjFS virtualization context is present (`Row 148`).
    pub fn read_projected_file(&self, relative_path: &Path) -> Result<Vec<u8>, String> {
        let root = self
            .active_root
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "ProjFS virtualization root is not mounted".to_string())?;

        let plaintext = self
            .shadow_cache
            .read_projected_file(&root, relative_path)?;

        if let Ok(guard) = self.projfs_handle.lock() {
            if let Some(ref handle) = *guard {
                let stream_id = *b"SENTINEL_PROJFS1";
                let _ = prj_write_file_data(handle.raw_context(), &stream_id, &plaintext, 0);
            }
        }

        Ok(plaintext)
    }

    pub fn is_degraded_no_projfs(&self) -> bool {
        self.degraded_no_projfs.lock().map(|g| *g).unwrap_or(false)
    }

    pub fn shadow_cache(&self) -> &Arc<ShadowCacheManager> {
        &self.shadow_cache
    }
}

#[async_trait]
impl VirtualFileSystemProvider for ProjFsProvider {
    async fn mount_sanitized_volume(
        &self,
        raw_volume_path: &Path,
        virtual_mount_point: &Path,
    ) -> Result<(), String> {
        info!(
            "ProjFS mounting read-once sanitized virtualization root: {} -> {}",
            raw_volume_path.display(),
            virtual_mount_point.display()
        );

        let cache = Arc::clone(&self.shadow_cache);
        let raw_buf = raw_volume_path.to_path_buf();
        let virt_buf = virtual_mount_point.to_path_buf();

        tokio::task::spawn_blocking(move || cache.ingest_volume_read_once(&raw_buf, &virt_buf))
            .await
            .map_err(|e| format!("ProjFS ingestion join error: {e}"))??;

        match prj_start_virtualizing_root(virtual_mount_point) {
            Ok(handle) => {
                info!(
                    "PrjStartVirtualizing active on virtualization root {}",
                    virtual_mount_point.display()
                );
                if let Ok(mut h_guard) = self.projfs_handle.lock() {
                    *h_guard = Some(handle);
                }
                if let Ok(mut d_guard) = self.degraded_no_projfs.lock() {
                    *d_guard = false;
                }
            }
            Err(e) => {
                let code = DegradationEvent::PostureReducedNoProjfs.event_code();
                warn!(
                    "[{}] Native PrjStartVirtualizing unavailable ({}); using on-demand encrypted ShadowCache hydration",
                    code, e
                );
                if let Ok(mut d_guard) = self.degraded_no_projfs.lock() {
                    *d_guard = true;
                }
                #[cfg(test)]
                let ledger_path = std::env::temp_dir()
                    .join("OmniConnect_ShadowCache")
                    .join("shadow_cache_audit.jsonl");
                #[cfg(not(test))]
                let ledger_path = {
                    #[cfg(windows)]
                    {
                        PathBuf::from(
                            r"C:\ProgramData\OmniConnect\AuditLedger\shadow_cache_audit.jsonl",
                        )
                    }
                    #[cfg(not(windows))]
                    {
                        PathBuf::from("/var/lib/omniconnect/audit_ledger/shadow_cache_audit.jsonl")
                    }
                };
                let mut ledger = AuditLedger::open(ledger_path);
                let _ = ledger.append_event(
                    code,
                    format!("root={} reason={}", virtual_mount_point.display(), e),
                );
            }
        }

        if let Ok(mut guard) = self.active_root.lock() {
            *guard = Some(virtual_mount_point.to_path_buf());
        }

        Ok(())
    }

    async fn on_file_first_open(&self, relative_path: &Path) -> Result<PathBuf, String> {
        let root = self
            .active_root
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "ProjFS virtualization root is not mounted".to_string())?;

        // Verify decryption and SHA-256 integrity (`read_projected_file`) and hydrate with MotW (`ZoneId=3`)
        let _verified_bytes = self.read_projected_file(relative_path)?;
        self.shadow_cache
            .resolve_projected_file(&root, relative_path)
    }

    async fn unmount_volume(&self, virtual_mount_point: &Path) -> Result<(), String> {
        info!(
            "ProjFS stopping virtualization and crypto-erasing session cache: {}",
            virtual_mount_point.display()
        );
        // Drop ProjFsInstanceHandle (`PrjStopVirtualizing`) before tearing down session cache (`Row 149`)
        if let Ok(mut h_guard) = self.projfs_handle.lock() {
            *h_guard = None;
        }
        self.shadow_cache.teardown_session(virtual_mount_point)?;
        if let Ok(mut guard) = self.active_root.lock() {
            *guard = None;
        }
        Ok(())
    }

    fn take_withheld_threats(
        &self,
        virtual_mount_point: &Path,
    ) -> Vec<crate::scanner::universal_scanner::UniversalThreat> {
        self.shadow_cache.take_withheld_threats(virtual_mount_point)
    }
}
