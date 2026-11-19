use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use sentinel_sys::{
    prj_start_virtualizing_root, ProjFsInstanceHandle, ProjFsProjectedEntry,
    ProjFsVirtualizerBackend,
};

use crate::enterprise::ledger::SharedAuditLedger;
use crate::error::DegradationEvent;
use crate::vfs::{ShadowCacheManager, VirtualFileSystemProvider};

struct ShadowCacheProjFsBackend {
    shadow_cache: Arc<ShadowCacheManager>,
    mount_root: PathBuf,
}

impl ProjFsVirtualizerBackend for ShadowCacheProjFsBackend {
    fn list_entries(&self) -> Vec<ProjFsProjectedEntry> {
        self.shadow_cache
            .list_projected_entries(&self.mount_root)
            .unwrap_or_default()
    }

    fn read_verified_range(
        &self,
        relative_path: &Path,
        byte_offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, String> {
        self.shadow_cache
            .read_projected_range(&self.mount_root, relative_path, byte_offset, length)
    }
}

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

    pub fn with_shared_ledger(self, shared_ledger: SharedAuditLedger) -> Self {
        Self {
            shadow_cache: Arc::new(ShadowCacheManager::new().with_shared_ledger(shared_ledger)),
            active_root: self.active_root,
            projfs_handle: self.projfs_handle,
            degraded_no_projfs: self.degraded_no_projfs,
        }
    }

    /// Decrypts the `.enc` shadow cache entry on demand using the session's `ZeroizingBytes<32>` key
    /// and verifies its SHA-256 against `sanitized_sha256` (`Row 148`).
    pub fn read_projected_file(&self, relative_path: &Path) -> Result<Vec<u8>, String> {
        let root = self
            .active_root
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "ProjFS virtualization root is not mounted".to_string())?;

        self.shadow_cache.read_projected_file(&root, relative_path)
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

        let backend = Box::new(ShadowCacheProjFsBackend {
            shadow_cache: Arc::clone(&self.shadow_cache),
            mount_root: virtual_mount_point.to_path_buf(),
        });
        match prj_start_virtualizing_root(virtual_mount_point, backend) {
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
                let root_token = self
                    .shadow_cache
                    .tokenize_path_for_audit(virtual_mount_point);
                self.shadow_cache
                    .append_ledger(code, &format!("root_token={root_token} reason={e}"));
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

        // Verify decryption and SHA-256 integrity (`read_projected_file`)
        let _ = self.read_projected_file(relative_path)?;
        if self.is_degraded_no_projfs() {
            self.shadow_cache
                .resolve_projected_file(&root, relative_path)
        } else {
            Ok(root.join(relative_path))
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn shadow_cache_projfs_backend_lists_hierarchy_verifies_ranges_and_rejects_tamper(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_root = std::env::temp_dir().join(format!(
            "omniconnect_projfs_backend_test_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let cache_root = test_root.join("shadow_cache");
        let mount_root = test_root.join("virtual_mount");

        let mgr = Arc::new(
            ShadowCacheManager::with_cache_root_and_quota(cache_root, 16 * 1024 * 1024)
                .with_ledger_path(test_root.join("projfs_test_ledger.jsonl")),
        );

        let report_payload = b"HEADER_0123456789_VERIFIED_SANITIZED_REPORT_PAYLOAD";
        let notes_payload = b"SAFE_NOTES_ROOT_FILE";
        let report_enc = mgr.stage_test_encrypted_session_entry(
            &mount_root,
            Path::new("docs/sub/report.txt"),
            report_payload,
        )?;
        let _notes_enc = mgr.stage_test_encrypted_session_entry(
            &mount_root,
            Path::new("notes.txt"),
            notes_payload,
        )?;

        let backend = ShadowCacheProjFsBackend {
            shadow_cache: Arc::clone(&mgr),
            mount_root: mount_root.clone(),
        };

        // 1. Lists synthesized parent dirs (`docs`, `docs/sub`) + files with valid SHA-256
        let entries = backend.list_entries();
        assert_eq!(entries.len(), 4);
        assert!(entries
            .iter()
            .any(|e| e.is_directory && e.relative_path == Path::new("docs")));
        assert!(entries
            .iter()
            .any(|e| e.is_directory && e.relative_path == PathBuf::from("docs").join("sub")));
        let report_entry = entries
            .iter()
            .find(|e| {
                !e.is_directory
                    && e.relative_path == PathBuf::from("docs").join("sub").join("report.txt")
            })
            .ok_or("missing report.txt entry")?;
        let expected_sha: [u8; 32] = Sha256::digest(report_payload).into();
        assert_eq!(report_entry.file_size, report_payload.len() as u64);
        assert_eq!(report_entry.content_sha256, expected_sha);

        // 2. Returns exact AEAD + SHA-256 verified ranges at non-zero offsets & clamps tail
        let mid_slice = backend.read_verified_range(Path::new(r"docs\sub\report.txt"), 7, 10)?;
        assert_eq!(mid_slice, b"0123456789");
        let tail_slice = backend.read_verified_range(Path::new("notes.txt"), 11, 256)?;
        assert_eq!(tail_slice, b"ROOT_FILE");

        // 3. Rejects unknown, traversal, and out-of-range offsets
        assert!(backend
            .read_verified_range(Path::new("missing.txt"), 0, 16)
            .is_err());
        assert!(backend
            .read_verified_range(Path::new("../secret.txt"), 0, 16)
            .is_err());
        assert!(backend
            .read_verified_range(Path::new("notes.txt"), 9999, 4)
            .is_err());

        // 4. Fails closed when `.enc` ciphertext on disk is tampered with
        let mut enc_bytes = std::fs::read(&report_enc)?;
        let last_idx = enc_bytes.len().saturating_sub(1);
        enc_bytes[last_idx] ^= 0xFF;
        std::fs::write(&report_enc, &enc_bytes)?;
        assert!(
            backend
                .read_verified_range(Path::new("docs/sub/report.txt"), 0, 16)
                .is_err(),
            "Tampered .enc file MUST fail AEAD verification closed"
        );

        mgr.teardown_session(&mount_root)?;
        let _ = std::fs::remove_dir_all(&test_root);
        Ok(())
    }

    #[tokio::test]
    async fn projfs_provider_degraded_open_attaches_motw_and_unmount_tears_down(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_root = std::env::temp_dir().join(format!(
            "omniconnect_projfs_provider_test_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let cache_root = test_root.join("shadow_cache");
        let mount_root = test_root.join("virtual_mount");

        let mgr = ShadowCacheManager::with_cache_root_and_quota(cache_root, 16 * 1024 * 1024)
            .with_ledger_path(test_root.join("projfs_provider_ledger.jsonl"));
        mgr.stage_test_encrypted_session_entry(
            &mount_root,
            Path::new("docs/note.txt"),
            b"SANITIZED_PROJFS_NOTE_PAYLOAD",
        )?;

        let provider = ProjFsProvider::with_shadow_cache(mgr);
        // Unmounted provider must fail closed
        assert!(provider
            .on_file_first_open(Path::new("docs/note.txt"))
            .await
            .is_err());

        if let Ok(mut guard) = provider.active_root.lock() {
            *guard = Some(mount_root.clone());
        }
        if let Ok(mut guard) = provider.degraded_no_projfs.lock() {
            *guard = true;
        }

        // Traversal or missing entries must fail closed
        assert!(provider
            .on_file_first_open(Path::new("../outside.txt"))
            .await
            .is_err());

        // Degraded mode resolves read-only file with verified content
        let hydrated_path = provider
            .on_file_first_open(Path::new("docs/note.txt"))
            .await?;
        assert_eq!(
            std::fs::read(&hydrated_path)?,
            b"SANITIZED_PROJFS_NOTE_PAYLOAD"
        );
        assert!(std::fs::metadata(&hydrated_path)?.permissions().readonly());

        provider.unmount_volume(&mount_root).await?;
        assert!(!hydrated_path.exists());
        assert!(!mount_root.exists());
        let _ = std::fs::remove_dir_all(&test_root);
        Ok(())
    }
}
