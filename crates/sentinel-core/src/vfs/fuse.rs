use async_trait::async_trait;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tracing::info;

use crate::vfs::{ShadowCacheManager, VirtualFileSystemProvider};

/// Linux FUSE3 Read-Only Userspace VFS Provider (`BUG-CORE-13`, `Row 150`, Phase 3.2)
///
/// Ingests removable volumes once into the encrypted `ShadowCacheManager` (`/var/lib/omniconnect/shadow_cache/<session>`),
/// enforces read-only mount permissions on `virtual_mount_point` (using `bindfs`/`fusermount3` when
/// `/dev/fuse` is available, or read-only on-demand hydration), and decrypts/verifies `sanitized_sha256`
/// before serving any file.
pub struct FuseVfsProvider {
    shadow_cache: Arc<ShadowCacheManager>,
    active_root: Arc<Mutex<Option<PathBuf>>>,
    fuse_mounted: Arc<Mutex<bool>>,
}

impl Default for FuseVfsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseVfsProvider {
    pub fn new() -> Self {
        Self {
            shadow_cache: Arc::new(ShadowCacheManager::new()),
            active_root: Arc::new(Mutex::new(None)),
            fuse_mounted: Arc::new(Mutex::new(false)),
        }
    }

    pub fn read_projected_file(&self, relative_path: &Path) -> Result<Vec<u8>, String> {
        let root = self
            .active_root
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "FUSE3 mount root is not active".to_string())?;
        self.shadow_cache.read_projected_file(&root, relative_path)
    }
}

#[async_trait]
impl VirtualFileSystemProvider for FuseVfsProvider {
    async fn mount_sanitized_volume(
        &self,
        raw_volume_path: &Path,
        virtual_mount_point: &Path,
    ) -> Result<(), String> {
        info!(
            "FUSE3 mounting read-once sanitized projection: {} -> {}",
            raw_volume_path.display(),
            virtual_mount_point.display()
        );

        let cache = Arc::clone(&self.shadow_cache);
        let raw_buf = raw_volume_path.to_path_buf();
        let virt_buf = virtual_mount_point.to_path_buf();

        tokio::task::spawn_blocking(move || cache.ingest_volume_read_once(&raw_buf, &virt_buf))
            .await
            .map_err(|e| format!("FUSE3 ingestion join error: {}", e))??;

        #[cfg(target_os = "linux")]
        {
            if Path::new("/dev/fuse").exists() {
                if let Ok(status) = Command::new("bindfs")
                    .args([
                        "-r",
                        "--no-allow-other",
                        &virtual_mount_point.to_string_lossy(),
                        &virtual_mount_point.to_string_lossy(),
                    ])
                    .status()
                {
                    if status.success() {
                        if let Ok(mut fm) = self.fuse_mounted.lock() {
                            *fm = true;
                        }
                    }
                }
            } else {
                warn!("FUSE3 /dev/fuse device not present; using read-only ShadowCache hydration");
            }
        }

        if let Ok(meta) = fs::metadata(virtual_mount_point) {
            let mut perms = meta.permissions();
            perms.set_readonly(true);
            let _ = fs::set_permissions(virtual_mount_point, perms);
        }

        if let Ok(mut guard) = self.active_root.lock() {
            *guard = Some(virtual_mount_point.to_path_buf());
        }
        Ok(())
    }

    async fn on_file_First_open(&self, relative_path: &Path) -> Result<PathBuf, String> {
        let root = self
            .active_root
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "FUSE3 mount root is not active".to_string())?;
        if let Ok(meta) = fs::metadata(&root) {
            let mut perms = meta.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                perms.set_mode(0o700);
            }
            #[cfg(not(unix))]
            #[allow(clippy::permissions_set_readonly_false)]
            {
                perms.set_readonly(false);
            }
            let _ = fs::set_permissions(&root, perms);
        }
        let res = self
            .shadow_cache
            .resolve_projected_file(&root, relative_path);
        if let Ok(meta) = fs::metadata(&root) {
            let mut perms = meta.permissions();
            perms.set_readonly(true);
            let _ = fs::set_permissions(&root, perms);
        }
        res
    }

    async fn unmount_volume(&self, virtual_mount_point: &Path) -> Result<(), String> {
        info!(
            "FUSE3 unmounting volume and crypto-erasing session cache: {}",
            virtual_mount_point.display()
        );
        if let Ok(mut fm) = self.fuse_mounted.lock() {
            if *fm {
                let _ = Command::new("fusermount3")
                    .args(["-u", &virtual_mount_point.to_string_lossy()])
                    .status();
                *fm = false;
            }
        }
        if let Ok(meta) = fs::metadata(virtual_mount_point) {
            let mut perms = meta.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                perms.set_mode(0o700);
            }
            #[cfg(not(unix))]
            #[allow(clippy::permissions_set_readonly_false)]
            {
                perms.set_readonly(false);
            }
            let _ = fs::set_permissions(virtual_mount_point, perms);
        }
        self.shadow_cache.teardown_session(virtual_mount_point)?;
        if let Ok(mut guard) = self.active_root.lock() {
            *guard = None;
        }
        Ok(())
    }
}
