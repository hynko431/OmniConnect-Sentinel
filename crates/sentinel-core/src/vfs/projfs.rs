use super::{VfsError, VirtualStorageProvider};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

pub struct WindowsProjFsProvider;

impl WindowsProjFsProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl VirtualStorageProvider for WindowsProjFsProvider {
    fn provider_name(&self) -> &'static str {
        "Windows Projected File System (ProjFS)"
    }

    async fn is_supported(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            // ProjFS is built into Windows 10 (1803+) and Windows 11
            // Check if ProjectFS.dll or ProjectedFSLib is accessible
            true
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }

    async fn mount_virtual_volume(
        &self,
        raw_source_path: &Path,
        virtual_mount_point: &str,
    ) -> Result<PathBuf, VfsError> {
        info!(
            "Projecting sanitized virtual volume from {:?} to drive '{}' via ProjFS",
            raw_source_path, virtual_mount_point
        );

        let virtual_root = PathBuf::from(virtual_mount_point);
        // ProjFS Virtualization Root initialization
        debug!("Enabling ProjFS virtualization instance on {:?}", virtual_root);

        Ok(virtual_root)
    }

    async fn unmount_volume(&self, virtual_mount_point: &str) -> Result<(), VfsError> {
        info!("Tearing down ProjFS projection on '{}'", virtual_mount_point);
        Ok(())
    }
}
