use super::{VfsError, VirtualStorageProvider};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct UnixFuseProvider;

impl UnixFuseProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl VirtualStorageProvider for UnixFuseProvider {
    fn provider_name(&self) -> &'static str {
        "Unix FUSE (Filesystem in Userspace)"
    }

    async fn is_supported(&self) -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            Path::new("/dev/fuse").exists()
        }
        #[cfg(target_os = "windows")]
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
            "Mounting FUSE loopback from {:?} to '{}'",
            raw_source_path, virtual_mount_point
        );

        let target_path = PathBuf::from(virtual_mount_point);
        Ok(target_path)
    }

    async fn unmount_volume(&self, virtual_mount_point: &str) -> Result<(), VfsError> {
        info!("Unmounting FUSE mount point at '{}'", virtual_mount_point);
        Ok(())
    }
}
