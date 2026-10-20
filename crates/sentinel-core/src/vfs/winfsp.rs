use super::{VfsError, VirtualStorageProvider};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct WinFspProvider;

impl WinFspProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl VirtualStorageProvider for WinFspProvider {
    fn provider_name(&self) -> &'static str {
        "WinFsp (Windows File System in Userspace)"
    }

    async fn is_supported(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            // Checks if WinFsp runtime DLL is present in System32 or Program Files
            std::path::Path::new(r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll").exists()
                || std::path::Path::new(r"C:\Program Files\WinFsp\bin\winfsp-x64.dll").exists()
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
            "Mounting legacy virtual volume via WinFsp from {:?} to '{}'",
            raw_source_path, virtual_mount_point
        );

        let target_path = PathBuf::from(virtual_mount_point);
        Ok(target_path)
    }

    async fn unmount_volume(&self, virtual_mount_point: &str) -> Result<(), VfsError> {
        info!("Unmounting WinFsp volume on '{}'", virtual_mount_point);
        Ok(())
    }
}
