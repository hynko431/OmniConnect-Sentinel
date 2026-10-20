pub mod projfs;
pub mod winfsp;
pub mod fuse;

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum VfsError {
    #[error("VFS initialization failed: {0}")]
    InitFailed(String),
    #[error("Mount failure on target {0}: {1}")]
    MountError(String, String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Abstract Virtual Storage Provider presenting sanitized files to the OS Explorer
#[async_trait]
pub trait VirtualStorageProvider: Send + Sync {
    fn provider_name(&self) -> &'static str;
    async fn is_supported(&self) -> bool;
    async fn mount_virtual_volume(
        &self,
        raw_source_path: &Path,
        virtual_mount_point: &str,
    ) -> Result<PathBuf, VfsError>;
    async fn unmount_volume(&self, virtual_mount_point: &str) -> Result<(), VfsError>;
}

/// Selects the best VFS provider based on OS version and available subsystems
pub async fn resolve_best_vfs_provider() -> Box<dyn VirtualStorageProvider> {
    #[cfg(target_os = "windows")]
    {
        let projfs = projfs::WindowsProjFsProvider::new();
        if projfs.is_supported().await {
            info!("Selected native Windows Projected File System (ProjFS) provider");
            return Box::new(projfs);
        }

        let winfsp = winfsp::WinFspProvider::new();
        if winfsp.is_supported().await {
            info!("Selected WinFsp legacy fallback provider");
            return Box::new(winfsp);
        }

        info!("Defaulting to ProjFS with runtime feature enablement check");
        Box::new(projfs)
    }

    #[cfg(not(target_os = "windows"))]
    {
        info!("Selected Unix FUSE userspace filesystem provider");
        Box::new(fuse::UnixFuseProvider::new())
    }
}
