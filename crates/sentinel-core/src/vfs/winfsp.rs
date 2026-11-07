use async_trait::async_trait;
use std::path::{Path, PathBuf};

use crate::vfs::projfs::ProjFsProvider;
use crate::vfs::VirtualFileSystemProvider;

/// Legacy WinFsp Compatibility Wrapper (delegates to `ProjFsProvider` under Hardened Option B
/// so no third-party kernel driver is required).
pub struct WinFspProvider {
    inner: ProjFsProvider,
}

impl Default for WinFspProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl WinFspProvider {
    pub fn new() -> Self {
        Self {
            inner: ProjFsProvider::new(),
        }
    }
}

#[async_trait]
impl VirtualFileSystemProvider for WinFspProvider {
    async fn mount_sanitized_volume(
        &self,
        raw_volume_path: &Path,
        virtual_mount_point: &Path,
    ) -> Result<(), String> {
        self.inner
            .mount_sanitized_volume(raw_volume_path, virtual_mount_point)
            .await
    }

    async fn on_file_first_open(&self, relative_path: &Path) -> Result<PathBuf, String> {
        self.inner.on_file_first_open(relative_path).await
    }

    async fn unmount_volume(&self, virtual_mount_point: &Path) -> Result<(), String> {
        self.inner.unmount_volume(virtual_mount_point).await
    }
}
