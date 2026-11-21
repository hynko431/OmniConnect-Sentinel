use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use crate::enterprise::ledger::SharedAuditLedger;
use crate::error::DegradationEvent;
use crate::vfs::{ShadowCacheManager, StagingFolderProvider, VirtualFileSystemProvider};

/// Linux FUSE3 / Read-Only Staging VFS Provider (`BUG-CORE-13`, `Row 150`, `CSE-25`)
///
/// Replaces external `Command::new("bindfs")` subprocess shell-outs with honest, zero-shell
/// posture reporting:
/// - Ingests removable volumes once into the AES-256-GCM encrypted `ShadowCacheManager`
///   (`/var/lib/omniconnect/shadow_cache/<session>`).
/// - When native `fuser` kernel FUSE3 mounting is not compiled (`vfs-fuse`) or `/dev/fuse` is
///   absent, explicitly falls back to `StagingFolderProvider` with read-only ACLs (`0o500`/`0o444`)
///   and emits `DegradationEvent::PostureReducedNoFuse` (`POSTURE_REDUCED_NO_FUSE`) to both
///   structured logs and the tamper-evident `AuditLedger` (zero silent fallback, zero `bindfs`).
pub struct FuseVfsProvider {
    staging_fallback: StagingFolderProvider,
    active_root: Arc<Mutex<Option<PathBuf>>>,
    native_fuse_active: Arc<Mutex<bool>>,
}

impl Default for FuseVfsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseVfsProvider {
    pub fn new() -> Self {
        Self {
            staging_fallback: StagingFolderProvider::new_no_fuse(),
            active_root: Arc::new(Mutex::new(None)),
            native_fuse_active: Arc::new(Mutex::new(false)),
        }
    }

    pub fn with_shadow_cache(shadow_cache: ShadowCacheManager) -> Self {
        Self {
            staging_fallback: StagingFolderProvider::with_shadow_cache(shadow_cache)
                .with_degradation_event(DegradationEvent::PostureReducedNoFuse),
            active_root: Arc::new(Mutex::new(None)),
            native_fuse_active: Arc::new(Mutex::new(false)),
        }
    }

    pub fn with_shared_ledger(self, shared_ledger: SharedAuditLedger) -> Self {
        Self {
            staging_fallback: self.staging_fallback.with_shared_ledger(shared_ledger),
            active_root: self.active_root,
            native_fuse_active: self.native_fuse_active,
        }
    }

    /// Returns `true` ONLY when a live native kernel FUSE3 mount session is active.
    pub fn is_native_fuse_active(&self) -> bool {
        self.native_fuse_active
            .lock()
            .map(|guard| *guard)
            .unwrap_or(false)
    }

    /// Returns `true` ONLY when a real native `fuser` kernel FUSE3 implementation is compiled
    /// and `/dev/fuse` is accessible. Currently returns `false` so `resolve_best_vfs_provider_with_ledger`
    /// never claims native FUSE3 when operating on `StagingFolderProvider` (`POSTURE_REDUCED_NO_FUSE`).
    pub fn is_native_fuse_supported() -> bool {
        false
    }

    pub fn read_projected_file(&self, relative_path: &Path) -> Result<Vec<u8>, String> {
        let root = self
            .active_root
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "FUSE3 mount root is not active".to_string())?;
        self.staging_fallback
            .shadow_cache()
            .read_projected_file(&root, relative_path)
    }
}

#[async_trait]
impl VirtualFileSystemProvider for FuseVfsProvider {
    fn provider_name(&self) -> &'static str {
        if self.is_native_fuse_active() {
            "Linux FUSE3 Read-Only VFS (+ Read-Once ShadowCache)"
        } else {
            "Read-Only Staging Folder Fallback (POSTURE_REDUCED_NO_FUSE)"
        }
    }

    async fn mount_sanitized_volume(
        &self,
        raw_volume_path: &Path,
        virtual_mount_point: &Path,
    ) -> Result<(), String> {
        if let Ok(mut active) = self.native_fuse_active.lock() {
            *active = false;
        }
        if !Self::is_native_fuse_supported() {
            warn!(
                "[{}] Native FUSE3 (vfs-fuse / /dev/fuse) unavailable; delegating {} -> {} to hardened Read-Only StagingFolderProvider (zero bindfs shell-out)",
                DegradationEvent::PostureReducedNoFuse.event_code(),
                raw_volume_path.display(),
                virtual_mount_point.display()
            );
        } else {
            info!(
                "[{}] Native FUSE3 mount session not yet initialized; using Read-Only StagingFolderProvider for {}",
                DegradationEvent::PostureReducedNoFuse.event_code(),
                virtual_mount_point.display()
            );
        }

        // Delegate cleanly to StagingFolderProvider (configured with DegradationEvent::PostureReducedNoFuse),
        // which atomically creates the read-only staging root, records `POSTURE_REDUCED_NO_FUSE` in the
        // unified AuditLedger, ingests read-once into the encrypted ShadowCache, and materializes
        // verified read-only outputs while preserving withheld threats for QuarantineVault.
        self.staging_fallback
            .mount_sanitized_volume(raw_volume_path, virtual_mount_point)
            .await?;

        if let Ok(mut guard) = self.active_root.lock() {
            *guard = Some(virtual_mount_point.to_path_buf());
        }
        Ok(())
    }

    async fn on_file_first_open(&self, relative_path: &Path) -> Result<PathBuf, String> {
        self.staging_fallback
            .on_file_first_open(relative_path)
            .await
    }

    async fn unmount_volume(&self, virtual_mount_point: &Path) -> Result<(), String> {
        info!(
            "Unmounting Linux sanitized volume and crypto-erasing session cache: {}",
            virtual_mount_point.display()
        );
        if let Ok(mut active) = self.native_fuse_active.lock() {
            *active = false;
        }
        let res = self
            .staging_fallback
            .unmount_volume(virtual_mount_point)
            .await;
        if let Ok(mut guard) = self.active_root.lock() {
            *guard = None;
        }
        res
    }

    fn take_withheld_threats(
        &self,
        virtual_mount_point: &Path,
    ) -> Vec<crate::scanner::universal_scanner::UniversalThreat> {
        self.staging_fallback
            .take_withheld_threats(virtual_mount_point)
    }
}
