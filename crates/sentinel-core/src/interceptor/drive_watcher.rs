use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::info;

use sentinel_sys::{get_removable_drives, register_pnp_notification_watcher};

/// Real-Time Removable Volume Watcher (`BUG-CORE-12`, Phase 3.1, Row 139)
///
/// Queries `sentinel_sys::get_removable_drives()` (`DRIVE_REMOVABLE` & `BusTypeUsb` volumes
/// on Windows, removable `/media` & `/run/media` mounts on Linux) so fixed internal drives
/// (`D:\`, `E:\`) and SMB network shares (`Z:\`) are never scanned, listens for native PnP
/// device arrival notifications (`CM_Register_Notification` / `NETLINK_KOBJECT_UEVENT`), and
/// offloads scan callbacks onto `tokio::task::spawn_blocking` without `.await`ing inside the
/// detection loop so concurrent USB insertions are never missed.
pub struct DriveWatcher {
    known_drives: HashSet<PathBuf>,
}

impl Default for DriveWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl DriveWatcher {
    pub fn new() -> Self {
        let initial = Self::enumerate_mounted_drives();
        Self {
            known_drives: initial,
        }
    }

    pub fn enumerate_mounted_drives() -> HashSet<PathBuf> {
        get_removable_drives().into_iter().collect()
    }

    pub async fn watch_loop<F>(&mut self, on_drive_inserted: F)
    where
        F: Fn(PathBuf) + Send + Sync + 'static,
    {
        let callback = Arc::new(on_drive_inserted);
        info!(
            "DriveWatcher active. Baseline removable drives: {:?}",
            self.known_drives
        );

        let (pnp_tx, mut pnp_rx) = mpsc::unbounded_channel::<()>();
        let _pnp_guard = register_pnp_notification_watcher(move || {
            let _ = pnp_tx.send(());
        });

        let mut interval = Self::new_poll_interval();
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = pnp_rx.recv() => {}
            }

            let current = Self::enumerate_mounted_drives();

            for drive in &current {
                if !self.known_drives.contains(drive) {
                    info!("New removable USB volume detected: {}", drive.display());
                    let cb = Arc::clone(&callback);
                    let drive_clone = drive.clone();
                    // Spawn onto blocking pool without `.await`ing inside the detection loop
                    // so a second device inserted during a long scan is detected immediately (`Row 139`).
                    tokio::task::spawn_blocking(move || {
                        cb(drive_clone);
                    });
                }
            }

            self.known_drives = current;
        }
    }

    /// Creates a hardened stack-local `tokio::time::Interval` with `MissedTickBehavior::Delay` (`RUSTSEC-2026-0384` defense-in-depth).
    pub fn new_poll_interval() -> tokio::time::Interval {
        let mut ticker = tokio::time::interval(Duration::from_millis(800));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_drive_watcher_interval_uses_delay_missed_tick_behavior() {
        let mut ticker = DriveWatcher::new_poll_interval();
        assert_eq!(
            ticker.missed_tick_behavior(),
            tokio::time::MissedTickBehavior::Delay
        );
        assert_eq!(ticker.period(), Duration::from_millis(800));
        ticker.tick().await;
    }
}
