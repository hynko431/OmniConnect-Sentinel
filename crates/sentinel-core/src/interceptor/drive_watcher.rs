use std::collections::HashSet;
#[allow(unused_imports)]
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct DriveArrivalEvent {
    pub drive_root: PathBuf,
    pub volume_label: Option<String>,
    pub filesystem: Option<String>,
}

pub struct DriveWatcher;

impl DriveWatcher {
    /// Discovers all currently active drive roots on the system
    pub fn get_active_drives() -> Vec<PathBuf> {
        let mut drives = Vec::new();

        #[cfg(windows)]
        {
            // Scan drive letters A through Z
            for letter in b'A'..=b'Z' {
                let drive_str = format!("{}:\\", letter as char);
                let p = PathBuf::from(&drive_str);
                if p.exists() {
                    drives.push(p);
                }
            }
        }

        #[cfg(not(windows))]
        {
            // On Linux / macOS, check /media, /run/media, and /Volumes
            for mount_root in &["/media", "/run/media", "/Volumes"] {
                let p = Path::new(mount_root);
                if p.is_dir() {
                    if let Ok(entries) = std::fs::read_dir(p) {
                        for entry in entries.flatten() {
                            let ep = entry.path();
                            if ep.is_dir() {
                                drives.push(ep);
                            }
                        }
                    }
                }
            }
        }

        drives
    }

    /// Continuously monitors the system for new external / removable drive arrivals.
    /// When a newly inserted drive is detected, executes the provided callback.
    pub async fn listen_for_insertions<F>(
        poll_interval: Duration,
        mut callback: F,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: FnMut(DriveArrivalEvent) + Send + Sync + 'static,
    {
        info!("DriveWatcher sentry actively monitoring for hardware drive arrivals...");
        let mut known_drives: HashSet<PathBuf> = Self::get_active_drives().into_iter().collect();

        loop {
            sleep(poll_interval).await;
            let current_drives = Self::get_active_drives();
            let current_set: HashSet<PathBuf> = current_drives.iter().cloned().collect();

            // Detect newly arrived drives
            for drive in &current_set {
                if !known_drives.contains(drive) {
                    info!("🚨 Hardware Drive Insertion Detected: {:?}", drive);

                    let event = DriveArrivalEvent {
                        drive_root: drive.clone(),
                        volume_label: None,
                        filesystem: None,
                    };

                    callback(event);
                }
            }

            // Detect removed drives
            for removed in known_drives.difference(&current_set) {
                debug!("Device disconnected / dismounted: {:?}", removed);
            }

            known_drives = current_set;
        }
    }
}
