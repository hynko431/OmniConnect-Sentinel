pub mod drive_watcher;
pub mod linux_udev;
pub mod windows_umdf;

use crate::events::DeviceConnectedEvent;
use async_trait::async_trait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::Receiver;

#[async_trait]
pub trait DeviceInterceptor: Send + Sync {
    async fn start_monitoring(
        &self,
    ) -> Result<Receiver<DeviceConnectedEvent>, Box<dyn std::error::Error>>;
    async fn sever_data_lines(&self, device_id: &str) -> Result<(), Box<dyn std::error::Error>>;
    async fn enable_charge_only_mode(
        &self,
        device_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Pending physical user-presence confirmation entry for composite/input USB devices
/// (Master Plan v2 §3.1 #6 / Row 3, 142).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeviceConfirmation {
    pub device_id: String,
    pub challenge_code: String,
    pub created_at_unix: i64,
    pub confirmed: bool,
}

/// Manages explicit user-presence confirmation challenges required before re-enabling
/// composite HID+Storage or newly connected input devices disabled via `CM_Disable_DevNode`.
pub struct PendingDeviceConfirmationManager {
    state_file: PathBuf,
}

impl PendingDeviceConfirmationManager {
    pub fn new(state_file: PathBuf) -> Self {
        Self { state_file }
    }

    pub fn default_state_file() -> PathBuf {
        PathBuf::from(".sentinel_vault").join("pending_device_confirmations.json")
    }

    fn load_map(&self) -> io::Result<HashMap<String, PendingDeviceConfirmation>> {
        if !self.state_file.exists() {
            return Ok(HashMap::new());
        }
        let raw = fs::read_to_string(&self.state_file)?;
        serde_json::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn save_map(&self, map: &HashMap<String, PendingDeviceConfirmation>) -> io::Result<()> {
        if let Some(parent) = self.state_file.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let serialized = serde_json::to_string_pretty(map)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&self.state_file, serialized)
    }

    /// Generates a cryptographic 8-hex-character user-presence confirmation challenge for `device_id`.
    pub fn request_user_presence_confirmation(&self, device_id: &str) -> io::Result<String> {
        let mut random_bytes = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut random_bytes);
        let challenge_code = hex::encode_upper(random_bytes);

        let mut map = self.load_map()?;
        map.insert(
            device_id.to_string(),
            PendingDeviceConfirmation {
                device_id: device_id.to_string(),
                challenge_code: challenge_code.clone(),
                created_at_unix: chrono::Utc::now().timestamp(),
                confirmed: false,
            },
        );
        self.save_map(&map)?;
        Ok(challenge_code)
    }

    /// Validates the user-provided challenge token and re-enables the USB device node only upon match.
    pub fn confirm_device_with_challenge(
        &self,
        device_id: &str,
        provided_challenge: &str,
    ) -> io::Result<()> {
        let mut map = self.load_map()?;
        let entry = map.get_mut(device_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("No pending confirmation found for device '{device_id}'"),
            )
        })?;

        let expected = entry.challenge_code.trim().as_bytes();
        let actual = provided_challenge.trim().as_bytes();
        if expected.len() != actual.len()
            || expected
                .iter()
                .zip(actual.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid user-presence confirmation challenge code",
            ));
        }

        // Re-enable hardware device node via CfgMgr32 / sysfs
        sentinel_sys::enable_device_node(device_id)?;
        entry.confirmed = true;
        self.save_map(&map)?;
        Ok(())
    }

    pub fn is_confirmed(&self, device_id: &str) -> bool {
        self.load_map()
            .ok()
            .and_then(|m| m.get(device_id).map(|e| e.confirmed))
            .unwrap_or(false)
    }

    pub fn state_file_path(&self) -> &Path {
        &self.state_file
    }
}

/// Dynamically resolves the native userspace hardware interceptor based on host OS
pub fn resolve_best_interceptor() -> Box<dyn DeviceInterceptor> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows_umdf::WindowsUmdfInterceptor::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux_udev::LinuxUdevInterceptor::new())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Box::new(windows_umdf::WindowsUmdfInterceptor::new())
    }
}
