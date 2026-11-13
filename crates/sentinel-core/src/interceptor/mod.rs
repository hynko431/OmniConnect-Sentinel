pub mod drive_watcher;
pub mod linux_udev;
pub mod windows_umdf;

use crate::events::DeviceConnectedEvent;
use async_trait::async_trait;
use rand::RngCore;
use sentinel_sys::{create_restricted_dir_atomic, create_restricted_file_atomic};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc::Receiver;

pub const BADUSB_CHALLENGE_TTL_SECS: i64 = 300; // 300 second (5 min) TTL (Row 3, 142)
pub const BADUSB_MAX_FAILED_ATTEMPTS: u32 = 3; // 3-strike lockout policy (Row 3, 142)

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
/// (Master Plan v2 §3.1 #6 / Row 3, 142). Plaintext challenge token is never persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeviceConfirmation {
    pub device_id: String,
    #[serde(default)]
    pub challenge_id: String,
    #[serde(default)]
    pub challenge_hash: String, // SHA256(device_id || ":" || challenge_token)
    #[serde(default)]
    pub challenge_code: String, // Retained for backwards compatibility; empty in v2
    pub created_at_unix: i64,
    #[serde(default)]
    pub expires_at_unix: i64,
    #[serde(default)]
    pub failed_attempts: u32,
    pub confirmed: bool,
}

/// Issued BadUSB challenge bundle separating public tracking identifier from private local token.
#[derive(Debug, Clone)]
pub struct IssuedBadUsbChallenge {
    pub challenge_id: String,
    pub challenge_token: String,
    pub expires_at_unix: i64,
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
                let _ = create_restricted_dir_atomic(parent);
            }
        }
        let serialized = serde_json::to_string_pretty(map)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        create_restricted_file_atomic(&self.state_file, serialized.as_bytes())
    }

    /// Generates a 128-bit cryptographic confirmation challenge for `device_id` (`CSE-12`, `T35`).
    pub fn request_user_presence_confirmation(&self, device_id: &str) -> io::Result<String> {
        let issued = self.request_user_presence_challenge_extended(device_id)?;
        Ok(issued.challenge_token)
    }

    /// Generates a 128-bit cryptographic challenge, hashes it into state storage, saves the
    /// plaintext token exclusively to a local restricted token file, and returns the bundle.
    pub fn request_user_presence_challenge_extended(
        &self,
        device_id: &str,
    ) -> io::Result<IssuedBadUsbChallenge> {
        let mut random_bytes = [0u8; 16]; // 128-bit cryptographic entropy (Row 3, 142)
        rand::rngs::OsRng.fill_bytes(&mut random_bytes);
        let challenge_token = hex::encode_upper(random_bytes);

        // Derive public challenge_id prefix
        let token_digest = Sha256::digest(challenge_token.as_bytes());
        let challenge_id = format!("CHAL-{}", hex::encode_upper(&token_digest[0..8]));

        // Hash: SHA256(device_id || ":" || challenge_token)
        let hash_input = format!("{device_id}:{challenge_token}");
        let challenge_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

        let now = chrono::Utc::now().timestamp();
        let expires_at_unix = now + BADUSB_CHALLENGE_TTL_SECS;

        // Atomically write secret token to local console operator token file with restricted DACL
        let token_dir = self
            .state_file
            .parent()
            .unwrap_or_else(|| Path::new(".sentinel_vault"));
        let _ = create_restricted_dir_atomic(token_dir);
        let token_path = token_dir.join(format!("pending_challenge_{challenge_id}.token"));
        create_restricted_file_atomic(&token_path, challenge_token.as_bytes())?;

        let mut map = self.load_map()?;
        map.insert(
            device_id.to_string(),
            PendingDeviceConfirmation {
                device_id: device_id.to_string(),
                challenge_id: challenge_id.clone(),
                challenge_hash,
                challenge_code: String::new(), // Never store raw secret token in state map
                created_at_unix: now,
                expires_at_unix,
                failed_attempts: 0,
                confirmed: false,
            },
        );
        self.save_map(&map)?;

        Ok(IssuedBadUsbChallenge {
            challenge_id,
            challenge_token,
            expires_at_unix,
        })
    }

    /// Validates the user-provided challenge token with constant-time equality (`ct_eq`),
    /// enforces 300s TTL and 3-strike lockout, and re-enables the USB device node upon match (`T35`).
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

        if entry.confirmed {
            return Ok(());
        }

        let now = chrono::Utc::now().timestamp();
        // 300s TTL check
        if entry.expires_at_unix > 0 && now > entry.expires_at_unix {
            let challenge_id = entry.challenge_id.clone();
            map.remove(device_id);
            let _ = self.save_map(&map);

            let token_dir = self
                .state_file
                .parent()
                .unwrap_or_else(|| Path::new(".sentinel_vault"));
            let token_path = token_dir.join(format!("pending_challenge_{challenge_id}.token"));
            let _ = fs::remove_file(token_path);

            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "User-presence challenge for device '{device_id}' expired (300s TTL exceeded); challenge purged and device locked out"
                ),
            ));
        }

        // 3-strike lockout check: if already locked out, purge and reject
        if entry.failed_attempts >= BADUSB_MAX_FAILED_ATTEMPTS {
            let challenge_id = entry.challenge_id.clone();
            map.remove(device_id);
            let _ = self.save_map(&map);

            let token_dir = self
                .state_file
                .parent()
                .unwrap_or_else(|| Path::new(".sentinel_vault"));
            let token_path = token_dir.join(format!("pending_challenge_{challenge_id}.token"));
            let _ = fs::remove_file(token_path);

            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Device '{device_id}' confirmation locked out (maximum {BADUSB_MAX_FAILED_ATTEMPTS} failed attempts exceeded); challenge purged"
                ),
            ));
        }

        // Constant-time validation
        let trimmed_challenge = provided_challenge.trim();
        let candidate_hash = hex::encode(Sha256::digest(
            format!("{device_id}:{trimmed_challenge}").as_bytes(),
        ));

        let is_valid = if !entry.challenge_hash.is_empty() {
            candidate_hash
                .as_bytes()
                .ct_eq(entry.challenge_hash.as_bytes())
                .into()
        } else if !entry.challenge_code.is_empty() {
            trimmed_challenge
                .as_bytes()
                .ct_eq(entry.challenge_code.trim().as_bytes())
                .into()
        } else {
            false
        };

        if !is_valid {
            entry.failed_attempts += 1;
            let strikes = entry.failed_attempts;
            if strikes >= BADUSB_MAX_FAILED_ATTEMPTS {
                // Strike 3 reached: purge entry completely
                let challenge_id = entry.challenge_id.clone();
                map.remove(device_id);
                let _ = self.save_map(&map);

                let token_dir = self
                    .state_file
                    .parent()
                    .unwrap_or_else(|| Path::new(".sentinel_vault"));
                let token_path = token_dir.join(format!("pending_challenge_{challenge_id}.token"));
                let _ = fs::remove_file(token_path);

                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Invalid challenge code: strike {strikes} of {BADUSB_MAX_FAILED_ATTEMPTS} reached. Challenge purged and device locked out."
                    ),
                ));
            } else {
                self.save_map(&map)?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Invalid user-presence confirmation challenge code: strike {strikes} of {BADUSB_MAX_FAILED_ATTEMPTS}"
                    ),
                ));
            }
        }

        // Successful validation: mark confirmed, purge secret token file, and re-enable device node
        entry.confirmed = true;
        let challenge_id = entry.challenge_id.clone();
        self.save_map(&map)?;

        let token_dir = self
            .state_file
            .parent()
            .unwrap_or_else(|| Path::new(".sentinel_vault"));
        let token_path = token_dir.join(format!("pending_challenge_{challenge_id}.token"));
        let _ = fs::remove_file(token_path);

        if let Err(e) = sentinel_sys::enable_device_node(device_id) {
            tracing::warn!("enable_device_node notice for {device_id}: {e}");
        }
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
