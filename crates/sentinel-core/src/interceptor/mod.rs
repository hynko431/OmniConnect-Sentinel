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
#[serde(deny_unknown_fields)]
pub struct PendingDeviceConfirmation {
    pub device_id: String,
    pub challenge_id: String,
    pub challenge_hash: String, // SHA256(device_id || ":" || challenge_token)
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    #[serde(default)]
    pub failed_attempts: u32,
    pub confirmed: bool,
}

fn is_valid_challenge_id(challenge_id: &str) -> bool {
    challenge_id.len() == 21
        && challenge_id.starts_with("CHAL-")
        && challenge_id[5..].chars().all(|c| c.is_ascii_hexdigit())
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
    device_enabler: fn(&str) -> io::Result<()>,
}

impl PendingDeviceConfirmationManager {
    pub fn new(state_file: PathBuf) -> Self {
        Self {
            state_file,
            device_enabler: sentinel_sys::enable_device_node,
        }
    }

    /// Overrides the OS device re-enable callback (for deterministic unit/integration testing
    /// without synthetic USB PnP hardware nodes) (`CSE-26`). Production callers use the default
    /// `sentinel_sys::enable_device_node`.
    pub fn with_device_enabler(mut self, device_enabler: fn(&str) -> io::Result<()>) -> Self {
        self.device_enabler = device_enabler;
        self
    }

    pub fn default_state_file() -> PathBuf {
        PathBuf::from(".sentinel_vault").join("pending_device_confirmations.json")
    }

    fn token_dir(&self) -> &Path {
        self.state_file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".sentinel_vault"))
    }

    fn purge_token_file(&self, challenge_id: &str) {
        if !is_valid_challenge_id(challenge_id) {
            return;
        }
        let token_path = self
            .token_dir()
            .join(format!("pending_challenge_{challenge_id}.token"));
        if token_path.exists() {
            let _ = create_restricted_file_atomic(&token_path, &[0u8; 32]);
            let _ = fs::remove_file(&token_path);
        }
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
        if device_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "device_id must not be empty",
            ));
        }

        let mut map = self.load_map()?;
        let now = sentinel_sys::now_unix_secs();

        // Purge any superseded `.token` file for the same `device_id` (e.g. USB bus re-enumeration)
        if let Some(prev) = map.remove(device_id) {
            self.purge_token_file(&prev.challenge_id);
        }

        // Opportunistically reap any expired unconfirmed challenges so stale `.token` files never accumulate
        let expired_keys: Vec<(String, String)> = map
            .iter()
            .filter(|(_, entry)| {
                !entry.confirmed
                    && (entry.created_at_unix <= 0
                        || entry.expires_at_unix <= 0
                        || entry.expires_at_unix < entry.created_at_unix
                        || entry.expires_at_unix.saturating_sub(entry.created_at_unix)
                            > BADUSB_CHALLENGE_TTL_SECS
                        || now > entry.expires_at_unix
                        || now.saturating_sub(entry.created_at_unix) > BADUSB_CHALLENGE_TTL_SECS)
            })
            .map(|(k, v)| (k.clone(), v.challenge_id.clone()))
            .collect();
        for (exp_dev, exp_chal_id) in expired_keys {
            map.remove(&exp_dev);
            self.purge_token_file(&exp_chal_id);
        }

        let mut random_bytes = [0u8; 16]; // 128-bit cryptographic entropy (Row 3, 142)
        rand::rngs::OsRng.fill_bytes(&mut random_bytes);
        let challenge_token = hex::encode_upper(random_bytes);
        sentinel_sys::zeroize_slice(&mut random_bytes);

        // Derive public challenge_id prefix
        let token_digest = Sha256::digest(challenge_token.as_bytes());
        let challenge_id = format!("CHAL-{}", hex::encode_upper(&token_digest[0..8]));

        // Hash: SHA256(device_id || ":" || challenge_token)
        let hash_input = format!("{device_id}:{challenge_token}");
        let challenge_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

        let expires_at_unix = now + BADUSB_CHALLENGE_TTL_SECS;

        // Atomically write secret token to local console operator token file with restricted DACL
        let token_dir = self.token_dir();
        let _ = create_restricted_dir_atomic(token_dir);
        let token_path = token_dir.join(format!("pending_challenge_{challenge_id}.token"));
        create_restricted_file_atomic(&token_path, challenge_token.as_bytes())?;

        map.insert(
            device_id.to_string(),
            PendingDeviceConfirmation {
                device_id: device_id.to_string(),
                challenge_id: challenge_id.clone(),
                challenge_hash,
                created_at_unix: now,
                expires_at_unix,
                failed_attempts: 0,
                confirmed: false,
            },
        );
        if let Err(e) = self.save_map(&map) {
            self.purge_token_file(&challenge_id);
            return Err(e);
        }

        Ok(IssuedBadUsbChallenge {
            challenge_id,
            challenge_token,
            expires_at_unix,
        })
    }

    /// Validates the user-provided challenge token with constant-time equality (`ct_eq`),
    /// enforces unconditional 300s TTL and 3-strike lockout, and re-enables the USB device node upon match (`T35`).
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

        if entry.device_id != device_id || !is_valid_challenge_id(&entry.challenge_id) {
            let challenge_id = entry.challenge_id.clone();
            map.remove(device_id);
            let _ = self.save_map(&map);
            self.purge_token_file(&challenge_id);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Corrupted confirmation state binding for device '{device_id}'; purged"),
            ));
        }

        if entry.confirmed {
            return Ok(());
        }

        let now = sentinel_sys::now_unix_secs();
        // Unconditional fail-closed 300s TTL check (`expires_at_unix <= 0` or `created_at_unix <= 0` also rejected)
        let ttl_invalid_or_expired = entry.created_at_unix <= 0
            || entry.expires_at_unix <= 0
            || entry.expires_at_unix < entry.created_at_unix
            || entry.expires_at_unix.saturating_sub(entry.created_at_unix)
                > BADUSB_CHALLENGE_TTL_SECS
            || now > entry.expires_at_unix
            || now.saturating_sub(entry.created_at_unix) > BADUSB_CHALLENGE_TTL_SECS;
        if ttl_invalid_or_expired {
            let challenge_id = entry.challenge_id.clone();
            map.remove(device_id);
            let _ = self.save_map(&map);
            self.purge_token_file(&challenge_id);

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
            self.purge_token_file(&challenge_id);

            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Device '{device_id}' confirmation locked out (maximum {BADUSB_MAX_FAILED_ATTEMPTS} failed attempts exceeded); challenge purged"
                ),
            ));
        }

        // Constant-time SHA-256 hash validation (legacy plaintext fallback strictly prohibited)
        let trimmed_challenge = provided_challenge.trim();
        let candidate_hash = hex::encode(Sha256::digest(
            format!("{device_id}:{trimmed_challenge}").as_bytes(),
        ));

        let is_valid = if entry.challenge_hash.len() == 64
            && entry.challenge_hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            let expected_lower = entry.challenge_hash.to_ascii_lowercase();
            candidate_hash
                .as_bytes()
                .ct_eq(expected_lower.as_bytes())
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
                self.purge_token_file(&challenge_id);

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

        // Re-enable the OS device node BEFORE marking confirmed or purging the challenge token (`CSE-26`):
        // strictly propagate OS errors (e.g. non-admin PermissionDenied or unplugged NotFound) rather
        // than swallowing failures and falsely reporting success.
        (self.device_enabler)(device_id)?;

        // Successful validation + hardware re-enable: mark confirmed and purge secret token file
        entry.confirmed = true;
        let challenge_id = entry.challenge_id.clone();
        self.save_map(&map)?;
        self.purge_token_file(&challenge_id);

        Ok(())
    }

    pub fn is_confirmed(&self, device_id: &str) -> bool {
        self.load_map()
            .ok()
            .and_then(|m| {
                m.get(device_id)
                    .map(|e| e.confirmed && e.device_id == device_id)
            })
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
