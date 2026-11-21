use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub node_id: String,
    pub environment: AgentMode,
    pub cdr_service_endpoint: String,
    #[serde(default = "default_siem_syslog_endpoint")]
    pub siem_syslog_endpoint: String,
    #[serde(default = "default_siem_allowed_private_cidrs")]
    pub siem_allowed_private_cidrs: Vec<String>,
    #[serde(default = "default_siem_client_cert_path")]
    pub siem_client_cert_path: Option<PathBuf>,
    #[serde(default = "default_siem_client_key_path")]
    pub siem_client_key_path: Option<PathBuf>,
    #[serde(default = "default_siem_ca_cert_path")]
    pub siem_ca_cert_path: Option<PathBuf>,
    pub quarantine_vault_path: PathBuf,
    #[serde(default = "default_safe_drive_mount_path")]
    pub safe_drive_mount_path: PathBuf,
    pub vfs_provider: VfsProviderPreference,
    pub auto_sanitize_removable_media: bool,
    pub charge_only_fallback_enabled: bool,
    pub telemetry_reporting_enabled: bool,
    pub hardware_whitelist: Vec<HardwareIdentifier>,
}

/// Environment variable overriding the OS-specific default SafeDrive virtual mount root (`CSE-18`).
pub const SAFE_DRIVE_DIR_ENV: &str = "SENTINEL_SAFE_DRIVE_DIR";

/// Returns the OS-gated default SafeDrive virtual mount path when `SENTINEL_SAFE_DRIVE_DIR` is unset:
/// - Windows: `C:\ProgramData\OmniConnect\SafeDrive`
/// - Unix: `/run/omniconnect/safedrive`
pub fn default_os_safe_drive_mount_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\OmniConnect\SafeDrive")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/run/omniconnect/safedrive")
    }
}

/// Pure resolver for the SafeDrive mount path honoring an optional non-empty environment override.
pub fn resolve_safe_drive_mount_path(env_override: Option<&str>) -> PathBuf {
    if let Some(raw) = env_override {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    default_os_safe_drive_mount_path()
}

/// Resolves the active SafeDrive mount path from `SENTINEL_SAFE_DRIVE_DIR` or OS defaults (`CSE-18`).
pub fn default_safe_drive_mount_path() -> PathBuf {
    let env_override = std::env::var(SAFE_DRIVE_DIR_ENV).ok();
    resolve_safe_drive_mount_path(env_override.as_deref())
}

pub fn default_quarantine_vault_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\OmniConnect\Quarantine")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/omniconnect/quarantine")
    }
}

pub fn default_siem_syslog_endpoint() -> String {
    if let Ok(ep) = std::env::var("SENTINEL_SIEM_ENDPOINT") {
        let trimmed = ep.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "offline://siem.omniconnect.local:6514".to_string()
}

/// Resolves operator-pinned internal RFC 1918 / IPv6 ULA SIEM CIDRs from `SENTINEL_SIEM_ALLOW_CIDRS` (`CSE-23`).
pub fn default_siem_allowed_private_cidrs() -> Vec<String> {
    std::env::var("SENTINEL_SIEM_ALLOW_CIDRS")
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn default_siem_client_cert_path() -> Option<PathBuf> {
    std::env::var("SENTINEL_SIEM_CLIENT_CERT_PEM")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

pub fn default_siem_client_key_path() -> Option<PathBuf> {
    std::env::var("SENTINEL_SIEM_CLIENT_KEY_PEM")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

pub fn default_siem_ca_cert_path() -> Option<PathBuf> {
    std::env::var("SENTINEL_SIEM_CA_CERT_PEM")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentMode {
    EnterpriseManaged,
    ConsumerFreemium,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VfsProviderPreference {
    AutoDetect,
    ProjFsOnly,
    WinFspFallback,
    LinuxFuse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareIdentifier {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial_number: Option<String>,
    pub friendly_name: String,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            node_id: uuid::Uuid::new_v4().to_string(),
            environment: AgentMode::EnterpriseManaged,
            cdr_service_endpoint: sentinel_sys::DEFAULT_NAMED_PIPE_ENDPOINT.to_string(),
            siem_syslog_endpoint: default_siem_syslog_endpoint(),
            siem_allowed_private_cidrs: default_siem_allowed_private_cidrs(),
            siem_client_cert_path: default_siem_client_cert_path(),
            siem_client_key_path: default_siem_client_key_path(),
            siem_ca_cert_path: default_siem_ca_cert_path(),
            quarantine_vault_path: default_quarantine_vault_path(),
            safe_drive_mount_path: default_safe_drive_mount_path(),
            vfs_provider: VfsProviderPreference::AutoDetect,
            auto_sanitize_removable_media: true,
            charge_only_fallback_enabled: true,
            telemetry_reporting_enabled: true,
            hardware_whitelist: vec![HardwareIdentifier {
                vendor_id: 0x0781, // SanDisk Enterprise Token
                product_id: 0x5583,
                serial_number: None,
                friendly_name: "Corporate Encrypted Hardware Key".to_string(),
            }],
        }
    }
}
