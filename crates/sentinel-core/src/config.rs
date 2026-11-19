use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub node_id: String,
    pub environment: AgentMode,
    pub cdr_service_endpoint: String,
    #[serde(default = "default_siem_syslog_endpoint")]
    pub siem_syslog_endpoint: String,
    pub quarantine_vault_path: PathBuf,
    pub vfs_provider: VfsProviderPreference,
    pub auto_sanitize_removable_media: bool,
    pub charge_only_fallback_enabled: bool,
    pub telemetry_reporting_enabled: bool,
    pub hardware_whitelist: Vec<HardwareIdentifier>,
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
            quarantine_vault_path: PathBuf::from(r"C:\ProgramData\OmniConnect\Quarantine"),
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
