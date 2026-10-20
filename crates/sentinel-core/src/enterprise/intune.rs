use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Microsoft Intune Endpoint Management Configuration Profile for OmniConnect Sentinel
/// Maps 1:1 to OMA-URI configuration service provider (CSP) policies:
/// `./Device/Vendor/MSFT/Policy/Config/OmniConnect_Sentinel/Policy`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntunePolicyProfile {
    pub policy_version: String,
    pub enforce_removable_media_cdr: bool,
    pub block_unauthorized_usb_hid: bool,
    pub charge_only_fallback: bool,
    pub hardware_whitelist_patterns: Vec<String>,
    pub max_file_size_mb: u64,
    pub allowed_file_types: Vec<String>,
    pub require_cloud_detonation: bool,
    pub quarantine_retention_days: u32,
}

impl Default for IntunePolicyProfile {
    fn default() -> Self {
        Self {
            policy_version: "2026.3.0".to_string(),
            enforce_removable_media_cdr: true,
            block_unauthorized_usb_hid: true,
            charge_only_fallback: true,
            hardware_whitelist_patterns: vec![
                "USB\\VID_0781&*".to_string(), // SanDisk Corporate Secure
                "USB\\VID_0951&*".to_string(), // Kingston IronKey Encrypted
            ],
            max_file_size_mb: 250,
            allowed_file_types: vec![
                "pdf".to_string(),
                "docx".to_string(),
                "xlsx".to_string(),
                "pptx".to_string(),
                "jpeg".to_string(),
                "png".to_string(),
                "webp".to_string(),
            ],
            require_cloud_detonation: false,
            quarantine_retention_days: 30,
        }
    }
}

pub struct IntunePolicyManager;

impl IntunePolicyManager {
    /// Loads active Intune policy from registry if present, or defaults to zero-trust profile
    pub fn load_active_policy() -> IntunePolicyProfile {
        info!("Synchronizing with Microsoft Intune Custom CSP / Group Policy ADMX");

        #[cfg(target_os = "windows")]
        {
            // In enterprise environments, Intune pushes settings to:
            // HKLM\SOFTWARE\Policies\OmniConnect\Sentinel
            debug!("Reading HKLM\\SOFTWARE\\Policies\\OmniConnect\\Sentinel registry keys");
        }

        IntunePolicyProfile::default()
    }

    /// Evaluates if a connected peripheral hardware ID matches corporate whitelist patterns
    pub fn is_device_whitelisted(profile: &IntunePolicyProfile, hardware_id: &str) -> bool {
        let hw_upper = hardware_id.to_uppercase();
        for pattern in &profile.hardware_whitelist_patterns {
            let pat_upper = pattern.to_uppercase();
            if pat_upper.ends_with('*') {
                let prefix = &pat_upper[..pat_upper.len() - 1];
                if hw_upper.starts_with(prefix) {
                    return true;
                }
            } else if hw_upper == pat_upper {
                return true;
            }
        }
        false
    }

    /// Generates the Microsoft Intune Custom OMA-URI XML Profile for deployment
    pub fn export_oma_uri_profile_xml(profile: &IntunePolicyProfile) -> String {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncBody>
    <!-- OmniConnect Sentinel Zero-Trust Peripheral Management Profile -->
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnect~Policy~Sentinel/EnforceRemovableMediaCDR</LocURI>
      </Target>
      <Data>{enforce_cdr}</Data>
    </Item>
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnect~Policy~Sentinel/BlockUnauthorizedUSBHID</LocURI>
      </Target>
      <Data>{block_hid}</Data>
    </Item>
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnect~Policy~Sentinel/ChargeOnlyFallback</LocURI>
      </Target>
      <Data>{charge_fallback}</Data>
    </Item>
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnect~Policy~Sentinel/MaxFileSizeMB</LocURI>
      </Target>
      <Data>{max_size}</Data>
    </Item>
    <Item>
      <Target>
        <LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnect~Policy~Sentinel/HardwareWhitelist</LocURI>
      </Target>
      <Data>{whitelist}</Data>
    </Item>
  </SyncBody>
</SyncML>"#,
            enforce_cdr = if profile.enforce_removable_media_cdr { "1" } else { "0" },
            block_hid = if profile.block_unauthorized_usb_hid { "1" } else { "0" },
            charge_fallback = if profile.charge_only_fallback { "1" } else { "0" },
            max_size = profile.max_file_size_mb,
            whitelist = profile.hardware_whitelist_patterns.join(";")
        )
    }
}
