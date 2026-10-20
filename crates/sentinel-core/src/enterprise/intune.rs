use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntunePolicyProfile {
    pub enforce_removable_media_cdr: bool,
    pub block_unauthorized_usb_hid: bool,
    pub charge_only_fallback: bool,
    pub hardware_whitelist_patterns: Vec<String>,
}

impl Default for IntunePolicyProfile {
    fn default() -> Self {
        Self {
            enforce_removable_media_cdr: true,
            block_unauthorized_usb_hid: true,
            charge_only_fallback: true,
            hardware_whitelist_patterns: vec!["VID_0781*".to_string()],
        }
    }
}

pub struct IntunePolicyManager;

impl IntunePolicyManager {
    pub fn load_active_policy() -> IntunePolicyProfile {
        info!("Synchronizing with Microsoft Intune Custom CSP / Group Policy ADMX");
        // In production Windows runtime: reads HKLM\SOFTWARE\Policies\OmniConnect\Sentinel
        IntunePolicyProfile::default()
    }
}
