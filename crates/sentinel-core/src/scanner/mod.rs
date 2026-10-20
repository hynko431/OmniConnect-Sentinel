pub mod tier0_yara;
pub mod tier1_cdr_client;
pub mod tier3_sandbox;
pub mod quarantine;
pub mod secure_shredder;
pub mod universal_scanner;
pub mod polyglot_scanner;
pub mod ntfs_ads_scanner;
pub mod unicode_trojan_detector;
pub mod content_scanner;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: PathBuf,
    pub original_sha256: String,
    pub sanitized_sha256: Option<String>,
    pub threat_score: u8,
    pub is_quarantined: bool,
    pub sanitized_elements: Vec<String>,
}
