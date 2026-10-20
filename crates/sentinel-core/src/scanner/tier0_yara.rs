use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::debug;

pub struct Tier0YaraScanner;

#[derive(Debug, Clone)]
pub struct FastTriageReport {
    pub sha256_hex: String,
    pub entropy: f32,
    pub is_executable: bool,
    pub suspicious_strings: Vec<String>,
    pub threat_score: u8,
}

impl Tier0YaraScanner {
    pub fn calculate_entropy(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let mut occurrences = [0usize; 256];
        for &byte in data {
            occurrences[byte as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy = 0.0;

        for &count in &occurrences {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    pub fn scan_bytes(data: &[u8], _path: &Path) -> FastTriageReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256_hex = hex::encode(hasher.finalize());

        let entropy = Self::calculate_entropy(data);
        let is_executable = data.starts_with(b"MZ") || data.starts_with(&[0x7F, 0x45, 0x4C, 0x46]);

        let mut suspicious_strings = Vec::new();
        let mut threat_score = 0u8;

        // Check for common malicious script markers
        let sample_text = String::from_utf8_lossy(&data[..data.len().min(8192)]);
        if sample_text.contains("-ExecutionPolicy Bypass") || sample_text.contains("-w hidden") {
            suspicious_strings.push("POWERSHELL_OBFUSCATION_FLAGS".to_string());
            threat_score += 40;
        }
        if sample_text.contains("VirtualAlloc") && sample_text.contains("CreateRemoteThread") {
            suspicious_strings.push("INJECTION_API_STRINGS".to_string());
            threat_score += 50;
        }

        if entropy > 7.5 && is_executable {
            suspicious_strings.push("HIGH_ENTROPY_PACKED_BINARY".to_string());
            threat_score += 35;
        }

        debug!(
            "Tier 0 triage: entropy={:.2}, exec={}, score={}",
            entropy, is_executable, threat_score
        );

        FastTriageReport {
            sha256_hex,
            entropy,
            is_executable,
            suspicious_strings,
            threat_score: threat_score.min(100),
        }
    }
}
