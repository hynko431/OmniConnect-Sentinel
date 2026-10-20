use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub entry_id: String,
    pub original_file_path: PathBuf,
    pub original_sha256: String,
    pub threat_score: u8,
    pub quarantined_at_utc: chrono::DateTime<chrono::Utc>,
    pub quarantine_container_path: PathBuf,
}

pub struct QuarantineVault {
    vault_dir: PathBuf,
    cipher_key: [u8; 32],
}

impl QuarantineVault {
    pub fn new(vault_dir: PathBuf) -> Self {
        fs::create_dir_all(&vault_dir).unwrap_or_default();
        // In enterprise deployment, key is derived from TPM 2.0 or Windows DPAPI
        let mut cipher_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut cipher_key);

        Self {
            vault_dir,
            cipher_key,
        }
    }

    pub fn quarantine_file(
        &self,
        file_bytes: &[u8],
        original_path: &Path,
        threat_score: u8,
        sha256_hex: &str,
    ) -> Result<QuarantineEntry, Box<dyn std::error::Error + Send + Sync>> {
        warn!(
            "Quarantining suspicious/malicious file: {:?} (Threat Score: {})",
            original_path, threat_score
        );

        let cipher = Aes256Gcm::new_from_slice(&self.cipher_key)?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted_payload = cipher
            .encrypt(nonce, file_bytes)
            .map_err(|e| format!("AES-256-GCM encryption failed: {}", e))?;

        let entry_id = uuid::Uuid::new_v4().to_string();
        let quar_filename = format!("{}_{}.quar", sha256_hex, &entry_id[..8]);
        let quar_path = self.vault_dir.join(&quar_filename);

        let mut quar_file = File::create(&quar_path)?;
        quar_file.write_all(&nonce_bytes)?;
        quar_file.write_all(&encrypted_payload)?;

        let entry = QuarantineEntry {
            entry_id,
            original_file_path: original_path.to_path_buf(),
            original_sha256: sha256_hex.to_string(),
            threat_score,
            quarantined_at_utc: chrono::Utc::now(),
            quarantine_container_path: quar_path,
        };

        let meta_filename = format!("{}_{}.json", sha256_hex, &entry.entry_id[..8]);
        let meta_path = self.vault_dir.join(meta_filename);
        let meta_json = serde_json::to_string_pretty(&entry)?;
        fs::write(meta_path, meta_json)?;

        info!("File successfully encrypted and stored in vault: {:?}", entry.quarantine_container_path);
        Ok(entry)
    }
}
