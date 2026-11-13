use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use sentinel_sys::{create_restricted_dir_atomic, create_restricted_file_atomic, sync_directory};

use crate::enterprise::ledger::{AuditLedger, AuditSubsystem, SharedAuditLedger};

/// Minimum CERT-In and NIST SP 800-53 `AU-9` / `AU-10` retention window (180 days).
pub const SIEM_RETENTION_DAYS: i64 = 180;
/// Maximum CEF header field length (`signature_id`, `name`) per ArcSight CEF v0 (`Row 165`).
pub const MAX_CEF_HEADER_CHARS: usize = 255;
/// Maximum CEF extension value length per ArcSight CEF v0 (`Row 165`, `BUG-CORE-09`).
pub const MAX_CEF_EXT_CHARS: usize = 1023;
/// Maximum sealed SIEM spool size on disk (128 MiB, `CSE-13`).
pub const MAX_SPOOL_SIZE_BYTES: u64 = 128 * 1024 * 1024;

const SPOOL_KDF_SALT: &[u8] = b"OmniConnect-Sentinel-Siem-Spool-AES256GCM";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalconTelemetryEvent {
    pub severity: u8,
    pub signature_id: String,
    pub name: String,
    pub device_vendor_id: String,
    pub device_product_id: String,
    pub serial_number: String,
    pub file_sha256: Option<String>,
    pub action_taken: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemSpoolRecord {
    pub timestamp_unix: i64,
    pub timestamp_rfc3339: String,
    pub cef_payload: String,
    pub delivered: bool,
}

/// CrowdStrike Falcon & SIEM CEF Syslog Bridge (`BUG-CORE-09`, `CSE-13`, `T33`)
///
/// Implements RFC 5425 TLS 1.3 octet-counted syslog on TCP 6514 (replacing cleartext UDP 514),
/// AES-256-GCM encrypted on-disk spooling (`siem_spool.sealed` <= 128 MiB) with 180-day retention,
/// and single-root WORM-anchored `SharedAuditLedger` integration.
pub struct CrowdStrikeFalconBridge {
    syslog_endpoint: String,
    spool_path: PathBuf,
    ledger_path: PathBuf,
    shared_ledger: Option<SharedAuditLedger>,
    custom_ca_cert_pem: Option<Vec<u8>>,
    allow_loopback_for_testing: bool,
}

impl CrowdStrikeFalconBridge {
    pub fn new(syslog_endpoint: impl Into<String>) -> Self {
        let base_dir = default_siem_spool_dir();
        let spool_path = base_dir.join("siem_spool.sealed");
        let ledger_path = base_dir.join("sentinel_unified_audit.jsonl");
        Self {
            syslog_endpoint: syslog_endpoint.into(),
            spool_path,
            ledger_path,
            shared_ledger: None,
            custom_ca_cert_pem: None,
            allow_loopback_for_testing: false,
        }
    }

    pub fn with_spool_path(syslog_endpoint: impl Into<String>, spool_path: PathBuf) -> Self {
        let ledger_path = spool_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("sentinel_unified_audit.jsonl");
        Self {
            syslog_endpoint: syslog_endpoint.into(),
            spool_path,
            ledger_path,
            shared_ledger: None,
            custom_ca_cert_pem: None,
            allow_loopback_for_testing: false,
        }
    }

    pub fn with_shared_ledger(mut self, shared_ledger: SharedAuditLedger) -> Self {
        self.shared_ledger = Some(shared_ledger);
        self
    }

    pub fn with_custom_ca(mut self, ca_pem: Vec<u8>) -> Self {
        self.custom_ca_cert_pem = Some(ca_pem);
        self
    }

    pub fn with_allow_loopback_for_testing(mut self, allow: bool) -> Self {
        self.allow_loopback_for_testing = allow;
        self
    }

    pub fn spool_path(&self) -> &Path {
        &self.spool_path
    }

    pub fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    /// Escapes CEF header fields (`signature_id`, `name`):
    /// - `\` -> `\\`
    /// - `|` -> `\|`
    /// - `\r` and `\n` replaced with `' '`
    /// - Caps output length at 255 characters (`MAX_CEF_HEADER_CHARS`, `Row 165`, `BUG-CORE-09`).
    pub fn escape_cef_header(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len().min(MAX_CEF_HEADER_CHARS));
        let mut char_count = 0usize;
        for c in raw.chars() {
            let escaped = match c {
                '\\' => "\\\\",
                '|' => "\\|",
                '\r' | '\n' => " ",
                _ => {
                    if char_count + 1 > MAX_CEF_HEADER_CHARS
                        || out.len() + c.len_utf8() > MAX_CEF_HEADER_CHARS
                    {
                        break;
                    }
                    out.push(c);
                    char_count += 1;
                    continue;
                }
            };
            let esc_chars = escaped.chars().count();
            if char_count + esc_chars > MAX_CEF_HEADER_CHARS
                || out.len() + escaped.len() > MAX_CEF_HEADER_CHARS
            {
                break;
            }
            out.push_str(escaped);
            char_count += esc_chars;
        }
        out
    }

    /// Escapes CEF extension key-value values (`dvchost`, `cs1`, `cs2`, `cs3`, `fileHash`, `act`, `msg`):
    /// - `\` -> `\\`
    /// - `=` -> `\=`
    /// - `\n` -> `\n` (literal two-character escape)
    /// - `\r` -> `\r` (literal two-character escape)
    /// - Caps value length at 1,023 characters (`MAX_CEF_EXT_CHARS`, `Row 165`, `BUG-CORE-09`).
    pub fn escape_cef_ext(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len().min(MAX_CEF_EXT_CHARS));
        let mut char_count = 0usize;
        for c in raw.chars() {
            let escaped = match c {
                '\\' => "\\\\",
                '=' => "\\=",
                '\n' => "\\n",
                '\r' => "\\r",
                _ => {
                    if char_count + 1 > MAX_CEF_EXT_CHARS
                        || out.len() + c.len_utf8() > MAX_CEF_EXT_CHARS
                    {
                        break;
                    }
                    out.push(c);
                    char_count += 1;
                    continue;
                }
            };
            let esc_chars = escaped.chars().count();
            if char_count + esc_chars > MAX_CEF_EXT_CHARS
                || out.len() + escaped.len() > MAX_CEF_EXT_CHARS
            {
                break;
            }
            out.push_str(escaped);
            char_count += esc_chars;
        }
        out
    }

    pub fn format_cef_payload(&self, event: &FalconTelemetryEvent) -> String {
        let timestamp = Utc::now().to_rfc3339();
        let sha_val = event.file_sha256.as_deref().unwrap_or("N/A");

        let safe_sig_id = Self::escape_cef_header(&event.signature_id);
        let safe_name = Self::escape_cef_header(&event.name);
        let safe_sev = event.severity.min(10);

        let safe_vid = Self::escape_cef_ext(&event.device_vendor_id);
        let safe_pid = Self::escape_cef_ext(&event.device_product_id);
        let safe_sn = Self::escape_cef_ext(&event.serial_number);
        let safe_sha = Self::escape_cef_ext(sha_val);
        let safe_act = Self::escape_cef_ext(&event.action_taken);
        let safe_msg = Self::escape_cef_ext(&event.details);

        format!(
            "CEF:0|OmniConnect|Sentinel|0.1.0|{safe_sig_id}|{safe_name}|{safe_sev}|rt={timestamp} cs1Label=VendorID cs1={safe_vid} cs2Label=ProductID cs2={safe_pid} cs3Label=SerialNumber cs3={safe_sn} fileHash={safe_sha} act={safe_act} msg={safe_msg}"
        )
    }

    /// Emits a CEF alert to the SIEM endpoint over RFC 5425 TLS 1.3, spools securely in `siem_spool.sealed`
    /// when offline (`CSE-13`, `T33`), enforces 180-day retention, and appends to the unified `AuditLedger`.
    pub fn emit_alert(&self, event: &FalconTelemetryEvent) -> Result<(), String> {
        let now = Utc::now();
        let cef_line = self.format_cef_payload(event);
        info!("SIEM CEF Telemetry: {}", cef_line);

        let mut delivered = false;
        if !self.syslog_endpoint.trim().is_empty()
            && !self.syslog_endpoint.starts_with("offline://")
        {
            match self.send_rfc5425_syslog(&cef_line) {
                Ok(()) => {
                    delivered = true;
                }
                Err(e) => {
                    warn!(
                        "RFC 5425 TLS syslog transmit to {} deferred ({}); buffering in encrypted on-disk SIEM spool",
                        self.syslog_endpoint, e
                    );
                }
            }
        }

        let record = SiemSpoolRecord {
            timestamp_unix: now.timestamp(),
            timestamp_rfc3339: now.to_rfc3339(),
            cef_payload: cef_line.clone(),
            delivered,
        };
        self.append_spool_record(&record)?;
        let _ = self.prune_expired_records(SIEM_RETENTION_DAYS);

        let alert_data = serde_json::json!({
            "signature_id": event.signature_id,
            "severity": event.severity,
            "action_taken": event.action_taken,
            "delivered_immediately": delivered,
            "spool_path": self.spool_path.to_string_lossy(),
        });
        self.record_audit_event("SIEM_CEF_ALERT", alert_data);

        Ok(())
    }

    /// Emits a periodic 60-second WORM head checkpoint into the unified `AuditLedger` (`CSE-13`).
    pub fn emit_worm_checkpoint(&self) -> Result<String, String> {
        if let Some(shared) = &self.shared_ledger {
            if let Ok(mut guard) = shared.lock() {
                let head = guard.emit_worm_checkpoint()?;
                return Ok(head.head_hash);
            }
        }
        let mut ledger = AuditLedger::open(&self.ledger_path);
        let head = ledger.emit_worm_checkpoint()?;
        Ok(head.head_hash)
    }

    fn record_audit_event(&self, event: &str, data: serde_json::Value) {
        if let Some(shared) = &self.shared_ledger {
            if let Ok(mut guard) = shared.lock() {
                let _ =
                    guard.append_subsystem_event(AuditSubsystem::SiemFalcon, event, data.clone());
                return;
            }
        }
        let mut ledger = AuditLedger::open(&self.ledger_path);
        let _ = ledger.append_subsystem_event(AuditSubsystem::SiemFalcon, event, data);
    }

    /// Sends a CEF message over RFC 5425 TLS 1.3 octet-counted framing (`CSE-13`, `T33`).
    pub fn send_rfc5425_syslog(&self, cef_line: &str) -> Result<(), String> {
        let endpoint = &self.syslog_endpoint;
        let cleaned = endpoint
            .strip_prefix("tls://")
            .or_else(|| endpoint.strip_prefix("syslog+tls://"))
            .unwrap_or(endpoint);

        let (host, port) = if let Some((h, p)) = cleaned.split_once(':') {
            let parsed_port: u16 = p
                .parse()
                .map_err(|e| format!("Invalid port in endpoint: {e}"))?;
            (h, parsed_port)
        } else {
            (cleaned, 6514)
        };

        let target_addrs: Vec<SocketAddr> = format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|e| format!("Failed resolving SIEM host '{host}:{port}': {e}"))?
            .collect();

        if target_addrs.is_empty() {
            return Err(format!(
                "DNS resolution returned 0 addresses for '{host}:{port}'"
            ));
        }

        if !self.allow_loopback_for_testing {
            for addr in &target_addrs {
                crate::scanner::tier3_sandbox::validate_egress_ip(addr.ip())?;
            }
        }

        let validated_addr = target_addrs[0];
        let mut tcp_stream =
            TcpStream::connect_timeout(&validated_addr, Duration::from_millis(1500))
                .map_err(|e| format!("SIEM endpoint unreachable at {validated_addr}: {e}"))?;
        let _ = tcp_stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = tcp_stream.set_write_timeout(Some(Duration::from_secs(5)));

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca) = &self.custom_ca_cert_pem {
            use rustls_pki_types::pem::PemObject;
            for c in rustls_pki_types::CertificateDer::pem_slice_iter(ca).flatten() {
                let _ = root_store.add(c);
            }
        }

        let client_config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth();

        let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| format!("Invalid DNS SNI for SIEM host '{host}': {e}"))?;

        let mut conn = rustls::ClientConnection::new(Arc::new(client_config), server_name)
            .map_err(|e| format!("TLS client connection init failed: {e}"))?;

        let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp_stream);

        // RFC 5425 octet-counted framing: <MSG-LEN> <SYSLOG-MSG>\n
        let framed = format!("{} {}\n", cef_line.len(), cef_line);
        tls_stream
            .write_all(framed.as_bytes())
            .map_err(|e| format!("Failed transmitting RFC 5425 TLS syslog: {e}"))?;
        tls_stream
            .flush()
            .map_err(|e| format!("TLS flush failed: {e}"))?;

        Ok(())
    }

    fn derive_spool_cipher() -> Result<Aes256Gcm, String> {
        let mut hasher = Sha256::new();
        hasher.update(SPOOL_KDF_SALT);
        #[cfg(windows)]
        if let Ok(sn) = std::env::var("COMPUTERNAME") {
            hasher.update(sn.as_bytes());
        }
        #[cfg(not(windows))]
        if let Ok(hn) = std::env::var("HOSTNAME") {
            hasher.update(hn.as_bytes());
        }
        let key = hasher.finalize();
        Aes256Gcm::new_from_slice(&key)
            .map_err(|e| format!("Failed initializing AES-256-GCM cipher: {e}"))
    }

    /// Appends a single `SiemSpoolRecord` to the AEAD-encrypted on-disk SIEM spool (`Row 169`, `CSE-13`).
    pub fn append_spool_record(&self, record: &SiemSpoolRecord) -> Result<(), String> {
        let mut records = self.read_spool_records().unwrap_or_default();
        records.push(record.clone());
        self.write_spool_records(&records)
    }

    /// Reads all records currently stored in the AEAD-encrypted on-disk SIEM spool.
    pub fn read_spool_records(&self) -> Result<Vec<SiemSpoolRecord>, String> {
        if !self.spool_path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read(&self.spool_path).map_err(|e| {
            format!(
                "Failed reading SIEM spool '{}': {}",
                self.spool_path.display(),
                e
            )
        })?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        if raw.len() < 12 {
            return Err("Corrupted SIEM spool: header truncated".to_string());
        }
        let (nonce_bytes, ciphertext) = raw.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Self::derive_spool_cipher()?;
        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("SIEM spool AEAD authentication failed: {e}"))?;
        serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Corrupt SIEM spool JSON after decryption: {e}"))
    }

    /// Flushes undelivered (`delivered == false`) SIEM records over RFC 5425 TLS 1.3
    /// and updates the encrypted spool on disk (`Row 169`, `CSE-13`).
    pub fn flush_spool(&self) -> Result<usize, String> {
        if !self.spool_path.exists() {
            return Ok(0);
        }
        let mut records = self.read_spool_records()?;
        let mut newly_delivered = 0usize;

        if !self.syslog_endpoint.trim().is_empty()
            && !self.syslog_endpoint.starts_with("offline://")
        {
            for rec in &mut records {
                if !rec.delivered && self.send_rfc5425_syslog(&rec.cef_payload).is_ok() {
                    rec.delivered = true;
                    newly_delivered += 1;
                }
            }
        }

        self.write_spool_records(&records)?;
        Ok(newly_delivered)
    }

    /// Prunes SIEM spool records older than `retention_days` (default 180 days per CERT-In / NIST `AU-9`/`AU-10`) (`Row 169`).
    pub fn prune_expired_records(&self, retention_days: i64) -> Result<usize, String> {
        if !self.spool_path.exists() {
            return Ok(0);
        }
        let cutoff_unix = Utc::now().timestamp() - (retention_days.max(1) * 86_400);
        let records = self.read_spool_records()?;
        let initial_len = records.len();
        let retained: Vec<SiemSpoolRecord> = records
            .into_iter()
            .filter(|r| r.timestamp_unix >= cutoff_unix)
            .collect();
        let pruned_count = initial_len.saturating_sub(retained.len());
        if pruned_count > 0 {
            self.write_spool_records(&retained)?;
        }
        Ok(pruned_count)
    }

    fn write_spool_records(&self, records: &[SiemSpoolRecord]) -> Result<(), String> {
        // Enforce 128 MiB bounding: drop oldest records if serialized payload exceeds capacity
        let mut retained = records.to_vec();
        let mut serialized = serde_json::to_vec(&retained)
            .map_err(|e| format!("Failed serializing SIEM spool records: {e}"))?;

        while serialized.len() as u64 > MAX_SPOOL_SIZE_BYTES && retained.len() > 1 {
            retained.remove(0);
            serialized = serde_json::to_vec(&retained)
                .map_err(|e| format!("Failed serializing pruned SIEM spool records: {e}"))?;
        }

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Self::derive_spool_cipher()?;
        let ciphertext = cipher
            .encrypt(nonce, serialized.as_slice())
            .map_err(|e| format!("Failed AEAD-encrypting SIEM spool: {e}"))?;

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        create_restricted_file_atomic(&self.spool_path, &output).map_err(|e| {
            format!(
                "Failed writing encrypted SIEM spool '{}': {e}",
                self.spool_path.display()
            )
        })?;

        if let Some(parent) = self.spool_path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = sync_directory(parent);
            }
        }
        Ok(())
    }
}

fn default_siem_spool_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(pd) = std::env::var("ProgramData") {
            let candidate = PathBuf::from(pd)
                .join("OmniConnect")
                .join("Sentinel")
                .join("SiemSpool");
            if create_restricted_dir_atomic(&candidate).is_ok() {
                return candidate;
            }
        }
        if let Ok(lad) = std::env::var("LOCALAPPDATA") {
            let candidate = PathBuf::from(lad)
                .join("OmniConnect")
                .join("Sentinel")
                .join("SiemSpool");
            if create_restricted_dir_atomic(&candidate).is_ok() {
                return candidate;
            }
        }
    }
    #[cfg(not(windows))]
    {
        let candidate = PathBuf::from("/var/lib/omniconnect/siem_spool");
        if create_restricted_dir_atomic(&candidate).is_ok() {
            return candidate;
        }
        if let Ok(home) = std::env::var("HOME") {
            let candidate = PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("omniconnect")
                .join("siem_spool");
            if create_restricted_dir_atomic(&candidate).is_ok() {
                return candidate;
            }
        }
    }
    #[cfg(test)]
    {
        std::env::temp_dir().join("omniconnect_sentinel_siem")
    }
    #[cfg(not(test))]
    {
        if let Ok(cwd) = std::env::current_dir() {
            let dir = cwd.join(".sentinel_audit");
            if create_restricted_dir_atomic(&dir).is_ok() {
                return dir;
            }
        }
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\ProgramData\OmniConnect\Sentinel\SiemSpool")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/var/lib/omniconnect/siem_spool")
        }
    }
}
