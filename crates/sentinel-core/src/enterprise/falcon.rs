use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

use sentinel_sys::{
    create_restricted_dir_atomic, create_restricted_file_atomic,
    create_restricted_file_handle_atomic, ensure_not_symlink_or_reparse_point, seal_key_bytes,
    sync_directory, unseal_key_bytes, write_protected_key_file, zeroize_slice, SealedKeyBlob,
    ZeroizingBytes,
};

use crate::enterprise::ledger::{
    tokenize_path_for_ledger, AuditLedger, AuditSubsystem, SharedAuditLedger,
};

/// Minimum CERT-In and NIST SP 800-53 `AU-9` / `AU-10` retention window (180 days).
pub const SIEM_RETENTION_DAYS: i64 = 180;
/// Maximum CEF header field length (`signature_id`, `name`) per ArcSight CEF v0 (`Row 165`).
pub const MAX_CEF_HEADER_CHARS: usize = 255;
/// Maximum CEF extension value length per ArcSight CEF v0 (`Row 165`, `BUG-CORE-09`).
pub const MAX_CEF_EXT_CHARS: usize = 1023;
/// Maximum sealed SIEM spool size on disk (128 MiB, `CSE-13`).
pub const MAX_SPOOL_SIZE_BYTES: u64 = 128 * 1024 * 1024;

const SIEM_SPOOL_MAGIC_V2: &[u8; 8] = b"OCSIEM2\0";
static SIEM_SPOOL_IO_LOCK: Mutex<()> = Mutex::new(());

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
        if let Ok(guard) = shared_ledger.lock() {
            self.ledger_path = guard.path().to_path_buf();
        }
        self.shared_ledger = Some(shared_ledger);
        self
    }

    pub fn with_ledger_path(mut self, ledger_path: PathBuf) -> Self {
        self.ledger_path = ledger_path;
        self
    }

    pub fn tokenize_path(&self, raw_path: &Path) -> Result<String, String> {
        tokenize_path_for_ledger(self.shared_ledger.as_ref(), &self.ledger_path, raw_path)
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

        let spool_path_token = self
            .tokenize_path(&self.spool_path)
            .unwrap_or_else(|_| "TOKENIZATION_UNAVAILABLE".to_string());
        let alert_data = serde_json::json!({
            "signature_id": event.signature_id,
            "severity": event.severity,
            "action_taken": event.action_taken,
            "delivered_immediately": delivered,
            "spool_path_token": spool_path_token,
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

    /// Validates a SIEM syslog endpoint (`CSE-13`, `T33`), rejecting cleartext schemes, port `514`,
    /// malformed ports/paths/userinfo, and unbracketed multi-colon hosts, while supporting IPv4,
    /// DNS names, bracketed IPv6 (`tls://[2001:db8::1]:6514`), and `offline://...`.
    pub fn validate_syslog_endpoint(endpoint: &str) -> Result<(&str, u16, bool), String> {
        let trimmed = endpoint.trim();
        if trimmed.is_empty() {
            return Err("SIEM syslog endpoint must not be empty".to_string());
        }
        let lower = trimmed.to_ascii_lowercase();
        let (is_offline, rest) = if lower.starts_with("tls://") {
            (false, &trimmed["tls://".len()..])
        } else if lower.starts_with("syslog+tls://") {
            (false, &trimmed["syslog+tls://".len()..])
        } else if lower.starts_with("offline://") {
            (true, &trimmed["offline://".len()..])
        } else if trimmed.contains("://") {
            return Err(format!(
                "Cleartext or unsupported syslog transport rejected for '{trimmed}': RFC 5425 TLS 1.3 (tls:// or syslog+tls://) or offline:// is required"
            ));
        } else {
            (false, trimmed)
        };

        if rest.is_empty()
            || rest.contains("://")
            || rest.chars().any(|c| {
                c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '?' | '#' | '@')
            })
        {
            return Err(format!(
                "Malformed SIEM syslog endpoint '{trimmed}': unexpected empty host, path, query, or control character"
            ));
        }

        let (host, port) = if rest.starts_with('[') {
            let close_idx = rest.find(']').ok_or_else(|| {
                format!("Malformed bracketed IPv6 SIEM endpoint '{trimmed}': missing ']'")
            })?;
            let inner_host = &rest[1..close_idx];
            if inner_host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(format!(
                    "Invalid IPv6 address in bracketed SIEM endpoint '{trimmed}'"
                ));
            }
            let after = &rest[close_idx + 1..];
            if after.is_empty() {
                (inner_host, 6514u16)
            } else if let Some(port_str) = after.strip_prefix(':') {
                let parsed_port: u16 = port_str
                    .parse()
                    .map_err(|e| format!("Invalid port in endpoint '{trimmed}': {e}"))?;
                (inner_host, parsed_port)
            } else {
                return Err(format!(
                    "Invalid suffix after bracketed IPv6 host in SIEM endpoint '{trimmed}'"
                ));
            }
        } else {
            if rest.contains(']') {
                return Err(format!(
                    "Malformed SIEM endpoint '{trimmed}': unmatched ']'"
                ));
            }
            if let Some((h, p)) = rest.rsplit_once(':') {
                if h.is_empty() || h.contains(':') || p.is_empty() {
                    return Err(format!(
                        "Malformed SIEM endpoint '{trimmed}': use '[ipv6]' or '[ipv6]:port' for IPv6 endpoints"
                    ));
                }
                let parsed_port: u16 = p
                    .parse()
                    .map_err(|e| format!("Invalid port in endpoint '{trimmed}': {e}"))?;
                (h, parsed_port)
            } else {
                (rest, 6514u16)
            }
        };

        if port == 0 {
            return Err(format!("SIEM port 0 is invalid in endpoint '{trimmed}'"));
        }
        if port == 514 {
            return Err(
                "Legacy cleartext syslog port 514 is prohibited; RFC 5425 TLS 1.3 requires TLS port 6514"
                    .to_string(),
            );
        }

        Ok((host, port, is_offline))
    }

    /// Sends a CEF message over RFC 5425 TLS 1.3 octet-counted framing (`CSE-13`, `T33`).
    pub fn send_rfc5425_syslog(&self, cef_line: &str) -> Result<(), String> {
        let (host, port, is_offline) = Self::validate_syslog_endpoint(&self.syslog_endpoint)?;
        if is_offline {
            return Err("SIEM endpoint configured for offline:// local spooling".to_string());
        }

        let target_addrs: Vec<SocketAddr> = (host, port)
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

    pub fn spool_key_path(&self) -> PathBuf {
        let mut os = self.spool_path.as_os_str().to_os_string();
        os.push(".spool_key.sealed");
        PathBuf::from(os)
    }

    fn spool_seal_context(&self) -> String {
        format!(
            "OmniConnect-Sentinel-SIEM-Spool-Key:{}",
            self.spool_path.display()
        )
    }

    fn load_or_init_spool_dek(
        &self,
        allow_create: bool,
    ) -> Result<(ZeroizingBytes<32>, String), String> {
        if let Some(parent) = self.spool_path.parent() {
            if !parent.as_os_str().is_empty() {
                create_restricted_dir_atomic(parent).map_err(|e| {
                    format!(
                        "Failed creating restricted SIEM spool directory {}: {}",
                        parent.display(),
                        e
                    )
                })?;
            }
        }
        let key_path = self.spool_key_path();
        let context = self.spool_seal_context();

        if key_path.exists() {
            ensure_not_symlink_or_reparse_point(&key_path).map_err(|e| {
                format!(
                    "SIEM_SPOOL_KEY_INTEGRITY_FAIL: Refusing symlink/reparse key file {}: {}",
                    key_path.display(),
                    e
                )
            })?;
            let raw = fs::read(&key_path).map_err(|e| {
                format!(
                    "SIEM_SPOOL_KEY_INTEGRITY_FAIL: Failed reading sealed spool key {}: {}",
                    key_path.display(),
                    e
                )
            })?;
            let sealed: SealedKeyBlob = serde_json::from_slice(&raw).map_err(|e| {
                format!(
                    "SIEM_SPOOL_KEY_INTEGRITY_FAIL: Corrupted JSON in {}: {}",
                    key_path.display(),
                    e
                )
            })?;
            let mut unsealed = unseal_key_bytes(&sealed, context.as_bytes()).map_err(|e| {
                format!(
                    "SIEM_SPOOL_KEY_INTEGRITY_FAIL: Failed unsealing {}: {}",
                    key_path.display(),
                    e
                )
            })?;
            if unsealed.len() != 32 {
                zeroize_slice(&mut unsealed);
                return Err(format!(
                    "SIEM_SPOOL_KEY_INTEGRITY_FAIL: Unexpected spool DEK length {}",
                    unsealed.len()
                ));
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&unsealed);
            zeroize_slice(&mut unsealed);
            let dek = ZeroizingBytes::new(key_arr);
            zeroize_slice(&mut key_arr);
            return Ok((dek, sealed.kek_id));
        }

        if !allow_create
            || (self.spool_path.exists()
                && fs::metadata(&self.spool_path)
                    .map(|m| m.len() > 0)
                    .unwrap_or(true))
        {
            return Err(format!(
                "SIEM_SPOOL_KEY_INTEGRITY_FAIL: Sealed SIEM spool key '{}' is missing for existing/requested spool '{}'",
                key_path.display(),
                self.spool_path.display()
            ));
        }

        let mut fresh_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut fresh_key);
        let dek = ZeroizingBytes::new(fresh_key);
        zeroize_slice(&mut fresh_key);

        let key_id = format!(
            "SIEM-SPOOL-DEK-{}",
            hex::encode(&Sha256::digest(dek.as_slice())[..8]).to_ascii_uppercase()
        );
        let sealed = seal_key_bytes(dek.as_slice(), context.as_bytes(), &key_id)
            .map_err(|e| format!("Failed sealing SIEM spool DEK: {e}"))?;
        let json = serde_json::to_vec_pretty(&sealed)
            .map_err(|e| format!("Failed serializing sealed SIEM spool DEK: {e}"))?;
        write_protected_key_file(&key_path, &json).map_err(|e| {
            format!(
                "Failed writing protected SIEM spool key '{}': {}",
                key_path.display(),
                e
            )
        })?;
        Ok((dek, key_id))
    }

    /// Appends a single `SiemSpoolRecord` to the AEAD-encrypted on-disk SIEM spool (`Row 169`, `CSE-13`).
    pub fn append_spool_record(&self, record: &SiemSpoolRecord) -> Result<(), String> {
        let _guard = SIEM_SPOOL_IO_LOCK
            .lock()
            .map_err(|e| format!("SIEM spool lock poisoned: {e}"))?;
        let mut records = self.read_spool_records_locked()?;
        records.push(record.clone());
        self.write_spool_records_locked(&records)
    }

    /// Reads all records currently stored in the AEAD-encrypted on-disk SIEM spool.
    pub fn read_spool_records(&self) -> Result<Vec<SiemSpoolRecord>, String> {
        let _guard = SIEM_SPOOL_IO_LOCK
            .lock()
            .map_err(|e| format!("SIEM spool lock poisoned: {e}"))?;
        self.read_spool_records_locked()
    }

    fn read_spool_records_locked(&self) -> Result<Vec<SiemSpoolRecord>, String> {
        if !self.spool_path.exists() {
            return Ok(Vec::new());
        }
        ensure_not_symlink_or_reparse_point(&self.spool_path).map_err(|e| {
            format!(
                "SIEM_SPOOL_INTEGRITY_FAIL: Refusing symlink/reparse spool {}: {}",
                self.spool_path.display(),
                e
            )
        })?;
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
        if raw.len() < SIEM_SPOOL_MAGIC_V2.len() + 12 + 16 || !raw.starts_with(SIEM_SPOOL_MAGIC_V2)
        {
            return Err("Corrupted or legacy-unauthenticated SIEM spool header".to_string());
        }
        let (dek, key_id) = self.load_or_init_spool_dek(false)?;
        let payload = &raw[SIEM_SPOOL_MAGIC_V2.len()..];
        let (nonce_bytes, ciphertext) = payload.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let aad = format!("SENTINEL-SIEM-SPOOL-V2|{key_id}");
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.as_slice()));
        let mut decrypted = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|e| format!("SIEM spool AEAD authentication failed: {e}"))?;
        let parsed = serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Corrupt SIEM spool JSON after decryption: {e}"));
        zeroize_slice(&mut decrypted);
        parsed
    }

    /// Flushes undelivered (`delivered == false`) SIEM records over RFC 5425 TLS 1.3
    /// and updates the encrypted spool on disk (`Row 169`, `CSE-13`).
    pub fn flush_spool(&self) -> Result<usize, String> {
        let _guard = SIEM_SPOOL_IO_LOCK
            .lock()
            .map_err(|e| format!("SIEM spool lock poisoned: {e}"))?;
        if !self.spool_path.exists() {
            return Ok(0);
        }
        let mut records = self.read_spool_records_locked()?;
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

        self.write_spool_records_locked(&records)?;
        Ok(newly_delivered)
    }

    /// Prunes SIEM spool records older than `retention_days` (default 180 days per CERT-In / NIST `AU-9`/`AU-10`) (`Row 169`).
    pub fn prune_expired_records(&self, retention_days: i64) -> Result<usize, String> {
        let _guard = SIEM_SPOOL_IO_LOCK
            .lock()
            .map_err(|e| format!("SIEM spool lock poisoned: {e}"))?;
        if !self.spool_path.exists() {
            return Ok(0);
        }
        let cutoff_unix = Utc::now().timestamp() - (retention_days.max(1) * 86_400);
        let records = self.read_spool_records_locked()?;
        let initial_len = records.len();
        let retained: Vec<SiemSpoolRecord> = records
            .into_iter()
            .filter(|r| r.timestamp_unix >= cutoff_unix)
            .collect();
        let pruned_count = initial_len.saturating_sub(retained.len());
        if pruned_count > 0 {
            self.write_spool_records_locked(&retained)?;
        }
        Ok(pruned_count)
    }

    fn write_spool_records_locked(&self, records: &[SiemSpoolRecord]) -> Result<(), String> {
        if self.spool_path.exists() {
            ensure_not_symlink_or_reparse_point(&self.spool_path).map_err(|e| {
                format!(
                    "SIEM_SPOOL_INTEGRITY_FAIL: Refusing symlink/reparse spool {}: {}",
                    self.spool_path.display(),
                    e
                )
            })?;
        }
        // Enforce 128 MiB bounding: drop oldest records if serialized payload exceeds capacity
        let mut retained = records.to_vec();
        let mut serialized = serde_json::to_vec(&retained)
            .map_err(|e| format!("Failed serializing SIEM spool records: {e}"))?;

        while serialized.len() as u64 > MAX_SPOOL_SIZE_BYTES && retained.len() > 1 {
            retained.remove(0);
            zeroize_slice(&mut serialized);
            serialized = serde_json::to_vec(&retained)
                .map_err(|e| format!("Failed serializing pruned SIEM spool records: {e}"))?;
        }

        let (dek, key_id) = self.load_or_init_spool_dek(true)?;
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = format!("SENTINEL-SIEM-SPOOL-V2|{key_id}");
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.as_slice()));
        let ciphertext_res = cipher.encrypt(
            nonce,
            Payload {
                msg: serialized.as_slice(),
                aad: aad.as_bytes(),
            },
        );
        zeroize_slice(&mut serialized);
        let ciphertext =
            ciphertext_res.map_err(|e| format!("Failed AEAD-encrypting SIEM spool: {e}"))?;

        let mut output = Vec::with_capacity(SIEM_SPOOL_MAGIC_V2.len() + 12 + ciphertext.len());
        output.extend_from_slice(SIEM_SPOOL_MAGIC_V2);
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

fn is_siem_spool_dir_writable(dir: &Path) -> bool {
    if create_restricted_dir_atomic(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(
        ".sentinel_spool_probe_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    match create_restricted_file_handle_atomic(&probe) {
        Ok(f) => {
            drop(f);
            let _ = fs::remove_file(&probe);
        }
        Err(_) => return false,
    }
    let spool_file = dir.join("siem_spool.sealed");
    if spool_file.exists()
        && fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&spool_file)
            .is_err()
    {
        return false;
    }
    let key_file = dir.join("siem_spool.sealed.spool_key.sealed");
    if key_file.exists() && fs::read(&key_file).is_err() {
        return false;
    }
    true
}

fn default_siem_spool_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(pd) = std::env::var("ProgramData") {
            let candidate = PathBuf::from(pd)
                .join("OmniConnect")
                .join("Sentinel")
                .join("SiemSpool");
            if is_siem_spool_dir_writable(&candidate) {
                return candidate;
            }
        }
        if let Ok(lad) = std::env::var("LOCALAPPDATA") {
            let candidate = PathBuf::from(lad)
                .join("OmniConnect")
                .join("Sentinel")
                .join("SiemSpool");
            if is_siem_spool_dir_writable(&candidate) {
                return candidate;
            }
        }
    }
    #[cfg(not(windows))]
    {
        let candidate = PathBuf::from("/var/lib/omniconnect/siem_spool");
        if is_siem_spool_dir_writable(&candidate) {
            return candidate;
        }
        if let Ok(home) = std::env::var("HOME") {
            let candidate = PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("omniconnect")
                .join("siem_spool");
            if is_siem_spool_dir_writable(&candidate) {
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
            if is_siem_spool_dir_writable(&dir) {
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
