use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use sentinel_sys::{apply_system_admin_dacl, sync_directory};

use crate::enterprise::ledger::AuditLedger;

/// Minimum CERT-In and NIST SP 800-53 `AU-9` / `AU-10` retention window (180 days).
pub const SIEM_RETENTION_DAYS: i64 = 180;
/// Maximum CEF header field length (`signature_id`, `name`) per ArcSight CEF v0 (`Row 165`).
pub const MAX_CEF_HEADER_CHARS: usize = 255;
/// Maximum CEF extension value length per ArcSight CEF v0 (`Row 165`, `BUG-CORE-09`).
pub const MAX_CEF_EXT_CHARS: usize = 1023;

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

/// CrowdStrike Falcon & SIEM CEF Syslog Bridge (`BUG-CORE-09`, `Rows 23, 165, 169`, Phase 4.1 & 4.2)
///
/// Implements strict ArcSight Common Event Format (CEF v0) header (255-char cap) and extension
/// (1,023-char cap) escaping so attacker-controlled USB descriptor strings or filenames containing
/// `\n`, `\r`, `|`, `=`, or `\` cannot forge SIEM events. Buffers events on disk while offline
/// with a 180-day retention archive and records every alert in the signed `AuditLedger`.
pub struct CrowdStrikeFalconBridge {
    syslog_endpoint: String,
    spool_path: PathBuf,
    ledger_path: PathBuf,
}

impl CrowdStrikeFalconBridge {
    pub fn new(syslog_endpoint: impl Into<String>) -> Self {
        let base_dir = default_siem_spool_dir();
        let spool_path = base_dir.join("siem_spool.jsonl");
        let ledger_path = base_dir.join("siem_audit_ledger_v2.jsonl");
        Self {
            syslog_endpoint: syslog_endpoint.into(),
            spool_path,
            ledger_path,
        }
    }

    pub fn with_spool_path(syslog_endpoint: impl Into<String>, spool_path: PathBuf) -> Self {
        let ledger_path = spool_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("siem_audit_ledger_v2.jsonl");
        Self {
            syslog_endpoint: syslog_endpoint.into(),
            spool_path,
            ledger_path,
        }
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
            "CEF:0|OmniConnect|Sentinel|0.1.0|{}|{}|{}|rt={} cs1Label=VendorID cs1={} cs2Label=ProductID cs2={} cs3Label=SerialNumber cs3={} fileHash={} act={} msg={}",
            safe_sig_id,
            safe_name,
            safe_sev,
            timestamp,
            safe_vid,
            safe_pid,
            safe_sn,
            safe_sha,
            safe_act,
            safe_msg
        )
    }

    /// Emits a CEF alert to the SIEM endpoint, spools on disk when UDP transmission fails or is
    /// offline (`Row 169`), enforces 180-day retention, and appends a signed record to `AuditLedger` (`Row 23`).
    pub fn emit_alert(&self, event: &FalconTelemetryEvent) -> Result<(), String> {
        let now = Utc::now();
        let cef_line = self.format_cef_payload(event);
        info!("SIEM CEF Telemetry: {}", cef_line);

        let mut delivered = false;
        if !self.syslog_endpoint.trim().is_empty()
            && !self.syslog_endpoint.starts_with("offline://")
        {
            if let Ok(socket) = UdpSocket::bind("127.0.0.1:0") {
                match socket.send_to(cef_line.as_bytes(), &self.syslog_endpoint) {
                    Ok(sent) if sent == cef_line.len() => {
                        delivered = true;
                    }
                    Ok(_) => {
                        warn!(
                            "Partial UDP syslog transmit to {}; buffering in on-disk SIEM spool",
                            self.syslog_endpoint
                        );
                    }
                    Err(e) => {
                        warn!(
                            "UDP syslog transmit to {} deferred ({}); buffering in on-disk SIEM spool",
                            self.syslog_endpoint, e
                        );
                    }
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

        let mut ledger = AuditLedger::open(&self.ledger_path);
        ledger.append_event(
            "SIEM_CEF_ALERT",
            serde_json::json!({
                "signature_id": event.signature_id,
                "severity": event.severity,
                "action_taken": event.action_taken,
                "delivered_immediately": delivered,
                "spool_path": self.spool_path.to_string_lossy(),
            }),
        )?;

        Ok(())
    }

    /// Appends a single `SiemSpoolRecord` to the DACL-protected on-disk SIEM spool (`Row 169`).
    pub fn append_spool_record(&self, record: &SiemSpoolRecord) -> Result<(), String> {
        if let Some(parent) = self.spool_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "Failed creating SIEM spool directory '{}': {}",
                        parent.display(),
                        e
                    )
                })?;
                apply_system_admin_dacl(parent).map_err(|e| {
                    format!("Failed applying SYSTEM/Admin DACL to SIEM spool dir: {}", e)
                })?;
            }
        }

        let is_new = !self.spool_path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.spool_path)
            .map_err(|e| {
                format!(
                    "Failed opening SIEM spool '{}': {}",
                    self.spool_path.display(),
                    e
                )
            })?;
        if is_new {
            apply_system_admin_dacl(&self.spool_path).map_err(|e| {
                format!(
                    "Failed applying SYSTEM/Admin DACL to SIEM spool file: {}",
                    e
                )
            })?;
        }

        let mut line = serde_json::to_string(record)
            .map_err(|e| format!("Failed serializing SIEM spool record: {}", e))?;
        line.push('\n');
        file.write_all(line.as_bytes())
            .map_err(|e| format!("Failed writing SIEM spool record: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("Failed fsyncing SIEM spool record: {}", e))?;
        drop(file);

        if let Some(parent) = self.spool_path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = sync_directory(parent);
            }
        }
        Ok(())
    }

    /// Reads all records currently stored in the on-disk SIEM spool.
    pub fn read_spool_records(&self) -> Result<Vec<SiemSpoolRecord>, String> {
        if !self.spool_path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&self.spool_path).map_err(|e| {
            format!(
                "Failed opening SIEM spool '{}': {}",
                self.spool_path.display(),
                e
            )
        })?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res
                .map_err(|e| format!("Error reading SIEM spool line {}: {}", idx + 1, e))?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: SiemSpoolRecord = serde_json::from_str(&line)
                .map_err(|e| format!("Corrupt SIEM spool record at line {}: {}", idx + 1, e))?;
            records.push(rec);
        }
        Ok(records)
    }

    /// Flushes undelivered (`delivered == false`) SIEM records over UDP and updates the spool on disk (`Row 169`).
    pub fn flush_spool(&self) -> Result<usize, String> {
        if !self.spool_path.exists() {
            return Ok(0);
        }
        let mut records = self.read_spool_records()?;
        let mut newly_delivered = 0usize;

        if !self.syslog_endpoint.trim().is_empty()
            && !self.syslog_endpoint.starts_with("offline://")
        {
            if let Ok(socket) = UdpSocket::bind("127.0.0.1:0") {
                for rec in &mut records {
                    if !rec.delivered {
                        if let Ok(sent) =
                            socket.send_to(rec.cef_payload.as_bytes(), &self.syslog_endpoint)
                        {
                            if sent == rec.cef_payload.len() {
                                rec.delivered = true;
                                newly_delivered += 1;
                            }
                        }
                    }
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
        let tmp_path = self.spool_path.with_extension("jsonl.tmp");
        {
            let mut tmp_file = fs::File::create(&tmp_path).map_err(|e| {
                format!(
                    "Failed creating temp SIEM spool '{}': {}",
                    tmp_path.display(),
                    e
                )
            })?;
            for rec in records {
                let mut line = serde_json::to_string(rec)
                    .map_err(|e| format!("Failed serializing SIEM spool record: {}", e))?;
                line.push('\n');
                tmp_file
                    .write_all(line.as_bytes())
                    .map_err(|e| format!("Failed writing temp SIEM spool: {}", e))?;
            }
            tmp_file
                .sync_all()
                .map_err(|e| format!("Failed syncing temp SIEM spool: {}", e))?;
        }
        fs::rename(&tmp_path, &self.spool_path)
            .map_err(|e| format!("Failed renaming temp SIEM spool: {}", e))?;
        apply_system_admin_dacl(&self.spool_path)
            .map_err(|e| format!("Failed applying SYSTEM/Admin DACL to SIEM spool: {}", e))?;
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
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        let candidate = PathBuf::from(pd)
            .join("OmniConnect")
            .join("Sentinel")
            .join("SiemSpool");
        if fs::create_dir_all(&candidate).is_ok() {
            return candidate;
        }
    }
    std::env::temp_dir().join("omniconnect_sentinel_siem")
}
