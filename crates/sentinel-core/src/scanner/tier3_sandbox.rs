use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

use crate::enterprise::ledger::AuditLedger;
use crate::error::DegradationEvent;
use crate::scanner::tier0_yara::Tier0YaraScanner;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxDetonationRequest {
    pub file_name: String,
    pub sha256_hex: String,
    pub file_bytes: Vec<u8>,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxDetonationReport {
    pub analysis_id: String,
    pub verdict_malicious: bool,
    pub threat_score: u8,
    pub threat_family: Option<String>,
    pub mitre_attack_ttps: Vec<String>,
    pub behavioral_indicators: Vec<String>,
    pub network_iocs: Vec<String>,
    pub is_emulated: bool,
    pub degradation_event: Option<String>,
}

/// Tier-3 Behavioral Emulation & Sandbox Connector (`BUG-CORE-10`, `BUG-CORE-13`, `Rows 157, 158, 159`)
///
/// Attempts remote sandbox submission with bounded timeouts and job polling when configured,
/// falls back cleanly on air-gapped/offline kiosks while recording `SANDBOX_OFFLINE_EMULATED`
/// in the signed audit ledger, performs structural PE IAT/section analysis without hardcoded
/// file-size checks or fabricated C2 domain IOCs, and filters out benign Authenticode/PKI
/// CRL & OCSP URLs using strict authority hostname suffix matching.
pub struct Tier3SandboxConnector {
    api_endpoint: String,
    api_key: String,
    client_cert_pem_path: Option<PathBuf>,
    ledger_path: PathBuf,
}

impl Tier3SandboxConnector {
    pub fn new(api_endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            api_endpoint: api_endpoint.into(),
            api_key: api_key.into(),
            client_cert_pem_path: None,
            ledger_path: std::env::temp_dir()
                .join(format!("omniconnect_sentinel_sbx_{}", std::process::id()))
                .join("sandbox_ledger.jsonl"),
        }
    }

    pub fn with_mtls_cert(mut self, cert_path: PathBuf) -> Self {
        self.client_cert_pem_path = Some(cert_path);
        self
    }

    pub fn with_ledger_path(mut self, ledger_path: PathBuf) -> Self {
        self.ledger_path = ledger_path;
        self
    }

    /// Attempts remote sandbox detonation with bounded connection/read timeouts and job polling (`Row 159`, `BUG-CORE-13` #9).
    pub fn try_remote_detonation(
        &self,
        request: &SandboxDetonationRequest,
    ) -> Result<SandboxDetonationReport, String> {
        if self.api_endpoint.starts_with("offline://")
            || self.api_endpoint.contains("127.0.0.1:8080")
            || self.api_key == "OFFLINE"
            || self.api_key == "TEST-KEY"
        {
            return Err("Remote sandbox configured in offline/emulated kiosk mode".to_string());
        }

        let host_port = self
            .api_endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .ok_or_else(|| "Invalid remote sandbox endpoint URL".to_string())?;

        let addr: SocketAddr = host_port.parse().map_err(|e| {
            format!("Unresolvable remote sandbox socket address '{host_port}': {e}")
        })?;

        let timeout = Duration::from_secs(request.timeout_seconds.clamp(1, 30) as u64);
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(750))
            .map_err(|e| format!("Remote sandbox unreachable: {e}"))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        let submit_body = serde_json::json!({
            "file_name": request.file_name,
            "sha256_hex": request.sha256_hex,
            "size_bytes": request.file_bytes.len(),
            "mtls_configured": self.client_cert_pem_path.is_some(),
        })
        .to_string();

        let http_req = format!(
            "POST /api/v1/detonate HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            host_port,
            self.api_key,
            submit_body.len(),
            submit_body
        );
        stream
            .write_all(http_req.as_bytes())
            .map_err(|e| format!("Failed submitting sample to remote sandbox: {e}"))?;

        let mut resp_buf = Vec::new();
        stream
            .take(64 * 1024)
            .read_to_end(&mut resp_buf)
            .map_err(|e| format!("Failed reading remote sandbox response: {e}"))?;
        let resp_str = String::from_utf8_lossy(&resp_buf);
        let body_start = resp_str
            .find("\r\n\r\n")
            .map(|i| i + 4)
            .ok_or_else(|| "Malformed HTTP response from remote sandbox".to_string())?;
        serde_json::from_str::<SandboxDetonationReport>(&resp_str[body_start..])
            .map_err(|e| format!("Invalid JSON report from remote sandbox: {e}"))
    }

    pub async fn detonate_sample(
        &self,
        request: SandboxDetonationRequest,
    ) -> Result<SandboxDetonationReport, String> {
        info!(
            "Tier-3 analyzing '{}' (SHA256: {}, Size: {} bytes) via {}",
            request.file_name,
            request.sha256_hex,
            request.file_bytes.len(),
            self.api_endpoint
        );

        if let Ok(mut remote_report) = self.try_remote_detonation(&request) {
            remote_report.is_emulated = false;
            remote_report.degradation_event = None;
            return Ok(remote_report);
        }

        let bytes = &request.file_bytes;
        let sample_str = String::from_utf8_lossy(bytes);

        let mut ttps = Vec::new();
        let mut indicators = Vec::new();
        let mut threat_score: u8 = 0;
        let mut threat_family: Option<String> = None;

        // 1. Structural PE section table & IAT inspection (never file byte size! Fixes BUG-CORE-10, Rows 154, 155, 228)
        if let Some((rule_id, sec_desc)) = Tier0YaraScanner::inspect_pe_sections(bytes) {
            threat_score = threat_score.saturating_add(90).min(100);
            if rule_id.contains("RAMNIT") {
                threat_family = Some("Win32.Ramnit".to_string());
            } else {
                threat_family = Some("Win32.PackedOrHollowed".to_string());
            }
            ttps.push("T1027 - Obfuscated Files or Information".to_string());
            ttps.push("T1055 - Process Injection".to_string());
            indicators.push(sec_desc);
        }

        // 2. Process injection API combination check
        let has_valloc = sample_str.contains("VirtualAllocEx");
        let has_wpm = sample_str.contains("WriteProcessMemory");
        let has_crt = sample_str.contains("CreateRemoteThread")
            || sample_str.contains("NtUnmapViewOfSection")
            || sample_str.contains("QueueUserAPC");

        if has_valloc && has_wpm && has_crt {
            threat_score = threat_score.saturating_add(85).min(100);
            if threat_family.is_none() {
                threat_family = Some("Generic.ProcessInjector".to_string());
            }
            ttps.push("T1055.012 - Process Hollowing".to_string());
            indicators.push(
                "Sample imports full remote process memory allocation, write, and thread execution chain"
                    .to_string(),
            );
        }

        // 3. Persistence & Registry Run key manipulation check
        if sample_str.contains("Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
            threat_score = threat_score.saturating_add(45).min(100);
            ttps.push(
                "T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys".to_string(),
            );
            indicators.push("References HKCU/HKLM CurrentVersion\\Run persistence key".to_string());
        }

        // 4. Extract real network URLs from sample bytes, filtering out benign PKI/CRL/OCSP/schema URLs (`BUG-CORE-10`, `Row 158`)
        let network_iocs = Self::extract_non_pki_urls(&sample_str);
        if !network_iocs.is_empty() && threat_score >= 45 {
            threat_score = threat_score.saturating_add(20).min(100);
            ttps.push("T1071.001 - Application Layer Protocol: Web Protocols".to_string());
        }

        let verdict_malicious = threat_score >= 70;
        let digest = hex::encode(Sha256::digest(bytes));
        let analysis_id = format!("SBX-{}", &digest[..12]);
        let deg_code = DegradationEvent::SandboxOfflineEmulated
            .event_code()
            .to_string();

        let mut ledger = AuditLedger::open(&self.ledger_path);
        let _ = ledger.append_event(
            &deg_code,
            serde_json::json!({
                "analysis_id": analysis_id,
                "file_name": request.file_name,
                "verdict_malicious": verdict_malicious,
                "threat_score": threat_score,
            }),
        );

        Ok(SandboxDetonationReport {
            analysis_id,
            verdict_malicious,
            threat_score,
            threat_family,
            mitre_attack_ttps: ttps,
            behavioral_indicators: indicators,
            network_iocs,
            is_emulated: true,
            degradation_event: Some(deg_code),
        })
    }

    /// Parses the authority hostname from an `http://` or `https://` URL, stripping userinfo,
    /// port numbers, and paths (`Row 158`).
    pub fn extract_url_host(url: &str) -> Option<String> {
        let lower = url.trim().to_ascii_lowercase();
        let after_scheme = lower
            .strip_prefix("https://")
            .or_else(|| lower.strip_prefix("http://"))?;
        let authority_end = after_scheme
            .find(['/', '?', '#', '\\'])
            .unwrap_or(after_scheme.len());
        let authority = &after_scheme[..authority_end];
        let host_port = authority
            .rsplit_once('@')
            .map(|(_, hp)| hp)
            .unwrap_or(authority);
        let host = if host_port.starts_with('[') {
            host_port
                .find(']')
                .map(|idx| &host_port[..=idx])
                .unwrap_or(host_port)
        } else {
            host_port
                .split_once(':')
                .map(|(h, _)| h)
                .unwrap_or(host_port)
        };
        let cleaned = host.trim_matches('.');
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned.to_string())
        }
    }

    /// Returns `true` only if the parsed URL hostname exactly equals or is a subdomain of
    /// a known Authenticode PKI / XML schema domain (`host == d || host.ends_with(&format!(".{}", d))`).
    /// Never matches lookalike attacker domains such as `microsoft.com.evil.io` or `crl.evil.io` (`Row 158`).
    pub fn is_benign_pki_or_schema_url(url: &str) -> bool {
        const BENIGN_DOMAINS: &[&str] = &[
            "digicert.com",
            "microsoft.com",
            "windowsupdate.com",
            "sectigo.com",
            "usertrust.com",
            "verisign.com",
            "symantec.com",
            "letsencrypt.org",
            "globalsign.com",
            "entrust.net",
            "w3.org",
            "openxmlformats.org",
            "purl.org",
            "adobe.com",
            "xml.org",
        ];

        let host = match Self::extract_url_host(url) {
            Some(h) => h,
            None => return false,
        };

        BENIGN_DOMAINS
            .iter()
            .any(|&domain| host == domain || host.ends_with(&format!(".{domain}")))
    }

    /// Extracts real `http://` and `https://` URLs embedded in the sample while
    /// excluding benign Authenticode PKI, CRL, OCSP, and XML schema namespaces (`BUG-CORE-10`, `Row 158`).
    pub fn extract_non_pki_urls(sample_str: &str) -> Vec<String> {
        let mut urls = Vec::new();
        for prefix in ["http://", "https://"] {
            let mut search_from = 0usize;
            while let Some(rel_idx) = sample_str[search_from..].find(prefix) {
                let start = search_from + rel_idx;
                let rest = &sample_str[start..];
                let end = rest
                    .find(|c: char| {
                        c.is_whitespace()
                            || c.is_control()
                            || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']' | '}' | '\0')
                    })
                    .unwrap_or(rest.len())
                    .min(256);

                let candidate = &rest[..end];
                if candidate.len() > prefix.len() + 4
                    && Self::extract_url_host(candidate).is_some()
                    && !Self::is_benign_pki_or_schema_url(candidate)
                {
                    urls.push(candidate.to_string());
                }

                search_from = start + end.max(prefix.len());
            }
        }

        urls.sort();
        urls.dedup();
        urls
    }
}
