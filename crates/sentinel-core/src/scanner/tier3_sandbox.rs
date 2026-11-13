use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use crate::enterprise::ledger::{AuditLedger, AuditSubsystem, SharedAuditLedger};
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

/// Validates that an IP address is permissible for remote sandbox egress (Anti-SSRF, `CSE-08`, `T33`).
/// Blocks loopback, RFC 1918 private, link-local, cloud metadata (`169.254.169.254`), broadcast, and multicast.
pub fn validate_egress_ip(ip: IpAddr) -> Result<(), String> {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback() {
                return Err(format!(
                    "SSRF_VIOLATION: Loopback IPv4 address '{ipv4}' is prohibited"
                ));
            }
            let oct = ipv4.octets();
            // AWS / Azure / GCP IMDS cloud metadata & link-local: 169.254.0.0/16
            if oct[0] == 169 && oct[1] == 254 || ipv4.is_link_local() {
                return Err(format!(
                    "SSRF_VIOLATION: Link-local / IMDS cloud metadata address '{ipv4}' is prohibited"
                ));
            }
            if ipv4.is_private() {
                return Err(format!(
                    "SSRF_VIOLATION: RFC 1918 private IPv4 address '{ipv4}' is prohibited"
                ));
            }
            if ipv4.is_broadcast()
                || ipv4.is_multicast()
                || ipv4.is_unspecified()
                || ipv4.is_documentation()
            {
                return Err(format!(
                    "SSRF_VIOLATION: Non-routable or multicast IPv4 address '{ipv4}' is prohibited"
                ));
            }
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() {
                return Err(format!(
                    "SSRF_VIOLATION: Loopback IPv6 address '{ipv6}' is prohibited"
                ));
            }
            if ipv6.is_multicast() || ipv6.is_unspecified() {
                return Err(format!(
                    "SSRF_VIOLATION: Non-routable or multicast IPv6 address '{ipv6}' is prohibited"
                ));
            }
            let seg = ipv6.segments();
            // IPv6 Unique Local Address: fc00::/7
            if (seg[0] & 0xfe00) == 0xfc00 {
                return Err(format!(
                    "SSRF_VIOLATION: Unique local IPv6 address '{ipv6}' is prohibited"
                ));
            }
            // IPv6 Link-Local: fe80::/10
            if (seg[0] & 0xffc0) == 0xfe80 {
                return Err(format!(
                    "SSRF_VIOLATION: Link-local IPv6 address '{ipv6}' is prohibited"
                ));
            }
            let octets = ipv6.octets();
            // 1. Standard IPv4-mapped IPv6: ::ffff:A.B.C.D
            if let Some(mapped) = ipv6.to_ipv4_mapped() {
                return validate_egress_ip(IpAddr::V4(mapped));
            }

            // 2. IPv4-compatible IPv6 (RFC 4291 §2.5.5.1): ::A.B.C.D (first 96 bits are 0)
            if octets[0..12] == [0u8; 12] && !ipv6.is_unspecified() && !ipv6.is_loopback() {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return validate_egress_ip(IpAddr::V4(v4));
            }

            // 3. SIIT IPv4-translated IPv6: ::ffff:0:A.B.C.D
            if octets[0..8] == [0u8; 8]
                && octets[8..10] == [0xff, 0xff]
                && octets[10..12] == [0u8; 2]
            {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return validate_egress_ip(IpAddr::V4(v4));
            }

            // 4. Well-Known Prefix NAT64: 64:ff9b::/96
            if octets[0..4] == [0x00, 0x64, 0xff, 0x9b] && octets[4..12] == [0u8; 8] {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return validate_egress_ip(IpAddr::V4(v4));
            }
        }
    }
    Ok(())
}

/// Validates that a string does not contain CRLF or control characters (Anti-CRLF Injection, `CSE-08`, `T33`).
pub fn validate_crlf_safe(name: &str, val: &str) -> Result<(), String> {
    if val.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
        return Err(format!(
            "CRLF_INJECTION: Value for '{name}' contains prohibited control characters"
        ));
    }
    Ok(())
}

/// Tier-3 Behavioral Emulation & Sandbox Connector (`BUG-CORE-10`, `BUG-CORE-13`, `CSE-08`, `CSE-13`)
///
/// Implements `rustls` TLS 1.3 Client-Cert mTLS transport with DNS-rebind-safe SSRF IP validation,
/// strict CRLF header injection guards, and single-root `SharedAuditLedger` logging.
pub struct Tier3SandboxConnector {
    api_endpoint: String,
    api_key: String,
    client_cert_pem_path: Option<PathBuf>,
    custom_ca_cert_pem: Option<Vec<u8>>,
    ledger_path: PathBuf,
    shared_ledger: Option<SharedAuditLedger>,
    allow_loopback_for_testing: bool,
}

impl Tier3SandboxConnector {
    pub fn new(api_endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        #[cfg(test)]
        let ledger_path = std::env::temp_dir()
            .join(format!("omniconnect_sentinel_sbx_{}", std::process::id()))
            .join("sandbox_ledger.jsonl");
        #[cfg(not(test))]
        let ledger_path = {
            #[cfg(windows)]
            {
                PathBuf::from(r"C:\ProgramData\OmniConnect\AuditLedger\sandbox_ledger.jsonl")
            }
            #[cfg(not(windows))]
            {
                PathBuf::from("/var/lib/omniconnect/audit_ledger/sandbox_ledger.jsonl")
            }
        };
        Self {
            api_endpoint: api_endpoint.into(),
            api_key: api_key.into(),
            client_cert_pem_path: None,
            custom_ca_cert_pem: None,
            ledger_path,
            shared_ledger: None,
            allow_loopback_for_testing: false,
        }
    }

    pub fn with_mtls_cert(mut self, cert_path: PathBuf) -> Self {
        self.client_cert_pem_path = Some(cert_path);
        self
    }

    pub fn with_custom_ca(mut self, ca_pem: Vec<u8>) -> Self {
        self.custom_ca_cert_pem = Some(ca_pem);
        self
    }

    pub fn with_ledger_path(mut self, ledger_path: PathBuf) -> Self {
        self.ledger_path = ledger_path;
        self
    }

    pub fn with_shared_ledger(mut self, shared_ledger: SharedAuditLedger) -> Self {
        self.shared_ledger = Some(shared_ledger);
        self
    }

    pub fn with_allow_loopback_for_testing(mut self, allow: bool) -> Self {
        self.allow_loopback_for_testing = allow;
        self
    }

    /// Attempts remote sandbox detonation over `rustls` TLS 1.3 with client-cert mTLS,
    /// DNS-rebind-safe SSRF filtering, and CRLF validation (`CSE-08`, `T33`).
    pub fn try_remote_detonation(
        &self,
        request: &SandboxDetonationRequest,
    ) -> Result<SandboxDetonationReport, String> {
        if self.api_endpoint.starts_with("offline://")
            || self.api_key == "OFFLINE"
            || self.api_key == "TEST-KEY"
        {
            return Err("Remote sandbox configured in offline/emulated kiosk mode".to_string());
        }

        // 1. CRLF Injection Guard: Validate headers / api_key before anything touches the network
        validate_crlf_safe("api_key", &self.api_key)?;

        // 2. Enforce HTTPS URL scheme (reject http://, file://, etc.)
        let url = url::Url::parse(&self.api_endpoint).map_err(|e| {
            format!(
                "Invalid remote sandbox endpoint URL '{}': {e}",
                self.api_endpoint
            )
        })?;
        if url.scheme() != "https" {
            return Err(format!(
                "INSECURE_TRANSPORT_REJECTED: Scheme '{}' is prohibited; remote sandbox egress strictly requires https://",
                url.scheme()
            ));
        }

        let host = url
            .host_str()
            .ok_or_else(|| "Missing host in remote sandbox URL".to_string())?;
        let port = url.port_or_known_default().unwrap_or(443);

        // 3. DNS-Rebind-Safe SSRF Filter: Resolve host and validate all resolved IPs
        let target_addrs: Vec<SocketAddr> = format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|e| format!("Failed resolving remote sandbox host '{host}:{port}': {e}"))?
            .collect();

        if target_addrs.is_empty() {
            return Err(format!(
                "DNS resolution returned zero addresses for '{host}:{port}'"
            ));
        }

        if !self.allow_loopback_for_testing {
            for addr in &target_addrs {
                validate_egress_ip(addr.ip())?;
            }
        }

        // Connect directly to the validated IP to prevent DNS rebinding TOCTOU
        let validated_addr = target_addrs[0];
        let timeout = Duration::from_secs(request.timeout_seconds.clamp(1, 30) as u64);
        let mut tcp_stream =
            TcpStream::connect_timeout(&validated_addr, Duration::from_millis(1500))
                .map_err(|e| format!("Remote sandbox unreachable at {validated_addr}: {e}"))?;
        let _ = tcp_stream.set_read_timeout(Some(timeout));
        let _ = tcp_stream.set_write_timeout(Some(timeout));

        // 4. rustls TLS 1.3 Client-Cert mTLS Transport
        use rustls_pki_types::pem::PemObject;
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(custom_ca_bytes) = &self.custom_ca_cert_pem {
            for c in rustls_pki_types::CertificateDer::pem_slice_iter(custom_ca_bytes).flatten() {
                let _ = root_store.add(c);
            }
        }

        let client_config = if let Some(cert_path) = &self.client_cert_pem_path {
            let cert_data = fs::read(cert_path).map_err(|e| {
                format!(
                    "Failed reading client mTLS certificate {}: {e}",
                    cert_path.display()
                )
            })?;
            let cert_chain: Vec<rustls_pki_types::CertificateDer<'static>> =
                rustls_pki_types::CertificateDer::pem_slice_iter(&cert_data)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("Failed parsing client mTLS certificates: {e}"))?;

            let private_key = match rustls_pki_types::PrivateKeyDer::from_pem_slice(&cert_data) {
                Ok(key) => key,
                Err(rustls_pki_types::pem::Error::NoItemsFound) => {
                    return Err("No private key found in client mTLS certificate PEM".to_string());
                }
                Err(e) => {
                    return Err(format!("Failed parsing client mTLS private key: {e}"));
                }
            };

            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_client_auth_cert(cert_chain, private_key)
                .map_err(|e| format!("mTLS client configuration failed: {e}"))?
        } else {
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| format!("Invalid DNS SNI hostname '{host}': {e}"))?;

        let mut conn = rustls::ClientConnection::new(Arc::new(client_config), server_name)
            .map_err(|e| format!("Failed creating TLS client connection: {e}"))?;

        let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp_stream);

        let submit_body = serde_json::json!({
            "file_name": request.file_name,
            "sha256_hex": request.sha256_hex,
            "size_bytes": request.file_bytes.len(),
            "mtls_configured": self.client_cert_pem_path.is_some(),
        })
        .to_string();

        let path_and_query = url.path();
        let request_path = if path_and_query.is_empty() {
            "/api/v1/detonate"
        } else {
            path_and_query
        };

        let http_req = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            request_path,
            host,
            port,
            self.api_key,
            submit_body.len(),
            submit_body
        );

        tls_stream
            .write_all(http_req.as_bytes())
            .map_err(|e| format!("Failed submitting sample over TLS 1.3 to remote sandbox: {e}"))?;
        tls_stream
            .flush()
            .map_err(|e| format!("TLS flush failed: {e}"))?;

        let mut resp_buf = Vec::new();
        tls_stream
            .take(64 * 1024)
            .read_to_end(&mut resp_buf)
            .map_err(|e| format!("Failed reading remote sandbox response over TLS 1.3: {e}"))?;

        let resp_str = String::from_utf8_lossy(&resp_buf);
        let body_start = resp_str
            .find("\r\n\r\n")
            .map(|i| i + 4)
            .ok_or_else(|| "Malformed HTTP response from remote sandbox".to_string())?;

        let report = serde_json::from_str::<SandboxDetonationReport>(&resp_str[body_start..])
            .map_err(|e| format!("Invalid JSON report from remote sandbox: {e}"))?;

        // Record successful remote detonation to audit ledger
        self.record_audit_event(
            "SANDBOX_REMOTE_DETONATION",
            serde_json::json!({
                "analysis_id": report.analysis_id,
                "file_name": request.file_name,
                "verdict_malicious": report.verdict_malicious,
                "threat_score": report.threat_score,
                "mtls": self.client_cert_pem_path.is_some(),
            }),
        );

        Ok(report)
    }

    fn record_audit_event(&self, event: &str, data: serde_json::Value) {
        if let Some(shared) = &self.shared_ledger {
            if let Ok(mut guard) = shared.lock() {
                let _ =
                    guard.append_subsystem_event(AuditSubsystem::Tier3Sandbox, event, data.clone());
                return;
            }
        }
        let mut ledger = AuditLedger::open(&self.ledger_path);
        let _ = ledger.append_subsystem_event(AuditSubsystem::Tier3Sandbox, event, data);
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

        self.record_audit_event(
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
