//! Optional pluggable external antivirus CLI and RFC 3507 ICAP `RESPMOD` adapter interface (`CSE-27`).
//!
//! Designed strictly for air-gapped OT kiosks and managed endpoints that layer secondary signature
//! engines (e.g., ClamAV `clamdscan`, Windows Defender `MpCmdRun.exe`, or an on-prem ICAP appliance)
//! alongside OmniConnect Sentinel's built-in Tier-0 YARA + sandboxed CDR pipeline.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sentinel_sys::{ensure_not_symlink_or_reparse_point, open_untrusted_readonly_nofollow};

use crate::enterprise::falcon::AllowedCidr;
use crate::error::SentinelError;

/// Structured verdict returned by an external AV CLI or ICAP scanner adapter (`CSE-27`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAvVerdict {
    pub engine_name: String,
    pub infected: bool,
    pub signature_name: Option<String>,
    pub detail: String,
}

/// Pluggable secondary AV scanner trait implemented by CLI and ICAP adapters (`CSE-27`).
pub trait ExternalAvScannerAdapter: Send + Sync {
    fn engine_name(&self) -> &str;
    fn scan_file_path(&self, path: &Path) -> Result<ExternalAvVerdict, SentinelError>;
}

/// Safe, shell-free external AV CLI adapter (`CSE-27`):
/// - Requires an absolute path to the scanner binary (no `PATH` hijacking, no shell invocation).
/// - Rejects symlinked target files before spawning the scanner process.
/// - Fails closed (`Err`) on unexpected exit codes or spawn failures.
#[derive(Debug, Clone)]
pub struct CliAvAdapter {
    pub engine_name: String,
    pub binary_path: PathBuf,
    pub extra_args: Vec<String>,
    pub clean_exit_codes: Vec<i32>,
    pub infected_exit_codes: Vec<i32>,
}

impl CliAvAdapter {
    pub fn new(
        engine_name: impl Into<String>,
        binary_path: PathBuf,
        extra_args: Vec<String>,
    ) -> Result<Self, SentinelError> {
        if !binary_path.is_absolute() {
            return Err(SentinelError::WalkAccessDenied(format!(
                "CLI AV adapter binary '{}' must be an absolute path",
                binary_path.display()
            )));
        }
        Ok(Self {
            engine_name: engine_name.into(),
            binary_path,
            extra_args,
            clean_exit_codes: vec![0],
            infected_exit_codes: vec![1],
        })
    }
}

impl ExternalAvScannerAdapter for CliAvAdapter {
    fn engine_name(&self) -> &str {
        &self.engine_name
    }

    fn scan_file_path(&self, path: &Path) -> Result<ExternalAvVerdict, SentinelError> {
        ensure_not_symlink_or_reparse_point(path).map_err(|e| {
            SentinelError::WalkAccessDenied(format!(
                "CLI AV adapter '{}' refused symlink/reparse target '{}': {e}",
                self.engine_name,
                path.display()
            ))
        })?;
        if !self.binary_path.is_absolute() {
            return Err(SentinelError::WalkAccessDenied(format!(
                "CLI AV adapter binary '{}' must be an absolute path",
                self.binary_path.display()
            )));
        }
        ensure_not_symlink_or_reparse_point(&self.binary_path).map_err(|e| {
            SentinelError::WalkAccessDenied(format!(
                "CLI AV adapter '{}' refused symlink/reparse binary '{}': {e}",
                self.engine_name,
                self.binary_path.display()
            ))
        })?;

        let output = Command::new(&self.binary_path)
            .args(&self.extra_args)
            .arg(path)
            .output()
            .map_err(|e| {
                SentinelError::WalkAccessDenied(format!(
                    "CLI AV adapter '{}' failed spawning '{}': {e}",
                    self.engine_name,
                    self.binary_path.display()
                ))
            })?;

        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if !stdout.is_empty() {
            stdout.clone()
        } else {
            stderr
        };

        if self.clean_exit_codes.contains(&code) {
            return Ok(ExternalAvVerdict {
                engine_name: self.engine_name.clone(),
                infected: false,
                signature_name: None,
                detail,
            });
        }
        if self.infected_exit_codes.contains(&code) {
            let sig = stdout
                .lines()
                .find(|l| !l.trim().is_empty())
                .map(|l| l.trim().chars().take(128).collect::<String>());
            return Ok(ExternalAvVerdict {
                engine_name: self.engine_name.clone(),
                infected: true,
                signature_name: sig,
                detail,
            });
        }

        Err(SentinelError::WalkAccessDenied(format!(
            "CLI AV adapter '{}' returned unexpected exit code {code}: {detail}",
            self.engine_name
        )))
    }
}

/// Validates that an ICAP target socket address is strictly loopback (`127.0.0.1` / `::1`) or
/// explicitly within operator-pinned RFC 1918 / ULA `allowed_cidrs` (preventing SSRF) (`CSE-27`).
pub fn validate_icap_target_addr(
    addr: SocketAddr,
    allowed_cidrs: &[AllowedCidr],
) -> Result<(), SentinelError> {
    let ip = addr.ip();
    if ip.is_loopback() {
        return Ok(());
    }
    if allowed_cidrs.iter().any(|c| c.contains(ip)) {
        return Ok(());
    }
    match ip {
        IpAddr::V4(_) | IpAddr::V6(_) => Err(SentinelError::PolicySignatureInvalid(format!(
            "ICAP_SSRF_BLOCKED: target ICAP address '{addr}' is neither loopback nor inside operator-pinned private CIDRs"
        ))),
    }
}

/// Builds a standards-compliant RFC 3507 ICAP `RESPMOD` header framing a streaming HTTP response
/// body for `file_name` (`CSE-27`).
pub fn build_icap_respmod_header(
    host: &str,
    port: u16,
    service_name: &str,
    file_name: &str,
    content_length: u64,
) -> Result<String, SentinelError> {
    for (label, val) in [
        ("host", host),
        ("service_name", service_name),
        ("file_name", file_name),
    ] {
        if val.trim().is_empty() || val.chars().any(|c| c.is_control()) {
            return Err(SentinelError::PolicySignatureInvalid(format!(
                "ICAP_INVALID_PARAM: '{label}' must be non-empty without control characters"
            )));
        }
    }
    let clean_service = service_name.trim_start_matches('/');
    let clean_name = file_name.replace(['"', ';', '\r', '\n'], "_");
    // Bracket bare IPv6 host literals per RFC 3986 / RFC 3507 (e.g. `::1` -> `[::1]`)
    let formatted_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let http_res_hdr = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"{clean_name}\"\r\nContent-Length: {content_length}\r\n\r\n"
    );
    let res_body_offset = http_res_hdr.len();
    let icap_hdr = format!(
        "RESPMOD icap://{formatted_host}:{port}/{clean_service} ICAP/1.0\r\n\
         Host: {formatted_host}:{port}\r\n\
         Allow: 204\r\n\
         Encapsulated: res-hdr=0, res-body={res_body_offset}\r\n\
         \r\n\
         {http_res_hdr}"
    );
    Ok(icap_hdr)
}

/// Parses an RFC 3507 ICAP `RESPMOD` response header block into an `ExternalAvVerdict` (`CSE-27`).
///
/// - Requires complete header termination (`\r\n\r\n`); truncated responses fail closed (`Err`).
/// - `ICAP/1.0 204` -> clean (`infected: false`).
/// - `X-Infection-Found:` or `X-Virus-ID:` header -> infected (`infected: true`, extracting threat name).
/// - `ICAP/1.0 200` without infection headers -> clean (`infected: false`).
/// - Malformed / non-2xx status -> fail-closed `Err`.
pub fn parse_icap_respmod_response(
    engine_name: &str,
    raw_response: &str,
) -> Result<ExternalAvVerdict, SentinelError> {
    let header_block = match raw_response.split_once("\r\n\r\n") {
        Some((hdr, _)) => hdr,
        None => {
            return Err(SentinelError::WalkAccessDenied(format!(
                "ICAP adapter '{engine_name}' received truncated or unterminated response header (missing CRLFCRLF)"
            )));
        }
    };
    let mut lines = header_block.lines();
    let status_line = lines.next().unwrap_or("").trim();
    if !status_line.starts_with("ICAP/1.0 ") {
        return Err(SentinelError::WalkAccessDenied(format!(
            "ICAP adapter '{engine_name}' received malformed status line: '{status_line}'"
        )));
    }
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|tok| tok.parse::<u16>().ok())
        .ok_or_else(|| {
            SentinelError::WalkAccessDenied(format!(
                "ICAP adapter '{engine_name}' missing numeric status code in '{status_line}'"
            ))
        })?;

    let mut infection_sig: Option<String> = None;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if kl == "x-virus-id" && !val.is_empty() {
                infection_sig = Some(val.to_string());
            } else if kl == "x-infection-found" && !val.is_empty() {
                // RFC/ClamAV format: `Type=0; Resolution=2; Threat=Win.Test.EICAR_HDB-1;`
                let extracted = val
                    .split(';')
                    .find_map(|part| {
                        let p = part.trim();
                        p.strip_prefix("Threat=")
                            .or_else(|| p.strip_prefix("threat="))
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                    })
                    .unwrap_or(val);
                infection_sig = Some(extracted.to_string());
            }
        }
    }

    if let Some(sig) = infection_sig {
        return Ok(ExternalAvVerdict {
            engine_name: engine_name.to_string(),
            infected: true,
            signature_name: Some(sig.clone()),
            detail: format!("ICAP {status_code} reported threat '{sig}'"),
        });
    }

    match status_code {
        204 | 200 => Ok(ExternalAvVerdict {
            engine_name: engine_name.to_string(),
            infected: false,
            signature_name: None,
            detail: format!("ICAP {status_code} clean"),
        }),
        _ => Err(SentinelError::WalkAccessDenied(format!(
            "ICAP adapter '{engine_name}' failed closed on ICAP status {status_code}: {status_line}"
        ))),
    }
}

/// Pluggable RFC 3507 ICAP `RESPMOD` external AV scanner streaming files in `O(64 KiB)` chunks (`CSE-27`).
#[derive(Debug, Clone)]
pub struct IcapAvAdapter {
    pub engine_name: String,
    pub server_addr: SocketAddr,
    pub service_name: String,
    pub allowed_cidrs: Vec<AllowedCidr>,
    pub timeout: Duration,
}

impl IcapAvAdapter {
    pub fn new(
        engine_name: impl Into<String>,
        server_addr: SocketAddr,
        service_name: impl Into<String>,
        allowed_cidrs: Vec<AllowedCidr>,
    ) -> Result<Self, SentinelError> {
        validate_icap_target_addr(server_addr, &allowed_cidrs)?;
        Ok(Self {
            engine_name: engine_name.into(),
            server_addr,
            service_name: service_name.into(),
            allowed_cidrs,
            timeout: Duration::from_secs(10),
        })
    }
}

impl ExternalAvScannerAdapter for IcapAvAdapter {
    fn engine_name(&self) -> &str {
        &self.engine_name
    }

    fn scan_file_path(&self, path: &Path) -> Result<ExternalAvVerdict, SentinelError> {
        validate_icap_target_addr(self.server_addr, &self.allowed_cidrs)?;
        let mut file = open_untrusted_readonly_nofollow(path).map_err(|e| {
            SentinelError::WalkAccessDenied(format!(
                "ICAP adapter '{}' failed opening '{}': {e}",
                self.engine_name,
                path.display()
            ))
        })?;
        let file_len = file
            .metadata()
            .map_err(|e| SentinelError::WalkAccessDenied(format!("ICAP metadata error: {e}")))?
            .len();
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("payload.bin");
        let host_literal = match self.server_addr.ip() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        let header = build_icap_respmod_header(
            &host_literal,
            self.server_addr.port(),
            &self.service_name,
            file_name,
            file_len,
        )?;

        let mut stream =
            TcpStream::connect_timeout(&self.server_addr, self.timeout).map_err(|e| {
                SentinelError::WalkAccessDenied(format!(
                    "ICAP adapter '{}' connect failed ({}): {e}",
                    self.engine_name, self.server_addr
                ))
            })?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        stream.write_all(header.as_bytes()).map_err(|e| {
            SentinelError::WalkAccessDenied(format!("ICAP header write failed: {e}"))
        })?;

        // Stream file bytes in O(64 KiB) HTTP chunked encoding
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf).map_err(|e| {
                SentinelError::WalkAccessDenied(format!("ICAP file read failed: {e}"))
            })?;
            if n == 0 {
                break;
            }
            write!(stream, "{n:x}\r\n").map_err(|e| {
                SentinelError::WalkAccessDenied(format!("ICAP chunk header write failed: {e}"))
            })?;
            stream.write_all(&buf[..n]).map_err(|e| {
                SentinelError::WalkAccessDenied(format!("ICAP chunk body write failed: {e}"))
            })?;
            stream.write_all(b"\r\n").map_err(|e| {
                SentinelError::WalkAccessDenied(format!("ICAP chunk terminator write failed: {e}"))
            })?;
        }
        stream.write_all(b"0\r\n\r\n").map_err(|e| {
            SentinelError::WalkAccessDenied(format!("ICAP final chunk write failed: {e}"))
        })?;
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Write);

        // Read bounded ICAP response header (max 16 KiB); fail closed if `\r\n\r\n` terminator is never received
        let mut resp_buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        let mut header_complete = false;
        while resp_buf.len() < 16 * 1024 {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    resp_buf.extend_from_slice(&chunk[..n]);
                    if resp_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        header_complete = true;
                        break;
                    }
                }
                Err(e) => {
                    if resp_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        header_complete = true;
                        break;
                    }
                    return Err(SentinelError::WalkAccessDenied(format!(
                        "ICAP response read failed: {e}"
                    )));
                }
            }
        }
        if !header_complete {
            return Err(SentinelError::WalkAccessDenied(format!(
                "ICAP adapter '{}' failed closed: response headers truncated or exceeded 16 KiB without CRLFCRLF terminator",
                self.engine_name
            )));
        }
        let resp_str = String::from_utf8_lossy(&resp_buf);
        parse_icap_respmod_response(&self.engine_name, &resp_str)
    }
}
