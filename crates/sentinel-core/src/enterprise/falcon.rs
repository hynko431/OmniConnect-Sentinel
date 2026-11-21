use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

use sentinel_sys::{
    create_restricted_dir_atomic, create_restricted_file_atomic,
    create_restricted_file_handle_atomic, ensure_not_symlink_or_reparse_point, seal_key_bytes,
    sign_ecdsa_p256_with_private_blob, sync_directory, unseal_key_bytes, verify_ecdsa_p256_digest,
    write_protected_key_file, zeroize_slice, SealedKeyBlob, ZeroizingBytes,
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
/// Maximum sealed SIEM active spool segment size on disk (128 MiB, `CSE-13`, `CSE-23`).
pub const MAX_SPOOL_SIZE_BYTES: u64 = 128 * 1024 * 1024;
/// High-watermark threshold (%) triggering a `SIEM_SPOOL_HIGH_WATERMARK` audit alert (`CSE-23`).
pub const SPOOL_HIGH_WATERMARK_PCT: u64 = 80;

const SIEM_SPOOL_MAGIC_V2: &[u8; 8] = b"OCSIEM2\0";
static SIEM_SPOOL_IO_LOCK: Mutex<()> = Mutex::new(());
static ROLLOVER_SEQ_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Operator-pinned internal private CIDR range (strictly RFC 1918 IPv4 or RFC 4193 IPv6 ULA)
/// authorized for enterprise on-prem SIEM syslog collectors (`CSE-23`).
///
/// Unconditionally rejects wildcard `/0`, loopback (`127.0.0.0/8`, `::1`), link-local / cloud
/// metadata (`169.254.0.0/16`, `fe80::/10`), multicast, broadcast, and public/unspecified CIDRs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowedCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl<'de> Deserialize<'de> for AllowedCidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawCidr {
            Str(String),
            Obj { network: IpAddr, prefix_len: u8 },
        }
        let formatted = match RawCidr::deserialize(deserializer)? {
            RawCidr::Str(s) => s,
            RawCidr::Obj {
                network,
                prefix_len,
            } => format!("{network}/{prefix_len}"),
        };
        AllowedCidr::parse(&formatted).map_err(serde::de::Error::custom)
    }
}

impl AllowedCidr {
    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    fn ipv4_range(ip: Ipv4Addr, prefix_len: u8) -> (u32, u32) {
        let clamped = prefix_len.min(32);
        let mask = if clamped == 0 {
            0u32
        } else {
            u32::MAX << (32 - clamped)
        };
        let start = u32::from(ip) & mask;
        let end = start | !mask;
        (start, end)
    }

    fn ipv6_range(ip: Ipv6Addr, prefix_len: u8) -> (u128, u128) {
        let clamped = prefix_len.min(128);
        let mask = if clamped == 0 {
            0u128
        } else {
            u128::MAX << (128 - clamped)
        };
        let start = u128::from(ip) & mask;
        let end = start | !mask;
        (start, end)
    }

    /// Parses and validates an operator-pinned private SIEM CIDR (e.g., `10.20.0.0/16`, `192.168.10.5/32`, `fd00:1234::/48`).
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let (ip_str, prefix_str) = trimmed.split_once('/').ok_or_else(|| {
            format!("Invalid CIDR '{trimmed}': expected '<ip>/<prefix_len>' format")
        })?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| format!("Invalid IP address in CIDR '{trimmed}': {e}"))?;
        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|e| format!("Invalid prefix length in CIDR '{trimmed}': {e}"))?;

        match ip {
            IpAddr::V4(v4) => {
                if prefix_len == 0 || prefix_len > 32 {
                    return Err(format!(
                        "Invalid IPv4 CIDR prefix length '/{prefix_len}' in '{trimmed}' (must be 1..=32)"
                    ));
                }
                let (start, end) = Self::ipv4_range(v4, prefix_len);
                let in_10 = start >= u32::from(Ipv4Addr::new(10, 0, 0, 0))
                    && end <= u32::from(Ipv4Addr::new(10, 255, 255, 255));
                let in_172 = start >= u32::from(Ipv4Addr::new(172, 16, 0, 0))
                    && end <= u32::from(Ipv4Addr::new(172, 31, 255, 255));
                let in_192 = start >= u32::from(Ipv4Addr::new(192, 168, 0, 0))
                    && end <= u32::from(Ipv4Addr::new(192, 168, 255, 255));
                if !(in_10 || in_172 || in_192) {
                    return Err(format!(
                        "CIDR_POLICY_REJECTED: '{trimmed}' is outside RFC 1918 private blocks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16); loopback, link-local, IMDS, and non-private CIDRs are prohibited"
                    ));
                }
                Ok(Self {
                    network: IpAddr::V4(Ipv4Addr::from(start)),
                    prefix_len,
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len == 0 || prefix_len > 128 {
                    return Err(format!(
                        "Invalid IPv6 CIDR prefix length '/{prefix_len}' in '{trimmed}' (must be 1..=128)"
                    ));
                }
                let (start, end) = Self::ipv6_range(v6, prefix_len);
                let ula_start = u128::from(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0));
                let ula_end = u128::from(Ipv6Addr::new(
                    0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                ));
                if !(start >= ula_start && end <= ula_end) {
                    return Err(format!(
                        "CIDR_POLICY_REJECTED: '{trimmed}' is outside RFC 4193 IPv6 ULA block (fc00::/7)"
                    ));
                }
                Ok(Self {
                    network: IpAddr::V6(Ipv6Addr::from(start)),
                    prefix_len,
                })
            }
        }
    }

    /// Returns `true` if `ip` lies strictly inside this CIDR range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(cand)) => {
                if self.prefix_len == 0 || self.prefix_len > 32 {
                    return false;
                }
                let (start, end) = Self::ipv4_range(net, self.prefix_len);
                let v = u32::from(cand);
                v >= start && v <= end
            }
            (IpAddr::V6(net), IpAddr::V6(cand)) => {
                if self.prefix_len == 0 || self.prefix_len > 128 {
                    return false;
                }
                let (start, end) = Self::ipv6_range(net, self.prefix_len);
                let v = u128::from(cand);
                v >= start && v <= end
            }
            _ => false,
        }
    }
}

/// Maximum validity window (15 minutes) for a signed SIEM spool retention override (`CSE-23`).
pub const OVERRIDE_MAX_AGE_SECS: i64 = 900;
/// Maximum permitted forward clock skew (60 seconds) on signed spool override timestamps (`CSE-23`).
pub const OVERRIDE_MAX_FUTURE_SKEW_SECS: i64 = 60;

/// Cryptographically signed operator override authorizing retention pruning shorter than
/// the CERT-In 180-day statutory floor (`CSE-23`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSpoolPruneOverride {
    pub operator_id: String,
    pub reason: String,
    pub retention_days: i64,
    pub issued_unix: i64,
    pub nonce: String,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}

impl SignedSpoolPruneOverride {
    /// Unambiguous length-prefixed canonical SHA-256 digest preventing cross-field delimiter smuggling.
    fn canonical_digest(&self) -> [u8; 32] {
        let payload = format!(
            "SENTINEL-SIEM-PRUNE-OVERRIDE-V2|op:{}:{}|rsn:{}:{}|ret:{}|ts:{}|n:{}:{}",
            self.operator_id.len(),
            self.operator_id,
            self.reason.len(),
            self.reason,
            self.retention_days,
            self.issued_unix,
            self.nonce.len(),
            self.nonce
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(payload.as_bytes()));
        out
    }

    pub fn sign(
        operator_id: impl Into<String>,
        reason: impl Into<String>,
        retention_days: i64,
        priv_key_blob: &[u8],
        pub_key_bytes: &[u8],
    ) -> Result<Self, String> {
        if retention_days < 0 {
            return Err(format!(
                "OVERRIDE_REJECTED: Negative retention_days ({retention_days}) is invalid"
            ));
        }
        let mut override_ev = Self {
            operator_id: operator_id.into(),
            reason: reason.into(),
            retention_days,
            issued_unix: Utc::now().timestamp(),
            nonce: uuid::Uuid::new_v4().to_string(),
            signer_public_key_hex: hex::encode(pub_key_bytes),
            signature_hex: String::new(),
        };
        let digest = override_ev.canonical_digest();
        let sig = sign_ecdsa_p256_with_private_blob(priv_key_blob, &digest)
            .map_err(|e| format!("Failed signing SIEM spool prune override: {e}"))?;
        override_ev.signature_hex = hex::encode(sig);
        Ok(override_ev)
    }

    pub fn verify(&self, pinned_operator_pubkeys: &[Vec<u8>]) -> Result<(), String> {
        if self.operator_id.trim().is_empty()
            || self.reason.trim().is_empty()
            || self.nonce.trim().is_empty()
        {
            return Err(
                "OVERRIDE_REJECTED: Signed spool prune override missing operator_id, reason, or nonce"
                    .to_string(),
            );
        }
        if self.retention_days < 0 {
            return Err(format!(
                "OVERRIDE_REJECTED: Negative retention_days ({}) is invalid",
                self.retention_days
            ));
        }
        let now = Utc::now().timestamp();
        if now.saturating_sub(self.issued_unix) > OVERRIDE_MAX_AGE_SECS {
            return Err(format!(
                "OVERRIDE_EXPIRED: Signed spool prune override exceeded {OVERRIDE_MAX_AGE_SECS}s TTL"
            ));
        }
        if self.issued_unix.saturating_sub(now) > OVERRIDE_MAX_FUTURE_SKEW_SECS {
            return Err(format!(
                "OVERRIDE_FUTURE_SKEW: Signed spool prune override timestamp exceeds +{OVERRIDE_MAX_FUTURE_SKEW_SECS}s skew"
            ));
        }
        let pub_bytes = hex::decode(&self.signer_public_key_hex)
            .map_err(|e| format!("Invalid override signer public key hex: {e}"))?;
        if !pinned_operator_pubkeys.iter().any(|pk| pk == &pub_bytes) {
            return Err(
                "OVERRIDE_REJECTED: Signer public key is not in pinned operator root keys"
                    .to_string(),
            );
        }
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| format!("Invalid override signature hex: {e}"))?;
        let digest = self.canonical_digest();
        let ok = verify_ecdsa_p256_digest(&pub_bytes, &digest, &sig_bytes)
            .map_err(|e| format!("Override ECDSA P-256 verification error: {e}"))?;
        if !ok {
            return Err("OVERRIDE_REJECTED: Invalid ECDSA P-256 signature".to_string());
        }
        Ok(())
    }
}

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

/// CrowdStrike Falcon & SIEM CEF Syslog Bridge (`BUG-CORE-09`, `CSE-13`, `CSE-23`, `T33`, `T51`)
///
/// Implements RFC 5425 TLS 1.3 octet-counted syslog on TCP 6514 (with optional real client-cert
/// mTLS and operator-pinned RFC 1918/ULA CIDR allowlists), AES-256-GCM encrypted on-disk spooling
/// (`siem_spool.sealed`) with sealed rollover archive segments & 80% high-watermark alerting
/// (zero silent <180-day CERT-In eviction), and single-root `SharedAuditLedger` integration.
pub struct CrowdStrikeFalconBridge {
    syslog_endpoint: String,
    spool_path: PathBuf,
    ledger_path: PathBuf,
    shared_ledger: Option<SharedAuditLedger>,
    custom_ca_cert_pem: Option<Vec<u8>>,
    client_cert_pem: Option<Vec<u8>>,
    client_key_pem: Option<Vec<u8>>,
    tls_config_error: Option<String>,
    allowed_private_cidrs: Vec<AllowedCidr>,
    max_spool_bytes: u64,
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
            client_cert_pem: None,
            client_key_pem: None,
            tls_config_error: None,
            allowed_private_cidrs: Vec::new(),
            max_spool_bytes: MAX_SPOOL_SIZE_BYTES,
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
            client_cert_pem: None,
            client_key_pem: None,
            tls_config_error: None,
            allowed_private_cidrs: Vec::new(),
            max_spool_bytes: MAX_SPOOL_SIZE_BYTES,
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

    /// Configures real TLS 1.3 client-certificate mTLS (`with_client_auth_cert`) for SIEM egress (`CSE-23`).
    pub fn with_client_mtls(mut self, client_cert_pem: Vec<u8>, client_key_pem: Vec<u8>) -> Self {
        self.client_cert_pem = Some(client_cert_pem);
        self.client_key_pem = Some(client_key_pem);
        self
    }

    /// Configures optional TLS 1.3 client-cert mTLS paths fail-closed: if only one of cert/key is
    /// provided or a file cannot be read, records a fail-closed `MTLS_CONFIG_ERROR` so egress never
    /// silently downgrades to `with_no_client_auth()` (`CSE-23`).
    pub fn with_client_mtls_optional(
        mut self,
        client_cert_pem: Option<Vec<u8>>,
        client_key_pem: Option<Vec<u8>>,
    ) -> Self {
        self.client_cert_pem = client_cert_pem;
        self.client_key_pem = client_key_pem;
        self
    }

    /// Records a fail-closed TLS/mTLS initialization error (e.g., unreadable CA or client PEM) so
    /// subsequent SIEM sends never silently downgrade to unauthenticated TLS (`CSE-23`).
    pub fn with_tls_config_error(mut self, err: impl Into<String>) -> Self {
        self.tls_config_error = Some(err.into());
        self
    }

    /// Configures operator-pinned internal RFC 1918 / IPv6 ULA SIEM CIDR ranges (`CSE-23`).
    pub fn with_allowed_private_cidrs(mut self, cidrs: Vec<AllowedCidr>) -> Self {
        self.allowed_private_cidrs = cidrs;
        self
    }

    /// Sets the active spool segment capacity ceiling before sealed rollover archiving (clamped `>= 1024`).
    pub fn with_max_spool_bytes(mut self, max_bytes: u64) -> Self {
        self.max_spool_bytes = max_bytes.max(1024);
        self
    }

    /// Returns `true` ONLY when valid client certificate + private key PEMs are configured and
    /// actively bound into `rustls::ClientConfig::with_client_auth_cert` (`CSE-23`).
    pub fn is_mtls_enforced(&self) -> bool {
        self.build_tls_client_config()
            .map(|(_, mtls)| mtls)
            .unwrap_or(false)
    }

    /// Validates a resolved SIEM IP against unconditional SSRF blocks AND operator-pinned
    /// RFC 1918 / IPv6 ULA SIEM allowlists (`CSE-23`, `T51`).
    ///
    /// Unconditionally blocks loopback (`127.0.0.0/8`, `::1`), link-local & cloud metadata
    /// (`169.254.0.0/16`, `fe80::/10`), broadcast, multicast, unspecified, and IPv4-embedded IPv6
    /// representations of prohibited addresses.
    pub fn validate_siem_egress_ip(
        ip: IpAddr,
        allowed_private_cidrs: &[AllowedCidr],
    ) -> Result<(), String> {
        let normalized = match ip {
            IpAddr::V6(v6) => {
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    IpAddr::V4(mapped)
                } else {
                    let octets = v6.octets();
                    let is_ipv4_compat =
                        octets[0..12] == [0u8; 12] && !v6.is_unspecified() && !v6.is_loopback();
                    let is_siit_v4 = octets[0..8] == [0u8; 8]
                        && octets[8..10] == [0xff, 0xff]
                        && octets[10..12] == [0u8; 2];
                    let is_nat64_v4 =
                        octets[0..4] == [0x00, 0x64, 0xff, 0x9b] && octets[4..12] == [0u8; 8];
                    if is_ipv4_compat || is_siit_v4 || is_nat64_v4 {
                        IpAddr::V4(Ipv4Addr::new(
                            octets[12], octets[13], octets[14], octets[15],
                        ))
                    } else {
                        IpAddr::V6(v6)
                    }
                }
            }
            IpAddr::V4(v4) => IpAddr::V4(v4),
        };

        match normalized {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                if v4.is_loopback() {
                    return Err(format!(
                        "SSRF_VIOLATION: Loopback IPv4 SIEM address '{v4}' is unconditionally prohibited"
                    ));
                }
                if (oct[0] == 169 && oct[1] == 254) || v4.is_link_local() {
                    return Err(format!(
                        "SSRF_VIOLATION: Link-local / IMDS cloud metadata SIEM address '{v4}' is unconditionally prohibited"
                    ));
                }
                if v4.is_broadcast()
                    || v4.is_multicast()
                    || v4.is_unspecified()
                    || v4.is_documentation()
                {
                    return Err(format!(
                        "SSRF_VIOLATION: Non-routable SIEM IPv4 address '{v4}' is prohibited"
                    ));
                }
                if v4.is_private() {
                    if allowed_private_cidrs
                        .iter()
                        .any(|cidr| cidr.contains(IpAddr::V4(v4)))
                    {
                        return Ok(());
                    }
                    return Err(format!(
                        "SSRF_VIOLATION: RFC 1918 private SIEM IPv4 '{v4}' is not in operator-pinned allowed_private_cidrs"
                    ));
                }
                Ok(())
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() {
                    return Err(format!(
                        "SSRF_VIOLATION: Loopback/non-routable SIEM IPv6 '{v6}' is unconditionally prohibited"
                    ));
                }
                let seg = v6.segments();
                if (seg[0] & 0xffc0) == 0xfe80 {
                    return Err(format!(
                        "SSRF_VIOLATION: Link-local SIEM IPv6 '{v6}' is unconditionally prohibited"
                    ));
                }
                if (seg[0] & 0xfe00) == 0xfc00 {
                    if allowed_private_cidrs
                        .iter()
                        .any(|cidr| cidr.contains(IpAddr::V6(v6)))
                    {
                        return Ok(());
                    }
                    return Err(format!(
                        "SSRF_VIOLATION: IPv6 ULA SIEM address '{v6}' is not in operator-pinned allowed_private_cidrs"
                    ));
                }
                Ok(())
            }
        }
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

    fn is_endpoint_offline(&self) -> bool {
        let trimmed = self.syslog_endpoint.trim();
        trimmed.is_empty() || trimmed.to_ascii_lowercase().starts_with("offline://")
    }

    /// Emits a CEF alert to the SIEM endpoint over RFC 5425 TLS 1.3, spools securely in `siem_spool.sealed`
    /// when offline (`CSE-13`, `T33`), enforces 180-day retention, and appends to the unified `AuditLedger`.
    pub fn emit_alert(&self, event: &FalconTelemetryEvent) -> Result<(), String> {
        let now = Utc::now();
        let cef_line = self.format_cef_payload(event);
        info!("SIEM CEF Telemetry: {}", cef_line);

        let mut delivered = false;
        if !self.is_endpoint_offline() {
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

        let mtls_enforced = self.is_mtls_enforced();
        let spool_path_token = self
            .tokenize_path(&self.spool_path)
            .unwrap_or_else(|_| "TOKENIZATION_UNAVAILABLE".to_string());
        let alert_data = serde_json::json!({
            "signature_id": event.signature_id,
            "severity": event.severity,
            "action_taken": event.action_taken,
            "delivered_immediately": delivered,
            "mtls_enforced": mtls_enforced,
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

    fn build_tls_client_config(&self) -> Result<(rustls::ClientConfig, bool), String> {
        use rustls_pki_types::pem::PemObject;
        if let Some(ref cfg_err) = self.tls_config_error {
            return Err(format!("MTLS_CONFIG_ERROR: {cfg_err}"));
        }
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca) = &self.custom_ca_cert_pem {
            let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
                rustls_pki_types::CertificateDer::pem_slice_iter(ca)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("MTLS_CONFIG_ERROR: Invalid custom CA PEM: {e}"))?;
            if ca_certs.is_empty() {
                return Err(
                    "MTLS_CONFIG_ERROR: custom_ca_cert_pem contains 0 valid certificates"
                        .to_string(),
                );
            }
            for c in ca_certs {
                root_store
                    .add(c)
                    .map_err(|e| format!("MTLS_CONFIG_ERROR: Failed adding custom CA cert: {e}"))?;
            }
        }

        let builder =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store);

        match (&self.client_cert_pem, &self.client_key_pem) {
            (Some(cert_pem), Some(key_pem)) => {
                let cert_chain: Vec<rustls_pki_types::CertificateDer<'static>> =
                    rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| format!("Failed parsing SIEM mTLS client certificate: {e}"))?;
                if cert_chain.is_empty() {
                    return Err(
                        "MTLS_CONFIG_ERROR: SIEM client_cert_pem contains 0 certificates"
                            .to_string(),
                    );
                }
                let priv_key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem)
                    .map_err(|e| format!("Failed parsing SIEM mTLS client private key: {e}"))?;
                let cfg = builder
                    .with_client_auth_cert(cert_chain, priv_key)
                    .map_err(|e| format!("SIEM TLS 1.3 mTLS configuration failed: {e}"))?;
                Ok((cfg, true))
            }
            (None, None) => Ok((builder.with_no_client_auth(), false)),
            _ => Err(
                "MTLS_CONFIG_ERROR: Both client_cert_pem and client_key_pem are required for SIEM mTLS"
                    .to_string(),
            ),
        }
    }

    /// Sends a CEF message over RFC 5425 TLS 1.3 octet-counted framing with optional real mTLS
    /// and operator-pinned RFC 1918/ULA CIDR allowlist validation (`CSE-13`, `CSE-23`, `T33`, `T51`).
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
                Self::validate_siem_egress_ip(addr.ip(), &self.allowed_private_cidrs)?;
            }
        }

        let (client_config, _mtls_enforced) = self.build_tls_client_config()?;

        let validated_addr = target_addrs[0];
        let mut tcp_stream =
            TcpStream::connect_timeout(&validated_addr, Duration::from_millis(1500))
                .map_err(|e| format!("SIEM endpoint unreachable at {validated_addr}: {e}"))?;
        let _ = tcp_stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = tcp_stream.set_write_timeout(Some(Duration::from_secs(5)));

        let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| format!("Invalid DNS/IP SNI for SIEM host '{host}': {e}"))?;

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

        // Send RFC 8446 close_notify and briefly poll for any fatal TLS 1.3 post-handshake alert
        // (such as `CertificateRequired` / `BadCertificate` from an mTLS-enforcing SIEM collector)
        // so rejected handshakes are NEVER misclassified as delivered (`CSE-23`).
        tls_stream.conn.send_close_notify();
        let _ = tls_stream.flush();
        let _ = tls_stream
            .sock
            .set_read_timeout(Some(Duration::from_millis(150)));
        let mut alert_probe = [0u8; 1];
        match tls_stream.read(&mut alert_probe) {
            Ok(_) => Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(format!(
                "SIEM peer rejected TLS 1.3 session/frame (post-handshake alert): {e}"
            )),
        }
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
        self.read_encrypted_segment_locked(&self.spool_path, None)
    }

    fn rollover_archive_prefix(&self) -> String {
        let stem = self
            .spool_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("siem_spool");
        format!("{stem}.archive.")
    }

    fn list_rollover_archives_locked(&self) -> Result<Vec<PathBuf>, String> {
        let Some(parent) = self.spool_path.parent() else {
            return Ok(Vec::new());
        };
        if parent.as_os_str().is_empty() || !parent.exists() {
            return Ok(Vec::new());
        }
        let prefix = self.rollover_archive_prefix();
        let mut archives = Vec::new();
        let entries = fs::read_dir(parent).map_err(|e| {
            format!(
                "Failed listing SIEM archive directory {}: {e}",
                parent.display()
            )
        })?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with(&prefix) && name_str.ends_with(".sealed") {
                archives.push(path);
            }
        }
        archives.sort();
        Ok(archives)
    }

    /// Lists all sealed CERT-In rollover archive segment files alongside `self.spool_path` (`CSE-23`).
    pub fn list_rollover_archives(&self) -> Result<Vec<PathBuf>, String> {
        let _guard = SIEM_SPOOL_IO_LOCK
            .lock()
            .map_err(|e| format!("SIEM spool lock poisoned: {e}"))?;
        self.list_rollover_archives_locked()
    }

    fn read_encrypted_segment_locked(
        &self,
        path: &Path,
        aad_suffix: Option<&str>,
    ) -> Result<Vec<SiemSpoolRecord>, String> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        ensure_not_symlink_or_reparse_point(path).map_err(|e| {
            format!(
                "SIEM_SPOOL_INTEGRITY_FAIL: Refusing symlink/reparse spool segment {}: {}",
                path.display(),
                e
            )
        })?;
        let raw = fs::read(path).map_err(|e| {
            format!(
                "Failed reading SIEM spool segment '{}': {e}",
                path.display()
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
        let aad = match aad_suffix {
            Some(seg) => format!("SENTINEL-SIEM-SPOOL-V2|{key_id}|ARCHIVE|{seg}"),
            None => format!("SENTINEL-SIEM-SPOOL-V2|{key_id}"),
        };
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

    fn write_encrypted_segment_locked(
        &self,
        path: &Path,
        records: &[SiemSpoolRecord],
        aad_suffix: Option<&str>,
    ) -> Result<usize, String> {
        if path.exists() {
            ensure_not_symlink_or_reparse_point(path).map_err(|e| {
                format!(
                    "SIEM_SPOOL_INTEGRITY_FAIL: Refusing symlink/reparse spool {}: {}",
                    path.display(),
                    e
                )
            })?;
        }
        let mut serialized = serde_json::to_vec(records)
            .map_err(|e| format!("Failed serializing SIEM spool records: {e}"))?;
        let plain_len = serialized.len();

        let (dek, key_id) = self.load_or_init_spool_dek(true)?;
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = match aad_suffix {
            Some(seg) => format!("SENTINEL-SIEM-SPOOL-V2|{key_id}|ARCHIVE|{seg}"),
            None => format!("SENTINEL-SIEM-SPOOL-V2|{key_id}"),
        };
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

        create_restricted_file_atomic(path, &output).map_err(|e| {
            format!(
                "Failed writing encrypted SIEM spool '{}': {e}",
                path.display()
            )
        })?;

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = sync_directory(parent);
            }
        }
        Ok(plain_len)
    }

    /// Reads all records across sealed rollover archive segments AND the active spool (`CSE-23`).
    pub fn read_all_retained_records(&self) -> Result<Vec<SiemSpoolRecord>, String> {
        let _guard = SIEM_SPOOL_IO_LOCK
            .lock()
            .map_err(|e| format!("SIEM spool lock poisoned: {e}"))?;
        let mut all = Vec::new();
        for archive_path in self.list_rollover_archives_locked()? {
            let seg_name = archive_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut seg_records =
                self.read_encrypted_segment_locked(&archive_path, Some(&seg_name))?;
            all.append(&mut seg_records);
        }
        let mut active = self.read_spool_records_locked()?;
        all.append(&mut active);
        Ok(all)
    }

    /// Flushes undelivered (`delivered == false`) SIEM records across both sealed rollover archives
    /// and the active spool over RFC 5425 TLS 1.3 / mTLS (`Row 169`, `CSE-13`, `CSE-23`, `T51`).
    ///
    /// Preserves strict FIFO order: on the first send/SSRF/mTLS failure, persists any already-delivered
    /// prefix via `write_encrypted_segment_locked` (avoiding spurious high-watermark alerts) and
    /// propagates `Err(e)` fail-closed instead of silently returning `Ok(0)`.
    pub fn flush_spool(&self) -> Result<usize, String> {
        let _guard = SIEM_SPOOL_IO_LOCK
            .lock()
            .map_err(|e| format!("SIEM spool lock poisoned: {e}"))?;
        if self.is_endpoint_offline() {
            return Ok(0);
        }
        // Fail closed on invalid endpoint scheme/port or broken/partial mTLS configuration even
        // when the local spool has 0 undelivered records (`CSE-23`).
        let (_host, _port, _is_offline) = Self::validate_syslog_endpoint(&self.syslog_endpoint)?;
        let _ = self.build_tls_client_config()?;
        let mut newly_delivered = 0usize;
        let mut first_send_err: Option<String> = None;

        // 1. Drain rollover archives chronologically first
        for archive_path in self.list_rollover_archives_locked()? {
            if first_send_err.is_some() {
                break;
            }
            let seg_name = archive_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut seg_records =
                self.read_encrypted_segment_locked(&archive_path, Some(&seg_name))?;
            let mut seg_changed = false;
            for rec in &mut seg_records {
                if !rec.delivered {
                    match self.send_rfc5425_syslog(&rec.cef_payload) {
                        Ok(()) => {
                            rec.delivered = true;
                            newly_delivered += 1;
                            seg_changed = true;
                        }
                        Err(e) => {
                            first_send_err = Some(e);
                            break;
                        }
                    }
                }
            }
            if seg_changed {
                let _ = self.write_encrypted_segment_locked(
                    &archive_path,
                    &seg_records,
                    Some(&seg_name),
                )?;
            }
        }

        // 2. Drain active spool (persisted directly via write_encrypted_segment_locked so drains
        //    never trigger spurious SIEM_SPOOL_HIGH_WATERMARK alerts)
        if first_send_err.is_none() && self.spool_path.exists() {
            let mut records = self.read_spool_records_locked()?;
            let mut active_changed = false;
            for rec in &mut records {
                if !rec.delivered {
                    match self.send_rfc5425_syslog(&rec.cef_payload) {
                        Ok(()) => {
                            rec.delivered = true;
                            newly_delivered += 1;
                            active_changed = true;
                        }
                        Err(e) => {
                            first_send_err = Some(e);
                            break;
                        }
                    }
                }
            }
            if active_changed {
                let _ = self.write_encrypted_segment_locked(&self.spool_path, &records, None)?;
            }
        }

        if newly_delivered > 0 {
            self.record_audit_event(
                "SIEM_SPOOL_FLUSHED",
                serde_json::json!({
                    "delivered_count": newly_delivered,
                    "mtls_enforced": self.is_mtls_enforced(),
                }),
            );
        }

        if let Some(err) = first_send_err {
            return Err(err);
        }
        Ok(newly_delivered)
    }

    fn override_nonces_path(&self) -> PathBuf {
        let mut os = self.spool_path.as_os_str().to_os_string();
        os.push(".override_nonces.json");
        PathBuf::from(os)
    }

    fn record_and_check_override_nonce_locked(
        &self,
        nonce: &str,
        issued_unix: i64,
    ) -> Result<(), String> {
        #[derive(Serialize, Deserialize)]
        struct ConsumedOverrideNonce {
            nonce: String,
            issued_unix: i64,
        }

        let nonce_path = self.override_nonces_path();
        let mut seen: Vec<ConsumedOverrideNonce> = if nonce_path.exists() {
            ensure_not_symlink_or_reparse_point(&nonce_path).map_err(|e| {
                format!(
                    "OVERRIDE_NONCE_STORE_INTEGRITY_FAIL: Refusing symlink/reparse {}: {e}",
                    nonce_path.display()
                )
            })?;
            let raw = fs::read(&nonce_path)
                .map_err(|e| format!("Failed reading override nonce store: {e}"))?;
            serde_json::from_slice(&raw)
                .map_err(|e| format!("Corrupt override nonce store JSON: {e}"))?
        } else {
            Vec::new()
        };

        let now = Utc::now().timestamp();
        let min_live_issued = now
            .saturating_sub(OVERRIDE_MAX_AGE_SECS)
            .saturating_sub(OVERRIDE_MAX_FUTURE_SKEW_SECS);
        seen.retain(|entry| entry.issued_unix >= min_live_issued);

        if seen.iter().any(|existing| existing.nonce == nonce) {
            return Err(format!(
                "OVERRIDE_REPLAY_REJECTED: Signed spool prune override nonce '{nonce}' was already consumed"
            ));
        }

        seen.push(ConsumedOverrideNonce {
            nonce: nonce.to_string(),
            issued_unix,
        });
        let encoded = serde_json::to_vec(&seen)
            .map_err(|e| format!("Failed serializing override nonce store: {e}"))?;
        if let Some(parent) = nonce_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                create_restricted_dir_atomic(parent)
                    .map_err(|e| format!("Failed creating override nonce store directory: {e}"))?;
            }
        }
        create_restricted_file_atomic(&nonce_path, &encoded)
            .map_err(|e| format!("Failed persisting override nonce store: {e}"))?;
        Ok(())
    }

    /// Prunes SIEM spool records strictly older than `retention_days`.
    /// Enforces the CERT-In / NIST `AU-9`/`AU-10` 180-day floor: refuses `retention_days < 180`
    /// without an explicit ECDSA P-256 signed operator override (`CSE-23`, `T51`).
    pub fn prune_expired_records(&self, retention_days: i64) -> Result<usize, String> {
        if retention_days < SIEM_RETENTION_DAYS {
            return Err(format!(
                "CERT_IN_RETENTION_VIOLATION: Refusing to prune SIEM records younger than {SIEM_RETENTION_DAYS} days (requested {retention_days} days) without a signed operator override"
            ));
        }
        let _guard = SIEM_SPOOL_IO_LOCK
            .lock()
            .map_err(|e| format!("SIEM spool lock poisoned: {e}"))?;
        self.prune_records_locked(retention_days)
    }

    /// Prunes SIEM spool records younger than 180 days ONLY with a cryptographically verified,
    /// non-expired, non-replayed ECDSA P-256 `SignedSpoolPruneOverride`, recording
    /// `SIEM_SPOOL_OPERATOR_PRUNE_OVERRIDE` in the tamper-evident `AuditLedger` (`CSE-23`).
    pub fn prune_records_with_signed_override(
        &self,
        override_event: &SignedSpoolPruneOverride,
        pinned_operator_pubkeys: &[Vec<u8>],
    ) -> Result<usize, String> {
        override_event.verify(pinned_operator_pubkeys)?;
        let _guard = SIEM_SPOOL_IO_LOCK
            .lock()
            .map_err(|e| format!("SIEM spool lock poisoned: {e}"))?;
        self.record_and_check_override_nonce_locked(
            override_event.nonce.trim(),
            override_event.issued_unix,
        )?;
        let pruned = self.prune_records_locked(override_event.retention_days.max(0))?;
        self.record_audit_event(
            "SIEM_SPOOL_OPERATOR_PRUNE_OVERRIDE",
            serde_json::json!({
                "operator_id": override_event.operator_id,
                "reason": override_event.reason,
                "retention_days": override_event.retention_days,
                "nonce": override_event.nonce,
                "pruned_count": pruned,
            }),
        );
        Ok(pruned)
    }

    fn prune_records_locked(&self, retention_days: i64) -> Result<usize, String> {
        let cutoff_unix = Utc::now().timestamp() - (retention_days.max(0) * 86_400);
        let mut total_pruned = 0usize;

        // Prune expired records in rollover archives (delete archive only if 100% expired)
        for archive_path in self.list_rollover_archives_locked()? {
            let seg_name = archive_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let records = self.read_encrypted_segment_locked(&archive_path, Some(&seg_name))?;
            let initial_len = records.len();
            let retained: Vec<SiemSpoolRecord> = records
                .into_iter()
                .filter(|r| r.timestamp_unix >= cutoff_unix)
                .collect();
            let pruned = initial_len.saturating_sub(retained.len());
            if pruned > 0 {
                total_pruned += pruned;
                if retained.is_empty() {
                    fs::remove_file(&archive_path).map_err(|e| {
                        format!(
                            "Failed removing expired SIEM rollover archive '{}': {e}",
                            archive_path.display()
                        )
                    })?;
                } else {
                    let _ = self.write_encrypted_segment_locked(
                        &archive_path,
                        &retained,
                        Some(&seg_name),
                    )?;
                }
            }
        }

        if self.spool_path.exists() {
            let records = self.read_spool_records_locked()?;
            let initial_len = records.len();
            let retained: Vec<SiemSpoolRecord> = records
                .into_iter()
                .filter(|r| r.timestamp_unix >= cutoff_unix)
                .collect();
            let pruned = initial_len.saturating_sub(retained.len());
            if pruned > 0 {
                total_pruned += pruned;
                let _ = self.write_encrypted_segment_locked(&self.spool_path, &retained, None)?;
            }
        }

        Ok(total_pruned)
    }

    /// Allocates a collision-proof, lexicographically ordered rollover archive path that never
    /// overwrites an existing sealed CERT-In archive across process restarts or NTP backward steps.
    fn allocate_unique_rollover_archive_path_locked(&self) -> Result<(PathBuf, String), String> {
        let parent = self.spool_path.parent().unwrap_or_else(|| Path::new("."));
        let prefix = self.rollover_archive_prefix();
        let existing_count = self.list_rollover_archives_locked()?.len() as u64;
        let ts = Utc::now().timestamp().max(0) as u64;

        for _ in 0..64 {
            let seq = ROLLOVER_SEQ_COUNTER
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(existing_count);
            let mut rnd = [0u8; 4];
            rand::rngs::OsRng.fill_bytes(&mut rnd);
            let archive_name = format!("{prefix}{ts:020}.{seq:08}.{}.sealed", hex::encode(rnd));
            let candidate = parent.join(&archive_name);
            if fs::symlink_metadata(&candidate).is_err() {
                return Ok((candidate, archive_name));
            }
        }
        Err("Failed allocating unique non-colliding SIEM rollover archive filename".to_string())
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

        let mut serialized = serde_json::to_vec(records)
            .map_err(|e| format!("Failed serializing SIEM spool records: {e}"))?;
        let pre_rollover_bytes = serialized.len() as u64;
        zeroize_slice(&mut serialized);

        let high_watermark_bytes = self
            .max_spool_bytes
            .saturating_mul(SPOOL_HIGH_WATERMARK_PCT)
            / 100;

        let active_bytes = if pre_rollover_bytes > self.max_spool_bytes && records.len() > 1 {
            // CSE-23 CERT-In 180-day protection: NEVER silently evict records via `remove(0)`.
            // Roll older records into a collision-proof AEAD-sealed rollover archive segment beside the active spool.
            let split_idx = records.len().saturating_sub(1);
            let archive_slice = &records[..split_idx];
            let active_slice = &records[split_idx..];

            let (archive_path, archive_name) =
                self.allocate_unique_rollover_archive_path_locked()?;

            let _ = self.write_encrypted_segment_locked(
                &archive_path,
                archive_slice,
                Some(&archive_name),
            )?;
            let archive_token = self
                .tokenize_path(&archive_path)
                .unwrap_or_else(|_| "TOKENIZATION_UNAVAILABLE".to_string());
            self.record_audit_event(
                "SIEM_SPOOL_ROLLOVER_ARCHIVED",
                serde_json::json!({
                    "archive_segment_token": archive_token,
                    "archived_records": archive_slice.len(),
                    "active_records": active_slice.len(),
                    "retention_days": SIEM_RETENTION_DAYS,
                }),
            );

            self.write_encrypted_segment_locked(&self.spool_path, active_slice, None)? as u64
        } else {
            self.write_encrypted_segment_locked(&self.spool_path, records, None)? as u64
        };

        if pre_rollover_bytes >= high_watermark_bytes || active_bytes >= high_watermark_bytes {
            let observed = pre_rollover_bytes.max(active_bytes);
            let util_pct = observed
                .saturating_mul(100)
                .checked_div(self.max_spool_bytes)
                .unwrap_or(100);
            let spool_path_token = self
                .tokenize_path(&self.spool_path)
                .unwrap_or_else(|_| "TOKENIZATION_UNAVAILABLE".to_string());
            self.record_audit_event(
                "SIEM_SPOOL_HIGH_WATERMARK",
                serde_json::json!({
                    "observed_bytes": observed,
                    "capacity_bytes": self.max_spool_bytes,
                    "utilization_pct": util_pct,
                    "record_count": records.len(),
                    "mtls_enforced": self.is_mtls_enforced(),
                    "spool_path_token": spool_path_token,
                }),
            );
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
