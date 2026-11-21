#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::Semaphore;

use axum::body::Body;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use clap::{Parser, Subcommand};
use http::{header, HeaderMap, Request, StatusCode};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sentinel_cdr::policy::SanitizationPolicy;
use sentinel_cdr::worker::{WorkerLauncher, WorkerRequest};
use sentinel_core::enterprise::falcon::{CrowdStrikeFalconBridge, FalconTelemetryEvent};
use sentinel_core::enterprise::intune::{
    default_break_glass_nonce_store_path, default_enterprise_root_public_keys, BreakGlassToken,
    IntunePolicyManager, SignedPolicyBundle,
};
use sentinel_core::enterprise::kiosk::{verify_kiosk_passport, AirGappedKioskManager};
use sentinel_core::enterprise::ledger::{
    default_unified_ledger_path, get_or_init_global_shared_ledger, tokenize_path_for_ledger,
    AuditLedger, AuditSubsystem,
};
use sentinel_core::error::SentinelMetrics;
use sentinel_core::interceptor::drive_watcher::DriveWatcher;
use sentinel_core::interceptor::PendingDeviceConfirmationManager;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::secure_shredder::{
    validate_shred_receipt_fail_closed, SecureShredder, ShredMethod, ShredReceipt,
};
use sentinel_core::scanner::tier0_yara::Tier0YaraScanner;
use sentinel_core::scanner::tier3_sandbox::{SandboxDetonationRequest, Tier3SandboxConnector};
use sentinel_core::scanner::universal_scanner::{UniversalScanner, UniversalThreat};
use sentinel_sys::{verify_system_posture, write_mark_of_the_web};

#[derive(Parser)]
#[command(name = "sentinel")]
#[command(about = "OmniConnect Sentinel CLI - Universal Connection & CDR Scanner", long_about = None)]
struct Cli {
    /// Emit structured JSON logs with trace_id, device_id, file_sha256, stage, and duration_us (`Rows 33, 205`)
    #[arg(long, global = true, default_value_t = false)]
    json_logs: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sanitize a document or image using native Rust Deep CDR
    Sanitize {
        /// Path to input file (PDF, DOCX/XLSX/PPTX, JPEG, PNG, WebP, SVG, OLE2, TXT, CSV, ZIP)
        #[arg(short, long)]
        input: PathBuf,

        /// Path to write disarmed output file
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Inspect a file for polyglot overlays, ADS streams, YARA signatures, entropy, and risk markers
    Inspect {
        /// Path to file
        #[arg(short, long)]
        path: PathBuf,

        /// Emit structured JSON output instead of human-readable table
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Detonate an executable in the OpenSandbox microVM environment (behavioral analysis)
    Detonate {
        /// Path to target executable or payload
        #[arg(short, long)]
        path: PathBuf,

        /// MicroVM profile (e.g. win11-whvp-microvm, ubuntu22-kvm)
        #[arg(short, long, default_value = "win11-whvp-microvm")]
        vm: String,

        /// OpenSandbox endpoint (`https://...` with mTLS or `offline://opensandbox.local`)
        #[arg(short, long, default_value = "offline://opensandbox.local")]
        endpoint: String,
    },
    /// Scan an external drive or folder recursively for viruses, worms, and suspicious payloads
    ScanDrive {
        /// Target drive or directory path (e.g. E:\ or E:)
        #[arg(short, long)]
        path: PathBuf,

        /// Maximum regular files to inspect
        #[arg(short, long, default_value_t = 2000)]
        limit: usize,

        /// Enable interactive remediation prompt on threats
        #[arg(short, long, default_value_t = false)]
        interactive: bool,
    },
    /// Permanently shred a malicious file or carrier (NIST SP 800-88 Rev. 2 Clear)
    Shred {
        /// Target file path to permanently obliterate
        #[arg(short, long)]
        path: PathBuf,

        /// Number of overwrite passes (default: 3)
        #[arg(short = 'n', long, default_value_t = 3)]
        passes: u8,

        /// Best-effort unallocated free-space fill in parent directory after unlinking (Master Plan v2 §1.2)
        #[arg(long, default_value_t = false)]
        fill_free_space: bool,
    },
    /// Autonomous background sentry monitoring for removable drive insertions
    Watch {
        /// Polling interval in milliseconds
        #[arg(short = 'i', long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Launch the interactive Web & Native Rune Desktop Dashboard over 127.0.0.1 with session auth
    Ui {
        /// Port to serve the dashboard API on (binds strictly to 127.0.0.1)
        #[arg(short, long, default_value_t = 8088)]
        port: u16,

        /// Serve watermarked demo fixture data for sales demos (Master Plan v2 §4.3)
        #[arg(long, default_value_t = false)]
        demo: bool,

        /// Launch the native GPU-rendered Rune Framework desktop UI (`sentinel-ui`) instead of opening a browser
        #[arg(long, default_value_t = false)]
        native: bool,

        /// Start the localhost API server without auto-launching a browser or native window
        #[arg(long, default_value_t = false)]
        no_browser: bool,

        /// Optional explicitly allowlisted read-only kiosk intake root for POST /api/v1/scan (`CSE-17`)
        #[arg(long)]
        kiosk_intake_root: Option<PathBuf>,
    },
    /// Manage Microsoft Intune OMA-URI deployment profiles
    Intune {
        /// Export custom OMA-URI XML profile for Intune Admin Center
        #[arg(short, long)]
        export: Option<PathBuf>,
    },
    /// Emit sample CrowdStrike Falcon FDR / CEF Syslog telemetry (RFC 5425 TLS 1.3 port 6514)
    Telemetry {
        /// Event type (e.g. DeviceArrival, ExploitBlocked, FileSanitized)
        #[arg(short, long, default_value = "DeviceArrival")]
        event: String,

        /// RFC 5425 TLS 1.3 syslog endpoint (`host:6514` or `offline://...`; defaults to SENTINEL_SIEM_ENDPOINT or `offline://siem.omniconnect.local:6514`; port 514 prohibited)
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Manage the AEAD-encrypted SIEM CEF telemetry spool (`CSE-23`)
    Siem {
        #[command(subcommand)]
        action: SiemAction,
    },
    /// Run an Air-Gapped Kiosk session with posture verification, real scan + isolated CDR disarm,
    /// NIST SP 800-88 Rev. 2 session wipe & signed CDR Passport (`CSE-17`, `F-01`)
    Kiosk {
        /// Media serial number or identifier
        #[arg(short, long, default_value = "USB-MEDIA-SCADA-01")]
        media: String,

        /// Read-only untrusted intake directory to scan and disarm through isolated CDR (`CSE-17`)
        #[arg(long)]
        intake_dir: Option<PathBuf>,

        /// Optional sanitized export directory in which to write CDR-rebuilt outputs and .sentinel-passport.json
        #[arg(long)]
        export_dir: Option<PathBuf>,
    },
    /// Verify a detached ECDSA-P256 signed CDR Kiosk Passport (.sentinel-passport.json) and all sanitized files
    VerifyPassport {
        /// Optional positional path to sanitized export directory or .sentinel-passport.json
        #[arg(value_name = "TARGET")]
        target: Option<PathBuf>,

        /// Path to sanitized export directory or .sentinel-passport.json manifest
        #[arg(short = 'm', long = "manifest", alias = "path")]
        manifest: Option<PathBuf>,

        /// Optional pinned kiosk ECDSA P-256 public key file (hex, raw ECS1/SEC1, or PEM SPKI)
        #[arg(long = "pub-key", alias = "public-key")]
        pub_key: Option<PathBuf>,
    },
    /// Manage the AES-256-GCM Quarantine Vault (list, restore, migrate legacy entries)
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Verify the tamper-evident SHA-256 + ECDSA-P256 signed chain head Audit Ledger
    Ledger {
        #[command(subcommand)]
        action: LedgerAction,
    },
    /// Confirm physical user presence for a blocked composite/input USB device via challenge token
    ConfirmDevice {
        /// USB PnP Device Instance ID (e.g. USB\VID_1234&PID_5678\SN001)
        #[arg(long)]
        device_id: String,

        /// 128-bit hex user-presence confirmation challenge code or path to local .token file
        #[arg(long)]
        challenge: String,
    },
    /// Verify an ECDSA P-256 signed emergency break-glass token with expiry & nonce replay guard (`CSE-26`)
    BreakGlass {
        /// Path to ECDSA P-256 signed BreakGlassToken JSON file
        #[arg(short, long)]
        token: PathBuf,

        /// Optional custom pinned enterprise root public key file (raw ECS1/SEC1 or hex; defaults to pinned enterprise roots)
        #[arg(long)]
        root_key: Option<PathBuf>,

        /// Optional path to persistent break-glass nonce replay store
        #[arg(long)]
        nonce_store: Option<PathBuf>,

        /// Optional path to AuditLedger JSONL file (defaults to unified global ledger)
        #[arg(long)]
        ledger: Option<PathBuf>,
    },
    /// Verify an enterprise signed policy bundle against pinned root public keys (Master Plan v2 §4.2 Sub-Phase 0.4)
    PolicyVerify {
        /// Path to SignedPolicyBundle JSON file
        #[arg(short, long)]
        bundle: PathBuf,

        /// Optional custom root public key path (defaults to pinned enterprise roots)
        #[arg(long)]
        root_key: Option<PathBuf>,

        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,
    },
    /// Verify offline SOC RSA-3072+ OAEP escrow recovery package (top-level alias for `vault verify-escrow`)
    #[command(name = "vault-verify-escrow")]
    VaultVerifyEscrow {
        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,

        /// Path to the offline SOC RSA private key
        #[arg(long)]
        soc_priv_key: PathBuf,
    },
}

#[derive(Subcommand)]
enum VaultAction {
    /// List all quarantined artifacts in the vault
    List {
        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,
    },
    /// Authenticate, decrypt, and restore a quarantined artifact by entry ID
    Restore {
        /// Quarantine entry UUID
        #[arg(short, long)]
        id: String,

        /// Destination file path for the restored artifact
        #[arg(short, long)]
        output: PathBuf,

        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,
    },
    /// Mark legacy v1 key-less quarantine entries as UNRECOVERABLE_LEGACY and keep or delete them
    Migrate {
        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,

        /// Migration action for legacy entries: 'keep' (retain inert ciphertext) or 'delete' (shred)
        #[arg(long, default_value = "keep")]
        action: String,
    },
    /// Overwrite wrapped DEK and clear a quarantined artifact from the vault (NIST SP 800-88 Rev. 2 Clear)
    Purge {
        /// Quarantine entry UUID
        #[arg(short, long)]
        id: String,

        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,
    },
    /// Verify offline SOC RSA-3072+ OAEP escrow recovery package (vault_kek.escrow)
    VerifyEscrow {
        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,

        /// Path to the offline SOC RSA private key
        #[arg(long)]
        soc_priv_key: PathBuf,
    },
    /// Provision Hybrid Post-Quantum OCESCROW3 (RSA-3072 + FIPS 203 ML-KEM-768) recovery envelope
    ProvisionHybridEscrowV3 {
        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,

        /// Path to HybridSocPublicKeyBundle JSON file
        #[arg(long)]
        hybrid_pub_key: PathBuf,
    },
    /// Verify offline SOC Hybrid Post-Quantum OCESCROW3 (RSA-3072 + ML-KEM-768) recovery envelope
    VerifyHybridEscrowV3 {
        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,

        /// Path to HybridSocPrivateKeyBundle JSON file
        #[arg(long)]
        hybrid_priv_key: PathBuf,
    },
    /// Recover a broken TPM/DPAPI vault by decrypting `vault_kek.escrow` and atomically re-sealing `vault_kek.sealed` (`CSE-16`)
    RecoverEscrow {
        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,

        /// Path to the offline SOC RSA-3072+ private key file
        #[arg(long)]
        soc_priv_key: PathBuf,
    },
    /// Recover a broken TPM/DPAPI vault via Hybrid Post-Quantum OCESCROW3 (`RSA-3072` + `ML-KEM-768`) and atomically re-seal `vault_kek.sealed` (`CSE-16`)
    RecoverHybridEscrowV3 {
        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,

        /// Path to HybridSocPrivateKeyBundle JSON file
        #[arg(long)]
        hybrid_priv_key: PathBuf,
    },
}

#[derive(Subcommand)]
enum LedgerAction {
    /// Verify the cryptographic SHA-256 hash chain and ECDSA-P256 signed chain head of the audit ledger
    Verify {
        /// Path to audit ledger JSONL file (defaults to unified system audit ledger)
        #[arg(short, long)]
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SiemAction {
    /// Drain undelivered SIEM CEF records from the encrypted on-disk spool over RFC 5425 TLS 1.3 / mTLS (`CSE-23`)
    Flush {
        /// RFC 5425 TLS 1.3 syslog endpoint (`tls://host:6514`; defaults to SENTINEL_SIEM_ENDPOINT)
        #[arg(long)]
        endpoint: Option<String>,

        /// Optional explicit path to the encrypted SIEM spool file (`siem_spool.sealed`)
        #[arg(long)]
        spool_path: Option<PathBuf>,

        /// Operator-pinned internal RFC 1918 / IPv6 ULA SIEM CIDR(s) permitted for egress
        #[arg(long = "allow-private-cidr")]
        allow_private_cidrs: Vec<String>,

        /// Optional PEM client certificate path for TLS 1.3 mTLS
        #[arg(long)]
        client_cert_pem: Option<PathBuf>,

        /// Optional PEM client private key path for TLS 1.3 mTLS
        #[arg(long)]
        client_key_pem: Option<PathBuf>,

        /// Optional custom CA certificate PEM path for internal SIEM PKI
        #[arg(long)]
        custom_ca_pem: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let use_json_logs = cli.json_logs
        || std::env::var("SENTINEL_LOG_FORMAT")
            .map(|v| v.eq_ignore_ascii_case("json"))
            .unwrap_or(false);

    if use_json_logs {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("info"))
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("info"))
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    let root_trace_id = uuid::Uuid::new_v4().to_string();
    let _cli_span = tracing::info_span!(
        "sentinel_cli",
        trace_id = %root_trace_id,
        device_id = "LOCAL-HOST-NODE"
    )
    .entered();

    match cli.command {
        Commands::Sanitize { input, output } => {
            let started = Instant::now();
            info!(stage = "cdr_ingest", "Reading input file: {:?}", input);
            let input_bytes = fs::read(&input)?;
            let original_len = input_bytes.len();
            let file_sha256 = hex::encode(Sha256::digest(&input_bytes));
            let file_name = input
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("input.bin")
                .to_string();

            let policy = SanitizationPolicy::default();
            let launcher = WorkerLauncher::new();

            // Route CLI sanitization strictly through isolated sandboxed worker (`Invariant I3`)
            let outcome = launcher.sanitize_isolated(WorkerRequest {
                file_name,
                policy,
                raw_bytes: input_bytes,
            })?;
            fs::write(&output, &outcome.clean_bytes)?;

            // Apply Mark-of-the-Web (ZoneId=3) to released files and propagate errors (Phase 2.6, Row 136)
            write_mark_of_the_web(&output, 3)?;

            let duration_us = started.elapsed().as_micros() as u64;
            SentinelMetrics::global().record_cdr_processed(
                &format!("{:?}", outcome.detected_format),
                "sanitized",
                outcome.processing_time_ms,
            );

            info!(
                trace_id = %root_trace_id,
                device_id = "LOCAL-HOST-NODE",
                file_sha256 = %file_sha256,
                stage = "cdr_complete",
                duration_us = duration_us,
                "Sanitization successful!"
            );
            info!("  Format: {:?}", outcome.detected_format);
            info!("  Original Size: {} bytes", original_len);
            info!("  Cleaned Size:  {} bytes", outcome.clean_bytes.len());
            info!("  Elements Disarmed: {}", outcome.disarm_report.len());
            info!("  Processing Time:   {} ms", outcome.processing_time_ms);
            info!(
                "Clean file written to: {:?} (Mark-of-the-Web ZoneId=3 applied)",
                output
            );
        }
        Commands::Inspect { path, json } => {
            // Complete structural, polyglot, ADS, content, and YARA inspection via isolated worker (`BUG-CLI-02` #1, Invariant I3)
            let bytes = fs::read(&path)?;
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("target.bin");

            let launcher = WorkerLauncher::new();
            let inspection = launcher.inspect_isolated(&bytes, file_name)?;
            let yara = Tier0YaraScanner::new_with_persisted_offline_packs()
                .with_shared_ledger(get_or_init_global_shared_ledger(None));
            let yara_res = yara.scan_bytes(&bytes, &path.to_string_lossy());
            let threats = UniversalScanner::scan_file_checked(&path)?;

            if json {
                let payload = serde_json::json!({
                    "path": path,
                    "size_bytes": bytes.len(),
                    "detected_format": format!("{:?}", inspection.detected_format),
                    "true_mime_type": inspection.true_mime_type,
                    "entropy_score": inspection.entropy_score,
                    "is_malicious_polyglot": inspection.is_malicious_polyglot,
                    "cdr_risk_tags": inspection.risk_tags,
                    "tier0_yara": yara_res,
                    "universal_threats": threats,
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                println!("\n===========================================================");
                println!("         OMNICONNECT SENTINEL: DEEP FILE INSPECTION        ");
                println!("===========================================================");
                println!("File Path:              {path:?}");
                println!("File Size:              {} bytes", bytes.len());
                println!(
                    "Detected Format:        {:?} ({})",
                    inspection.detected_format, inspection.true_mime_type
                );
                println!(
                    "Shannon Entropy:        {:.2} bits/byte",
                    inspection.entropy_score
                );
                println!(
                    "Polyglot Verdict:       {}",
                    if inspection.is_malicious_polyglot {
                        "POLYGLOT DETECTED"
                    } else {
                        "Clean"
                    }
                );
                println!(
                    "CDR Risk Markers:       {}",
                    if !inspection.risk_tags.is_empty() {
                        format!("DETECTED ({})", inspection.risk_tags.join(", "))
                    } else {
                        "None".to_string()
                    }
                );
                println!(
                    "Tier-0 YARA Verdict:    {}",
                    if yara_res.matched {
                        format!(
                            "MATCHED [{}] ({})",
                            yara_res.rule_name.as_deref().unwrap_or("RULE"),
                            yara_res.threat_details.as_deref().unwrap_or("")
                        )
                    } else {
                        "Clean".to_string()
                    }
                );

                if threats.is_empty() {
                    println!("\n✅ Universal Deep Scanner: 0 threats found.");
                } else {
                    println!(
                        "\n🚨 Universal Deep Scanner Identified {} Threat(s):",
                        threats.len()
                    );
                    for (idx, t) in threats.iter().enumerate() {
                        println!(
                            "  {}. [{}] {} (Category: {:?}, Severity: {:?}, Score: {}/100, CDR-Disarmable: {})",
                            idx + 1,
                            t.mitre_technique,
                            t.threat_name,
                            t.carrier_category,
                            t.severity,
                            t.risk_score,
                            t.can_disarm_via_cdr
                        );
                        println!("     Details: {}", t.technical_details);
                    }
                }
            }
        }
        Commands::Detonate { path, vm, endpoint } => {
            info!(
                "Reading target binary for OpenSandbox detonation: {:?}",
                path
            );
            let bytes = fs::read(&path)?;
            let file_name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let sha256_hex = hex::encode(hasher.finalize());

            let trimmed_sand_ep = endpoint.trim();
            let lower_sand_ep = trimmed_sand_ep.to_ascii_lowercase();
            if !(lower_sand_ep.starts_with("https://") || lower_sand_ep.starts_with("offline://")) {
                return Err(format!(
                    "Rejected insecure sandbox endpoint '{trimmed_sand_ep}': https:// (mTLS) or offline:// is required"
                )
                .into());
            }
            let shared_ledger = get_or_init_global_shared_ledger(None);
            let client = Tier3SandboxConnector::new(trimmed_sand_ep, "LOCAL-KEY")
                .with_shared_ledger(shared_ledger);
            let req = SandboxDetonationRequest {
                file_name: file_name.clone(),
                sha256_hex: sha256_hex.clone(),
                file_bytes: bytes,
                timeout_seconds: 60,
            };

            let report = client.detonate_sample(req).await?;
            println!("\n===========================================================");
            println!("       OPENSANDBOX BEHAVIORAL DETONATION REPORT           ");
            println!("===========================================================");
            println!("Analysis ID:            {}", report.analysis_id);
            println!("File Name:              {file_name}");
            println!("SHA256:                 {sha256_hex}");
            println!(
                "Verdict:                {}",
                if report.verdict_malicious {
                    "MALICIOUS"
                } else {
                    "CLEAN / BENIGN"
                }
            );
            println!("Threat Score:           {}/100", report.threat_score);
            println!(
                "Threat Family:          {}",
                report.threat_family.as_deref().unwrap_or("None")
            );
            println!("VM Profile:             {vm}");
            println!("Containment Mode:       Air-Gapped Network Sinkhole");
            println!(
                "Engine Execution:       {}",
                if report.is_emulated {
                    "Deterministic Static/Heuristic Emulation (Offline Fallback — is_emulated=true)"
                } else {
                    "Live MicroVM (WHVP/QEMU)"
                }
            );

            if !report.mitre_attack_ttps.is_empty() {
                println!("\n🎯 [MITRE ATT&CK TECHNIQUES IDENTIFIED]");
                for t in &report.mitre_attack_ttps {
                    println!("   • {t}");
                }
            }

            if !report.behavioral_indicators.is_empty() {
                println!("\n🌲 [BEHAVIORAL INDICATORS]");
                for ind in &report.behavioral_indicators {
                    println!("   • {ind}");
                }
            }

            if !report.network_iocs.is_empty() {
                println!("\n🌐 [EXTRACTED NON-PKI NETWORK IOCS]");
                for url in &report.network_iocs {
                    println!("   • {url}");
                }
            }
        }
        Commands::ScanDrive {
            path,
            limit,
            interactive,
        } => {
            info!("===========================================================");
            info!("   OmniConnect Sentinel - Universal Threat & Drive Scanner ");
            info!(
                "   Scanning Target: {:?} (Limit: {} files, Interactive: {})",
                path, limit, interactive
            );
            info!("===========================================================");

            // Fail-closed directory scan (`BUG-CORE-14`) without hardcoded 229,376-byte Ramnit false-positives (`BUG-CORE-10`)
            let scan_report = UniversalScanner::scan_directory_detailed(&path, limit);

            for t in &scan_report.threats {
                println!(
                    "🚨 [THREAT DETECTED]: {:?} -> {} (Severity: {:?}, Score: {}/100)",
                    t.file_path, t.threat_name, t.severity, t.risk_score
                );
            }

            for err in &scan_report.errors {
                println!("⚠️ [SCAN ACCESS ERROR]: {:?} -> {}", err.path, err.reason);
            }

            println!("\n===========================================================");
            println!("                 SCAN RESULTS & THREAT REPORT              ");
            println!("===========================================================");
            println!("Regular Files Scanned:      {}", scan_report.files_scanned);
            println!("Inaccessible / Walk Errors: {}", scan_report.errors.len());
            println!("File Limit Reached:         {}", scan_report.limit_reached);
            println!(
                "Scan Completeness Verdict:  {}",
                if scan_report.complete {
                    "COMPLETE (100% of reachable regular files verified)"
                } else {
                    "INCOMPLETE (Fail-Closed: review walk errors or increase --limit)"
                }
            );
            println!("Universal Threats Found:    {}", scan_report.threats.len());

            if interactive && !scan_report.threats.is_empty() {
                println!("\n🚨 [INTERACTIVE REMEDIATION ENGAGED]");
                // Instantiate QuarantineVault ONCE outside the remediation loop (`BUG-CORE-02`, Invariant I4)
                let shared_ledger = get_or_init_global_shared_ledger(None);
                let vault = QuarantineVault::open(PathBuf::from(".sentinel_vault"))?
                    .with_shared_ledger(shared_ledger);
                println!(
                    "Prompting for remediation on {} discovered threat(s)...",
                    scan_report.threats.len()
                );
                for threat in &scan_report.threats {
                    prompt_remediation(threat, &vault)?;
                }
            } else if !scan_report.threats.is_empty() {
                println!("\n🚨 Run with --interactive to interactively shred or quarantine detected threats.");
            } else if scan_report.complete {
                println!("\n✅ No hidden threats, polyglots, or malicious carrier vectors found on drive.");
            }
        }
        Commands::Shred {
            path,
            passes,
            fill_free_space,
        } => {
            let shared_ledger = get_or_init_global_shared_ledger(None);
            execute_shred_command(&path, passes, fill_free_space, Some(&shared_ledger), 0)?;
        }
        Commands::Watch { interval_ms } => {
            println!("===========================================================");
            println!("      OMNICONNECT SENTINEL: AUTONOMOUS DRIVE SENTRY        ");
            println!("===========================================================");
            println!(
                "Actively monitoring for removable media insertions (Interval: {interval_ms} ms)..."
            );
            println!("Press Ctrl+C to terminate sentinel sentry.\n");

            let shared_ledger = get_or_init_global_shared_ledger(None);
            let vault = std::sync::Arc::new(
                QuarantineVault::open(PathBuf::from(".sentinel_vault"))?
                    .with_shared_ledger(shared_ledger),
            );
            let mut watcher = DriveWatcher::new();
            watcher
                .watch_loop(move |drive_root| {
                    println!(
                        "\n🚨 [EXTERNAL DRIVE DETECTED]: Removable Media connected at {drive_root:?}"
                    );
                    let report = UniversalScanner::scan_directory_detailed(&drive_root, 2000);
                    if report.threats.is_empty() && report.complete {
                        println!(
                            "✅ Drive {:?} scanned cleanly ({} files).",
                            drive_root, report.files_scanned
                        );
                    } else {
                        println!(
                            "🚨 FOUND {} POTENTIAL THREAT(S) ON DRIVE {:?} (Complete: {})",
                            report.threats.len(),
                            drive_root,
                            report.complete
                        );
                        for threat in &report.threats {
                            if let Err(e) = prompt_remediation(threat, &vault) {
                                eprintln!("❌ Remediation error: {e}");
                            }
                        }
                    }
                })
                .await;
        }
        Commands::Ui {
            port,
            demo,
            native,
            no_browser,
            kiosk_intake_root,
        } => {
            // Serve the dashboard over localhost (127.0.0.1:{port}) with session auth & live /api/v1/status (`BUG-CLI-02` #2)
            serve_dashboard_ui(port, demo, native, no_browser, kiosk_intake_root).await?;
        }
        Commands::Intune { export } => {
            let shared_ledger = get_or_init_global_shared_ledger(None);
            let mut mgr = IntunePolicyManager::new().with_shared_ledger(shared_ledger);
            let policy = mgr.load_active_policy();
            println!("\n===========================================================");
            println!("       MICROSOFT INTUNE CUSTOM CSP POLICY PROFILE          ");
            println!("===========================================================");
            println!("Policy ID:                   {}", policy.policy_id);
            println!("Policy Version:              {}", policy.version);
            println!(
                "Enforce USB Zero-Trust:      {}",
                policy.enforce_usb_zero_trust
            );
            println!(
                "Block Composite HID+Storage: {}",
                policy.block_composite_hid_storage
            );
            println!(
                "Require CDR for Documents:   {}",
                policy.require_cdr_for_documents
            );
            println!(
                "Max Sanitization File Size:  {} MB",
                policy.max_sanitization_file_size_mb
            );
            println!(
                "Allowed Hardware IDs:        {:?}",
                policy.allowed_hardware_ids
            );
            println!("Enforcement Mode:            {}", policy.enforcement_mode);

            if let Some(out_path) = export {
                let xml = mgr.export_oma_uri_profile_xml();
                fs::write(&out_path, &xml)?;
                println!("\n✅ Exported XML-escaped Intune OMA-URI profile to: {out_path:?}");
            } else {
                println!("\n💡 Tip: Use --export <PATH.xml> to save the deployment profile.");
            }
        }
        Commands::PolicyVerify {
            bundle,
            root_key,
            vault_dir,
        } => {
            let bundle_json = fs::read_to_string(&bundle)?;
            let signed_bundle: SignedPolicyBundle = serde_json::from_str(&bundle_json)?;

            let mut mgr = IntunePolicyManager::new().with_vault_dir(vault_dir);
            if let Some(rk_path) = root_key {
                let rk_bytes = fs::read(rk_path)?;
                mgr = mgr.with_pinned_root_public_keys(vec![rk_bytes]);
            }

            match mgr.apply_signed_bundle(&signed_bundle) {
                Ok(pol) => {
                    println!("\n===========================================================");
                    println!("             POLICY VERIFICATION SUCCEEDED                 ");
                    println!("===========================================================");
                    println!("Policy ID:                   {}", pol.policy_id);
                    println!("Policy Version:              {}", pol.version);
                    println!(
                        "Enforce USB Zero-Trust:      {}",
                        pol.enforce_usb_zero_trust
                    );
                    println!(
                        "Block Composite HID+Storage: {}",
                        pol.block_composite_hid_storage
                    );
                    println!(
                        "Require CDR for Documents:   {}",
                        pol.require_cdr_for_documents
                    );
                    println!(
                        "Max Sanitization Size:       {} MB",
                        pol.max_sanitization_file_size_mb
                    );
                    println!(
                        "Allowed Hardware IDs:        {:?}",
                        pol.allowed_hardware_ids
                    );
                    println!("Enforcement Mode:            {}", pol.enforcement_mode);
                    println!("\n✅ Enterprise signature and anti-rollback verified successfully.");
                }
                Err(err) => {
                    eprintln!("\n❌ [POLICY VERIFICATION REJECTED]: {err}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Telemetry { event, endpoint } => {
            let resolved_ep =
                endpoint.unwrap_or_else(sentinel_core::config::default_siem_syslog_endpoint);
            let trimmed_ep = resolved_ep.trim();
            if let Err(err) = CrowdStrikeFalconBridge::validate_syslog_endpoint(trimmed_ep) {
                return Err(
                    format!("Rejected insecure SIEM endpoint '{trimmed_ep}': {err}").into(),
                );
            }
            let mut parsed_cidrs = Vec::new();
            for c in sentinel_core::config::default_siem_allowed_private_cidrs() {
                parsed_cidrs.push(
                    sentinel_core::enterprise::falcon::AllowedCidr::parse(&c)
                        .map_err(|e| format!("Invalid SIEM allowed private CIDR '{c}': {e}"))?,
                );
            }
            let shared_ledger = get_or_init_global_shared_ledger(None);
            let mut bridge = CrowdStrikeFalconBridge::new(trimmed_ep)
                .with_shared_ledger(shared_ledger)
                .with_allowed_private_cidrs(parsed_cidrs);
            if let Some(ca_path) = sentinel_core::config::default_siem_ca_cert_path() {
                sentinel_sys::ensure_not_symlink_or_reparse_point(&ca_path)?;
                bridge = bridge.with_custom_ca(fs::read(&ca_path)?);
            }
            match (
                sentinel_core::config::default_siem_client_cert_path(),
                sentinel_core::config::default_siem_client_key_path(),
            ) {
                (Some(cert_path), Some(key_path)) => {
                    sentinel_sys::ensure_not_symlink_or_reparse_point(&cert_path)?;
                    sentinel_sys::ensure_not_symlink_or_reparse_point(&key_path)?;
                    bridge = bridge.with_client_mtls(fs::read(&cert_path)?, fs::read(&key_path)?);
                }
                (Some(_), None) | (None, Some(_)) => {
                    return Err(
                        "MTLS_CONFIG_ERROR: Both SENTINEL_SIEM_CLIENT_CERT_PEM and SENTINEL_SIEM_CLIENT_KEY_PEM must be supplied together"
                            .into(),
                    );
                }
                (None, None) => {}
            }
            let ev = FalconTelemetryEvent {
                severity: 9,
                signature_id: format!("SENTINEL-{}", event.to_uppercase()),
                name: format!("OmniConnect Sentinel Peripheral Event ({event})"),
                device_vendor_id: "0x0781".to_string(),
                device_product_id: "0x5581".to_string(),
                serial_number: "SN-EDGE-WIN11-01".to_string(),
                file_sha256: Some(
                    "7efc45df51d52223415b08c77a0828128b517288c81661e2a9a8109804cbb0c6".to_string(),
                ),
                action_taken: "ENCRYPTED_AND_QUARANTINED".to_string(),
                details: "Zero-Trust peripheral policy enforcement telemetry".to_string(),
            };

            println!("\n===========================================================");
            println!("     CROWDSTRIKE FALCON / SIEM CEF TELEMETRY STREAM        ");
            println!("===========================================================");
            println!("CEF v0 Payload:\n{}\n", bridge.format_cef_payload(&ev));
            bridge.emit_alert(&ev)?;
        }
        Commands::Siem { action } => match action {
            SiemAction::Flush {
                endpoint,
                spool_path,
                allow_private_cidrs,
                client_cert_pem,
                client_key_pem,
                custom_ca_pem,
            } => {
                let resolved_ep =
                    endpoint.unwrap_or_else(sentinel_core::config::default_siem_syslog_endpoint);
                let trimmed_ep = resolved_ep.trim();
                if let Err(err) = CrowdStrikeFalconBridge::validate_syslog_endpoint(trimmed_ep) {
                    return Err(
                        format!("Rejected insecure SIEM endpoint '{trimmed_ep}': {err}").into(),
                    );
                }

                let mut parsed_cidrs = Vec::new();
                let raw_cidrs = if allow_private_cidrs.is_empty() {
                    sentinel_core::config::default_siem_allowed_private_cidrs()
                } else {
                    allow_private_cidrs
                };
                for c in &raw_cidrs {
                    parsed_cidrs.push(
                        sentinel_core::enterprise::falcon::AllowedCidr::parse(c)
                            .map_err(|e| format!("Invalid --allow-private-cidr '{c}': {e}"))?,
                    );
                }

                let shared_ledger = get_or_init_global_shared_ledger(None);
                let mut bridge = match spool_path {
                    Some(sp) => CrowdStrikeFalconBridge::with_spool_path(trimmed_ep, sp),
                    None => CrowdStrikeFalconBridge::new(trimmed_ep),
                }
                .with_shared_ledger(shared_ledger)
                .with_allowed_private_cidrs(parsed_cidrs);

                if let Some(ca_path) =
                    custom_ca_pem.or_else(sentinel_core::config::default_siem_ca_cert_path)
                {
                    sentinel_sys::ensure_not_symlink_or_reparse_point(&ca_path)?;
                    bridge = bridge.with_custom_ca(fs::read(&ca_path)?);
                }
                let cert_opt =
                    client_cert_pem.or_else(sentinel_core::config::default_siem_client_cert_path);
                let key_opt =
                    client_key_pem.or_else(sentinel_core::config::default_siem_client_key_path);
                match (cert_opt, key_opt) {
                    (Some(cert_path), Some(key_path)) => {
                        sentinel_sys::ensure_not_symlink_or_reparse_point(&cert_path)?;
                        sentinel_sys::ensure_not_symlink_or_reparse_point(&key_path)?;
                        bridge =
                            bridge.with_client_mtls(fs::read(&cert_path)?, fs::read(&key_path)?);
                    }
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(
                            "MTLS_CONFIG_ERROR: Both --client-cert-pem and --client-key-pem must be supplied together"
                                .into(),
                        );
                    }
                    (None, None) => {}
                }

                let flushed = bridge.flush_spool()?;
                println!("\n===========================================================");
                println!("              SIEM SPOOL FLUSH COMPLETE (`CSE-23`)          ");
                println!("===========================================================");
                println!("Endpoint:        {trimmed_ep}");
                println!("mTLS Enforced:   {}", bridge.is_mtls_enforced());
                println!("Flushed Records: {flushed}");
            }
        },
        Commands::Kiosk {
            media,
            intake_dir,
            export_dir,
        } => {
            if !sentinel_core::enterprise::kiosk::is_valid_media_id(&media) {
                return Err(format!(
                    "Invalid media_id '{media}': must match ^[A-Za-z0-9_-]{{1,64}}$"
                )
                .into());
            }
            let scratch = {
                #[cfg(test)]
                {
                    std::env::temp_dir().join("sentinel_kiosk_scratch")
                }
                #[cfg(not(test))]
                {
                    resolve_restricted_runtime_dir("KioskScratch", ".sentinel_kiosk_scratch")
                }
            };
            let shared_ledger = get_or_init_global_shared_ledger(None);
            let mut kiosk = AirGappedKioskManager::from_terminal_id(
                "KIOSK-TERMINAL-SCADA-01".to_string(),
                scratch.clone(),
            )
            .with_shared_ledger(shared_ledger.clone());

            println!("\n===========================================================");
            println!("          AIR-GAPPED INDUSTRIAL KIOSK SESSION              ");
            println!("===========================================================");
            let posture = kiosk.verify_posture();
            println!(
                "OS Write-Blocker Policy Status: {}",
                if posture.write_protect_active {
                    "ACTIVE & ENGAGED (StorageDevicePolicies WriteProtect=1)"
                } else {
                    "NOT SET IN REGISTRY (Non-Compliant)"
                }
            );
            println!(
                "{}",
                AirGappedKioskManager::format_hardware_write_blocker_banner(
                    &posture.hardware_write_blocker
                )
            );

            // Enforce strict endpoint posture gate before starting session (`Row 22`, `High #18`)
            let session_id = kiosk.begin_kiosk_session_with_posture(&posture)?;
            let rel_media_enc = PathBuf::from(&session_id).join("media_manifest.enc");
            let session_dir = kiosk.write_encrypted_session_file(
                &rel_media_enc,
                format!("MEDIA={media} SESSION={session_id}").as_bytes(),
            )?;
            let _verified = kiosk.read_encrypted_session_file(&rel_media_enc)?;

            println!("Session ID:                     {session_id}");
            println!("Ephemeral Session Workspace:    {session_dir:?}");

            if intake_dir.is_some() || export_dir.is_some() {
                let mut intune =
                    IntunePolicyManager::new().with_shared_ledger(shared_ledger.clone());
                let pol = intune.load_active_policy();
                let vault = QuarantineVault::open(PathBuf::from(".sentinel_vault"))?
                    .with_shared_ledger(shared_ledger.clone());
                let launcher = WorkerLauncher::new();
                let pipeline_res = execute_kiosk_intake_and_export(
                    &kiosk,
                    &vault,
                    &launcher,
                    &KioskPipelineParams {
                        intake_dir: intake_dir.as_deref(),
                        export_dir: export_dir.as_deref(),
                        media_id: &media,
                        policy_id: &pol.policy_id,
                        policy_sequence: pol.version as u64,
                        max_files: 2000,
                    },
                );
                let wiped_files = kiosk.end_session_and_shred()?;
                println!(
                    "NIST SP 800-88 Rev. 2 Wipe:     COMPLETED ({wiped_files} session files shredded)"
                );
                let summary = pipeline_res?;
                println!(
                    "Files Scanned & CDR-Rebuilt:    {} file(s) (0 threats)",
                    summary.files_sanitized
                );
                if let Some(passport) = summary.passport {
                    println!(
                        "Signed CDR Passport Emitted:    {} ({} sanitized files)",
                        passport.passport_id,
                        passport.sanitized_files.len()
                    );
                }
            } else {
                let wiped_files = kiosk.end_session_and_shred()?;
                println!(
                    "NIST SP 800-88 Rev. 2 Wipe:     COMPLETED ({wiped_files} session files shredded)"
                );
            }

            println!(
                "Kiosk Posture State:            {}",
                format_honest_kiosk_posture_label(&posture)
            );
            println!();
        }
        Commands::VerifyPassport {
            target,
            manifest,
            pub_key,
        } => {
            let resolved_target = manifest.or(target).ok_or_else(|| {
                "Must specify sanitized export directory or --manifest <path> for verify-passport"
                    .to_string()
            })?;
            let trusted_pub = match pub_key {
                Some(pk_path) => Some(fs::read(&pk_path).map_err(|e| {
                    format!(
                        "Failed reading trusted public key '{}': {e}",
                        pk_path.display()
                    )
                })?),
                None => None,
            };
            match verify_kiosk_passport(&resolved_target, trusted_pub.as_deref()) {
                Ok(passport) => {
                    println!("\n===========================================================");
                    println!("       OMNICONNECT SENTINEL: CDR PASSPORT VERIFIED         ");
                    println!("===========================================================");
                    println!("Passport ID:       {}", passport.passport_id);
                    println!("Kiosk Terminal:    {}", passport.kiosk_id);
                    println!("Media ID:          {}", passport.media_id);
                    println!(
                        "Policy Binding:    {} (seq={})",
                        passport.policy_id, passport.policy_sequence
                    );
                    println!(
                        "NTP Clock Sync:    {} ({})",
                        passport.ntp_sync.ntp_synchronized, passport.ntp_sync.clock_source
                    );
                    println!("Binary Exe SHA256: {}", passport.binary_exe_sha256);
                    println!(
                        "Binary .dep-v0:    {}",
                        passport
                            .binary_dep_v0_sha256
                            .as_deref()
                            .unwrap_or("NONE (non-auditable build)")
                    );
                    println!(
                        "Verified Files:    {} file(s) intact (ECDSA-P256-SHA256 valid)",
                        passport.sanitized_files.len()
                    );
                    println!(
                        "✅ CDR Passport signature and all sanitized file SHA-256 hashes verified!"
                    );
                }
                Err(err) => {
                    eprintln!("❌ [CDR PASSPORT VERIFICATION FAILED]: {err}");
                    std::process::exit(1);
                }
            }
        }
        Commands::VaultVerifyEscrow {
            vault_dir,
            soc_priv_key,
        } => {
            execute_verify_escrow(&vault_dir, &soc_priv_key)?;
        }
        Commands::Vault { action } => match action {
            VaultAction::List { vault_dir } => {
                let shared_ledger = get_or_init_global_shared_ledger(None);
                let vault = QuarantineVault::open(vault_dir)?.with_shared_ledger(shared_ledger);
                let entries = vault.list()?;
                println!("\n===========================================================");
                println!("         OMNICONNECT SENTINEL: QUARANTINE VAULT            ");
                println!("===========================================================");
                println!(
                    "KEK ID:      {} (Posture: {:?})",
                    vault.kek_id(),
                    vault.key_posture()
                );
                println!("Total Items: {}\n", entries.len());
                for e in entries {
                    println!(
                        "• [{}] {} ({} bytes, SHA256: {}, Status: {})",
                        e.entry_id,
                        e.original_path,
                        e.original_size_bytes,
                        e.original_sha256,
                        e.recovery_status
                    );
                }
            }
            VaultAction::Restore {
                id,
                output,
                vault_dir,
            } => {
                let shared_ledger = get_or_init_global_shared_ledger(None);
                let vault = QuarantineVault::open(vault_dir)?.with_shared_ledger(shared_ledger);
                let restored = vault.restore_file(&id, &output)?;
                println!("✅ Restored quarantine entry '{id}' to {restored:?}");
            }
            VaultAction::Migrate { vault_dir, action } => {
                use sentinel_core::scanner::quarantine::LegacyMigrationAction;
                let shared_ledger = get_or_init_global_shared_ledger(None);
                let vault = QuarantineVault::open(vault_dir)?.with_shared_ledger(shared_ledger);
                let migrate_action = if action.eq_ignore_ascii_case("delete") {
                    LegacyMigrationAction::Delete
                } else {
                    LegacyMigrationAction::Keep
                };
                let migrated_ids = vault.migrate_legacy_entries_with_action(migrate_action)?;
                println!(
                    "✅ Migrated {} legacy v1 quarantine artifact(s) as UNRECOVERABLE_LEGACY (action: {:?}).",
                    migrated_ids.len(),
                    migrate_action
                );
            }
            VaultAction::Purge { id, vault_dir } => {
                let shared_ledger = get_or_init_global_shared_ledger(None);
                let vault = QuarantineVault::open(vault_dir)?.with_shared_ledger(shared_ledger);
                vault.purge(&id)?;
                println!(
                    "✅ Overwrote wrapped DEK and cleared quarantine entry '{id}' (NIST SP 800-88 Rev. 2 Clear)."
                );
            }
            VaultAction::VerifyEscrow {
                vault_dir,
                soc_priv_key,
            } => {
                execute_verify_escrow(&vault_dir, &soc_priv_key)?;
            }
            VaultAction::ProvisionHybridEscrowV3 {
                vault_dir,
                hybrid_pub_key,
            } => {
                let shared_ledger = get_or_init_global_shared_ledger(None);
                let vault = QuarantineVault::open(vault_dir)?.with_shared_ledger(shared_ledger);
                let raw_pub = fs::read(&hybrid_pub_key)?;
                let pub_bundle: sentinel_sys::HybridSocPublicKeyBundle =
                    serde_json::from_slice(&raw_pub)
                        .map_err(|e| format!("Invalid HybridSocPublicKeyBundle JSON: {e}"))?;
                let escrow_v3 = vault.provision_hybrid_soc_escrow_v3(&pub_bundle)?;
                println!("✅ Provisioned Hybrid Post-Quantum OCESCROW3 envelope!");
                println!("   KEK ID:             {}", escrow_v3.kek_id);
                println!("   Algorithm:          {}", escrow_v3.algorithm);
                println!("   RSA Fingerprint:    {}", escrow_v3.soc_rsa_fingerprint);
                println!(
                    "   ML-KEM Fingerprint: {}",
                    escrow_v3.soc_mlkem768_fingerprint
                );
            }
            VaultAction::VerifyHybridEscrowV3 {
                vault_dir,
                hybrid_priv_key,
            } => {
                let escrow_path = vault_dir
                    .join(sentinel_core::scanner::quarantine::HYBRID_ESCROW_V3_JSON_FILENAME);
                if !escrow_path.exists() {
                    return Err(
                        format!("OCESCROW3 file not found: {}", escrow_path.display()).into(),
                    );
                }
                let raw_escrow = fs::read(&escrow_path)?;
                let mut escrow_v3: sentinel_sys::HybridSocEscrowBlobV3 =
                    serde_json::from_slice(&raw_escrow)
                        .map_err(|e| format!("Failed parsing OCESCROW3 JSON: {e}"))?;

                let wire_path = vault_dir
                    .join(sentinel_core::scanner::quarantine::HYBRID_ESCROW_V3_WIRE_FILENAME);
                if !wire_path.exists() {
                    return Err(format!(
                        "OCESCROW3 binary wire file not found: {}",
                        wire_path.display()
                    )
                    .into());
                }
                let disk_wire = fs::read(&wire_path)?;
                if disk_wire != escrow_v3.ocescrow3_wire_bytes {
                    return Err(
                        "OCESCROW3 verification failed: binary wire file diverges from JSON metadata (tampering detected)"
                            .into(),
                    );
                }
                escrow_v3.ocescrow3_wire_bytes = disk_wire;

                let mut raw_priv = fs::read(&hybrid_priv_key)?;
                let priv_bundle_res =
                    serde_json::from_slice::<sentinel_sys::HybridSocPrivateKeyBundle>(&raw_priv);
                sentinel_sys::zeroize_slice(&mut raw_priv);
                let priv_bundle = priv_bundle_res
                    .map_err(|e| format!("Failed parsing HybridSocPrivateKeyBundle: {e}"))?;
                let mut kek =
                    sentinel_sys::decrypt_kek_from_soc_escrow_hybrid_v3(&escrow_v3, &priv_bundle)
                        .map_err(|e| format!("OCESCROW3 decapsulation failed: {e}"))?;
                let mut hasher = Sha256::new();
                hasher.update(b"SENTINEL-KEK-ID-V2:");
                hasher.update(kek.as_slice());
                let computed_id = &hex::encode(hasher.finalize())[..16];
                sentinel_sys::zeroize_slice(&mut kek);
                if computed_id != escrow_v3.kek_id {
                    return Err(format!(
                        "OCESCROW3 verification failed: computed KEK ID '{computed_id}' != '{}'",
                        escrow_v3.kek_id
                    )
                    .into());
                }
                println!("✅ Offline SOC Hybrid Post-Quantum OCESCROW3 verified successfully!");
                println!("   KEK ID:             {}", escrow_v3.kek_id);
                println!("   Algorithm:          {}", escrow_v3.algorithm);
                println!("   RSA Fingerprint:    {}", escrow_v3.soc_rsa_fingerprint);
                println!(
                    "   ML-KEM Fingerprint: {}",
                    escrow_v3.soc_mlkem768_fingerprint
                );
            }
            VaultAction::RecoverEscrow {
                vault_dir,
                soc_priv_key,
            } => {
                let shared_ledger = get_or_init_global_shared_ledger(None);
                execute_recover_escrow(&vault_dir, &soc_priv_key, Some(shared_ledger))?;
            }
            VaultAction::RecoverHybridEscrowV3 {
                vault_dir,
                hybrid_priv_key,
            } => {
                let shared_ledger = get_or_init_global_shared_ledger(None);
                execute_recover_hybrid_escrow_v3(
                    &vault_dir,
                    &hybrid_priv_key,
                    Some(shared_ledger),
                )?;
            }
        },
        Commands::Ledger { action } => match action {
            LedgerAction::Verify { path } => {
                let resolved_path = path.unwrap_or_else(default_unified_ledger_path);
                let ledger = AuditLedger::open_result(resolved_path.clone())?;
                let verified_count = ledger.verify_chain()?;
                println!(
                    "✅ Audit ledger {resolved_path:?} verified intact ({verified_count} hash-chained records + ECDSA-P256 signed chain head)."
                );
            }
        },
        Commands::ConfirmDevice {
            device_id,
            challenge,
        } => {
            let trimmed = challenge.trim();
            let resolved_token = if Path::new(trimmed).is_file() {
                fs::read_to_string(trimmed)
                    .map_err(|e| format!("Failed to read challenge token file {trimmed}: {e}"))?
                    .trim()
                    .to_string()
            } else {
                trimmed.to_string()
            };
            let mgr = PendingDeviceConfirmationManager::new(
                PendingDeviceConfirmationManager::default_state_file(),
            );
            mgr.confirm_device_with_challenge(&device_id, &resolved_token)?;
            let shared_ledger = get_or_init_global_shared_ledger(None);
            if let Ok(mut ledger) = shared_ledger.lock() {
                let _ = ledger.append_subsystem_event(
                    AuditSubsystem::System,
                    "DEVICE_CONFIRMED_BY_USER",
                    serde_json::json!({
                        "message": format!("Device {device_id} authorized via physical user-presence challenge")
                    }),
                );
            }
            println!(
                "✅ Physical user-presence challenge verified. Re-enabled USB device node: {device_id}"
            );
        }
        Commands::BreakGlass {
            token,
            root_key,
            nonce_store,
            ledger,
        } => {
            let token_file =
                sentinel_sys::open_untrusted_readonly_nofollow(&token).map_err(|e| {
                    format!(
                        "Failed opening break-glass token '{}': {e}",
                        token.display()
                    )
                })?;
            let mut token_file = token_file;
            let token_bytes =
                sentinel_sys::read_untrusted_to_end_bounded(&mut token_file, 256 * 1024).map_err(
                    |e| {
                        format!(
                            "Failed reading break-glass token '{}': {e}",
                            token.display()
                        )
                    },
                )?;
            let parsed_token: BreakGlassToken = serde_json::from_slice(&token_bytes)
                .map_err(|e| format!("Invalid BreakGlassToken JSON: {e}"))?;

            let trusted_roots = if let Some(rk_path) = root_key {
                let raw_rk = fs::read(&rk_path).map_err(|e| {
                    format!(
                        "Failed reading break-glass root public key '{}': {e}",
                        rk_path.display()
                    )
                })?;
                // Support both raw 72-byte ECS1 / 65-byte SEC1 binary blobs and hex-encoded public key files
                let decoded_rk = if raw_rk.len() == 72 || raw_rk.len() == 65 {
                    raw_rk
                } else {
                    let trimmed_hex = String::from_utf8_lossy(&raw_rk).trim().to_string();
                    hex::decode(&trimmed_hex).map_err(|e| {
                        format!(
                            "Root public key '{}' is neither raw ECS1/SEC1 nor valid hex: {e}",
                            rk_path.display()
                        )
                    })?
                };
                vec![decoded_rk]
            } else {
                default_enterprise_root_public_keys()
            };

            let resolved_nonce_store =
                nonce_store.unwrap_or_else(default_break_glass_nonce_store_path);
            let now_unix = sentinel_sys::now_unix_secs();
            let shared_ledger = if let Some(ledger_path) = ledger {
                sentinel_core::enterprise::ledger::create_shared_audit_ledger(&ledger_path)?
            } else {
                get_or_init_global_shared_ledger(None)
            };

            match parsed_token.verify(&trusted_roots, &resolved_nonce_store, now_unix) {
                Ok(outcome) => {
                    if let Some(ref dev_id) = outcome.target_device_id {
                        sentinel_sys::enable_device_node(dev_id).map_err(|e| {
                            format!(
                                "Break-glass token '{}' verified, but OS enable_device_node('{dev_id}') failed: {e}",
                                outcome.token_id
                            )
                        })?;
                    }
                    if let Ok(mut guard) = shared_ledger.lock() {
                        let _ = guard.append_subsystem_event(
                            AuditSubsystem::System,
                            "BREAK_GLASS_ACTIVATED",
                            serde_json::json!({
                                "token_id": outcome.token_id,
                                "operator_id": outcome.operator_id,
                                "incident_ticket": outcome.incident_ticket,
                                "scope": outcome.scope,
                                "target_device_id": outcome.target_device_id,
                                "expires_at_unix": outcome.expires_at_unix,
                                "nonce_sha256": outcome.nonce_sha256,
                            }),
                        );
                    }
                    println!(
                        "✅ Break-glass token '{}' verified and activated for operator '{}' (ticket: {}, scope: {}, expires_at_unix: {}).",
                        outcome.token_id,
                        outcome.operator_id,
                        outcome.incident_ticket,
                        outcome.scope,
                        outcome.expires_at_unix
                    );
                }
                Err(err) => {
                    if let Ok(mut guard) = shared_ledger.lock() {
                        let _ = guard.append_subsystem_event(
                            AuditSubsystem::System,
                            "BREAK_GLASS_REJECTED",
                            serde_json::json!({
                                "token_id": parsed_token.token_id,
                                "operator_id": parsed_token.operator_id,
                                "reason": err.to_string(),
                            }),
                        );
                    }
                    eprintln!("❌ [BREAK-GLASS REJECTED]: {err}");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

fn execute_verify_escrow(
    vault_dir: &Path,
    soc_priv_key: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let escrow_path = vault_dir.join("vault_kek.escrow");
    if !escrow_path.exists() {
        return Err(format!("Escrow file not found: {}", escrow_path.display()).into());
    }
    let raw_escrow = fs::read(&escrow_path)?;
    let escrow: sentinel_sys::SocEscrowBlob = serde_json::from_slice(&raw_escrow)
        .map_err(|e| format!("Failed parsing escrow JSON: {e}"))?;
    let mut priv_bytes = fs::read(soc_priv_key)?;
    let kek_res = sentinel_sys::decrypt_kek_from_soc_escrow(&escrow, &priv_bytes);
    sentinel_sys::zeroize_slice(&mut priv_bytes);
    let mut kek = kek_res.map_err(|e| format!("Escrow decryption failed: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"SENTINEL-KEK-ID-V2:");
    hasher.update(kek.as_slice());
    let computed_id = &hex::encode(hasher.finalize())[..16];
    sentinel_sys::zeroize_slice(&mut kek);
    if computed_id != escrow.kek_id {
        return Err(format!(
            "Escrow verification failed: computed KEK ID '{}' does not match escrow KEK ID '{}'",
            computed_id, escrow.kek_id
        )
        .into());
    }
    println!("✅ Offline SOC RSA escrow verified successfully!");
    println!("   KEK ID:      {}", escrow.kek_id);
    println!("   Algorithm:   {}", escrow.algorithm);
    println!("   Fingerprint: {}", escrow.soc_key_fingerprint);
    Ok(())
}

/// Executes `sentinel vault recover-escrow`, decrypting `vault_kek.escrow` with the offline SOC
/// RSA-3072+ private key, atomically re-sealing `vault_kek.sealed` on this host, zeroizing key
/// buffers unconditionally, and recording `VAULT_ESCROW_RECOVERED` in the audit ledger (`CSE-16`).
fn execute_recover_escrow(
    vault_dir: &Path,
    soc_priv_key: &Path,
    shared_ledger: Option<sentinel_core::enterprise::ledger::SharedAuditLedger>,
) -> Result<(String, sentinel_sys::KeyProtectionPosture), String> {
    let mut priv_bytes = fs::read(soc_priv_key).map_err(|e| {
        format!(
            "Failed reading offline SOC RSA private key '{}': {e}",
            soc_priv_key.display()
        )
    })?;
    let recover_res = QuarantineVault::recover_from_soc_escrow_with_shared_ledger(
        vault_dir.to_path_buf(),
        &priv_bytes,
        shared_ledger,
    );
    sentinel_sys::zeroize_slice(&mut priv_bytes);
    let vault = recover_res?;
    let kek_id = vault.kek_id().to_string();
    let posture = vault.key_posture();
    println!("✅ Quarantine Vault recovered via offline SOC RSA-3072+ escrow and re-sealed!");
    println!("   Vault Dir:   {}", vault_dir.display());
    println!("   KEK ID:      {kek_id}");
    println!("   Key Posture: {posture:?}");
    Ok((kek_id, posture))
}

/// Executes `sentinel vault recover-hybrid-escrow-v3`, decapsulating `OCESCROW3` (`RSA-3072` +
/// `ML-KEM-768`), atomically re-sealing `vault_kek.sealed`, zeroizing raw key material, and
/// recording `VAULT_HYBRID_PQC_ESCROW_V3_RECOVERED` in the audit ledger (`CSE-16`).
fn execute_recover_hybrid_escrow_v3(
    vault_dir: &Path,
    hybrid_priv_key: &Path,
    shared_ledger: Option<sentinel_core::enterprise::ledger::SharedAuditLedger>,
) -> Result<(String, sentinel_sys::KeyProtectionPosture), String> {
    let mut raw_priv = fs::read(hybrid_priv_key).map_err(|e| {
        format!(
            "Failed reading HybridSocPrivateKeyBundle '{}': {e}",
            hybrid_priv_key.display()
        )
    })?;
    let parse_res: Result<sentinel_sys::HybridSocPrivateKeyBundle, _> =
        serde_json::from_slice(&raw_priv);
    sentinel_sys::zeroize_slice(&mut raw_priv);
    let priv_bundle =
        parse_res.map_err(|e| format!("Invalid HybridSocPrivateKeyBundle JSON: {e}"))?;
    let vault = QuarantineVault::recover_from_hybrid_soc_escrow_v3_with_shared_ledger(
        vault_dir.to_path_buf(),
        &priv_bundle,
        shared_ledger,
    )?;
    let kek_id = vault.kek_id().to_string();
    let posture = vault.key_posture();
    println!("✅ Quarantine Vault recovered via Hybrid PQC OCESCROW3 escrow and re-sealed!");
    println!("   Vault Dir:   {}", vault_dir.display());
    println!("   KEK ID:      {kek_id}");
    println!("   Key Posture: {posture:?}");
    Ok((kek_id, posture))
}

/// Summary returned by real Kiosk intake scanning + isolated CDR sanitization (`CSE-17`, `F-01`).
struct KioskPipelineSummary {
    files_sanitized: usize,
    passport: Option<sentinel_core::enterprise::kiosk::KioskSanitizationPassport>,
}

/// Formats an honest posture status derived directly from `PostureReport` (`CSE-17`, `F-01`).
/// Never prints `"SL-3 ENFORCED"` without physical hardware write-blocker attestation.
fn format_honest_kiosk_posture_label(posture: &sentinel_sys::PostureReport) -> String {
    if posture.is_compliant() {
        "SOFTWARE_POSTURE_VERIFIED (Hardware Write-Blocker: NOT_DETECTED; IEC 62443 SL-3 requires physical hardware controls)".to_string()
    } else {
        "NON_COMPLIANT (Software Posture Gates Incomplete)".to_string()
    }
}

fn collect_kiosk_intake_files_recursive(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(PathBuf, PathBuf)>,
) -> Result<(), String> {
    sentinel_sys::ensure_not_symlink_or_reparse_point(dir).map_err(|e| {
        format!(
            "KIOSK_INTAKE_SYMLINK_REJECTED: '{}' is a symlink or reparse point: {e}",
            dir.display()
        )
    })?;
    let mut entries: Vec<PathBuf> = Vec::new();
    for item in fs::read_dir(dir).map_err(|e| {
        format!(
            "Failed reading kiosk intake directory '{}': {e}",
            dir.display()
        )
    })? {
        let entry = item.map_err(|e| format!("Kiosk intake walk error: {e}"))?;
        entries.push(entry.path());
    }
    entries.sort();

    for path in entries {
        sentinel_sys::ensure_not_symlink_or_reparse_point(&path).map_err(|e| {
            format!(
                "KIOSK_INTAKE_SYMLINK_REJECTED: '{}' is a symlink or reparse point: {e}",
                path.display()
            )
        })?;
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("Failed reading metadata for '{}': {e}", path.display()))?;
        if sentinel_sys::is_reparse_point_or_symlink(&meta) {
            return Err(format!(
                "KIOSK_INTAKE_SYMLINK_REJECTED: '{}' is a symlink or reparse point",
                path.display()
            ));
        }
        if meta.is_dir() {
            collect_kiosk_intake_files_recursive(root, &path, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("Failed stripping intake prefix: {e}"))?
                .to_path_buf();
            out.push((rel, path));
        }
    }
    Ok(())
}

/// Parameters for real Kiosk intake scanning + isolated CDR sanitization (`CSE-17`, `F-01`).
struct KioskPipelineParams<'a> {
    intake_dir: Option<&'a Path>,
    export_dir: Option<&'a Path>,
    media_id: &'a str,
    policy_id: &'a str,
    policy_sequence: u64,
    max_files: usize,
}

/// Real Air-Gapped Kiosk intake scan + isolated CDR disarm + fail-closed passport issuance (`CSE-17`, `F-01`).
///
/// Guarantees:
/// - Refuses to sign `--export-dir` unless `--intake-dir` is supplied and scanned.
/// - Refuses empty intake directories (0 files scanned) or incomplete scans (`!scan_report.complete`).
/// - Quarantines every detected threat or CDR-rejected file via `quarantine_readonly_evidence`
///   and aborts without writing any file or `.sentinel-passport.json` into `--export-dir`.
/// - Writes **only** CDR-rebuilt bytes returned by `WorkerLauncher::sanitize_isolated` (Invariant I3).
fn execute_kiosk_intake_and_export(
    kiosk: &AirGappedKioskManager,
    vault: &QuarantineVault,
    launcher: &WorkerLauncher,
    params: &KioskPipelineParams<'_>,
) -> Result<KioskPipelineSummary, String> {
    let Some(in_dir) = params.intake_dir else {
        return Err(
            "KIOSK_INTAKE_REQUIRED: --export-dir requires --intake-dir; refusing to sign unscanned files"
                .to_string(),
        );
    };

    sentinel_sys::ensure_not_symlink_or_reparse_point(in_dir).map_err(|e| {
        format!(
            "KIOSK_INTAKE_SYMLINK_REJECTED: Intake directory '{}' is a symlink or reparse point: {e}",
            in_dir.display()
        )
    })?;
    let intake_meta = fs::symlink_metadata(in_dir).map_err(|e| {
        format!(
            "KIOSK_INTAKE_INVALID: Cannot read intake directory '{}': {e}",
            in_dir.display()
        )
    })?;
    if sentinel_sys::is_reparse_point_or_symlink(&intake_meta) || !intake_meta.is_dir() {
        return Err(format!(
            "KIOSK_INTAKE_INVALID: '{}' is not a regular non-symlink directory",
            in_dir.display()
        ));
    }

    let scan_limit = params.max_files.max(1);
    let scan_report = UniversalScanner::scan_directory_detailed(in_dir, scan_limit);
    if !scan_report.complete {
        return Err(format!(
            "KIOSK_SCAN_INCOMPLETE: Intake scan did not complete cleanly ({} error(s)); passport refused",
            scan_report.errors.len()
        ));
    }
    if scan_report.files_scanned == 0 {
        return Err(
            "KIOSK_INTAKE_EMPTY: 0 files found in --intake-dir; refusing to certify empty media"
                .to_string(),
        );
    }
    if !scan_report.threats.is_empty() {
        let mut quarantined_count = 0usize;
        let mut quarantine_errors: Vec<String> = Vec::new();
        for threat in &scan_report.threats {
            match vault.quarantine_readonly_evidence(
                &threat.file_path,
                &threat.threat_name,
                threat.risk_score,
            ) {
                Ok(_) => quarantined_count += 1,
                Err(q_err) => quarantine_errors.push(q_err),
            }
        }
        let err_suffix = if quarantine_errors.is_empty() {
            String::new()
        } else {
            format!("; quarantine_errors={:?}", quarantine_errors)
        };
        return Err(format!(
            "KIOSK_THREATS_DETECTED: {} threat(s) detected on intake media ({quarantined_count} quarantined{err_suffix}); export and passport refused",
            scan_report.threats.len()
        ));
    }

    let mut intake_files = Vec::new();
    collect_kiosk_intake_files_recursive(in_dir, in_dir, &mut intake_files)?;
    if intake_files.is_empty() {
        return Err(
            "KIOSK_INTAKE_EMPTY: 0 regular files collected from --intake-dir; passport refused"
                .to_string(),
        );
    }

    let policy = SanitizationPolicy::default();
    let mut sanitized_batch: Vec<(PathBuf, Vec<u8>, String)> =
        Vec::with_capacity(intake_files.len());
    for (rel_path, abs_path) in &intake_files {
        let mut f = sentinel_sys::open_untrusted_readonly_nofollow(abs_path).map_err(|e| {
            format!(
                "KIOSK_INTAKE_READ_ERROR: Failed opening '{}': {e}",
                abs_path.display()
            )
        })?;
        let raw_bytes = sentinel_sys::read_untrusted_to_end_bounded(&mut f, 64 * 1024 * 1024)
            .map_err(|e| {
                format!(
                    "KIOSK_INTAKE_READ_ERROR: Failed reading '{}': {e}",
                    abs_path.display()
                )
            })?;
        let file_name = abs_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("intake.bin")
            .to_string();

        match launcher.sanitize_isolated(WorkerRequest {
            file_name,
            policy: policy.clone(),
            raw_bytes,
        }) {
            Ok(outcome) => {
                let cdr_action = format!("DEEP_CDR_RECONSTRUCTED:{:?}", outcome.detected_format);
                sanitized_batch.push((rel_path.clone(), outcome.clean_bytes, cdr_action));
            }
            Err(cdr_err) => {
                let q_note = match vault.quarantine_readonly_evidence(
                    abs_path,
                    &format!("CDR.Rejected: {cdr_err}"),
                    90,
                ) {
                    Ok(entry) => format!("quarantined={}", entry.entry_id),
                    Err(q_err) => format!("quarantine_error={q_err}"),
                };
                return Err(format!(
                    "KIOSK_CDR_REJECTED: Isolated CDR rejected '{}' ({q_note}): {cdr_err}; export and passport refused",
                    rel_path.display()
                ));
            }
        }
    }

    let files_sanitized = sanitized_batch.len();
    let passport = if let Some(exp_dir) = params.export_dir {
        Some(kiosk.export_sanitized_batch_with_passport(
            exp_dir,
            params.media_id,
            params.policy_id,
            params.policy_sequence,
            &sanitized_batch,
        )?)
    } else {
        None
    };

    Ok(KioskPipelineSummary {
        files_sanitized,
        passport,
    })
}

/// Executes `sentinel shred` with fail-closed receipt verification and explicit error propagation
/// for both shredding and `--fill-free-space` (`CSE-15`, `I6`).
fn execute_shred_command(
    path: &Path,
    passes: u8,
    fill_free_space: bool,
    shared_ledger: Option<&sentinel_core::enterprise::ledger::SharedAuditLedger>,
    max_free_space_bytes: u64,
) -> Result<ShredReceipt, String> {
    println!("===========================================================");
    println!("      OMNICONNECT SENTINEL: ANTI-FORENSIC SECURE SHREDDER  ");
    println!("===========================================================");
    println!("Target Path: {path:?}");
    println!("Standard:    NIST SP 800-88 Rev. 2 Clear (Logical Overwrite + TRIM)");
    println!("Overwrites:  {passes} Passes (0x00, 0xFF, CSPRNG + Read-Back Verification)\n");

    let parent_dir = path.parent().map(|p| p.to_path_buf());
    match SecureShredder::shred_file_with_shared_ledger(
        path,
        ShredMethod::ClearMultiPass { passes },
        shared_ledger,
    ) {
        Ok(receipt) => {
            if let Err(verify_err) = validate_shred_receipt_fail_closed(&receipt) {
                eprintln!("⚠️ [SHRED INCOMPLETE / UNVERIFIED]: {verify_err}");
                return Err(verify_err);
            }
            println!("⚡ [SHREDDING COMPLETE]");
            println!("   NIST Standard:        {}", receipt.nist_standard);
            println!("   Rev. 2 Category:      {:?}", receipt.rev2_category);
            println!("   Sanitization Level:   {}", receipt.sanitization_level);
            println!("   Media Type:           {}", receipt.media_type);
            println!("   Original File Size:   {} bytes", receipt.file_size_bytes);
            println!(
                "   Overwrites Completed: {} passes",
                receipt.passes_completed
            );
            println!(
                "   MFT Scramble Cycles:  {} cycles",
                receipt.rename_cycles_completed
            );
            println!("   Hardware Flushed:     {}", receipt.flush_succeeded);
            println!("   Verification Passed:  {}", receipt.verify_read_ok);
            println!(
                "   Verification Hash:    SHA256[{}]",
                receipt.final_pass_sha256
            );
            if fill_free_space {
                if let Some(dir) = parent_dir {
                    let filled = SecureShredder::fill_free_space(&dir, max_free_space_bytes)
                        .map_err(|e| format!("Free-space fill failed after shredding: {e}"))?;
                    println!("   Free-Space Fill:      {filled} bytes (best-effort logical fill)");
                }
            }
            println!("\n✅ File {path:?} overwritten, verified, and unlinked.");
            Ok(receipt)
        }
        Err(e) => {
            eprintln!("❌ Shredding failed: {e}");
            Err(format!("Shredding failed: {e}"))
        }
    }
}

/// Outcome returned by interactive threat remediation (`CSE-15`, `F-13`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemediationOutcome {
    Shredded,
    Quarantined,
    Skipped,
    ShredAborted,
}

/// Interactive Threat Remediation helper (`BUG-CLI-01`, `CSE-15`, `F-13`):
/// 1. Reuses a single `QuarantineVault` instance (`BUG-CORE-02`).
/// 2. Defaults empty Enter / unrecognized input to safe `[3] SKIP` and fails closed on EOF
///    so accidental Enter presses or closed stdin never trigger irreversible shredding (`CSE-15`).
/// 3. Requires explicit secondary `"SHRED"` confirmation before running `SecureShredder`,
///    and gates success reporting on `validate_shred_receipt_fail_closed(&receipt)` (`I6`).
/// 4. Routes NTFS Alternate Data Stream threats (`threat.stream_name.is_some()`) to
///    `SecureShredder::shred_ntfs_stream` so the host file is preserved (`BUG-CLI-01` #1).
fn prompt_remediation(threat: &UniversalThreat, vault: &QuarantineVault) -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = std::io::stdout();
    prompt_remediation_with_io(threat, vault, &mut reader, &mut stdout).map(|_| ())
}

fn prompt_remediation_with_io<R: std::io::BufRead, W: std::io::Write>(
    threat: &UniversalThreat,
    vault: &QuarantineVault,
    reader: &mut R,
    writer: &mut W,
) -> Result<RemediationOutcome, String> {
    let _ = writeln!(
        writer,
        "\n================================================================================"
    );
    let _ = writeln!(writer, "🚨 [THREAT IDENTIFIED]: {:?}", threat.file_path);
    if let Some(stream) = &threat.stream_name {
        let _ = writeln!(writer, "   NTFS Stream:  {stream}");
    }
    let _ = writeln!(writer, "   Carrier:      {:?}", threat.carrier_category);
    let _ = writeln!(writer, "   Threat Name:  {}", threat.threat_name);
    let _ = writeln!(
        writer,
        "   Severity:     {:?} (Risk Score: {}/100)",
        threat.severity, threat.risk_score
    );
    let _ = writeln!(writer, "   MITRE ATT&CK: {}", threat.mitre_technique);
    let _ = writeln!(writer, "   Details:      {}", threat.technical_details);
    let _ = writeln!(
        writer,
        "--------------------------------------------------------------------------------"
    );
    let _ = writeln!(writer, "REMEDIATION CHOICES:");
    let _ = writeln!(
        writer,
        "  [1] PERMANENT ANTI-FORENSIC SHRED (NIST 800-88 Clear (logical) — requires 'SHRED' confirmation)"
    );
    let _ = writeln!(
        writer,
        "  [2] QUARANTINE TO ENCRYPTED VAULT (AES-256-GCM + Clear Original Plaintext)"
    );
    let _ = writeln!(writer, "  [3] SKIP / LEAVE UNTOUCHED (Safe Default)");
    write!(writer, "Select action [1-3] (Default: 3 - SKIP): ").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;

    let mut input = String::new();
    let bytes_read = reader.read_line(&mut input).map_err(|e| e.to_string())?;
    if bytes_read == 0 {
        let _ = writeln!(
            writer,
            "⚠️ Interactive remediation aborted on EOF (fail-closed: file untouched)."
        );
        return Err(
            "Interactive remediation aborted on EOF (fail-closed: no file modified)".into(),
        );
    }
    let choice = input.trim();

    if choice == "1" {
        write!(
            writer,
            "Type 'SHRED' to confirm irreversible NIST 800-88 Clear (anything else aborts): "
        )
        .map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;

        let mut confirm = String::new();
        let confirm_bytes = reader.read_line(&mut confirm).map_err(|e| e.to_string())?;
        if confirm_bytes == 0 {
            let _ = writeln!(
                writer,
                "⚠️ Shred confirmation aborted on EOF (fail-closed: file untouched)."
            );
            return Err("Shred confirmation aborted on EOF (fail-closed: no file modified)".into());
        }
        if confirm.trim() != "SHRED" {
            let _ = writeln!(
                writer,
                "⚠️ Shred confirmation did not match 'SHRED'; file left untouched."
            );
            return Ok(RemediationOutcome::ShredAborted);
        }

        if let Some(stream_name) = &threat.stream_name {
            let _ = writeln!(
                writer,
                "⚡ Surgically shredding NTFS Alternate Data Stream '{stream_name}' while preserving host file..."
            );
            let receipt = vault.shred_ads_to_vault_ledger(&threat.file_path, stream_name)?;
            if let Err(verify_err) = validate_shred_receipt_fail_closed(&receipt) {
                let _ = writeln!(writer, "⚠️ [SHRED INCOMPLETE / UNVERIFIED]: {verify_err}");
                return Err(verify_err);
            }
            let _ = writeln!(
                writer,
                "✅ [ADS STREAM ERADICATED]: {} ({} bytes overwritten, {}). Host file preserved!",
                receipt.original_path, receipt.file_size_bytes, receipt.sanitization_level
            );
        } else {
            let _ = writeln!(
                writer,
                "⚡ Executing NIST 800-88 Clear (logical) multi-pass shredding..."
            );
            let receipt = vault.shred_file_to_vault_ledger(
                &threat.file_path,
                ShredMethod::ClearMultiPass { passes: 3 },
            )?;
            if let Err(verify_err) = validate_shred_receipt_fail_closed(&receipt) {
                let _ = writeln!(writer, "⚠️ [SHRED INCOMPLETE / UNVERIFIED]: {verify_err}");
                return Err(verify_err);
            }
            let _ = writeln!(
                writer,
                "✅ [PERMANENTLY ERADICATED]: {} ({} bytes overwritten, {}).",
                receipt.original_path, receipt.file_size_bytes, receipt.sanitization_level
            );
        }
        Ok(RemediationOutcome::Shredded)
    } else if choice == "2" {
        let _ = writeln!(
            writer,
            "🔒 Quarantining to encrypted vault, verifying copy on disk (I4), and clearing source..."
        );
        let q = if let Some(stream_name) = &threat.stream_name {
            vault.quarantine_ntfs_stream(
                &threat.file_path,
                stream_name,
                &threat.threat_name,
                threat.risk_score,
            )?
        } else {
            vault.quarantine_file_with_score(
                &threat.file_path,
                &threat.threat_name,
                threat.risk_score,
            )?
        };
        let _ = writeln!(writer, "✅ Quarantined to: {}", q.vault_file_path);
        let _ = writeln!(
            writer,
            "✅ Source plaintext verified in vault and overwritten/unlinked via SecureShredder."
        );
        Ok(RemediationOutcome::Quarantined)
    } else {
        let _ = writeln!(writer, "⚠️ Threat skipped (safe default — file untouched).");
        Ok(RemediationOutcome::Skipped)
    }
}

/// Strict CSP for the local Web Dashboard (`Row 177`):
/// - No `'unsafe-inline'`
/// - No external `fonts.googleapis.com` or `fonts.gstatic.com` (works 100% air-gapped)
pub const STRICT_DASHBOARD_CSP: &str =
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'";

/// Maximum TTL (seconds) for one-time restricted bootstrap handoff files (`CSE-22`).
const BOOTSTRAP_HANDOFF_TTL_SECS: u64 = 30;

/// Shared state for the Axum Web Dashboard router (`Sub-Phase 5.1`, `Rows 172–185, 206, 227`).
pub struct DashboardAppState {
    pub port: u16,
    pub demo_mode: bool,
    pub bootstrap_token: Mutex<Option<(String, std::time::Instant)>>,
    pub bootstrap_handoff_files: Mutex<Vec<PathBuf>>,
    pub session_id: String,
    pub csrf_token: String,
    pub dashboard_dir: PathBuf,
    pub ui_staging_root: PathBuf,
    pub kiosk_intake_root: Option<PathBuf>,
    pub shred_scan_semaphore: Arc<Semaphore>,
    pub last_scan_complete: AtomicBool,
    pub last_scan_errors: Mutex<Vec<String>>,
    pub recent_events: Mutex<VecDeque<serde_json::Value>>,
    pub last_shred_receipt: Mutex<Option<ShredReceipt>>,
}

impl DashboardAppState {
    pub fn new(
        port: u16,
        demo_mode: bool,
        bootstrap_token: String,
        session_id: String,
        csrf_token: String,
        dashboard_dir: PathBuf,
        ui_staging_root: PathBuf,
    ) -> Self {
        let mut events = VecDeque::new();
        events.push_back(serde_json::json!({
            "event": "AGENT_STATUS_SYNC",
            "timestamp": sentinel_sys::now_rfc3339_utc(),
            "demo_mode": demo_mode,
            "complete": true,
            "detail": "Ring 3 Sentinel Agent initialized on 127.0.0.1",
        }));
        Self {
            port,
            demo_mode,
            bootstrap_token: Mutex::new(Some((bootstrap_token, std::time::Instant::now()))),
            bootstrap_handoff_files: Mutex::new(Vec::new()),
            session_id,
            csrf_token,
            dashboard_dir,
            ui_staging_root,
            kiosk_intake_root: None,
            shred_scan_semaphore: Arc::new(Semaphore::new(2)),
            last_scan_complete: AtomicBool::new(true),
            last_scan_errors: Mutex::new(Vec::new()),
            recent_events: Mutex::new(events),
            last_shred_receipt: Mutex::new(None),
        }
    }

    /// Registers a short-lived bootstrap handoff/redirect file for immediate cleanup upon exchange (`CSE-22`).
    pub fn register_bootstrap_handoff_file(&self, path: PathBuf) {
        let mut guard = match self.bootstrap_handoff_files.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.push(path);
    }

    /// Overwrites and deletes all registered bootstrap handoff/redirect files immediately (`CSE-22`).
    pub fn cleanup_bootstrap_handoff_files(&self) {
        let paths: Vec<PathBuf> = {
            let mut guard = match self.bootstrap_handoff_files.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *guard)
        };
        for p in paths {
            shred_and_remove_handoff_file(&p);
        }
    }
}

impl Drop for DashboardAppState {
    fn drop(&mut self) {
        self.cleanup_bootstrap_handoff_files();
    }
}

impl DashboardAppState {
    /// Configures an explicitly allowlisted read-only kiosk intake root for `POST /api/v1/scan` (`CSE-17`).
    pub fn with_kiosk_intake_root(mut self, kiosk_intake_root: Option<PathBuf>) -> Self {
        self.kiosk_intake_root = kiosk_intake_root;
        self
    }

    #[cfg(test)]
    pub fn new_with_token(
        port: u16,
        demo_mode: bool,
        token: String,
        dashboard_dir: PathBuf,
    ) -> Self {
        let staging = std::env::temp_dir().join(format!("sentinel_test_staging_{}", port));
        let _ = fs::create_dir_all(&staging);
        let csrf = format!("csrf_{token}");
        Self::new(
            port,
            demo_mode,
            token.clone(),
            token,
            csrf,
            dashboard_dir,
            staging,
        )
    }

    pub fn push_event(&self, event: serde_json::Value) {
        if let Ok(mut guard) = self.recent_events.lock() {
            if guard.len() >= 32 {
                guard.pop_front();
            }
            guard.push_back(event);
        }
    }
}

/// Validates that the `Host` header is an exact local authority (`127.0.0.1`, `localhost`,
/// `127.0.0.1:{port}`, or `localhost:{port}`), blocking DNS-rebinding domains such as
/// `127.0.0.1.attacker.tld` (`High #9`, `Row 174`).
pub fn is_valid_local_host_header(host: &str, port: u16) -> bool {
    let trimmed = host.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    trimmed == "127.0.0.1"
        || trimmed == "localhost"
        || trimmed == format!("127.0.0.1:{port}")
        || trimmed == format!("localhost:{port}")
}

/// Validates that any present `Origin` header is an exact local origin (`http://127.0.0.1`,
/// `http://localhost`, `http://127.0.0.1:{port}`, or `http://localhost:{port}`), blocking
/// cross-site WebSocket hijacking and DNS rebinding (`High #9`, `Row 174`).
pub fn is_valid_local_origin_header(origin: &str, port: u16) -> bool {
    let trimmed = origin.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    trimmed == "http://127.0.0.1"
        || trimmed == "http://localhost"
        || trimmed == format!("http://127.0.0.1:{port}")
        || trimmed == format!("http://localhost:{port}")
}

/// Constant-time validation of bearer token / session token using `subtle::ConstantTimeEq` (`Row 173`).
pub fn verify_bearer_token_constant_time(auth_header: Option<&str>, expected_token: &str) -> bool {
    let Some(raw) = auth_header else {
        return false;
    };
    let trimmed = raw.trim();
    if trimmed.len() <= 7 || !trimmed[..7].eq_ignore_ascii_case("bearer ") {
        return false;
    }
    let provided = trimmed[7..].trim().as_bytes();
    let expected = expected_token.as_bytes();
    if provided.len() != expected.len() || expected.is_empty() {
        return false;
    }
    bool::from(provided.ct_eq(expected))
}

/// Constant-time validation of the `X-Sentinel-CSRF` header against expected CSRF token (`Rows 175, 227`).
pub fn verify_csrf_token_constant_time(csrf_header: Option<&str>, expected_token: &str) -> bool {
    let Some(raw) = csrf_header else {
        return false;
    };
    let provided = raw.trim().as_bytes();
    let expected = expected_token.as_bytes();
    if provided.len() != expected.len() || expected.is_empty() {
        return false;
    }
    bool::from(provided.ct_eq(expected))
}

/// Strictly validates the browser launch URL against `^http://127\.0\.0\.1:\d+/` (`Row 179`).
pub fn is_valid_dashboard_launch_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://127.0.0.1:") else {
        return false;
    };
    let Some(slash_idx) = rest.find('/') else {
        return false;
    };
    let port_str = &rest[..slash_idx];
    if port_str.is_empty() || port_str.len() > 5 || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if port_str.parse::<u16>().map(|p| p == 0).unwrap_or(true) {
        return false;
    }
    let tail = &rest[slash_idx..];
    !tail.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '&' | '|' | ';' | '`' | '$' | '<' | '>' | '"' | '\'' | '(' | ')'
            )
    })
}

fn with_security_headers(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
) -> Response {
    let mut resp = http::Response::new(Body::from(body));
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    if let Ok(ct) = header::HeaderValue::from_str(content_type) {
        headers.insert(header::CONTENT_TYPE, ct);
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(STRICT_DASHBOARD_CSP),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        header::HeaderValue::from_static("no-referrer"),
    );
    resp.into_response()
}

fn check_host_and_origin(headers: &HeaderMap, port: u16) -> Result<(), Box<Response>> {
    let Some(host_val) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return Err(Box::new(with_security_headers(
            StatusCode::FORBIDDEN,
            "text/plain; charset=utf-8",
            b"Forbidden: Missing Host Header".to_vec(),
        )));
    };
    if !is_valid_local_host_header(host_val, port) {
        return Err(Box::new(with_security_headers(
            StatusCode::FORBIDDEN,
            "text/plain; charset=utf-8",
            b"Forbidden: Invalid Host Header (DNS Rebinding Blocked)".to_vec(),
        )));
    }
    if let Some(origin_val) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !is_valid_local_origin_header(origin_val, port) {
            return Err(Box::new(with_security_headers(
                StatusCode::FORBIDDEN,
                "text/plain; charset=utf-8",
                b"Forbidden: Cross-Origin Request Blocked".to_vec(),
            )));
        }
    }
    Ok(())
}

pub fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for header_val in headers.get_all(header::COOKIE) {
        let Ok(cookie_header) = header_val.to_str() else {
            continue;
        };
        for pair in cookie_header.split(';') {
            let mut parts = pair.trim().splitn(2, '=');
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

pub fn check_session_auth(
    headers: &HeaderMap,
    expected_session_id: &str,
) -> Result<(), Box<Response>> {
    // Session authentication relies strictly on HttpOnly; SameSite=Strict sentinel_sid cookie (`CEA-DEFECT-05`)
    if let Some(cookie_sid) = extract_cookie_value(headers, "sentinel_sid") {
        let provided = cookie_sid.trim().as_bytes();
        let expected = expected_session_id.as_bytes();
        if provided.len() == expected.len()
            && !expected.is_empty()
            && bool::from(provided.ct_eq(expected))
        {
            return Ok(());
        }
    }

    Err(Box::new(with_security_headers(
        StatusCode::UNAUTHORIZED,
        "application/json; charset=utf-8",
        br#"{"error":"UNAUTHORIZED","message":"Missing or invalid session credentials"}"#.to_vec(),
    )))
}

pub fn check_csrf_header(
    headers: &HeaderMap,
    expected_csrf_token: &str,
) -> Result<(), Box<Response>> {
    let csrf_str = headers.get("x-sentinel-csrf").and_then(|v| v.to_str().ok());
    if !verify_csrf_token_constant_time(csrf_str, expected_csrf_token) {
        return Err(Box::new(with_security_headers(
            StatusCode::FORBIDDEN,
            "application/json; charset=utf-8",
            br#"{"error":"CSRF_VALIDATION_FAILED","message":"Missing or invalid X-Sentinel-CSRF header"}"#.to_vec(),
        )));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct SessionExchangeRequest {
    bootstrap_token: String,
}

async fn handle_session_exchange(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    let req: Result<SessionExchangeRequest, _> = serde_json::from_slice(&body);
    let Ok(req) = req else {
        return with_security_headers(
            StatusCode::BAD_REQUEST,
            "application/json; charset=utf-8",
            br#"{"error":"BAD_REQUEST","message":"Invalid JSON payload"}"#.to_vec(),
        );
    };

    let mut guard = match state.bootstrap_token.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let mut expired = false;
    let valid = if let Some((ref expected, created_at)) = *guard {
        if created_at.elapsed().as_secs() > 120 {
            expired = true;
            false
        } else {
            let provided = req.bootstrap_token.trim().as_bytes();
            let exp_bytes = expected.as_bytes();
            if provided.len() == exp_bytes.len() && !exp_bytes.is_empty() {
                bool::from(provided.ct_eq(exp_bytes))
            } else {
                false
            }
        }
    } else {
        false
    };

    if !valid {
        if expired {
            let _ = guard.take();
            drop(guard);
            state.cleanup_bootstrap_handoff_files();
        }
        return with_security_headers(
            StatusCode::UNAUTHORIZED,
            "application/json; charset=utf-8",
            br#"{"error":"INVALID_BOOTSTRAP_TOKEN","message":"Bootstrap code invalid, expired, or already used"}"#.to_vec(),
        );
    }

    // Single-use: consume bootstrap token and delete any on-disk handoff/redirect files immediately (`CSE-22`)
    let _ = guard.take();
    drop(guard);
    state.cleanup_bootstrap_handoff_files();

    let cookie_val = format!(
        "sentinel_sid={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400",
        state.session_id
    );
    let body_json = serde_json::json!({
        "status": "AUTHENTICATED",
        "csrf_token": state.csrf_token
    });

    let mut resp = with_security_headers(
        StatusCode::OK,
        "application/json; charset=utf-8",
        serde_json::to_vec(&body_json).unwrap_or_default(),
    );
    if let Ok(hv) = header::HeaderValue::from_str(&cookie_val) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

fn is_prohibited_vault_infra_path(raw_lower: &str) -> bool {
    raw_lower.contains(".sentinel_vault")
        || raw_lower.contains(".sentinel_audit")
        || raw_lower.contains(".sentinel_shadow_cache")
        || raw_lower.contains("audit.jsonl")
        || raw_lower.contains("vault_kek")
        || raw_lower.contains("ledger_key.sealed")
        || raw_lower.contains("privacy_hmac.sealed")
        || raw_lower.contains("head.sig")
        || raw_lower.contains("spool_key.sealed")
        || raw_lower.contains("siem_spool")
        || raw_lower.contains("sentinel_unified_audit")
}

/// Validates that a configured scan root (`ui_staging_root` or `--kiosk-intake-root`) is neither
/// vault infrastructure nor a symlink/reparse point, and returns its canonical directory path (`CSE-17`).
fn validate_safe_scan_root(root: &Path) -> Result<PathBuf, (StatusCode, &'static str)> {
    let root_lower = root.to_string_lossy().to_lowercase();
    if is_prohibited_vault_infra_path(&root_lower) {
        return Err((
            StatusCode::FORBIDDEN,
            "Access to Sentinel vault infrastructure is prohibited",
        ));
    }
    if sentinel_sys::ensure_not_symlink_or_reparse_point(root).is_err() {
        return Err((
            StatusCode::FORBIDDEN,
            "Reparse points and symbolic links are prohibited",
        ));
    }
    let meta = fs::symlink_metadata(root).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Scan root directory does not exist",
        )
    })?;
    if sentinel_sys::is_reparse_point_or_symlink(&meta) {
        return Err((
            StatusCode::FORBIDDEN,
            "Reparse points and symbolic links are prohibited",
        ));
    }
    if !meta.is_dir() {
        return Err((StatusCode::BAD_REQUEST, "Scan root path is not a directory"));
    }
    root.canonicalize().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed resolving scan root directory",
        )
    })
}

pub fn resolve_contained_ui_target(
    user_path: &Path,
    staging_root: &Path,
) -> Result<PathBuf, (StatusCode, &'static str)> {
    use std::path::Component;

    // 1. Inspect raw path string immediately for sensitive vault keywords or NUL bytes before any filesystem access
    let raw_str = user_path.to_string_lossy();
    if raw_str.contains('\0') {
        return Err((
            StatusCode::FORBIDDEN,
            "Null bytes in target path are prohibited",
        ));
    }
    let raw_lower = raw_str.to_lowercase();
    if is_prohibited_vault_infra_path(&raw_lower) {
        return Err((
            StatusCode::FORBIDDEN,
            "Access to Sentinel vault infrastructure is prohibited",
        ));
    }

    // 2. Reject path traversal ('..') unconditionally BEFORE any disk access
    for comp in user_path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err((
                StatusCode::FORBIDDEN,
                "Path traversal ('..') is strictly prohibited",
            ));
        }
    }

    // 3. Reject Windows rooted (`\...`, `/...`), drive-relative (`C:...`), and ALL NTFS ADS colons
    // (on both relative AND absolute inputs, after optional leading `X:` drive prefix on Windows)
    // BEFORE joining or probing `.exists()` (`CEA-DEFECT-05` zero oracle)
    if !user_path.is_absolute()
        && (raw_str.starts_with('/')
            || raw_str.starts_with('\\')
            || raw_str.contains(':')
            || user_path
                .components()
                .any(|c| matches!(c, Component::Prefix(_) | Component::RootDir)))
    {
        return Err((
            StatusCode::FORBIDDEN,
            "Target path is outside the designated UI staging root",
        ));
    }
    let colon_check_tail = if cfg!(windows) && user_path.is_absolute() {
        let after_verbatim = raw_str.strip_prefix(r"\\?\").unwrap_or(&raw_str);
        let mut chars = after_verbatim.chars();
        if matches!(
            (chars.next(), chars.next()),
            (Some(c), Some(':')) if c.is_ascii_alphabetic()
        ) {
            chars.as_str()
        } else {
            after_verbatim
        }
    } else {
        raw_str.as_ref()
    };
    if colon_check_tail.contains(':') {
        return Err((
            StatusCode::FORBIDDEN,
            "Alternate data streams and drive-relative colons are strictly prohibited",
        ));
    }

    let canonical_root = validate_safe_scan_root(staging_root)?;

    // 4. Absolute path containment check: verify boundary BEFORE probing exists()
    let candidate = if user_path.is_absolute() {
        let is_within_staging =
            user_path.starts_with(staging_root) || user_path.starts_with(&canonical_root);
        if !is_within_staging {
            return Err((
                StatusCode::FORBIDDEN,
                "Target path is outside the designated UI staging root",
            ));
        }
        user_path.to_path_buf()
    } else {
        staging_root.join(user_path)
    };

    // 5. Walk every prefix component inside staging_root BEFORE candidate.exists() so symlinks/
    // junctions targeting external existing vs non-existing host paths never create an oracle
    let rel_inside_root = candidate
        .strip_prefix(staging_root)
        .or_else(|_| candidate.strip_prefix(&canonical_root))
        .map_err(|_| {
            (
                StatusCode::FORBIDDEN,
                "Target path is outside the designated UI staging root",
            )
        })?;
    let mut walk = canonical_root.clone();
    for comp in rel_inside_root.components() {
        match comp {
            Component::Normal(seg) => {
                walk.push(seg);
                if fs::symlink_metadata(&walk).is_ok()
                    && sentinel_sys::ensure_not_symlink_or_reparse_point(&walk).is_err()
                {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "Reparse points and symbolic links are prohibited",
                    ));
                }
            }
            _ => {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Target path is outside the designated UI staging root",
                ));
            }
        }
    }

    if !candidate.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            "Target path does not exist in UI staging root",
        ));
    }

    if sentinel_sys::ensure_not_symlink_or_reparse_point(&candidate).is_err() {
        return Err((
            StatusCode::FORBIDDEN,
            "Reparse points and symbolic links are prohibited",
        ));
    }

    let canonical_target = match candidate.canonicalize() {
        Ok(t) => t,
        Err(_) => {
            return Err((
                StatusCode::FORBIDDEN,
                "Failed resolving canonical target path",
            ))
        }
    };

    if !canonical_target.starts_with(&canonical_root) {
        return Err((
            StatusCode::FORBIDDEN,
            "Target path is outside the designated UI staging root",
        ));
    }

    let s_lossy = canonical_target.to_string_lossy().to_lowercase();
    if s_lossy.contains(".sentinel_vault")
        || s_lossy.contains("audit.jsonl")
        || s_lossy.contains("vault_kek")
        || s_lossy.contains("ledger_key.sealed")
        || s_lossy.contains("privacy_hmac.sealed")
        || s_lossy.contains("head.sig")
        || s_lossy.contains("spool_key.sealed")
        || s_lossy.contains("siem_spool")
        || s_lossy.contains("sentinel_unified_audit")
    {
        return Err((
            StatusCode::FORBIDDEN,
            "Access to Sentinel vault infrastructure is prohibited",
        ));
    }

    Ok(canonical_target)
}

async fn handle_index(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    let raw_html = fs::read(state.dashboard_dir.join("index.html")).unwrap_or_default();
    with_security_headers(StatusCode::OK, "text/html; charset=utf-8", raw_html)
}

async fn handle_style(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    let bytes = fs::read(state.dashboard_dir.join("style.css"))
        .or_else(|_| fs::read(state.dashboard_dir.join("styles.css")))
        .unwrap_or_default();
    with_security_headers(StatusCode::OK, "text/css; charset=utf-8", bytes)
}

async fn handle_app_js(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    let bytes = fs::read(state.dashboard_dir.join("app.js")).unwrap_or_default();
    with_security_headers(
        StatusCode::OK,
        "application/javascript; charset=utf-8",
        bytes,
    )
}

async fn handle_api_status(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    if let Err(resp) = check_session_auth(&headers, &state.session_id) {
        return *resp;
    }

    let posture = verify_system_posture();
    let shared_ledger = get_or_init_global_shared_ledger(None);
    let mut pol_mgr = IntunePolicyManager::new().with_shared_ledger(shared_ledger.clone());
    let policy = pol_mgr.load_active_policy();
    let vault = QuarantineVault::new(PathBuf::from(".sentinel_vault"))
        .with_shared_ledger(shared_ledger.clone());
    let entries = vault.list_entries().unwrap_or_default();
    let chain_ok = shared_ledger
        .lock()
        .map(|g| g.verify_chain().is_ok())
        .unwrap_or(false);
    let connected_drives: Vec<serde_json::Value> = DriveWatcher::enumerate_mounted_drives()
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "mount_point": p.to_string_lossy(),
                "volume_name": p.to_string_lossy(),
                "is_removable": true,
            })
        })
        .collect();
    let metrics = SentinelMetrics::global().snapshot();
    let recent_events: Vec<serde_json::Value> = state
        .recent_events
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default();
    let scan_errors: Vec<String> = state
        .last_scan_errors
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let last_shred = state.last_shred_receipt.lock().ok().and_then(|g| g.clone());

    let status_json = serde_json::json!({
        "status": "ACTIVE",
        "demo_mode": state.demo_mode,
        "architecture": "Option B Hardened (Zero Custom Kernel Driver)",
        "session_authenticated": true,
        "csrf_token": state.csrf_token,
        "posture": {
            "automount_disabled": posture.automount_disabled,
            "user_deny_policy_present": posture.user_deny_policy_present,
            "install_restrictions_active": posture.install_restrictions_active,
            "write_protect_active": posture.write_protect_active,
            "removable_volumes_offline": posture.removable_volumes_offline,
            "is_compliant": posture.is_compliant(),
        },
        "mdm_policy": {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "enforce_usb_zero_trust": policy.enforce_usb_zero_trust,
            "block_composite_hid_storage": policy.block_composite_hid_storage,
            "require_cdr_for_documents": policy.require_cdr_for_documents,
        },
        "connected_volumes": connected_drives,
        "workers": {
            "active": metrics.sentinel_active_workers,
            "processed_total": metrics.sentinel_cdr_processed_total,
            "duration_ms_total": metrics.sentinel_cdr_duration_ms,
        },
        "files_cleaned": metrics.sentinel_cdr_processed_total,
        "quarantine_count": entries.len(),
        "audit_ledger_verified": chain_ok,
        "last_scan_complete": state.last_scan_complete.load(Ordering::Relaxed),
        "last_scan_errors": scan_errors,
        "recent_events": recent_events,
        "last_shred_receipt": last_shred,
    });

    with_security_headers(
        StatusCode::OK,
        "application/json; charset=utf-8",
        serde_json::to_vec(&status_json).unwrap_or_default(),
    )
}

async fn handle_api_ws(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    if let Err(resp) = check_session_auth(&headers, &state.session_id) {
        return *resp;
    }

    let events: Vec<serde_json::Value> = state
        .recent_events
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default();

    let payload = serde_json::json!({
        "event": "AGENT_EVENT_STREAM",
        "demo_mode": state.demo_mode,
        "complete": state.last_scan_complete.load(Ordering::Relaxed),
        "events": events,
    });

    let wants_sse = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/event-stream"))
        .unwrap_or(false);

    if wants_sse {
        let sse_frame = format!(
            "event: sentinel_sync\ndata: {}\n\n",
            serde_json::to_string(&payload).unwrap_or_default()
        );
        with_security_headers(
            StatusCode::OK,
            "text/event-stream; charset=utf-8",
            sse_frame.into_bytes(),
        )
    } else {
        with_security_headers(
            StatusCode::OK,
            "application/json; charset=utf-8",
            serde_json::to_vec(&payload).unwrap_or_default(),
        )
    }
}

#[derive(serde::Deserialize, Default)]
struct ScanApiRequest {
    path: Option<String>,
    max_files: Option<usize>,
}

async fn handle_api_scan(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    if let Err(resp) = check_session_auth(&headers, &state.session_id) {
        return *resp;
    }
    if let Err(resp) = check_csrf_header(&headers, &state.csrf_token) {
        return *resp;
    }

    let req: ScanApiRequest = serde_json::from_slice(&body).unwrap_or_default();
    let target_path = if let Some(ref p) = req.path {
        let candidate = PathBuf::from(p);
        let primary = resolve_contained_ui_target(&candidate, &state.ui_staging_root);
        let resolved = match primary {
            Ok(t) => Ok(t),
            Err(primary_err) => {
                // Only fall back to `--kiosk-intake-root` when the primary check was NOT a hard
                // symlink/traversal/vault violation inside `ui_staging_root`:
                // - relative path missing in `ui_staging_root` (`404`), OR
                // - absolute path outside `ui_staging_root` (`403` boundary mismatch).
                let allow_intake_fallback = primary_err.0 == StatusCode::NOT_FOUND
                    || (candidate.is_absolute()
                        && primary_err.0 == StatusCode::FORBIDDEN
                        && primary_err.1
                            == "Target path is outside the designated UI staging root");
                if allow_intake_fallback {
                    if let Some(ref intake_root) = state.kiosk_intake_root {
                        match resolve_contained_ui_target(&candidate, intake_root) {
                            Ok(t) => Ok(t),
                            Err(intake_err) => {
                                // Never downgrade a primary 403 external-path rejection to 400/404/500 (zero oracle)
                                if primary_err.0 == StatusCode::FORBIDDEN {
                                    Err(primary_err)
                                } else {
                                    Err(intake_err)
                                }
                            }
                        }
                    } else {
                        Err(primary_err)
                    }
                } else {
                    Err(primary_err)
                }
            }
        };
        match resolved {
            Ok(t) => t,
            Err((status, msg)) => {
                return with_security_headers(
                    status,
                    "application/json; charset=utf-8",
                    serde_json::to_vec(&serde_json::json!({
                        "error": "UNAUTHORIZED_SCAN_TARGET",
                        "message": msg,
                    }))
                    .unwrap_or_default(),
                );
            }
        }
    } else if let Some(ref intake_root) = state.kiosk_intake_root {
        match validate_safe_scan_root(intake_root) {
            Ok(canonical_intake) => canonical_intake,
            Err((status, msg)) => {
                state.last_scan_complete.store(false, Ordering::Relaxed);
                return with_security_headers(
                    status,
                    "application/json; charset=utf-8",
                    serde_json::to_vec(&serde_json::json!({
                        "error": "INVALID_KIOSK_INTAKE_ROOT",
                        "complete": false,
                        "message": msg,
                    }))
                    .unwrap_or_default(),
                );
            }
        }
    } else {
        match validate_safe_scan_root(&state.ui_staging_root) {
            Ok(canonical_staging) => canonical_staging,
            Err((status, msg)) => {
                state.last_scan_complete.store(false, Ordering::Relaxed);
                return with_security_headers(
                    status,
                    "application/json; charset=utf-8",
                    serde_json::to_vec(&serde_json::json!({
                        "error": "INVALID_STAGING_ROOT",
                        "complete": false,
                        "message": msg,
                    }))
                    .unwrap_or_default(),
                );
            }
        }
    };
    let max_files = req.max_files.unwrap_or(500).clamp(1, 5000);

    let permit = match state.shred_scan_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return with_security_headers(
                StatusCode::TOO_MANY_REQUESTS,
                "application/json; charset=utf-8",
                br#"{"error":"CONCURRENCY_LIMIT_EXCEEDED","message":"Maximum concurrent operations reached (limit: 2)"}"#.to_vec(),
            );
        }
    };

    let target_clone = target_path.clone();
    let report = match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        UniversalScanner::scan_directory_detailed(&target_clone, max_files)
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return with_security_headers(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json; charset=utf-8",
                serde_json::to_vec(&serde_json::json!({
                    "error": "SCAN_WORKER_PANIC",
                    "message": e.to_string(),
                }))
                .unwrap_or_default(),
            );
        }
    };

    // Fail closed if 0 files were scanned so empty staging folders can never certify USB media clean (`CSE-17`, `F-01`)
    if report.files_scanned == 0 {
        state.last_scan_complete.store(false, Ordering::Relaxed);
        return with_security_headers(
            StatusCode::BAD_REQUEST,
            "application/json; charset=utf-8",
            serde_json::to_vec(&serde_json::json!({
                "error": "EMPTY_SCAN_TARGET",
                "complete": false,
                "files_scanned": 0,
                "threats": [],
                "message": "0 files scanned — configure --kiosk-intake-root or stage files before scanning",
            }))
            .unwrap_or_default(),
        );
    }

    state
        .last_scan_complete
        .store(report.complete, Ordering::Relaxed);
    if let Ok(mut errs) = state.last_scan_errors.lock() {
        *errs = report
            .errors
            .iter()
            .map(|e| format!("{:?}: {} ({})", e.path, e.kind, e.reason))
            .collect();
    }
    for threat in &report.threats {
        SentinelMetrics::global().record_threat(
            &format!("{:?}", threat.carrier_category),
            &format!("{:?}", threat.severity),
        );
    }

    let shared_ledger = get_or_init_global_shared_ledger(None);
    let path_token = tokenize_path_for_ledger(
        Some(&shared_ledger),
        &default_unified_ledger_path(),
        &target_path,
    )
    .unwrap_or_else(|_| "TOKEN_UNAVAILABLE".to_string());
    state.push_event(serde_json::json!({
        "event": "SCAN_COMPLETE",
        "timestamp": sentinel_sys::now_rfc3339_utc(),
        "path_token": path_token,
        "files_scanned": report.files_scanned,
        "threats_found": report.threats.len(),
        "complete": report.complete,
        "errors": report.errors.len(),
    }));

    with_security_headers(
        StatusCode::OK,
        "application/json; charset=utf-8",
        serde_json::to_vec(&report).unwrap_or_default(),
    )
}

#[derive(serde::Deserialize, Default)]
struct ShredApiRequest {
    path: Option<String>,
    create_ephemeral_canary: Option<bool>,
}

/// Maps a `SecureShredder` error message to the appropriate HTTP status and error code (`CSE-15`).
/// Verification or hardware-flush failures return HTTP 500 (`SHRED_VERIFICATION_FAILED`);
/// caller/input failures return HTTP 400 (`SHRED_OPERATION_FAILED`).
fn classify_shred_error_http(err: &str) -> (StatusCode, &'static str) {
    if err.starts_with("SHRED_VERIFICATION_FAILED") {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "SHRED_VERIFICATION_FAILED",
        )
    } else {
        (StatusCode::BAD_REQUEST, "SHRED_OPERATION_FAILED")
    }
}

async fn handle_api_shred(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    if let Err(resp) = check_session_auth(&headers, &state.session_id) {
        return *resp;
    }
    if let Err(resp) = check_csrf_header(&headers, &state.csrf_token) {
        return *resp;
    }

    let req: ShredApiRequest = serde_json::from_slice(&body).unwrap_or_default();
    let target_path = if let Some(ref p) = req.path {
        match resolve_contained_ui_target(&PathBuf::from(p), &state.ui_staging_root) {
            Ok(t) => t,
            Err((status, msg)) => {
                tracing::warn!("UNAUTHORIZED_SHRED_BLOCKED: path '{p}' rejected: {msg}");
                return with_security_headers(
                    status,
                    "application/json; charset=utf-8",
                    serde_json::to_vec(&serde_json::json!({
                        "error": "UNAUTHORIZED_SHRED_TARGET",
                        "message": msg,
                    }))
                    .unwrap_or_default(),
                );
            }
        }
    } else if req.create_ephemeral_canary.unwrap_or(true) {
        let canary = state
            .ui_staging_root
            .join(format!("shred_canary_{}.bin", uuid::Uuid::new_v4()));
        if let Err(e) = fs::write(&canary, vec![0xA5u8; 64 * 1024]) {
            return with_security_headers(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json; charset=utf-8",
                serde_json::to_vec(&serde_json::json!({
                    "error": "SHRED_CANARY_INIT_FAILED",
                    "message": e.to_string(),
                }))
                .unwrap_or_default(),
            );
        }
        canary
    } else {
        return with_security_headers(
            StatusCode::BAD_REQUEST,
            "application/json; charset=utf-8",
            br#"{"error":"INVALID_SHRED_TARGET","message":"Missing path for shred operation"}"#
                .to_vec(),
        );
    };

    let permit = match state.shred_scan_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return with_security_headers(
                StatusCode::TOO_MANY_REQUESTS,
                "application/json; charset=utf-8",
                br#"{"error":"CONCURRENCY_LIMIT_EXCEEDED","message":"Maximum concurrent operations reached (limit: 2)"}"#.to_vec(),
            );
        }
    };

    let shared_ledger = get_or_init_global_shared_ledger(None);
    let shared_for_task = shared_ledger.clone();
    let target_clone = target_path.clone();
    let shred_result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SecureShredder::shred_file_with_shared_ledger(
            &target_clone,
            ShredMethod::ClearMultiPass { passes: 3 },
            Some(&shared_for_task),
        )
    })
    .await;

    let receipt = match shred_result {
        Ok(Ok(r)) => r,
        Ok(Err(err)) => {
            let (status, error_code) = classify_shred_error_http(&err);
            return with_security_headers(
                status,
                "application/json; charset=utf-8",
                serde_json::to_vec(&serde_json::json!({
                    "error": error_code,
                    "message": err,
                }))
                .unwrap_or_default(),
            );
        }
        Err(e) => {
            return with_security_headers(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json; charset=utf-8",
                serde_json::to_vec(&serde_json::json!({
                    "error": "SHRED_WORKER_PANIC",
                    "message": e.to_string(),
                }))
                .unwrap_or_default(),
            );
        }
    };

    if let Err(verify_err) = validate_shred_receipt_fail_closed(&receipt) {
        return with_security_headers(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json; charset=utf-8",
            serde_json::to_vec(&serde_json::json!({
                "error": "SHRED_VERIFICATION_FAILED",
                "message": verify_err,
            }))
            .unwrap_or_default(),
        );
    }

    if let Ok(mut guard) = state.last_shred_receipt.lock() {
        *guard = Some(receipt.clone());
    }
    let path_token = tokenize_path_for_ledger(
        Some(&shared_ledger),
        &default_unified_ledger_path(),
        Path::new(&receipt.original_path),
    )
    .unwrap_or_else(|_| "TOKEN_UNAVAILABLE".to_string());
    state.push_event(serde_json::json!({
        "event": "SHRED_COMPLETE",
        "timestamp": sentinel_sys::now_rfc3339_utc(),
        "path_token": path_token,
        "passes_completed": receipt.passes_completed,
        "rename_cycles_completed": receipt.rename_cycles_completed,
        "flush_succeeded": receipt.flush_succeeded,
        "media_type": receipt.media_type,
        "sanitization_level": receipt.sanitization_level,
    }));
    with_security_headers(
        StatusCode::OK,
        "application/json; charset=utf-8",
        serde_json::to_vec(&receipt).unwrap_or_default(),
    )
}

async fn handle_api_metrics(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    if let Err(resp) = check_session_auth(&headers, &state.session_id) {
        return *resp;
    }

    let posture = verify_system_posture();
    let prom_body = SentinelMetrics::global().render_prometheus(&posture);
    with_security_headers(
        StatusCode::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        prom_body.into_bytes(),
    )
}

async fn handle_not_found(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
    _req: Request<Body>,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    with_security_headers(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        b"Not Found".to_vec(),
    )
}

/// Builds the `axum::Router` for the Sentinel Web Dashboard (`Sub-Phase 5.1`, `Rows 172–185, 206, 227`).
pub fn build_dashboard_router(state: Arc<DashboardAppState>) -> Router {
    Router::new()
        .route("/", get(handle_index))
        .route("/index.html", get(handle_index))
        .route("/style.css", get(handle_style))
        .route("/styles.css", get(handle_style))
        .route("/app.js", get(handle_app_js))
        .route("/api/v1/session/exchange", post(handle_session_exchange))
        .route("/api/v1/status", get(handle_api_status))
        .route("/api/v1/ws", get(handle_api_ws))
        .route("/api/v1/scan", post(handle_api_scan))
        .route("/api/v1/shred", post(handle_api_shred))
        .route("/api/v1/metrics", get(handle_api_metrics))
        .fallback(handle_not_found)
        .with_state(state)
}

/// Serves the Sentinel Web Dashboard on `127.0.0.1:{port}` via `axum::Router` (`Sub-Phase 5.1`):
/// - Binds strictly to `127.0.0.1:{port}` (`Row 172`)
/// - Generates a single-use bootstrap code via `#bootstrap=<token>` exchange -> HttpOnly cookie + distinct CSRF token
/// - Enforces exact `Host` and `Origin` header validation (`127.0.0.1:{port}` / `localhost:{port}`) to block DNS rebinding (`High #9`, `Row 174`)
/// - Enforces CSRF validation (`X-Sentinel-CSRF`) on `POST /api/v1/scan` and `POST /api/v1/shred` (`Rows 175, 227`)
/// - Restricts scanning and shredding to `ui_staging_root` with bounded concurrency (`Semaphore::new(2)`)
/// - Exports all 7 labeled Prometheus metrics on `GET /api/v1/metrics` (`Row 206`)
fn is_restricted_runtime_dir_writable(dir: &Path) -> bool {
    if sentinel_sys::create_restricted_dir_atomic(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(
        ".sentinel_rt_probe_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    match sentinel_sys::create_restricted_file_handle_atomic(&probe) {
        Ok(f) => {
            drop(f);
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(not(test))]
fn resolve_restricted_runtime_dir(subpath: &str, fallback_cwd: &str) -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(pd) = std::env::var("ProgramData") {
            let p = PathBuf::from(pd).join("OmniConnect").join(subpath);
            if is_restricted_runtime_dir_writable(&p) {
                return p;
            }
        }
        if let Ok(lad) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(lad).join("OmniConnect").join(subpath);
            if is_restricted_runtime_dir_writable(&p) {
                return p;
            }
        }
    }
    #[cfg(not(windows))]
    {
        let p = PathBuf::from("/var/lib/omniconnect").join(subpath.to_ascii_lowercase());
        if is_restricted_runtime_dir_writable(&p) {
            return p;
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("omniconnect")
                .join(subpath.to_ascii_lowercase());
            if is_restricted_runtime_dir_writable(&p) {
                return p;
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join(fallback_cwd);
        if is_restricted_runtime_dir_writable(&p) {
            return p;
        }
    }
    std::env::temp_dir().join(fallback_cwd)
}

fn resolve_dashboard_dir() -> PathBuf {
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("dashboard");
        if candidate.join("index.html").is_file() {
            return candidate;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors().skip(1).take(4) {
            let candidate = ancestor.join("dashboard");
            if candidate.join("index.html").is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("dashboard")
}

fn resolve_native_rune_ui_binary() -> Option<PathBuf> {
    let bin_name = if cfg!(windows) {
        "sentinel-ui.exe"
    } else {
        "sentinel-ui"
    };
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(bin_name);
            if sibling.is_file() {
                return Some(sibling);
            }
        }
        for ancestor in exe.ancestors().skip(1).take(4) {
            roots.push(ancestor.to_path_buf());
        }
    }
    for root in roots {
        for rel in [
            PathBuf::from("sentinel-ui")
                .join("target")
                .join("release")
                .join(bin_name),
            PathBuf::from("sentinel-ui")
                .join("target")
                .join("debug")
                .join(bin_name),
        ] {
            let candidate = root.join(rel);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Safely overwrites (via no-follow handle) and deletes a short-lived bootstrap handoff/redirect
/// file, refusing to follow symlinks or NTFS reparse points (`CSE-22`).
fn shred_and_remove_handoff_file(path: &Path) {
    if sentinel_sys::ensure_not_symlink_or_reparse_point(path).is_err() {
        return;
    }
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if !meta.is_file() || sentinel_sys::is_reparse_point_or_symlink(&meta) {
        return;
    }
    if let Ok(mut file) = sentinel_sys::open_write_through(path) {
        let len = (meta.len() as usize).clamp(64, 4096);
        let zeros = vec![0u8; len];
        let _ = std::io::Write::write_all(&mut file, &zeros);
        let _ = file.set_len(0);
        let _ = file.sync_all();
    }
    let _ = fs::remove_file(path);
}

/// Writes a short-lived, ACL-restricted (`0600` / user-only DACL) JSON handoff file containing
/// the one-time bootstrap token and a 30-second expiry timestamp for native `sentinel-ui` (`CSE-22`).
fn write_native_bootstrap_handoff_file(
    staging_root: &Path,
    bootstrap_token: &str,
    ttl_secs: u64,
) -> std::io::Result<PathBuf> {
    let handoff_path = staging_root.join(format!(
        "bootstrap_handoff_{}.json",
        uuid::Uuid::new_v4().simple()
    ));
    let expires_unix = sentinel_sys::now_unix_secs() + (ttl_secs as i64);
    let payload = serde_json::json!({
        "bootstrap_token": bootstrap_token,
        "expires_unix": expires_unix,
    })
    .to_string();
    sentinel_sys::create_restricted_file_atomic(&handoff_path, payload.as_bytes())?;
    Ok(handoff_path)
}

/// Writes a short-lived, ACL-restricted (`0600` / user-only DACL) local HTML one-time redirect file
/// so `rundll32`/`open`/`xdg-open` process command lines NEVER contain `#bootstrap=<token>` (`CSE-22`).
fn write_browser_redirect_handoff_file(
    staging_root: &Path,
    actual_port: u16,
    bootstrap_token: &str,
) -> std::io::Result<PathBuf> {
    let target_url = format!("http://127.0.0.1:{actual_port}/#bootstrap={bootstrap_token}");
    if !is_valid_dashboard_launch_url(&target_url) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Refusing to write browser redirect: URL failed strict loopback validation",
        ));
    }
    let html_path = staging_root.join(format!(
        "bootstrap_launch_{}.html",
        uuid::Uuid::new_v4().simple()
    ));
    let html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url={target_url}\"><title>OmniConnect Sentinel</title></head><body>Redirecting to local OmniConnect Sentinel station...</body></html>"
    );
    sentinel_sys::create_restricted_file_atomic(&html_path, html.as_bytes())?;
    Ok(html_path)
}

/// Builds the CLI argument vector for launching native `sentinel-ui` strictly via `--bootstrap-file`
/// (guaranteeing zero secret bootstrap token on process command lines, `CSE-22`, `T50`).
fn build_native_ui_launch_args(
    actual_port: u16,
    handoff_file: &Path,
    demo_mode: bool,
) -> Vec<String> {
    let mut args = vec![
        "--port".to_string(),
        actual_port.to_string(),
        "--bootstrap-file".to_string(),
        handoff_file.to_string_lossy().into_owned(),
    ];
    if demo_mode {
        args.push("--demo".to_string());
    }
    args
}

/// Builds the OS browser launcher binary + argument vector targeting the local one-time redirect file
/// (guaranteeing zero `#bootstrap=` or token on `rundll32`/`open`/`xdg-open` command lines, `CSE-22`, `T50`).
fn build_browser_launch_command(handoff_html_path: &Path) -> (&'static str, Vec<String>) {
    let path_str = handoff_html_path.to_string_lossy().into_owned();
    #[cfg(target_os = "windows")]
    {
        (
            "rundll32.exe",
            vec!["url.dll,FileProtocolHandler".to_string(), path_str],
        )
    }
    #[cfg(target_os = "macos")]
    {
        ("open", vec![path_str])
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        ("xdg-open", vec![path_str])
    }
}

async fn serve_dashboard_ui(
    port: u16,
    demo_mode: bool,
    native_rune: bool,
    no_browser: bool,
    kiosk_intake_root: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
    let std_listener = std::net::TcpListener::bind(bind_addr)?;
    std_listener.set_nonblocking(true)?;
    let actual_port = std_listener.local_addr()?.port();

    let bootstrap_token = format!("boot_{}", uuid::Uuid::new_v4().simple());
    let session_id = format!("sid_{}", uuid::Uuid::new_v4().simple());
    let csrf_token = format!("csrf_{}", uuid::Uuid::new_v4().simple());

    let ui_staging_root = {
        #[cfg(test)]
        {
            std::env::temp_dir().join(format!("sentinel_ui_staging_{actual_port}"))
        }
        #[cfg(not(test))]
        {
            resolve_restricted_runtime_dir("UIStaging", ".sentinel_ui_staging")
                .join(format!("sentinel_ui_staging_{actual_port}"))
        }
    };
    let _ = sentinel_sys::create_restricted_dir_atomic(&ui_staging_root);

    let dashboard_dir = resolve_dashboard_dir();
    let state = Arc::new(
        DashboardAppState::new(
            actual_port,
            demo_mode,
            bootstrap_token.clone(),
            session_id,
            csrf_token,
            dashboard_dir,
            ui_staging_root.clone(),
        )
        .with_kiosk_intake_root(kiosk_intake_root),
    );

    info!("===========================================================");
    info!("   OmniConnect Sentinel - Localhost Defense Station Server ");
    info!("===========================================================");
    println!("\n🖥️ [SENTINEL DASHBOARD SERVER ACTIVE (AXUM)]");
    println!("   Bound Address:  http://127.0.0.1:{actual_port}/");
    println!("   Bootstrap Code: {bootstrap_token}");
    println!(
        "   Auth Model:     Single-Use Restricted Handoff File (30s TTL) -> HttpOnly Cookie + CSRF Header"
    );
    println!("   Staging Root:   {}", ui_staging_root.display());

    if native_rune {
        if let Some(rune_bin) = resolve_native_rune_ui_binary() {
            let handoff_file = write_native_bootstrap_handoff_file(
                &ui_staging_root,
                &bootstrap_token,
                BOOTSTRAP_HANDOFF_TTL_SECS,
            )?;
            state.register_bootstrap_handoff_file(handoff_file.clone());
            let ttl_path = handoff_file.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(BOOTSTRAP_HANDOFF_TTL_SECS))
                    .await;
                shred_and_remove_handoff_file(&ttl_path);
            });

            println!(
                "   UI Surface:     Native RUNE Framework GPU App ({})",
                rune_bin.display()
            );
            let launch_args = build_native_ui_launch_args(actual_port, &handoff_file, demo_mode);
            let mut cmd = std::process::Command::new(&rune_bin);
            cmd.args(&launch_args);
            if let Err(err) = cmd.spawn() {
                state.cleanup_bootstrap_handoff_files();
                tracing::warn!(
                    "Failed spawning native Rune UI ({}): {err}",
                    rune_bin.display()
                );
            }
        } else {
            println!("   UI Surface:     Native RUNE binary not built yet.");
            println!("   Build Hint:     cargo build --manifest-path sentinel-ui/Cargo.toml");
            println!("   Local Station:  http://127.0.0.1:{actual_port}/");
        }
    } else if !no_browser {
        // Launch default browser via short-lived restricted HTML redirect file so no
        // `#bootstrap=<token>` ever appears in process command-line arguments (`CSE-22`, `T50`).
        let redirect_html =
            write_browser_redirect_handoff_file(&ui_staging_root, actual_port, &bootstrap_token)?;
        state.register_bootstrap_handoff_file(redirect_html.clone());
        let ttl_path = redirect_html.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(BOOTSTRAP_HANDOFF_TTL_SECS)).await;
            shred_and_remove_handoff_file(&ttl_path);
        });

        let (launcher_bin, launcher_args) = build_browser_launch_command(&redirect_html);
        if let Err(err) = std::process::Command::new(launcher_bin)
            .args(&launcher_args)
            .spawn()
        {
            state.cleanup_bootstrap_handoff_files();
            tracing::warn!("Failed launching browser via {launcher_bin}: {err}");
        }
    }

    let app = build_dashboard_router(state);

    let listener = tokio::net::TcpListener::from_std(std_listener)?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_dashboard_axum_router_dns_rebinding_bearer_auth_csrf_and_metrics() {
        let dashboard_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("dashboard"))
            .unwrap_or_else(|| PathBuf::from("dashboard"));

        let staging_root =
            std::env::temp_dir().join(format!("sentinel_test_staging_{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&staging_root);

        let bootstrap_token = "boot-test-token-12345".to_string();
        let session_id = "sid-test-session-67890".to_string();
        let csrf_token = "csrf-test-token-abcde".to_string();

        let state = Arc::new(DashboardAppState::new(
            8088,
            false,
            bootstrap_token.clone(),
            session_id.clone(),
            csrf_token.clone(),
            dashboard_dir.clone(),
            staging_root.clone(),
        ));
        let app = build_dashboard_router(state);

        // 1. DNS rebinding Host (`127.0.0.1.attacker.tld`) MUST return 403 Forbidden (`High #9`)
        let req_rebind = Request::builder()
            .uri("/api/v1/status")
            .header(header::HOST, "127.0.0.1.attacker.tld")
            .header(header::AUTHORIZATION, format!("Bearer {session_id}"))
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_rebind = app
            .clone()
            .oneshot(req_rebind)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_rebind.status(), StatusCode::FORBIDDEN);

        // 2. Missing credentials on /api/v1/status MUST return 401 Unauthorized
        let req_unauth = Request::builder()
            .uri("/api/v1/status")
            .header(header::HOST, "127.0.0.1:8088")
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_unauth = app
            .clone()
            .oneshot(req_unauth)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_unauth.status(), StatusCode::UNAUTHORIZED);

        // 3. GET / MUST return 200 OK, strict CSP, Cache-Control: no-store, and ZERO sentinel-bearer-token meta
        let req_index = Request::builder()
            .uri("/")
            .header(header::HOST, "127.0.0.1:8088")
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_index = app
            .clone()
            .oneshot(req_index)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_index.status(), StatusCode::OK);
        let index_body_bytes = axum::body::to_bytes(resp_index.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let index_html = String::from_utf8_lossy(&index_body_bytes);
        assert!(
            !index_html.contains("sentinel-bearer-token"),
            "HTML must never contain sentinel-bearer-token meta tag"
        );

        // 4. Session Exchange: Invalid bootstrap code returns 401
        let req_bad_exchange = Request::builder()
            .method("POST")
            .uri("/api/v1/session/exchange")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"bootstrap_token":"wrong-code"}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_bad_exchange = app
            .clone()
            .oneshot(req_bad_exchange)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_bad_exchange.status(), StatusCode::UNAUTHORIZED);

        // 5. Session Exchange: Valid bootstrap code returns 200 OK + Set-Cookie + distinct csrf_token
        let req_good_exchange = Request::builder()
            .method("POST")
            .uri("/api/v1/session/exchange")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"bootstrap_token":"{bootstrap_token}"}}"#
            )))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_good_exchange = app
            .clone()
            .oneshot(req_good_exchange)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_good_exchange.status(), StatusCode::OK);
        let set_cookie = resp_good_exchange
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(set_cookie.contains("sentinel_sid="));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));

        let exchange_bytes = axum::body::to_bytes(resp_good_exchange.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let exchange_json: serde_json::Value =
            serde_json::from_slice(&exchange_bytes).unwrap_or_default();
        assert_eq!(exchange_json["csrf_token"], csrf_token);
        assert!(
            exchange_json.get("session_token").is_none(),
            "Session ID must NEVER be leaked in /api/v1/session/exchange JSON body (HttpOnly cookie only)"
        );
        assert_ne!(
            csrf_token, session_id,
            "CSRF token must be distinct from session ID"
        );

        // 5b. Authorization: Bearer <session_id> alone without HttpOnly cookie must be rejected
        let req_bearer_only = Request::builder()
            .uri("/api/v1/status")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::ORIGIN, "http://127.0.0.1:8088")
            .header(header::AUTHORIZATION, format!("Bearer {session_id}"))
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_bearer_only = app
            .clone()
            .oneshot(req_bearer_only)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(
            resp_bearer_only.status(),
            StatusCode::UNAUTHORIZED,
            "Session auth must rely strictly on HttpOnly cookie, never JS-readable bearer token"
        );

        // 6. Replay attack on single-use bootstrap code MUST return 401
        let req_replay_exchange = Request::builder()
            .method("POST")
            .uri("/api/v1/session/exchange")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"bootstrap_token":"{bootstrap_token}"}}"#
            )))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_replay_exchange = app
            .clone()
            .oneshot(req_replay_exchange)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(
            resp_replay_exchange.status(),
            StatusCode::UNAUTHORIZED,
            "Replay of bootstrap code must fail"
        );

        // 7. GET /api/v1/status with Cookie: sentinel_sid returns 200 OK + strict CSP + Cache-Control: no-store
        let req_ok = Request::builder()
            .uri("/api/v1/status")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::ORIGIN, "http://127.0.0.1:8088")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_ok = app
            .clone()
            .oneshot(req_ok)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_ok.status(), StatusCode::OK);
        let csp = resp_ok
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains("fonts.googleapis.com"));
        let cc = resp_ok
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(cc.contains("no-store"));

        // 8. POST /api/v1/shred without X-Sentinel-CSRF MUST return 403 Forbidden
        let req_no_csrf = Request::builder()
            .method("POST")
            .uri("/api/v1/shred")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .body(Body::from(r#"{"create_ephemeral_canary":true}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_no_csrf = app
            .clone()
            .oneshot(req_no_csrf)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_no_csrf.status(), StatusCode::FORBIDDEN);

        // 9. POST /api/v1/shred with session_id passed as CSRF token MUST return 403 Forbidden (CSRF token separation)
        let req_wrong_csrf = Request::builder()
            .method("POST")
            .uri("/api/v1/shred")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .header("x-sentinel-csrf", &session_id)
            .body(Body::from(r#"{"create_ephemeral_canary":true}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_wrong_csrf = app
            .clone()
            .oneshot(req_wrong_csrf)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_wrong_csrf.status(), StatusCode::FORBIDDEN);

        // 10a. POST /api/v1/shred attempting path traversal outside staging root MUST return 403 Forbidden
        let req_traversal = Request::builder()
            .method("POST")
            .uri("/api/v1/shred")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .header("x-sentinel-csrf", &csrf_token)
            .body(Body::from(r#"{"path":"../.sentinel_vault/audit.jsonl"}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_traversal = app
            .clone()
            .oneshot(req_traversal)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_traversal.status(), StatusCode::FORBIDDEN);

        // 10b. Sensitive vault path keyword rejection MUST return 403 Forbidden even if file does not exist on disk (CEA-DEFECT-01)
        let req_vault_keyword = Request::builder()
            .method("POST")
            .uri("/api/v1/shred")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .header("x-sentinel-csrf", &csrf_token)
            .body(Body::from(r#"{"path":".sentinel_vault/audit.jsonl"}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_vault_keyword = app
            .clone()
            .oneshot(req_vault_keyword)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_vault_keyword.status(), StatusCode::FORBIDDEN);

        // 10c. Absolute external host paths MUST return 403 Forbidden with zero existence oracle (CEA-DEFECT-02)
        for host_path in &[
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\drivers\\etc\\nonexistent_secret.sys",
        ] {
            let req_oracle = Request::builder()
                .method("POST")
                .uri("/api/v1/scan")
                .header(header::HOST, "127.0.0.1:8088")
                .header(header::COOKIE, format!("sentinel_sid={session_id}"))
                .header("x-sentinel-csrf", &csrf_token)
                .body(Body::from(format!(
                    r#"{{"path":"{}"}}"#,
                    host_path.replace('\\', "\\\\")
                )))
                .unwrap_or_else(|_| Request::new(Body::empty()));
            let resp_oracle = app
                .clone()
                .oneshot(req_oracle)
                .await
                .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
            assert_eq!(
                resp_oracle.status(),
                StatusCode::FORBIDDEN,
                "Host path must return 403 Forbidden: {host_path}"
            );
        }

        // 10d. Reload / Status CSRF token synchronization (CEA-DEFECT-03)
        let req_status_reload = Request::builder()
            .uri("/api/v1/status")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_status_reload = app
            .clone()
            .oneshot(req_status_reload)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_status_reload.status(), StatusCode::OK);
        let status_body = axum::body::to_bytes(resp_status_reload.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let status_parsed: serde_json::Value =
            serde_json::from_slice(&status_body).unwrap_or_default();
        assert_eq!(
            status_parsed.get("csrf_token").and_then(|v| v.as_str()),
            Some(csrf_token.as_str()),
            "GET /api/v1/status must return current CSRF token to prevent client lockout on reload"
        );

        // 11. POST /api/v1/shred with valid cookie + valid CSRF executes canary shred inside staging root and returns 200 OK
        let req_shred = Request::builder()
            .method("POST")
            .uri("/api/v1/shred")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .header("x-sentinel-csrf", &csrf_token)
            .body(Body::from(r#"{"create_ephemeral_canary":true}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_shred = app
            .clone()
            .oneshot(req_shred)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_shred.status(), StatusCode::OK);

        // 12. GET /api/v1/metrics exports all 7 Prometheus metric families
        let req_metrics = Request::builder()
            .uri("/api/v1/metrics")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_metrics = app
            .clone()
            .oneshot(req_metrics)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_metrics.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp_metrics.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let prom_text = String::from_utf8_lossy(&body_bytes);
        assert!(prom_text.contains("sentinel_active_workers"));
        assert!(prom_text.contains("sentinel_cdr_processed_total{"));
        assert!(prom_text.contains("sentinel_cdr_duration_ms{"));
        assert!(prom_text.contains("sentinel_threats_total{"));
        assert!(prom_text.contains("sentinel_vault_ops_total{"));
        assert!(prom_text.contains("sentinel_posture{feature="));
        assert!(prom_text.contains("sentinel_policy_drift_total"));

        // 13. Verify dashboard/app.js and dashboard/index.html have zero mock arrays or inline styles
        let app_js = fs::read_to_string(dashboard_dir.join("app.js")).unwrap_or_default();
        assert!(!app_js.contains("const DEVICES ="));
        assert!(!app_js.contains("STRESS_STREAM_ITEMS"));
        assert!(!app_js.contains("NORMAL_STREAM_ITEMS"));
        assert!(!app_js.contains("4,812"));
        assert!(app_js.contains("DISCONNECTED — NO LIVE DATA"));
        assert!(app_js.contains("SCAN INCOMPLETE — VOLUME HELD OFFLINE"));
        assert!(app_js.contains("initSession"));
        assert!(app_js.contains("window.history.replaceState"));
        assert!(app_js.contains("#bootstrap="));
        assert!(app_js.contains("exchangeBootstrapCode"));
        assert!(!app_js.contains("sessionBearerToken"));
        assert!(!app_js.contains("session_token"));

        let _ = fs::remove_dir_all(&staging_root);
    }

    #[test]
    fn ui_disconnected_state() {
        // Simple sanity check that the binary target compiles and tests link properly
    }

    #[tokio::test]
    async fn test_adversarial_cold_eye_dashboard_security_and_containment_probe(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dashboard_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("dashboard"))
            .unwrap_or_else(|| PathBuf::from("dashboard"));

        let staging_root =
            std::env::temp_dir().join(format!("sentinel_adv_staging_{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&staging_root);

        let bootstrap_token = format!("boot_adv_{}", uuid::Uuid::new_v4().simple());
        let session_id = format!("sid_adv_{}", uuid::Uuid::new_v4().simple());
        let csrf_token = format!("csrf_adv_{}", uuid::Uuid::new_v4().simple());

        let state = Arc::new(DashboardAppState::new(
            9191,
            false,
            bootstrap_token.clone(),
            session_id.clone(),
            csrf_token.clone(),
            dashboard_dir.clone(),
            staging_root.clone(),
        ));
        let app = build_dashboard_router(state.clone());

        // Probe 1: Expired Bootstrap Token Attack (TTL > 120s)
        {
            let mut guard = state
                .bootstrap_token
                .lock()
                .map_err(|e| format!("mutex poisoned: {e}"))?;
            *guard = Some((
                bootstrap_token.clone(),
                std::time::Instant::now() - std::time::Duration::from_secs(125),
            ));
        }
        let req_expired = Request::builder()
            .method("POST")
            .uri("/api/v1/session/exchange")
            .header(header::HOST, "127.0.0.1:9191")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"bootstrap_token":"{bootstrap_token}"}}"#
            )))?;
        let resp_expired = app.clone().oneshot(req_expired).await?;
        assert_eq!(
            resp_expired.status(),
            StatusCode::UNAUTHORIZED,
            "Expired bootstrap token (>120s) must be rejected with 401"
        );

        // Reset bootstrap token with fresh timestamp
        {
            let mut guard = state
                .bootstrap_token
                .lock()
                .map_err(|e| format!("mutex poisoned: {e}"))?;
            *guard = Some((bootstrap_token.clone(), std::time::Instant::now()));
        }

        // Probe 2: Token Prefix & Length Bypass Probes
        for bad_code in &[
            "",
            &bootstrap_token[..5],
            &format!("{bootstrap_token}extra"),
            "wrong_token_1234567890",
        ] {
            let req_bad = Request::builder()
                .method("POST")
                .uri("/api/v1/session/exchange")
                .header(header::HOST, "127.0.0.1:9191")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"bootstrap_token":"{bad_code}"}}"#)))?;
            let resp_bad = app.clone().oneshot(req_bad).await?;
            assert_eq!(
                resp_bad.status(),
                StatusCode::UNAUTHORIZED,
                "Malformed/mismatched bootstrap code '{bad_code}' must return 401"
            );
        }

        // Probe 3: Legitimate Bootstrap Exchange & Immediate Anti-Replay
        let req_exchange = Request::builder()
            .method("POST")
            .uri("/api/v1/session/exchange")
            .header(header::HOST, "127.0.0.1:9191")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"bootstrap_token":"{bootstrap_token}"}}"#
            )))?;
        let resp_exchange = app.clone().oneshot(req_exchange).await?;
        assert_eq!(resp_exchange.status(), StatusCode::OK);
        let set_cookie = resp_exchange
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(set_cookie.contains(&format!("sentinel_sid={session_id}")));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));

        // Attempt replay attack immediately
        let req_replay = Request::builder()
            .method("POST")
            .uri("/api/v1/session/exchange")
            .header(header::HOST, "127.0.0.1:9191")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"bootstrap_token":"{bootstrap_token}"}}"#
            )))?;
        let resp_replay = app.clone().oneshot(req_replay).await?;
        assert_eq!(
            resp_replay.status(),
            StatusCode::UNAUTHORIZED,
            "Replaying consumed bootstrap token must fail with 401"
        );

        // Probe 4: CSRF Cross-Substitution Attack (Submit session_id as CSRF token)
        let req_subst = Request::builder()
            .method("POST")
            .uri("/api/v1/scan")
            .header(header::HOST, "127.0.0.1:9191")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .header("x-sentinel-csrf", &session_id)
            .body(Body::from(r#"{"max_files":10}"#))?;
        let resp_subst = app.clone().oneshot(req_subst).await?;
        assert_eq!(
            resp_subst.status(),
            StatusCode::FORBIDDEN,
            "Submitting session_id as CSRF token must fail with 403 Forbidden"
        );

        // Probe 5: CSRF Missing / Altered Probes
        for bad_csrf in &["", "csrf_invalid_token", "csrf_adv_truncated", "null"] {
            let req_csrf_bad = Request::builder()
                .method("POST")
                .uri("/api/v1/shred")
                .header(header::HOST, "127.0.0.1:9191")
                .header(header::COOKIE, format!("sentinel_sid={session_id}"))
                .header("x-sentinel-csrf", *bad_csrf)
                .body(Body::from(r#"{"create_ephemeral_canary":true}"#))?;
            let resp_csrf_bad = app.clone().oneshot(req_csrf_bad).await?;
            assert_eq!(
                resp_csrf_bad.status(),
                StatusCode::FORBIDDEN,
                "Bad CSRF token '{bad_csrf}' must return 403 Forbidden"
            );
        }

        // Probe 6: Zero File Existence Oracle Probe (Absolute, Windows rooted `\...`, `/` rooted, and drive-relative `C:...`)
        let oracle_pairs = [
            (
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Windows\\System32\\definitely_nonexistent_secret_probe_9999.xyz",
            ),
            (
                "\\Windows\\System32\\cmd.exe",
                "\\Windows\\System32\\definitely_nonexistent_secret_probe_9999.xyz",
            ),
            (
                "/Windows/System32/cmd.exe",
                "/Windows/System32/definitely_nonexistent_secret_probe_9999.xyz",
            ),
            (
                "C:Windows\\System32\\cmd.exe",
                "C:Windows\\System32\\definitely_nonexistent_secret_probe_9999.xyz",
            ),
        ];

        for (existing_host_file, non_existing_host_file) in oracle_pairs {
            let req_exist = Request::builder()
                .method("POST")
                .uri("/api/v1/scan")
                .header(header::HOST, "127.0.0.1:9191")
                .header(header::COOKIE, format!("sentinel_sid={session_id}"))
                .header("x-sentinel-csrf", &csrf_token)
                .body(Body::from(format!(
                    r#"{{"path":"{}"}}"#,
                    existing_host_file.replace('\\', "\\\\")
                )))?;
            let resp_exist = app.clone().oneshot(req_exist).await?;
            let status_exist = resp_exist.status();
            let body_exist = axum::body::to_bytes(resp_exist.into_body(), 64 * 1024).await?;

            let req_nonexist = Request::builder()
                .method("POST")
                .uri("/api/v1/scan")
                .header(header::HOST, "127.0.0.1:9191")
                .header(header::COOKIE, format!("sentinel_sid={session_id}"))
                .header("x-sentinel-csrf", &csrf_token)
                .body(Body::from(format!(
                    r#"{{"path":"{}"}}"#,
                    non_existing_host_file.replace('\\', "\\\\")
                )))?;
            let resp_nonexist = app.clone().oneshot(req_nonexist).await?;
            let status_nonexist = resp_nonexist.status();
            let body_nonexist = axum::body::to_bytes(resp_nonexist.into_body(), 64 * 1024).await?;

            assert_eq!(
                status_exist,
                StatusCode::FORBIDDEN,
                "Host path {existing_host_file} must return 403 Forbidden"
            );
            assert_eq!(
                status_nonexist,
                StatusCode::FORBIDDEN,
                "Host path {non_existing_host_file} must return 403 Forbidden"
            );
            assert_eq!(
                body_exist, body_nonexist,
                "Responses for existing ({existing_host_file}) and non-existing ({non_existing_host_file}) host paths must be byte-for-byte identical (Zero Existence Oracle)"
            );
        }

        let top_alias = Cli::try_parse_from([
            "sentinel",
            "vault-verify-escrow",
            "--vault-dir",
            ".sentinel_vault",
            "--soc-priv-key",
            "soc.priv",
        ]);
        assert!(
            top_alias.is_ok(),
            "Top-level `sentinel vault-verify-escrow` CLI alias must parse cleanly"
        );

        // Probe 7: Sensitive Vault Keyword Probes (Must be 403 even for non-existent files)
        for vault_target in &[
            ".sentinel_vault",
            ".sentinel_vault/audit.jsonl",
            "audit.jsonl",
            "vault_kek",
            "subdir/.sentinel_vault/nonexistent.bin",
            ".SENTINEL_VAULT",
            "SUBDIR/AUDIT.JSONL",
            "VAULT_KEK.ESCROW",
        ] {
            let req_vault = Request::builder()
                .method("POST")
                .uri("/api/v1/shred")
                .header(header::HOST, "127.0.0.1:9191")
                .header(header::COOKIE, format!("sentinel_sid={session_id}"))
                .header("x-sentinel-csrf", &csrf_token)
                .body(Body::from(format!(r#"{{"path":"{vault_target}"}}"#)))?;
            let resp_vault = app.clone().oneshot(req_vault).await?;
            assert_eq!(
                resp_vault.status(),
                StatusCode::FORBIDDEN,
                "Vault sensitive keyword '{vault_target}' must return 403 Forbidden unconditionally"
            );
        }

        // Probe 8: Directory Traversal Attacks ('..')
        for traversal in &[
            "../outside.txt",
            "..\\outside.txt",
            "sub/../../outside.txt",
            "sub\\..\\..\\outside.txt",
        ] {
            let req_trav = Request::builder()
                .method("POST")
                .uri("/api/v1/shred")
                .header(header::HOST, "127.0.0.1:9191")
                .header(header::COOKIE, format!("sentinel_sid={session_id}"))
                .header("x-sentinel-csrf", &csrf_token)
                .body(Body::from(format!(
                    r#"{{"path":"{}"}}"#,
                    traversal.replace('\\', "\\\\")
                )))?;
            let resp_trav = app.clone().oneshot(req_trav).await?;
            assert_eq!(
                resp_trav.status(),
                StatusCode::FORBIDDEN,
                "Traversal '{traversal}' must return 403 Forbidden"
            );
        }

        // Probe 9: Semaphore Saturation / Concurrency Limiting (DoS Defense)
        let permit1 = state
            .shred_scan_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|e| format!("permit1: {e}"))?;
        let permit2 = state
            .shred_scan_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|e| format!("permit2: {e}"))?;

        let req_sat_scan = Request::builder()
            .method("POST")
            .uri("/api/v1/scan")
            .header(header::HOST, "127.0.0.1:9191")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .header("x-sentinel-csrf", &csrf_token)
            .body(Body::from(r#"{"max_files":10}"#))?;
        let resp_sat_scan = app.clone().oneshot(req_sat_scan).await?;
        assert_eq!(
            resp_sat_scan.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Scan operation with saturated semaphore must return 429 Too Many Requests"
        );

        let req_sat_shred = Request::builder()
            .method("POST")
            .uri("/api/v1/shred")
            .header(header::HOST, "127.0.0.1:9191")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .header("x-sentinel-csrf", &csrf_token)
            .body(Body::from(r#"{"create_ephemeral_canary":true}"#))?;
        let resp_sat_shred = app.clone().oneshot(req_sat_shred).await?;
        assert_eq!(
            resp_sat_shred.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Shred operation with saturated semaphore must return 429 Too Many Requests"
        );

        drop(permit1);
        drop(permit2);

        // Probe 10: Status CSRF synchronization
        let req_stat_unauth = Request::builder()
            .uri("/api/v1/status")
            .header(header::HOST, "127.0.0.1:9191")
            .body(Body::empty())?;
        let resp_stat_unauth = app.clone().oneshot(req_stat_unauth).await?;
        assert_eq!(resp_stat_unauth.status(), StatusCode::UNAUTHORIZED);

        let req_stat_auth = Request::builder()
            .uri("/api/v1/status")
            .header(header::HOST, "127.0.0.1:9191")
            .header(header::COOKIE, format!("sentinel_sid={session_id}"))
            .body(Body::empty())?;
        let resp_stat_auth = app.clone().oneshot(req_stat_auth).await?;
        assert_eq!(resp_stat_auth.status(), StatusCode::OK);
        let stat_bytes = axum::body::to_bytes(resp_stat_auth.into_body(), 1024 * 1024).await?;
        let stat_val: serde_json::Value = serde_json::from_slice(&stat_bytes)?;
        assert_eq!(stat_val["csrf_token"], csrf_token);

        // Probe 11: DOM Secret Eradication in index.html
        let req_idx = Request::builder()
            .uri("/")
            .header(header::HOST, "127.0.0.1:9191")
            .body(Body::empty())?;
        let resp_idx = app.clone().oneshot(req_idx).await?;
        assert_eq!(resp_idx.status(), StatusCode::OK);
        let idx_bytes = axum::body::to_bytes(resp_idx.into_body(), 1024 * 1024).await?;
        let idx_str = String::from_utf8_lossy(&idx_bytes);
        assert!(!idx_str.contains("sentinel-bearer-token"));
        assert!(!idx_str.contains(&session_id));
        assert!(!idx_str.contains(&bootstrap_token));
        assert!(!idx_str.contains(&csrf_token));
        assert!(!idx_str.contains("style="));
        assert!(!idx_str.contains("fonts.googleapis.com"));

        // Probe 12: Absolute path NTFS ADS colon oracle & multi-Cookie extraction (`CEA-DEFECT-05`)
        let abs_ads_existing = format!(
            "{}:secret_ads",
            staging_root.join("canary_probe.txt").display()
        );
        let abs_ads_nonexisting = format!(
            "{}:nonexistent_ads",
            staging_root.join("missing_probe.txt").display()
        );
        fs::write(staging_root.join("canary_probe.txt"), b"ok")?;
        let r_ads1 = resolve_contained_ui_target(Path::new(&abs_ads_existing), &staging_root);
        let r_ads2 = resolve_contained_ui_target(Path::new(&abs_ads_nonexisting), &staging_root);
        match r_ads1 {
            Err((code, _)) => assert_eq!(code, StatusCode::FORBIDDEN),
            Ok(p) => panic!("absolute ADS colon must return 403, got Ok({p:?})"),
        }
        match r_ads2 {
            Err((code, _)) => assert_eq!(code, StatusCode::FORBIDDEN),
            Ok(p) => {
                panic!("absolute ADS colon on missing file must return uniform 403, got Ok({p:?})")
            }
        }

        let mut multi_cookie_headers = HeaderMap::new();
        multi_cookie_headers.append(header::COOKIE, "other=1".parse()?);
        multi_cookie_headers.append(
            header::COOKIE,
            format!("sentinel_sid={session_id}").parse()?,
        );
        assert_eq!(
            extract_cookie_value(&multi_cookie_headers, "sentinel_sid").as_deref(),
            Some(session_id.as_str())
        );

        assert!(is_restricted_runtime_dir_writable(&staging_root));

        let _ = fs::remove_dir_all(&staging_root);
        Ok(())
    }

    #[test]
    fn t37_prompt_remediation_safe_default_eof_abort_and_shred_confirmation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use sentinel_core::scanner::universal_scanner::{CarrierCategory, ThreatSeverity};
        use std::io::Cursor;

        let test_root = std::env::temp_dir().join(format!(
            "sentinel_t37_cli_remediation_{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&test_root)?;
        let vault_dir = test_root.join("vault");
        let vault = QuarantineVault::open(vault_dir)?;

        let sample_path = test_root.join("critical_backup_2026.enc");
        fs::write(&sample_path, b"CRITICAL_CUSTOMER_BACKUP_DO_NOT_LOSE")?;

        let threat = UniversalThreat {
            file_path: sample_path.clone(),
            carrier_category: CarrierCategory::Executable,
            threat_name: "Heuristic.HighEntropy.FalsePositive".to_string(),
            severity: ThreatSeverity::High,
            risk_score: 96,
            mitre_technique: "T1027".to_string(),
            technical_details: "Simulated false-positive encrypted backup".to_string(),
            overlay_offset: None,
            stream_name: None,
            can_disarm_via_cdr: false,
        };

        // 1. Empty Enter press MUST default to safe SKIP (file untouched)
        let mut out = Vec::new();
        let mut empty_enter = Cursor::new(b"\n".as_slice());
        let outcome = prompt_remediation_with_io(&threat, &vault, &mut empty_enter, &mut out)?;
        assert_eq!(outcome, RemediationOutcome::Skipped);
        assert!(
            sample_path.exists(),
            "Empty Enter press must NEVER shred the file"
        );
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.contains("Default: 3 - SKIP"));

        // 1b. Unrecognized non-empty input MUST also default safely to SKIP (file untouched)
        for bad_input in [b"9\n".as_slice(), b"abc\n".as_slice()] {
            out.clear();
            let mut bad_reader = Cursor::new(bad_input);
            let bad_outcome =
                prompt_remediation_with_io(&threat, &vault, &mut bad_reader, &mut out)?;
            assert_eq!(bad_outcome, RemediationOutcome::Skipped);
            assert!(
                sample_path.exists(),
                "Unrecognized input must leave file intact"
            );
        }

        // 1c. Verify POST /api/v1/shred HTTP error classification (`CSE-15`)
        assert_eq!(
            classify_shred_error_http(
                "SHRED_VERIFICATION_FAILED: verification_passed=false, flush_succeeded=true"
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SHRED_VERIFICATION_FAILED"
            )
        );
        assert_eq!(
            classify_shred_error_http("Target file does not exist: foo.bin"),
            (StatusCode::BAD_REQUEST, "SHRED_OPERATION_FAILED")
        );

        // 2. Closed stdin (EOF) MUST fail closed and leave file untouched
        out.clear();
        let mut eof_reader = Cursor::new(b"".as_slice());
        let eof_res = prompt_remediation_with_io(&threat, &vault, &mut eof_reader, &mut out);
        assert!(eof_res.is_err(), "EOF must fail closed");
        assert!(sample_path.exists(), "EOF must NEVER shred the file");

        // 3. Selecting [1] without typing exact uppercase 'SHRED' confirmation MUST abort safely
        for wrong in [b"1\nyes\n".as_slice(), b"1\nshred\n".as_slice()] {
            out.clear();
            let mut wrong_confirm = Cursor::new(wrong);
            let abort_outcome =
                prompt_remediation_with_io(&threat, &vault, &mut wrong_confirm, &mut out)?;
            assert_eq!(abort_outcome, RemediationOutcome::ShredAborted);
            assert!(
                sample_path.exists(),
                "Missing exact uppercase 'SHRED' confirmation must leave file intact"
            );
        }

        // 4. Selecting [1] + EOF on confirmation MUST fail closed
        out.clear();
        let mut confirm_eof = Cursor::new(b"1\n".as_slice());
        let confirm_eof_res =
            prompt_remediation_with_io(&threat, &vault, &mut confirm_eof, &mut out);
        assert!(confirm_eof_res.is_err());
        assert!(sample_path.exists());

        // 5. Selecting [1] + exact 'SHRED' executes verified NIST 800-88 Clear
        out.clear();
        let mut explicit_shred = Cursor::new(b"1\nSHRED\n".as_slice());
        let shred_outcome =
            prompt_remediation_with_io(&threat, &vault, &mut explicit_shred, &mut out)?;
        assert_eq!(shred_outcome, RemediationOutcome::Shredded);
        assert!(
            !sample_path.exists(),
            "Explicit '1' + 'SHRED' must overwrite, verify, and unlink the target"
        );

        // 6. On Windows NTFS, verify ADS branch of `prompt_remediation_with_io` removes only the stream
        #[cfg(windows)]
        {
            let ads_host = test_root.join("ads_host_doc.txt");
            fs::write(&ads_host, b"BENIGN_HOST_DATA_T37")?;
            let ads_stream_path = format!("{}:hidden_payload", ads_host.display());
            if fs::write(&ads_stream_path, b"HIDDEN_ADS_PAYLOAD_T37").is_ok() {
                let ads_threat = UniversalThreat {
                    file_path: ads_host.clone(),
                    carrier_category: CarrierCategory::FilesystemHidden,
                    threat_name: "NTFS.ADS.Test".to_string(),
                    severity: ThreatSeverity::High,
                    risk_score: 92,
                    mitre_technique: "T1564.004".to_string(),
                    technical_details: "Test NTFS ADS stream".to_string(),
                    overlay_offset: None,
                    stream_name: Some("hidden_payload".to_string()),
                    can_disarm_via_cdr: false,
                };
                out.clear();
                let mut ads_shred = Cursor::new(b"1\nSHRED\n".as_slice());
                let ads_outcome =
                    prompt_remediation_with_io(&ads_threat, &vault, &mut ads_shred, &mut out)?;
                assert_eq!(ads_outcome, RemediationOutcome::Shredded);
                assert!(
                    ads_host.exists(),
                    "Host file must remain intact after ADS shred"
                );
                assert_eq!(fs::read(&ads_host)?, b"BENIGN_HOST_DATA_T37");
                assert!(
                    fs::metadata(&ads_stream_path).is_err(),
                    "ADS stream must be unlinked after shred"
                );
            }
        }

        // 7. Verify `execute_shred_command` fails closed (non-zero CLI exit) on missing file
        //    and succeeds with bounded `--fill-free-space` on an existing file
        let ledger_path = test_root.join("t37_cmd_ledger.jsonl");
        let shared_ledger = Arc::new(Mutex::new(AuditLedger::open_result(&ledger_path)?));
        let missing_target = test_root.join("does_not_exist_t37.bin");
        assert!(
            execute_shred_command(&missing_target, 3, false, Some(&shared_ledger), 0).is_err(),
            "Commands::Shred must propagate Err for missing target"
        );
        let cmd_target = test_root.join("cmd_shred_target.bin");
        fs::write(&cmd_target, vec![0xAAu8; 4096])?;
        let cmd_receipt = execute_shred_command(&cmd_target, 3, true, Some(&shared_ledger), 65536)?;
        assert!(cmd_receipt.verification_passed && cmd_receipt.flush_succeeded);
        assert!(!cmd_target.exists());

        // 8. Verify live `POST /api/v1/shred` router hits `classify_shred_error_http` and returns
        //    HTTP 400 `SHRED_OPERATION_FAILED` when shredding a directory inside staging root
        let staging_root = test_root.join("ui_staging");
        let staging_subdir = staging_root.join("non_file_dir");
        fs::create_dir_all(&staging_subdir)?;
        let bootstrap_token = "t37_bootstrap_token_fixed_0123456789abcdef".to_string();
        let session_id = "t37_session_id_fixed_0123456789abcdef".to_string();
        let csrf_token = "t37_csrf_token_fixed_0123456789abcdef".to_string();
        let state = Arc::new(DashboardAppState::new(
            8091,
            false,
            bootstrap_token,
            session_id.clone(),
            csrf_token.clone(),
            staging_root.clone(),
            staging_root.clone(),
        ));
        let router = build_dashboard_router(state);
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let bad_shred_req = Request::builder()
                .method("POST")
                .uri("/api/v1/shred")
                .header(header::HOST, "127.0.0.1:8091")
                .header(header::ORIGIN, "http://127.0.0.1:8091")
                .header(header::COOKIE, format!("sentinel_sid={session_id}"))
                .header("x-sentinel-csrf", &csrf_token)
                .body(Body::from(
                    serde_json::json!({ "path": "non_file_dir" }).to_string(),
                ))?;
            let bad_resp = router.clone().oneshot(bad_shred_req).await?;
            assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
            let bad_body = axum::body::to_bytes(bad_resp.into_body(), 1024 * 64).await?;
            let bad_json: serde_json::Value = serde_json::from_slice(&bad_body)?;
            assert_eq!(bad_json["error"], "SHRED_OPERATION_FAILED");
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        let _ = fs::remove_dir_all(&test_root);
        Ok(())
    }

    #[test]
    fn t39_cli_vault_recover_escrow_and_hybrid_v3_end_to_end(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_root = std::env::temp_dir().join(format!(
            "sentinel_t39_cli_escrow_recover_{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&test_root)?;

        // 1. Classical RSA-3072 escrow recovery end-to-end via `execute_recover_escrow`
        let rsa_vault_dir = test_root.join("rsa_vault");
        let rsa_ledger_path = test_root.join("rsa_ledger.jsonl");
        let rsa_ledger = Arc::new(Mutex::new(AuditLedger::open_result(&rsa_ledger_path)?));
        let (rsa_pub, rsa_priv) = sentinel_sys::generate_soc_rsa_keypair()?;
        let (_, wrong_rsa_priv) = sentinel_sys::generate_soc_rsa_keypair()?;

        let rsa_priv_path = test_root.join("soc_rsa_priv.der");
        let wrong_priv_path = test_root.join("wrong_rsa_priv.der");
        fs::write(&rsa_priv_path, &rsa_priv)?;
        fs::write(&wrong_priv_path, &wrong_rsa_priv)?;

        let sample_payload = b"CRITICAL_OT_CALIBRATION_RECIPE_T39_RSA";
        let sample_file = test_root.join("turbine_recipe_rsa.bin");
        fs::write(&sample_file, sample_payload)?;

        let vault = QuarantineVault::open_with_soc_public_key(rsa_vault_dir.clone(), &rsa_pub)?
            .with_shared_ledger(rsa_ledger.clone());
        let expected_kek_id = vault.kek_id().to_string();
        let entry = vault.quarantine_file(&sample_file, "T39.FalsePositive.RSA")?;
        drop(vault);

        // Corrupt host `vault_kek.sealed` to simulate dead TPM/motherboard
        let sealed_path = rsa_vault_dir.join("vault_kek.sealed");
        fs::write(&sealed_path, b"CORRUPTED_TPM_SEALED_BLOB")?;
        assert!(
            QuarantineVault::open(rsa_vault_dir.clone()).is_err(),
            "Corrupted vault_kek.sealed must fail closed before recovery"
        );

        // Wrong SOC private key MUST fail closed without overwriting `vault_kek.sealed`
        assert!(
            execute_recover_escrow(&rsa_vault_dir, &wrong_priv_path, Some(rsa_ledger.clone()))
                .is_err()
        );
        assert_eq!(fs::read(&sealed_path)?, b"CORRUPTED_TPM_SEALED_BLOB");

        // Correct SOC private key recovers, re-seals `vault_kek.sealed`, logs event, and restores file
        let (rec_kek_id, _) =
            execute_recover_escrow(&rsa_vault_dir, &rsa_priv_path, Some(rsa_ledger.clone()))?;
        assert_eq!(rec_kek_id, expected_kek_id);
        let reopened = QuarantineVault::open(rsa_vault_dir.clone())?;
        let restored_path = test_root.join("restored_rsa.bin");
        reopened.restore_file(&entry.entry_id, &restored_path)?;
        assert_eq!(fs::read(&restored_path)?, sample_payload);
        let rsa_log = fs::read_to_string(&rsa_ledger_path)?;
        assert!(rsa_log.contains("VAULT_ESCROW_RECOVERED"));

        // 2. Hybrid PQC OCESCROW3 recovery end-to-end via `execute_recover_hybrid_escrow_v3`
        let pqc_vault_dir = test_root.join("pqc_vault");
        let pqc_ledger_path = test_root.join("pqc_ledger.jsonl");
        let pqc_ledger = Arc::new(Mutex::new(AuditLedger::open_result(&pqc_ledger_path)?));
        let (pub_b, priv_b) = sentinel_sys::generate_hybrid_soc_keypair_with_bits(3072)?;
        let (_, wrong_priv_b) = sentinel_sys::generate_hybrid_soc_keypair_with_bits(3072)?;

        let pqc_priv_path = test_root.join("soc_hybrid_priv.json");
        let wrong_pqc_path = test_root.join("wrong_hybrid_priv.json");
        fs::write(&pqc_priv_path, serde_json::to_vec_pretty(&priv_b)?)?;
        fs::write(&wrong_pqc_path, serde_json::to_vec_pretty(&wrong_priv_b)?)?;

        let pqc_payload = b"CRITICAL_SUBSTATION_FW_T39_OCESCROW3";
        let pqc_file = test_root.join("substation_fw_pqc.bin");
        fs::write(&pqc_file, pqc_payload)?;

        let pqc_vault =
            QuarantineVault::open(pqc_vault_dir.clone())?.with_shared_ledger(pqc_ledger.clone());
        let pqc_expected_kek = pqc_vault.kek_id().to_string();
        pqc_vault.provision_hybrid_soc_escrow_v3(&pub_b)?;
        let pqc_entry = pqc_vault.quarantine_file(&pqc_file, "T39.FalsePositive.PQC")?;
        drop(pqc_vault);

        // Delete `vault_kek.sealed` completely to simulate total disk/TPM replacement
        let pqc_sealed = pqc_vault_dir.join("vault_kek.sealed");
        fs::remove_file(&pqc_sealed)?;
        assert!(!pqc_sealed.exists());

        // Wrong hybrid bundle must fail closed without creating `vault_kek.sealed`
        assert!(execute_recover_hybrid_escrow_v3(
            &pqc_vault_dir,
            &wrong_pqc_path,
            Some(pqc_ledger.clone())
        )
        .is_err());
        assert!(!pqc_sealed.exists());

        // Correct hybrid bundle recovers, re-seals, logs event, and restores exact plaintext
        let (rec_pqc_kek, _) = execute_recover_hybrid_escrow_v3(
            &pqc_vault_dir,
            &pqc_priv_path,
            Some(pqc_ledger.clone()),
        )?;
        assert_eq!(rec_pqc_kek, pqc_expected_kek);
        assert!(pqc_sealed.exists());
        let pqc_reopened = QuarantineVault::open(pqc_vault_dir.clone())?;
        let pqc_restored = test_root.join("restored_pqc.bin");
        pqc_reopened.restore_file(&pqc_entry.entry_id, &pqc_restored)?;
        assert_eq!(fs::read(&pqc_restored)?, pqc_payload);
        let pqc_log = fs::read_to_string(&pqc_ledger_path)?;
        assert!(pqc_log.contains("VAULT_HYBRID_PQC_ESCROW_V3_RECOVERED"));

        // Verify Clap CLI parses both new recovery subcommands cleanly
        let parsed_rsa = Cli::try_parse_from([
            "sentinel",
            "vault",
            "recover-escrow",
            "--vault-dir",
            "my_vault",
            "--soc-priv-key",
            "soc.der",
        ])?;
        assert!(matches!(
            parsed_rsa.command,
            Commands::Vault {
                action: VaultAction::RecoverEscrow { .. }
            }
        ));
        let parsed_pqc = Cli::try_parse_from([
            "sentinel",
            "vault",
            "recover-hybrid-escrow-v3",
            "--vault-dir",
            "my_vault",
            "--hybrid-priv-key",
            "soc_pqc.json",
        ])?;
        assert!(matches!(
            parsed_pqc.command,
            Commands::Vault {
                action: VaultAction::RecoverHybridEscrowV3 { .. }
            }
        ));

        let _ = fs::remove_dir_all(&test_root);
        Ok(())
    }

    #[test]
    fn t41_kiosk_pipeline_runs_real_scanner_and_cdr_and_rejects_unscanned_or_empty(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use sentinel_core::enterprise::kiosk::{
            KioskConfig, PASSPORT_MANIFEST_FILENAME, PASSPORT_PUBKEY_FILENAME,
        };

        let test_root = std::env::temp_dir().join(format!(
            "sentinel_t41_kiosk_pipeline_{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&test_root)?;
        let scratch_dir = test_root.join("kiosk_scratch");
        let vault_dir = test_root.join("vault");
        let export_dir = test_root.join("export");
        let empty_intake = test_root.join("empty_intake");
        let dirty_intake = test_root.join("dirty_intake");
        let unsupported_intake = test_root.join("unsupported_intake");
        let clean_intake = test_root.join("clean_intake");
        fs::create_dir_all(&empty_intake)?;
        fs::create_dir_all(&dirty_intake)?;
        fs::create_dir_all(&unsupported_intake)?;
        fs::create_dir_all(&clean_intake)?;

        let kiosk = AirGappedKioskManager::new(KioskConfig::default(), scratch_dir);
        let vault = QuarantineVault::open(vault_dir)?;

        // Resolve `sentinel-cdr-worker` from the active build profile (`target/<profile>/`) — auto-building
        // offline if absent so isolated CDR assertions NEVER silently skip on clean/release/custom target runs.
        let active_profile_dir = std::env::current_exe()?
            .parent()
            .and_then(|p| p.parent())
            .ok_or("active Cargo profile directory unavailable")?
            .to_path_buf();
        let worker_name = if cfg!(windows) {
            "sentinel-cdr-worker.exe"
        } else {
            "sentinel-cdr-worker"
        };
        let worker_bin = active_profile_dir.join(worker_name);
        if !worker_bin.is_file() {
            let mut build_cmd = std::process::Command::new("cargo");
            build_cmd.args([
                "build",
                "-p",
                "sentinel-cdr",
                "--bin",
                "sentinel-cdr-worker",
                "--offline",
            ]);
            if active_profile_dir.file_name().and_then(|n| n.to_str()) == Some("release") {
                build_cmd.arg("--release");
            }
            let status = build_cmd.status()?;
            assert!(
                status.success(),
                "Building sentinel-cdr-worker for T41 failed"
            );
        }
        let base_launcher = WorkerLauncher::new().with_worker_bin(worker_bin.clone());
        assert!(
            base_launcher.has_worker_binary(),
            "T41 requires compiled sentinel-cdr-worker binary (no silent skip)"
        );
        let launcher = {
            let probe = base_launcher.sanitize_isolated(WorkerRequest {
                file_name: "probe.txt".to_string(),
                policy: SanitizationPolicy::default(),
                raw_bytes: b"probe".to_vec(),
            });
            match probe {
                Err(sentinel_cdr::CdrError::SandboxFailure(ref msg))
                    if msg.contains("os error 87") =>
                {
                    let cfg = sentinel_sys::JobSandboxConfig {
                        enable_appcontainer: false,
                        ..Default::default()
                    };
                    WorkerLauncher::new()
                        .with_worker_bin(worker_bin)
                        .with_sandbox_config(cfg)
                }
                _ => base_launcher,
            }
        };

        // 1. `--export-dir` without `--intake-dir` MUST fail closed (`KIOSK_INTAKE_REQUIRED`)
        let no_intake = execute_kiosk_intake_and_export(
            &kiosk,
            &vault,
            &launcher,
            &KioskPipelineParams {
                intake_dir: None,
                export_dir: Some(&export_dir),
                media_id: "USB-T41-01",
                policy_id: "POL-T41",
                policy_sequence: 1,
                max_files: 2000,
            },
        );
        assert!(no_intake
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("KIOSK_INTAKE_REQUIRED")));
        assert!(!export_dir.join(PASSPORT_MANIFEST_FILENAME).exists());

        // 2. Empty `--intake-dir` MUST fail closed (`KIOSK_INTAKE_EMPTY`)
        let empty_res = execute_kiosk_intake_and_export(
            &kiosk,
            &vault,
            &launcher,
            &KioskPipelineParams {
                intake_dir: Some(&empty_intake),
                export_dir: Some(&export_dir),
                media_id: "USB-T41-02",
                policy_id: "POL-T41",
                policy_sequence: 1,
                max_files: 2000,
            },
        );
        assert!(empty_res
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("KIOSK_INTAKE_EMPTY")));
        assert!(!export_dir.join(PASSPORT_MANIFEST_FILENAME).exists());

        // 2b. Incomplete scan (`max_files: 1` on a 2-file intake dir) MUST fail closed (`KIOSK_SCAN_INCOMPLETE`)
        let truncated_intake = test_root.join("truncated_intake");
        fs::create_dir_all(&truncated_intake)?;
        fs::write(truncated_intake.join("a.txt"), b"file one")?;
        fs::write(truncated_intake.join("b.txt"), b"file two")?;
        let inc_res = execute_kiosk_intake_and_export(
            &kiosk,
            &vault,
            &launcher,
            &KioskPipelineParams {
                intake_dir: Some(&truncated_intake),
                export_dir: Some(&export_dir),
                media_id: "USB-T41-02B",
                policy_id: "POL-T41",
                policy_sequence: 1,
                max_files: 1,
            },
        );
        assert!(inc_res
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("KIOSK_SCAN_INCOMPLETE")));
        assert!(!export_dir.join(PASSPORT_MANIFEST_FILENAME).exists());

        // 2c. Symlink / NTFS directory junction as `--intake-dir` MUST fail closed (`KIOSK_INTAKE_SYMLINK_REJECTED`)
        let link_intake = test_root.join("link_intake");
        let link_created = {
            #[cfg(windows)]
            {
                std::process::Command::new("cmd")
                    .args([
                        "/C",
                        "mklink",
                        "/J",
                        &link_intake.to_string_lossy(),
                        &truncated_intake.to_string_lossy(),
                    ])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            }
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&truncated_intake, &link_intake).is_ok()
            }
        };
        if link_created {
            let link_res = execute_kiosk_intake_and_export(
                &kiosk,
                &vault,
                &launcher,
                &KioskPipelineParams {
                    intake_dir: Some(&link_intake),
                    export_dir: Some(&export_dir),
                    media_id: "USB-T41-02C",
                    policy_id: "POL-T41",
                    policy_sequence: 1,
                    max_files: 2000,
                },
            );
            assert!(link_res
                .as_ref()
                .err()
                .is_some_and(|e| e.contains("KIOSK_INTAKE_SYMLINK_REJECTED")));
            assert!(!export_dir.join(PASSPORT_MANIFEST_FILENAME).exists());
        }

        // 3. Infected/prohibited `--intake-dir` (.lnk shell shortcut magic bytes) MUST quarantine evidence
        //    into vault and refuse export/passport without mutating read-only intake media
        let lnk_payload = b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46SHORTCUT_PAYLOAD_T41";
        fs::write(dirty_intake.join("invoice_shortcut.lnk"), lnk_payload)?;
        let dirty_res = execute_kiosk_intake_and_export(
            &kiosk,
            &vault,
            &launcher,
            &KioskPipelineParams {
                intake_dir: Some(&dirty_intake),
                export_dir: Some(&export_dir),
                media_id: "USB-T41-03",
                policy_id: "POL-T41",
                policy_sequence: 1,
                max_files: 2000,
            },
        );
        let dirty_err = dirty_res.as_ref().err().cloned().unwrap_or_default();
        assert!(
            dirty_err.contains("KIOSK_THREATS_DETECTED"),
            "Expected KIOSK_THREATS_DETECTED, got: {dirty_err}"
        );
        assert!(!export_dir.join(PASSPORT_MANIFEST_FILENAME).exists());
        let vault_count_after_threat = vault.list()?.len();
        assert!(
            vault_count_after_threat >= 1,
            "Detected intake threat must be quarantined into vault as read-only evidence (err={dirty_err})"
        );
        assert!(
            dirty_intake.join("invoice_shortcut.lnk").exists(),
            "Read-only intake media file must not be mutated during read-only quarantine"
        );

        // 4. Unconditional isolated CDR assertions (NO silent skip):
        // 4a. Unsupported binary rejected by default-deny CDR allowlist -> quarantined + fails closed with no passport
        fs::write(
            unsupported_intake.join("mystery.xyz"),
            b"\x00\x01\x02\x03UNSUPPORTED",
        )?;
        let unsup_res = execute_kiosk_intake_and_export(
            &kiosk,
            &vault,
            &launcher,
            &KioskPipelineParams {
                intake_dir: Some(&unsupported_intake),
                export_dir: Some(&export_dir),
                media_id: "USB-T41-04",
                policy_id: "POL-T41",
                policy_sequence: 1,
                max_files: 2000,
            },
        );
        assert!(unsup_res
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("KIOSK_CDR_REJECTED")));
        assert!(!export_dir.join(PASSPORT_MANIFEST_FILENAME).exists());
        assert!(
            vault.list()?.len() > vault_count_after_threat,
            "CDR-rejected intake file must be persisted as read-only quarantine evidence"
        );

        // 4b. Clean text file passes scanner + isolated CDR and yields a verified passport
        let clean_txt = clean_intake.join("operator_notes.txt");
        fs::write(&clean_txt, b"SCADA shift handover: turbine 2 nominal.\n")?;
        let ok_summary = execute_kiosk_intake_and_export(
            &kiosk,
            &vault,
            &launcher,
            &KioskPipelineParams {
                intake_dir: Some(&clean_intake),
                export_dir: Some(&export_dir),
                media_id: "USB-T41-05",
                policy_id: "POL-T41",
                policy_sequence: 7,
                max_files: 2000,
            },
        )?;
        assert_eq!(ok_summary.files_sanitized, 1);
        let passport = ok_summary.passport.ok_or("expected signed passport")?;
        assert_eq!(passport.sanitized_files.len(), 1);
        assert!(passport.sanitized_files[0]
            .cdr_action
            .starts_with("DEEP_CDR_RECONSTRUCTED:"));
        let pub_bytes = fs::read(export_dir.join(PASSPORT_PUBKEY_FILENAME))?;
        let verified = verify_kiosk_passport(&export_dir, Some(&pub_bytes))?;
        assert_eq!(verified.passport_id, passport.passport_id);

        // 5. Honest posture label NEVER claims `"SL-3 ENFORCED"` (both compliant and non-compliant)
        let compliant_posture = sentinel_sys::PostureReport {
            automount_disabled: true,
            removable_volumes_offline: vec![],
            user_deny_policy_present: true,
            install_restrictions_active: true,
            write_protect_active: true,
            autoplay_suppressed: true,
            linux_authorized_default_zero: Some(true),
            hardware_write_blocker: sentinel_sys::HardwareWriteBlockerState::NotDetected,
        };
        let label = format_honest_kiosk_posture_label(&compliant_posture);
        assert!(!label.contains("SL-3 ENFORCED"));
        assert!(label.contains("SOFTWARE_POSTURE_VERIFIED"));

        let noncompliant_posture = sentinel_sys::PostureReport {
            automount_disabled: false,
            removable_volumes_offline: vec![],
            user_deny_policy_present: false,
            install_restrictions_active: false,
            write_protect_active: false,
            autoplay_suppressed: false,
            linux_authorized_default_zero: Some(false),
            hardware_write_blocker: sentinel_sys::HardwareWriteBlockerState::NotDetected,
        };
        let nc_label = format_honest_kiosk_posture_label(&noncompliant_posture);
        assert!(!nc_label.contains("SL-3 ENFORCED"));
        assert!(nc_label.contains("NON_COMPLIANT"));

        // 6. Live `POST /api/v1/scan` containment, empty-target fail-closed, and `--kiosk-intake-root` checks
        let staging_empty = test_root.join("ui_staging_empty");
        let intake_for_api = test_root.join("ui_kiosk_intake");
        let intake_subdir = intake_for_api.join("batch_01");
        fs::create_dir_all(&staging_empty)?;
        fs::create_dir_all(&intake_subdir)?;
        fs::write(intake_subdir.join("log.txt"), b"benign intake file")?;

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let sid = "t41_sid_0123456789abcdef".to_string();
            let csrf = "t41_csrf_0123456789abcdef".to_string();

            // 6a. Empty staging root without kiosk intake -> HTTP 400 `EMPTY_SCAN_TARGET`
            let state_empty = Arc::new(DashboardAppState::new(
                8092,
                false,
                "boot_t41".to_string(),
                sid.clone(),
                csrf.clone(),
                staging_empty.clone(),
                staging_empty.clone(),
            ));
            let router_empty = build_dashboard_router(state_empty.clone());
            let req_empty = Request::builder()
                .method("POST")
                .uri("/api/v1/scan")
                .header(header::HOST, "127.0.0.1:8092")
                .header(header::ORIGIN, "http://127.0.0.1:8092")
                .header(header::COOKIE, format!("sentinel_sid={sid}"))
                .header("x-sentinel-csrf", &csrf)
                .body(Body::from(r#"{"max_files":50}"#))?;
            let resp_empty = router_empty.oneshot(req_empty).await?;
            assert_eq!(resp_empty.status(), StatusCode::BAD_REQUEST);
            let body_empty = axum::body::to_bytes(resp_empty.into_body(), 64 * 1024).await?;
            let json_empty: serde_json::Value = serde_json::from_slice(&body_empty)?;
            assert_eq!(json_empty["error"], "EMPTY_SCAN_TARGET");
            assert_eq!(json_empty["complete"], false);
            assert!(!state_empty.last_scan_complete.load(Ordering::Relaxed));

            // 6b. Configured `--kiosk-intake-root` -> default scan AND explicit relative path inside intake return 200 OK
            let state_intake = Arc::new(
                DashboardAppState::new(
                    8093,
                    false,
                    "boot_t41_intake".to_string(),
                    sid.clone(),
                    csrf.clone(),
                    staging_empty.clone(),
                    staging_empty.clone(),
                )
                .with_kiosk_intake_root(Some(intake_for_api.clone())),
            );
            let router_intake = build_dashboard_router(state_intake);
            let req_intake = Request::builder()
                .method("POST")
                .uri("/api/v1/scan")
                .header(header::HOST, "127.0.0.1:8093")
                .header(header::ORIGIN, "http://127.0.0.1:8093")
                .header(header::COOKIE, format!("sentinel_sid={sid}"))
                .header("x-sentinel-csrf", &csrf)
                .body(Body::from(r#"{"max_files":50}"#))?;
            let resp_intake = router_intake.clone().oneshot(req_intake).await?;
            assert_eq!(resp_intake.status(), StatusCode::OK);
            let body_intake = axum::body::to_bytes(resp_intake.into_body(), 64 * 1024).await?;
            let json_intake: serde_json::Value = serde_json::from_slice(&body_intake)?;
            assert_eq!(json_intake["files_scanned"], 1);
            assert_eq!(json_intake["complete"], true);

            // 6c. Explicit relative `{"path": "batch_01"}` resolves cleanly inside `kiosk_intake_root`
            let req_rel = Request::builder()
                .method("POST")
                .uri("/api/v1/scan")
                .header(header::HOST, "127.0.0.1:8093")
                .header(header::ORIGIN, "http://127.0.0.1:8093")
                .header(header::COOKIE, format!("sentinel_sid={sid}"))
                .header("x-sentinel-csrf", &csrf)
                .body(Body::from(r#"{"path":"batch_01","max_files":50}"#))?;
            let resp_rel = router_intake.clone().oneshot(req_rel).await?;
            assert_eq!(resp_rel.status(), StatusCode::OK);

            // 6d. Traversal & external host path MUST still return uniform HTTP 403 (even with missing intake root)
            let state_missing_intake = Arc::new(
                DashboardAppState::new(
                    8094,
                    false,
                    "boot_t41_missing".to_string(),
                    sid.clone(),
                    csrf.clone(),
                    staging_empty.clone(),
                    staging_empty.clone(),
                )
                .with_kiosk_intake_root(Some(test_root.join("nonexistent_intake_root"))),
            );
            let router_missing = build_dashboard_router(state_missing_intake);
            for bad_path in [
                "../escape",
                "C:\\Windows\\System32\\cmd.exe",
                ".sentinel_vault",
            ] {
                let req_bad = Request::builder()
                    .method("POST")
                    .uri("/api/v1/scan")
                    .header(header::HOST, "127.0.0.1:8094")
                    .header(header::ORIGIN, "http://127.0.0.1:8094")
                    .header(header::COOKIE, format!("sentinel_sid={sid}"))
                    .header("x-sentinel-csrf", &csrf)
                    .body(Body::from(format!(
                        r#"{{"path":"{}"}}"#,
                        bad_path.replace('\\', "\\\\")
                    )))?;
                let resp_bad = router_missing.clone().oneshot(req_bad).await?;
                assert_eq!(
                    resp_bad.status(),
                    StatusCode::FORBIDDEN,
                    "Bad path '{bad_path}' must return uniform 403 Forbidden"
                );
            }

            // 6e. Vault-named `--kiosk-intake-root` and symlinked `--kiosk-intake-root` MUST return 403 Forbidden
            let vault_named_intake = test_root.join(".sentinel_vault");
            fs::create_dir_all(&vault_named_intake)?;
            let state_vault_intake = Arc::new(
                DashboardAppState::new(
                    8095,
                    false,
                    "boot_t41_vault".to_string(),
                    sid.clone(),
                    csrf.clone(),
                    staging_empty.clone(),
                    staging_empty.clone(),
                )
                .with_kiosk_intake_root(Some(vault_named_intake)),
            );
            let req_vault = Request::builder()
                .method("POST")
                .uri("/api/v1/scan")
                .header(header::HOST, "127.0.0.1:8095")
                .header(header::ORIGIN, "http://127.0.0.1:8095")
                .header(header::COOKIE, format!("sentinel_sid={sid}"))
                .header("x-sentinel-csrf", &csrf)
                .body(Body::from(r#"{"max_files":50}"#))?;
            let resp_vault = build_dashboard_router(state_vault_intake)
                .oneshot(req_vault)
                .await?;
            assert_eq!(resp_vault.status(), StatusCode::FORBIDDEN);

            if link_created {
                let state_link_intake = Arc::new(
                    DashboardAppState::new(
                        8096,
                        false,
                        "boot_t41_link".to_string(),
                        sid.clone(),
                        csrf.clone(),
                        staging_empty.clone(),
                        staging_empty.clone(),
                    )
                    .with_kiosk_intake_root(Some(link_intake.clone())),
                );
                let router_link = build_dashboard_router(state_link_intake);
                // Both omitted path AND explicit absolute path through symlinked intake root must return 403
                let req_link_none = Request::builder()
                    .method("POST")
                    .uri("/api/v1/scan")
                    .header(header::HOST, "127.0.0.1:8096")
                    .header(header::ORIGIN, "http://127.0.0.1:8096")
                    .header(header::COOKIE, format!("sentinel_sid={sid}"))
                    .header("x-sentinel-csrf", &csrf)
                    .body(Body::from(r#"{"max_files":50}"#))?;
                assert_eq!(
                    router_link.clone().oneshot(req_link_none).await?.status(),
                    StatusCode::FORBIDDEN
                );
                let canonical_target_file = truncated_intake.canonicalize()?.join("a.txt");
                let req_link_abs = Request::builder()
                    .method("POST")
                    .uri("/api/v1/scan")
                    .header(header::HOST, "127.0.0.1:8096")
                    .header(header::ORIGIN, "http://127.0.0.1:8096")
                    .header(header::COOKIE, format!("sentinel_sid={sid}"))
                    .header("x-sentinel-csrf", &csrf)
                    .body(Body::from(format!(
                        r#"{{"path":"{}"}}"#,
                        canonical_target_file
                            .to_string_lossy()
                            .replace('\\', "\\\\")
                    )))?;
                assert_eq!(
                    router_link.oneshot(req_link_abs).await?.status(),
                    StatusCode::FORBIDDEN
                );
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        let _ = fs::remove_dir_all(&test_root);
        Ok(())
    }

    #[test]
    fn t50_ui_launch_command_line_contains_zero_bootstrap_token(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_root = std::env::temp_dir().join(format!(
            "sentinel_t50_handoff_{}",
            uuid::Uuid::new_v4().simple()
        ));
        sentinel_sys::create_restricted_dir_atomic(&test_root)?;

        let secret_token = format!("boot_secret_{}", uuid::Uuid::new_v4().simple());
        let port = 8099u16;

        // 1. Native Rune UI launch args must use `--bootstrap-file` and contain ZERO bootstrap token
        let native_handoff = write_native_bootstrap_handoff_file(
            &test_root,
            &secret_token,
            BOOTSTRAP_HANDOFF_TTL_SECS,
        )?;
        assert!(native_handoff.is_file());
        let native_args = build_native_ui_launch_args(port, &native_handoff, false);
        assert!(
            native_args.iter().any(|a| a == "--bootstrap-file"),
            "Native UI must receive --bootstrap-file: {native_args:?}"
        );
        for arg in &native_args {
            assert!(
                !arg.contains(&secret_token) && !arg.contains("#bootstrap="),
                "Native UI launch argument leaked bootstrap secret: {arg}"
            );
        }

        // Verify restricted permissions/DACL on handoff file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&native_handoff)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Handoff file must be mode 0600 on Unix");
        }
        #[cfg(windows)]
        {
            let sddl = sentinel_sys::query_path_dacl_sddl(&native_handoff)?;
            assert!(
                !sddl.contains(";;;AU)") && !sddl.contains(";;;WD)"),
                "Handoff file DACL must exclude AU and WD: {sddl}"
            );
        }

        // Verify JSON contents include exact token and 30s TTL window
        let handoff_json: serde_json::Value = serde_json::from_slice(&fs::read(&native_handoff)?)?;
        assert_eq!(
            handoff_json["bootstrap_token"].as_str(),
            Some(secret_token.as_str())
        );
        let now = sentinel_sys::now_unix_secs();
        let exp = handoff_json["expires_unix"].as_i64().unwrap_or(0);
        assert!(
            exp >= now && exp <= now + (BOOTSTRAP_HANDOFF_TTL_SECS as i64) + 2,
            "Handoff expiry must enforce 30s TTL (now={now}, exp={exp})"
        );

        // 2. Browser launch command (`rundll32`/`open`/`xdg-open`) must contain ZERO `#bootstrap=` or token
        let browser_html = write_browser_redirect_handoff_file(&test_root, port, &secret_token)?;
        assert!(browser_html.is_file());
        let (launcher_bin, launcher_args) = build_browser_launch_command(&browser_html);
        assert!(!launcher_bin.is_empty());
        for arg in &launcher_args {
            assert!(
                !arg.contains(&secret_token) && !arg.contains("#bootstrap="),
                "Browser launcher argument leaked bootstrap token: {arg}"
            );
        }
        let html_body = fs::read_to_string(&browser_html)?;
        assert!(
            html_body.contains(&format!(
                "http://127.0.0.1:{port}/#bootstrap={secret_token}"
            )),
            "Restricted local HTML redirect file must carry loopback redirect target"
        );

        // 3. Exchanging the bootstrap token via `/api/v1/session/exchange` must IMMEDIATELY delete
        //    both registered handoff/redirect files from disk.
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let state = Arc::new(DashboardAppState::new(
                port,
                false,
                secret_token.clone(),
                "sid_t50_session".to_string(),
                "csrf_t50_token".to_string(),
                test_root.clone(),
                test_root.clone(),
            ));
            state.register_bootstrap_handoff_file(native_handoff.clone());
            state.register_bootstrap_handoff_file(browser_html.clone());

            let router = build_dashboard_router(state);
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/session/exchange")
                .header(header::HOST, format!("127.0.0.1:{port}"))
                .header(header::ORIGIN, format!("http://127.0.0.1:{port}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"bootstrap_token":"{secret_token}"}}"#
                )))?;
            let resp = router.oneshot(req).await?;
            assert_eq!(resp.status(), StatusCode::OK);
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        assert!(
            !native_handoff.exists(),
            "Native bootstrap handoff file must be deleted immediately after exchange"
        );
        assert!(
            !browser_html.exists(),
            "Browser redirect handoff file must be deleted immediately after exchange"
        );

        // 4. Dropping `DashboardAppState` before exchange MUST also delete registered handoff files
        let drop_handoff = write_native_bootstrap_handoff_file(
            &test_root,
            "boot_drop_cleanup",
            BOOTSTRAP_HANDOFF_TTL_SECS,
        )?;
        assert!(drop_handoff.is_file());
        {
            let drop_state = DashboardAppState::new(
                port,
                false,
                "boot_drop_cleanup".to_string(),
                "sid_drop".to_string(),
                "csrf_drop".to_string(),
                test_root.clone(),
                test_root.clone(),
            );
            drop_state.register_bootstrap_handoff_file(drop_handoff.clone());
        }
        assert!(
            !drop_handoff.exists(),
            "DashboardAppState Drop must delete any remaining bootstrap handoff files"
        );

        // 5. Verify `sentinel siem flush` CLI parsing (`CSE-23`)
        let parsed = Cli::try_parse_from([
            "sentinel",
            "siem",
            "flush",
            "--endpoint",
            "tls://10.20.30.40:6514",
            "--allow-private-cidr",
            "10.20.0.0/16",
        ])?;
        assert!(matches!(
            parsed.command,
            Commands::Siem {
                action: SiemAction::Flush { .. }
            }
        ));

        let _ = fs::remove_dir_all(&test_root);
        Ok(())
    }
}
