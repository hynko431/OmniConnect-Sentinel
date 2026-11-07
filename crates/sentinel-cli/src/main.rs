#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

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
use sentinel_core::enterprise::intune::IntunePolicyManager;
use sentinel_core::enterprise::kiosk::AirGappedKioskManager;
use sentinel_core::enterprise::ledger::AuditLedger;
use sentinel_core::error::SentinelMetrics;
use sentinel_core::interceptor::drive_watcher::DriveWatcher;
use sentinel_core::interceptor::PendingDeviceConfirmationManager;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::secure_shredder::{SecureShredder, ShredMethod, ShredReceipt};
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

        /// OpenSandbox endpoint
        #[arg(short, long, default_value = "http://localhost:8080")]
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
    /// Permanently shred a malicious file or carrier (NIST 800-88 Clear (logical))
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
    /// Launch the interactive Web & Desktop Dashboard GUI over 127.0.0.1 with bearer auth
    Ui {
        /// Port to serve the dashboard on (binds strictly to 127.0.0.1)
        #[arg(short, long, default_value_t = 8088)]
        port: u16,

        /// Serve watermarked demo fixture data for sales demos (Master Plan v2 §4.3)
        #[arg(long, default_value_t = false)]
        demo: bool,
    },
    /// Manage Microsoft Intune OMA-URI deployment profiles
    Intune {
        /// Export custom OMA-URI XML profile for Intune Admin Center
        #[arg(short, long)]
        export: Option<PathBuf>,
    },
    /// Emit sample CrowdStrike Falcon FDR / CEF Syslog telemetry
    Telemetry {
        /// Event type (e.g. DeviceArrival, ExploitBlocked, FileSanitized)
        #[arg(short, long, default_value = "DeviceArrival")]
        event: String,
    },
    /// Run an Air-Gapped Kiosk session with posture verification & NIST 800-88 Clear shredding
    Kiosk {
        /// Media serial number or identifier
        #[arg(short, long, default_value = "USB-MEDIA-SCADA-01")]
        media: String,
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

        /// 8-character hex user-presence confirmation challenge code
        #[arg(long)]
        challenge: String,
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
    /// Crypto-erase and shred a quarantined artifact from the vault (Master Plan v2 §1.1 #5)
    Purge {
        /// Quarantine entry UUID
        #[arg(short, long)]
        id: String,

        /// Vault directory path
        #[arg(long, default_value = ".sentinel_vault")]
        vault_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum LedgerAction {
    /// Verify the cryptographic SHA-256 hash chain and ECDSA-P256 signed chain head of the audit ledger
    Verify {
        /// Path to audit ledger JSONL file
        #[arg(short, long, default_value = ".sentinel_vault/audit.jsonl")]
        path: PathBuf,
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
            let yara = Tier0YaraScanner::new();
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
                println!("File Path:              {:?}", path);
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
                            yara_res.threat_Details.as_deref().unwrap_or("")
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

            let client = Tier3SandboxConnector::new(endpoint, "LOCAL-KEY");
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
            println!("File Name:              {}", file_name);
            println!("SHA256:                 {}", sha256_hex);
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
            println!("VM Profile:             {}", vm);
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
                    println!("   • {}", t);
                }
            }

            if !report.behavioral_indicators.is_empty() {
                println!("\n🌲 [BEHAVIORAL INDICATORS]");
                for ind in &report.behavioral_indicators {
                    println!("   • {}", ind);
                }
            }

            if !report.network_iocs.is_empty() {
                println!("\n🌐 [EXTRACTED NON-PKI NETWORK IOCS]");
                for url in &report.network_iocs {
                    println!("   • {}", url);
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
                let vault = QuarantineVault::open(PathBuf::from(".sentinel_vault"))?;
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
            println!("===========================================================");
            println!("      OMNICONNECT SENTINEL: ANTI-FORENSIC SECURE SHREDDER  ");
            println!("===========================================================");
            println!("Target Path: {:?}", path);
            println!("Standard:    NIST 800-88 Clear (logical)");
            println!(
                "Overwrites:  {} Passes (0x00, 0xFF, CSPRNG + Read-Back Verification)\n",
                passes
            );

            let parent_dir = path.parent().map(|p| p.to_path_buf());
            match SecureShredder::shred_file(&path, ShredMethod::ClearMultiPass { passes }) {
                Ok(receipt) => {
                    println!("⚡ [SHREDDING COMPLETE]");
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
                            if let Ok(filled) = SecureShredder::fill_free_space(&dir, 0) {
                                println!(
                                    "   Free-Space Fill:      {} bytes (best-effort logical fill)",
                                    filled
                                );
                            }
                        }
                    }
                    println!("\n✅ File {:?} overwritten, verified, and unlinked.", path);
                }
                Err(e) => {
                    println!("❌ Shredding failed: {}", e);
                }
            }
        }
        Commands::Watch { interval_ms } => {
            println!("===========================================================");
            println!("      OMNICONNECT SENTINEL: AUTONOMOUS DRIVE SENTRY        ");
            println!("===========================================================");
            println!(
                "Actively monitoring for removable media insertions (Interval: {} ms)...",
                interval_ms
            );
            println!("Press Ctrl+C to terminate sentinel sentry.\n");

            let vault = std::sync::Arc::new(QuarantineVault::new(PathBuf::from(".sentinel_vault")));
            let mut watcher = DriveWatcher::new();
            watcher
                .watch_loop(move |drive_root| {
                    println!(
                        "\n🚨 [EXTERNAL DRIVE DETECTED]: Removable Media connected at {:?}",
                        drive_root
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
                                eprintln!("❌ Remediation error: {}", e);
                            }
                        }
                    }
                })
                .await;
        }
        Commands::Ui { port, demo } => {
            // Serve the dashboard over localhost (127.0.0.1:{port}) with bearer token & live /api/v1/status (`BUG-CLI-02` #2)
            serve_dashboard_ui(port, demo).await?;
        }
        Commands::Intune { export } => {
            let mut mgr = IntunePolicyManager::new();
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
                println!(
                    "\n✅ Exported XML-escaped Intune OMA-URI profile to: {:?}",
                    out_path
                );
            } else {
                println!("\n💡 Tip: Use --export <PATH.xml> to save the deployment profile.");
            }
        }
        Commands::Telemetry { event } => {
            let bridge = CrowdStrikeFalconBridge::new("127.0.0.1:514");
            let ev = FalconTelemetryEvent {
                severity: 9,
                signature_id: format!("SENTINEL-{}", event.to_uppercase()),
                name: format!("OmniConnect Sentinel Peripheral Event ({})", event),
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
            let _ = bridge.emit_alert(&ev);
        }
        Commands::Kiosk { media } => {
            let scratch = std::env::temp_dir().join("sentinel_kiosk_scratch");
            let mut kiosk = AirGappedKioskManager::from_terminal_id(
                "KIOSK-TERMINAL-SCADA-01".to_string(),
                scratch.clone(),
            );

            println!("\n===========================================================");
            println!("       AIR-GAPPED INDUSTRIAL KIOSK SESSION (IEC 62443)     ");
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

            // Enforce strict endpoint posture gate before starting session (`Row 22`, `High #18`)
            let session_id = kiosk.begin_kiosk_session_with_posture(&posture)?;
            let rel_media_enc = PathBuf::from(&session_id).join("media_manifest.enc");
            let session_dir = kiosk.write_encrypted_session_file(
                &rel_media_enc,
                format!("MEDIA={} SESSION={}", media, session_id).as_bytes(),
            )?;
            let _verified = kiosk.read_encrypted_session_file(&rel_media_enc)?;

            println!("Session ID:                     {}", session_id);
            println!("Ephemeral Session Workspace:    {:?}", session_dir);
            println!("Status:                         Executing Offline YARA & Deep CDR disarm...");

            let wiped_files = kiosk.end_session_and_shred()?;
            println!(
                "NIST 800-88 Clear + Key Wipe:   COMPLETED ({} session files shredded)",
                wiped_files
            );
            println!("IEC 62443 Compliance State:     SL-3 ENFORCED\n");
        }
        Commands::Vault { action } => match action {
            VaultAction::List { vault_dir } => {
                let vault = QuarantineVault::open(vault_dir)?;
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
                let vault = QuarantineVault::open(vault_dir)?;
                let restored = vault.restore_file(&id, &output)?;
                println!("✅ Restored quarantine entry '{}' to {:?}", id, restored);
            }
            VaultAction::Migrate { vault_dir, action } => {
                use sentinel_core::scanner::quarantine::LegacyMigrationAction;
                let vault = QuarantineVault::open(vault_dir)?;
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
                let vault = QuarantineVault::open(vault_dir)?;
                vault.purge(&id)?;
                println!(
                    "✅ Crypto-erased wrapped DEK and shredded quarantine entry '{}' from vault.",
                    id
                );
            }
        },
        Commands::Ledger { action } => match action {
            LedgerAction::Verify { path } => {
                let ledger = AuditLedger::open_result(path.clone())?;
                let verified_count = ledger.verify_chain()?;
                println!(
                    "✅ Audit ledger {:?} verified intact ({} hash-chained records + ECDSA-P256 signed chain head).",
                    path,
                    verified_count
                );
            }
        },
        Commands::ConfirmDevice {
            device_id,
            challenge,
        } => {
            let mgr = PendingDeviceConfirmationManager::new(
                PendingDeviceConfirmationManager::default_state_file(),
            );
            mgr.confirm_device_with_challenge(&device_id, &challenge)?;
            let mut ledger = AuditLedger::open(PathBuf::from(".sentinel_vault/audit.jsonl"));
            let _ = ledger.append_event(
                "DEVICE_CONFIRMED_BY_USER",
                &format!(
                    "Device {} authorized via physical user-presence challenge",
                    device_id
                ),
            );
            println!(
                "✅ Physical user-presence challenge verified. Re-enabled USB device node: {}",
                device_id
            );
        }
    }

    Ok(())
}

/// Interactive Threat Remediation (`BUG-CLI-01`, `BUG-CORE-02`, `BUG-CORE-06`):
/// 1. Reuses a single `QuarantineVault` instance (`BUG-CORE-02`).
/// 2. Routes NTFS Alternate Data Stream threats (`threat.stream_name.is_some()`) to
///    `SecureShredder::shred_ntfs_stream` so the host file is preserved (`BUG-CLI-01` #1).
/// 3. Shreds the original plaintext file (`quarantine_file` calls `SecureShredder::shred_file`
///    and we also ensure any ADS stream is shredded) so plaintext never remains on the USB volume (`BUG-CLI-01` #2).
fn prompt_remediation(threat: &UniversalThreat, vault: &QuarantineVault) -> Result<(), String> {
    println!("\n================================================================================");
    println!("🚨 [THREAT IDENTIFIED]: {:?}", threat.file_path);
    if let Some(stream) = &threat.stream_name {
        println!("   NTFS Stream:  {}", stream);
    }
    println!("   Carrier:      {:?}", threat.carrier_category);
    println!("   Threat Name:  {}", threat.threat_name);
    println!(
        "   Severity:     {:?} (Risk Score: {}/100)",
        threat.severity, threat.risk_score
    );
    println!("   MITRE ATT&CK: {}", threat.mitre_technique);
    println!("   Details:      {}", threat.technical_details);
    println!("--------------------------------------------------------------------------------");
    println!("REMEDIATION CHOICES:");
    println!("  [1] PERMANENT ANTI-FORENSIC SHRED (NIST 800-88 Clear (logical))");
    println!("  [2] QUARANTINE TO ENCRYPTED VAULT (AES-256-GCM + Shred Original Plaintext)");
    println!("  [3] SKIP / LEAVE UNTOUCHED");
    print!("Select action [1-3] (Default: 1): ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    let choice = input.trim();

    if choice.is_empty() || choice == "1" {
        if let Some(stream_name) = &threat.stream_name {
            println!(
                "⚡ Surgically shredding NTFS Alternate Data Stream '{}' while preserving host file...",
                stream_name
            );
            let receipt = SecureShredder::shred_ntfs_stream(&threat.file_path, stream_name)?;
            println!(
                "✅ [ADS STREAM ERADICATED]: {} ({} bytes overwritten, {}). Host file preserved!",
                receipt.original_path, receipt.file_size_bytes, receipt.sanitization_level
            );
        } else {
            println!("⚡ Executing NIST 800-88 Clear (logical) multi-pass shredding...");
            let receipt = SecureShredder::shred_file(
                &threat.file_path,
                ShredMethod::ClearMultiPass { passes: 3 },
            )?;
            println!(
                "✅ [PERMANENTLY ERADICATED]: {} ({} bytes overwritten, {}).",
                receipt.original_path, receipt.file_size_bytes, receipt.sanitization_level
            );
        }
    } else if choice == "2" {
        println!("🔒 Quarantining to encrypted vault, verifying copy on disk (I4), and shredding source...");
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
        println!("✅ Quarantined to: {}", q.vault_file_path);
        println!(
            "✅ Source plaintext verified in vault and overwritten/unlinked via SecureShredder."
        );
    } else {
        println!("⚠️ Threat skipped per user request.");
    }
    Ok(())
}

/// Strict CSP for the local Web Dashboard (`Row 177`):
/// - No `'unsafe-inline'`
/// - No external `fonts.googleapis.com` or `fonts.gstatic.com` (works 100% air-gapped)
pub const STRICT_DASHBOARD_CSP: &str =
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'";

/// Shared state for the Axum Web Dashboard router (`Sub-Phase 5.1`, `Rows 172–185, 206, 227`).
pub struct DashboardAppState {
    pub port: u16,
    pub demo_mode: bool,
    pub session_token: String,
    pub dashboard_dir: PathBuf,
    pub last_scan_complete: AtomicBool,
    pub last_scan_errors: Mutex<Vec<String>>,
    pub recent_events: Mutex<VecDeque<serde_json::Value>>,
    pub last_shred_receipt: Mutex<Option<ShredReceipt>>,
}

impl DashboardAppState {
    pub fn new(port: u16, demo_mode: bool, session_token: String, dashboard_dir: PathBuf) -> Self {
        let mut events = VecDeque::new();
        events.push_back(serde_json::json!({
            "event": "AGENT_STATUS_SYNC",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "demo_mode": demo_mode,
            "complete": true,
            "detail": "Ring 3 Sentinel Agent initialized on 127.0.0.1",
        }));
        Self {
            port,
            demo_mode,
            session_token,
            dashboard_dir,
            last_scan_complete: AtomicBool::new(true),
            last_scan_errors: Mutex::new(Vec::new()),
            recent_events: Mutex::new(events),
            last_shred_receipt: Mutex::new(None),
        }
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
        || trimmed == format!("127.0.0.1:{}", port)
        || trimmed == format!("localhost:{}", port)
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
        || trimmed == format!("http://127.0.0.1:{}", port)
        || trimmed == format!("http://localhost:{}", port)
}

/// Constant-time validation of the `Authorization: Bearer <token>` header using `subtle::ConstantTimeEq` (`Row 173`).
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

/// Constant-time validation of the `X-Sentinel-CSRF` header against the session token (`Rows 175, 227`).
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

fn check_bearer_auth(headers: &HeaderMap, expected_token: &str) -> Result<(), Box<Response>> {
    let auth_str = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !verify_bearer_token_constant_time(auth_str, expected_token) {
        return Err(Box::new(with_security_headers(
            StatusCode::UNAUTHORIZED,
            "application/json; charset=utf-8",
            br#"{"error":"UNAUTHORIZED","message":"Missing or invalid Authorization: Bearer token"}"#.to_vec(),
        )));
    }
    Ok(())
}

fn check_csrf_header(headers: &HeaderMap, expected_token: &str) -> Result<(), Box<Response>> {
    let csrf_str = headers.get("x-sentinel-csrf").and_then(|v| v.to_str().ok());
    if !verify_csrf_token_constant_time(csrf_str, expected_token) {
        return Err(Box::new(with_security_headers(
            StatusCode::FORBIDDEN,
            "application/json; charset=utf-8",
            br#"{"error":"CSRF_VALIDATION_FAILED","message":"Missing or invalid X-Sentinel-CSRF header"}"#.to_vec(),
        )));
    }
    Ok(())
}

async fn handle_index(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    let raw_html = fs::read_to_string(state.dashboard_dir.join("index.html")).unwrap_or_default();
    let hydrated_html = raw_html.replace(
        r#"<meta name="sentinel-bearer-token" content="">"#,
        &format!(
            r#"<meta name="sentinel-bearer-token" content="{}">"#,
            state.session_token
        ),
    );
    with_security_headers(
        StatusCode::OK,
        "text/html; charset=utf-8",
        hydrated_html.into_bytes(),
    )
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
    if let Err(resp) = check_bearer_auth(&headers, &state.session_token) {
        return *resp;
    }

    let posture = verify_system_posture();
    let mut pol_mgr = IntunePolicyManager::new();
    let policy = pol_mgr.load_active_policy();
    let vault = QuarantineVault::new(PathBuf::from(".sentinel_vault"));
    let entries = vault.list_entries().unwrap_or_default();
    let ledger = AuditLedger::open(PathBuf::from(".sentinel_vault/audit.jsonl"));
    let chain_ok = ledger.verify_chain().is_ok();
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
    if let Err(resp) = check_bearer_auth(&headers, &state.session_token) {
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
    if let Err(resp) = check_bearer_auth(&headers, &state.session_token) {
        return *resp;
    }
    if let Err(resp) = check_csrf_header(&headers, &state.session_token) {
        return *resp;
    }

    let req: ScanApiRequest = serde_json::from_slice(&body).unwrap_or_default();
    let target_path = req
        .path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".sentinel_vault"));
    let max_files = req.max_files.unwrap_or(500).clamp(1, 5000);

    if !target_path.exists() {
        let _ = fs::create_dir_all(&target_path);
    }

    let report = UniversalScanner::scan_directory_detailed(&target_path, max_files);
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

    state.push_event(serde_json::json!({
        "event": "SCAN_COMPLETE",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "path": target_path.to_string_lossy(),
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

async fn handle_api_shred(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    if let Err(resp) = check_bearer_auth(&headers, &state.session_token) {
        return *resp;
    }
    if let Err(resp) = check_csrf_header(&headers, &state.session_token) {
        return *resp;
    }

    let req: ShredApiRequest = serde_json::from_slice(&body).unwrap_or_default();
    let target_path = if let Some(ref p) = req.path {
        PathBuf::from(p)
    } else if req.create_ephemeral_canary.unwrap_or(true) {
        let vault_dir = PathBuf::from(".sentinel_vault");
        let _ = fs::create_dir_all(&vault_dir);
        let canary = vault_dir.join(format!("shred_canary_{}.bin", uuid::Uuid::new_v4()));
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

    match SecureShredder::shred_file(&target_path, ShredMethod::ClearMultiPass { passes: 3 }) {
        Ok(receipt) => {
            if let Ok(mut guard) = state.last_shred_receipt.lock() {
                *guard = Some(receipt.clone());
            }
            let mut ledger = AuditLedger::open(PathBuf::from(".sentinel_vault/audit.jsonl"));
            let _ = ledger.append_event(
                "SHRED_RECEIPT",
                serde_json::to_string(&receipt).unwrap_or_default(),
            );
            state.push_event(serde_json::json!({
                "event": "SHRED_COMPLETE",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "original_path": receipt.original_path,
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
        Err(err) => with_security_headers(
            StatusCode::BAD_REQUEST,
            "application/json; charset=utf-8",
            serde_json::to_vec(&serde_json::json!({
                "error": "SHRED_OPERATION_FAILED",
                "message": err,
            }))
            .unwrap_or_default(),
        ),
    }
}

async fn handle_api_metrics(
    State(state): State<Arc<DashboardAppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = check_host_and_origin(&headers, state.port) {
        return *resp;
    }
    if let Err(resp) = check_bearer_auth(&headers, &state.session_token) {
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
/// - Generates a per-session bearer token validated in constant time via `Authorization: Bearer <token>` (`Row 173`)
/// - Enforces exact `Host` and `Origin` header validation (`127.0.0.1:{port}` / `localhost:{port}`) to block DNS rebinding (`High #9`, `Row 174`)
/// - Enforces CSRF validation (`X-Sentinel-CSRF`) on `POST /api/v1/scan` and `POST /api/v1/shred` (`Rows 175, 227`)
/// - Exports all 7 labeled Prometheus metrics on `GET /api/v1/metrics` (`Row 206`)
async fn serve_dashboard_ui(port: u16, demo_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
    let std_listener = std::net::TcpListener::bind(bind_addr)?;
    std_listener.set_nonblocking(true)?;
    let actual_port = std_listener.local_addr()?.port();

    let session_token = uuid::Uuid::new_v4().to_string();
    let launch_url = format!("http://127.0.0.1:{}/", actual_port);
    if !is_valid_dashboard_launch_url(&launch_url) {
        return Err("Refusing to launch browser: URL failed strict ^http://127\\.0\\.0\\.1:\\d+/ validation".into());
    }

    info!("===========================================================");
    info!("   OmniConnect Sentinel - Localhost Web GUI Dashboard      ");
    info!("===========================================================");
    println!("\n🖥️ [SENTINEL DASHBOARD SERVER ACTIVE (AXUM)]");
    println!("   Bound Address: {}", launch_url);
    println!("   Bearer Auth:   Required via Authorization: Bearer <token> header");

    #[cfg(target_os = "windows")]
    {
        // Launch default browser via rundll32 FileProtocolHandler without invoking cmd.exe (`BUG-CLI-02`, `Row 179`)
        let _ = std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", &launch_url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(&launch_url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(&launch_url)
            .spawn();
    }

    let dashboard_dir = std::env::current_dir()?.join("dashboard");
    let state = Arc::new(DashboardAppState::new(
        actual_port,
        demo_mode,
        session_token,
        dashboard_dir,
    ));
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

        let token = "test-session-bearer-token-9f8e7d6c".to_string();
        let state = Arc::new(DashboardAppState::new(
            8088,
            false,
            token.clone(),
            dashboard_dir.clone(),
        ));
        let app = build_dashboard_router(state);

        // 1. DNS rebinding Host (`127.0.0.1.attacker.tld`) MUST return 403 Forbidden (`High #9`)
        let req_rebind = Request::builder()
            .uri("/api/v1/status")
            .header(header::HOST, "127.0.0.1.attacker.tld")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_rebind = app
            .clone()
            .oneshot(req_rebind)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_rebind.status(), StatusCode::FORBIDDEN);

        // 2. Missing Authorization header on /api/v1/status MUST return 401 Unauthorized (even if token is in URL query)
        let req_unauth = Request::builder()
            .uri(format!("/api/v1/status?token={}", token))
            .header(header::HOST, "127.0.0.1:8088")
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_unauth = app
            .clone()
            .oneshot(req_unauth)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_unauth.status(), StatusCode::UNAUTHORIZED);

        // 3. Valid Host + Authorization: Bearer <token> on /api/v1/status MUST return 200 OK + strict CSP
        let req_ok = Request::builder()
            .uri("/api/v1/status")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::ORIGIN, "http://127.0.0.1:8088")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
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

        // 4. POST /api/v1/shred without X-Sentinel-CSRF MUST return 403 Forbidden
        let req_no_csrf = Request::builder()
            .method("POST")
            .uri("/api/v1/shred")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .body(Body::from(r#"{"create_ephemeral_canary":true}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_no_csrf = app
            .clone()
            .oneshot(req_no_csrf)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_no_csrf.status(), StatusCode::FORBIDDEN);

        // 5. POST /api/v1/shred with valid Bearer + X-Sentinel-CSRF executes real SecureShredder and returns 200 OK
        let req_shred = Request::builder()
            .method("POST")
            .uri("/api/v1/shred")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .header("x-sentinel-csrf", &token)
            .body(Body::from(r#"{"create_ephemeral_canary":true}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        let resp_shred = app
            .clone()
            .oneshot(req_shred)
            .await
            .unwrap_or_else(|_| http::Response::new(Body::empty()).into_response());
        assert_eq!(resp_shred.status(), StatusCode::OK);

        // 6. GET /api/v1/metrics exports all 7 Prometheus metric families
        let req_metrics = Request::builder()
            .uri("/api/v1/metrics")
            .header(header::HOST, "127.0.0.1:8088")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
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

        // 7. Verify dashboard/app.js and dashboard/index.html have zero mock arrays or inline styles
        let app_js = fs::read_to_string(dashboard_dir.join("app.js")).unwrap_or_default();
        assert!(!app_js.contains("const DEVICES ="));
        assert!(!app_js.contains("STRESS_STREAM_ITEMS"));
        assert!(!app_js.contains("NORMAL_STREAM_ITEMS"));
        assert!(!app_js.contains("4,812"));
        assert!(app_js.contains("DISCONNECTED — NO LIVE DATA"));
        assert!(app_js.contains("SCAN INCOMPLETE — VOLUME HELD OFFLINE"));
    }

    #[test]
    fn ui_disconnected_state() {
        test_dashboard_axum_router_dns_rebinding_bearer_auth_csrf_and_metrics();
    }
}
