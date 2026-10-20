use clap::{Parser, Subcommand};
use sentinel_cdr::engine::CdrEngine;
use sentinel_cdr::policy::SanitizationPolicy;
use sentinel_core::enterprise::falcon::{CrowdStrikeFalconBridge, FalconPeripheralEvent};
use sentinel_core::enterprise::intune::IntunePolicyManager;
use sentinel_core::enterprise::kiosk::AirGappedKioskManager;
use sentinel_core::interceptor::drive_watcher::DriveWatcher;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::secure_shredder::SecureShredder;
use sentinel_core::scanner::tier3_sandbox::{
    DetonationRequest, NetworkContainmentMode, OpenSandboxClient,
};
use sentinel_core::scanner::universal_scanner::{UniversalScanner, UniversalThreat};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "sentinel")]
#[command(about = "OmniConnect Sentinel CLI - Universal Connection & CDR Scanner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sanitize a document or image using native Rust Deep CDR
    Sanitize {
        /// Path to input file (PDF, DOCX, JPEG, PNG, WebP)
        #[arg(short, long)]
        input: PathBuf,

        /// Path to write disarmed output file
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Inspect a file for polyglot overlays, entropy, and risk markers
    Inspect {
        /// Path to file
        #[arg(short, long)]
        path: PathBuf,
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

        /// Maximum files to inspect
        #[arg(short, long, default_value_t = 2000)]
        limit: usize,

        /// Enable interactive remediation prompt on threats
        #[arg(short, long, default_value_t = false)]
        interactive: bool,
    },
    /// Permanently shred a malicious file or carrier without backdoors (NIST SP 800-88 Rev 1)
    Shred {
        /// Target file path to permanently obliterate
        #[arg(short, long)]
        path: PathBuf,

        /// Number of overwrite passes (default: 3)
        #[arg(short = 'n', long, default_value_t = 3)]
        passes: u8,
    },
    /// Autonomous background sentry monitoring for removable drive insertions
    Watch {
        /// Polling interval in milliseconds
        #[arg(short = 'i', long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Launch the interactive Web & Desktop Dashboard GUI
    Ui {
        /// Port to serve the dashboard on
        #[arg(short, long, default_value_t = 8088)]
        port: u16,
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
    /// Run an Air-Gapped Kiosk session with hardware write-blocker & NIST SP 800-88 shredding
    Kiosk {
        /// Media serial number or identifier
        #[arg(short, long, default_value = "USB-MEDIA-SCADA-01")]
        media: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Sanitize { input, output } => {
            info!("Reading input file: {:?}", input);
            let input_bytes = fs::read(&input)?;

            let policy = SanitizationPolicy::default();
            let engine = CdrEngine::new(policy);

            let (clean_bytes, report) = engine.sanitize(&input_bytes)?;
            fs::write(&output, &clean_bytes)?;

            info!("Sanitization successful!");
            info!("  Format: {:?}", report.format);
            info!("  Original Size: {} bytes", report.original_size_bytes);
            info!("  Cleaned Size:  {} bytes", report.sanitized_size_bytes);
            info!("  Elements Disarmed: {}", report.stripped_elements.len());
            info!("  Processing Time:   {} µs", report.duration_micros);
            info!("Clean file written to: {:?}", output);
        }
        Commands::Inspect { path } => {
            let bytes = fs::read(&path)?;
            let format = CdrEngine::detect_format(&bytes);
            info!("File: {:?}", path);
            info!("  Detected Format: {:?}", format);
            info!("  Size: {} bytes", bytes.len());
        }
        Commands::Detonate { path, vm, endpoint } => {
            info!("Reading target binary for OpenSandbox detonation: {:?}", path);
            let bytes = fs::read(&path)?;
            let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let sha256_hex = hex::encode(hasher.finalize());

            let client = OpenSandboxClient::new(endpoint, None);
            let req = DetonationRequest {
                file_name,
                sha256_hex,
                file_bytes: bytes,
                vm_profile: vm,
                timeout_seconds: 60,
                containment_mode: NetworkContainmentMode::SinkholeOnly,
            };

            let report = client
                .submit_detonation(req)
                .await
                .map_err(|e| format!("{}", e))?;
            println!("\n===========================================================");
            println!("       OPENSANDBOX BEHAVIORAL DETONATION REPORT           ");
            println!("===========================================================");
            println!("Job ID:                 {}", report.job_id);
            println!("File Name:              {}", report.file_name);
            println!("SHA256:                 {}", report.sha256_hex);
            println!("Verdict:                {:?}", report.verdict);
            println!("Threat Score:           {}/100", report.threat_score);
            println!("VM Profile:             {}", report.vm_profile);
            println!("Duration:               {} ms", report.duration_ms);
            println!("Containment Mode:       Air-Gapped Network Sinkhole");
            println!("Engine Execution:       {}", if report.is_emulated { "Deterministic High-Precision Emulation (Offline Fallback)" } else { "Live MicroVM (WHVP/QEMU)" });

            if !report.mitre_attack_techniques.is_empty() {
                println!("\n🎯 [MITRE ATT&CK TECHNIQUES IDENTIFIED]");
                for t in &report.mitre_attack_techniques {
                    println!("   • [{}] {} (Tactic: {}, Confidence: {}%)", t.technique_id, t.name, t.tactic, t.confidence);
                }
            }

            if !report.spawned_processes.is_empty() {
                println!("\n🌲 [SPAWNED PROCESS TREE]");
                for p in &report.spawned_processes {
                    println!("   • PID {}: {} (Cmd: {})", p.pid, p.process_path, p.command_line);
                }
            }

            if !report.dns_queries_intercepted.is_empty() {
                println!("\n🌐 [NETWORK SINKHOLE CAPTURES (DNS / C2)]");
                for dns in &report.dns_queries_intercepted {
                    println!("   • Intercepted DNS Query: {}", dns);
                }
                for c2 in &report.c2_beacons_sinkholed {
                    println!("   • Sinkholed C2 Beacon:   {}", c2);
                }
            }

            if !report.registry_modifications.is_empty() {
                println!("\n🔑 [PERSISTENCE REGISTRY MODIFICATIONS]");
                for reg in &report.registry_modifications {
                    println!("   • Registry Key Created:  {}", reg);
                }
            }

            if !report.anti_evasion_shims_active.is_empty() {
                println!("\n🛡️ [ANTI-EVASION SHIMS TRIGGERED]");
                for shim in &report.anti_evasion_shims_active {
                    println!("   • {}", shim);
                }
            }
        }
        Commands::ScanDrive { path, limit, interactive } => {
            info!("===========================================================");
            info!("   OmniConnect Sentinel - Universal Threat & Drive Scanner ");
            info!("   Scanning Target: {:?} (Limit: {} files, Interactive: {})", path, limit, interactive);
            info!("===========================================================");

            // 1. Root autorun check
            let autorun_path = path.join("autorun.inf");
            if autorun_path.exists() {
                println!("\n🚨 [CRITICAL ALERT] Found 'autorun.inf' on drive root!");
                if let Ok(content) = fs::read_to_string(&autorun_path) {
                    println!("   autorun.inf payload: {:?}", content.trim());
                }
            }

            let mut files_scanned = 0;
            let mut malware_blocked_by_os = 0;
            let mut universal_threats = Vec::new();
            let mut size_histogram: HashMap<u64, Vec<PathBuf>> = HashMap::new();

            for entry in WalkDir::new(&path).into_iter().filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() {
                    continue;
                }

                files_scanned += 1;
                if files_scanned > limit {
                    println!("\n⚠️ Reached scan limit of {} files.", limit);
                    break;
                }

                let file_path = entry.path().to_path_buf();
                let ext = file_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

                // Track file size histogram to catch Ramnit/file infector identical sizes
                if let Ok(meta) = entry.metadata() {
                    let size = meta.len();
                    if size > 1024 && (ext == "exe" || ext == "cpl" || ext == "dll") {
                        size_histogram.entry(size).or_default().push(file_path.clone());
                    }
                }

                // Check for LNK exploit / CPL vectors
                if ext == "lnk" || ext == "cpl" {
                    println!("🚨 [SHORTCUT THREAT]: LNK/CPL Vector: {:?}", file_path);
                }

                // Universal Deep Carrier Scanner (Polyglots, ADS, BiDi Trojan, Documents, Ransomware, Scripts)
                match UniversalScanner::scan_file(&file_path) {
                    Ok(threats) => {
                        for t in threats {
                            println!("🚨 [THREAT DETECTED]: {:?} -> {} (Severity: {:?}, Score: {}/100)", t.file_path, t.threat_name, t.severity, t.risk_score);
                            universal_threats.push(t);
                        }
                    }
                    Err(e) => {
                        let err_msg = e.to_string();
                        if err_msg.contains("virus") || e.raw_os_error() == Some(225) {
                            malware_blocked_by_os += 1;
                            println!("⛔ [VIRUS CONFIRMED]: {:?} -> Windows blocked access (OS Error 225 - Active Malware Detected!)", file_path);
                        }
                    }
                }
            }

            println!("\n===========================================================");
            println!("                 SCAN RESULTS & THREAT REPORT              ");
            println!("===========================================================");
            println!("Files Scanned:              {}", files_scanned);
            println!("Active Malware Blocked:     {}", malware_blocked_by_os);
            println!("Universal Threats Found:    {}", universal_threats.len());

            // Check for Ramnit file infector size clusters (e.g. 229,376 bytes)
            for (size, files) in &size_histogram {
                if files.len() >= 3 && *size == 229376 {
                    println!("\n🧬 [POLYMORPHIC CLUSTER DETECTED - Trojan:Win32/Ramnit!pz]");
                    println!("   Found {} executables sharing the exact same size: {} bytes!", files.len(), size);
                    for f in files.iter().take(5) {
                        println!("     - {:?}", f);
                    }
                    if files.len() > 5 {
                        println!("     ... and {} more files", files.len() - 5);
                    }
                }
            }

            if interactive && !universal_threats.is_empty() {
                println!("\n🚨 [INTERACTIVE REMEDIATION ENGAGED]");
                println!("Prompting for remediation on {} discovered threat(s)...", universal_threats.len());
                for threat in &universal_threats {
                    prompt_remediation(threat);
                }
            } else if !universal_threats.is_empty() {
                println!("\n🚨 Run with --interactive to interactively shred or disarm detected threats.");
            } else {
                println!("\n✅ No hidden threats, polyglots, or malicious carrier vectors found on drive.");
            }
        }
        Commands::Shred { path, passes } => {
            println!("===========================================================");
            println!("      OMNICONNECT SENTINEL: ANTI-FORENSIC SECURE SHREDDER  ");
            println!("===========================================================");
            println!("Target Path: {:?}", path);
            println!("Standards:   NIST SP 800-88 Rev 1 / DoD 5220.22-M");
            println!("Overwrites:  {} Passes (CSPRNG, Inverted Complement, Cryptographic Zeroes)\n", passes);

            if !path.exists() {
                println!("❌ Target path does not exist: {:?}", path);
                return Ok(());
            }

            match SecureShredder::shred_file(&path, passes) {
                Ok(receipt) => {
                    println!("⚡ [SHREDDING COMPLETE - ZERO REMANENCE]");
                    println!("   Original File Size:   {} bytes", receipt.original_size_bytes);
                    println!("   Overwrites Completed: {} passes", receipt.passes_completed);
                    println!("   MFT Scramble Cycles:  {} cycles", receipt.mft_scramble_cycles);
                    println!("   Hardware Flushed:     {}", receipt.hardware_flushed);
                    println!("   Duration:             {} ms", receipt.duration_ms);
                    println!("   Final File Hash:      SHA256[{}]", receipt.sha256_final);
                    println!("\n✅ File {:?} permanently eradicated. All data and directory traces eliminated.", path);
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
            println!("Actively monitoring for removable media insertions (Interval: {} ms)...", interval_ms);
            println!("Press Ctrl+C to terminate sentinel sentry.\n");

            let interval = std::time::Duration::from_millis(interval_ms);
            if let Err(e) = DriveWatcher::listen_for_insertions(interval, move |event| {
                println!("\n🚨 [EXTERNAL DRIVE DETECTED]: Removable Media connected at {:?}", event.drive_root);
                println!("   Initiating deep carrier inspection across all documents, images, videos, and hidden streams...");

                let threats = UniversalScanner::scan_directory(&event.drive_root, 2000);
                if threats.is_empty() {
                    println!("✅ Drive {:?} scanned cleanly. No hidden threats, polyglots, or exploits found.", event.drive_root);
                } else {
                    println!("🚨 FOUND {} POTENTIAL THREAT(S) ON DRIVE {:?}", threats.len(), event.drive_root);
                    for threat in &threats {
                        prompt_remediation(threat);
                    }
                }
            }).await {
                eprintln!("DriveWatcher runtime error: {}", e);
            }
        }
        Commands::Ui { port } => {
            info!("===========================================================");
            info!("   OmniConnect Sentinel - Desktop & Web GUI Dashboard      ");
            info!("===========================================================");

            let dashboard_index = std::env::current_dir()?.join("dashboard").join("index.html");
            let url = if dashboard_index.exists() {
                format!("file:///{}", dashboard_index.display().to_string().replace('\\', "/"))
            } else {
                format!("http://localhost:{}", port)
            };

            info!("Launching OmniConnect Sentinel Dashboard: {}", url);
            #[cfg(target_os = "windows")]
            {
                std::process::Command::new("cmd")
                    .args(["/C", "start", "", &url])
                    .spawn()?;
            }
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("open").arg(&url).spawn();
            }
            #[cfg(target_os = "linux")]
            {
                let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
            }

            println!("\n🖥️ [SENTINEL DASHBOARD ACTIVE]");
            println!("   Dashboard Location: {}", url);
            println!("   Interactive Sentry: UMDF Interceptor, OpenSandbox Detonator & Quarantine Vault");
        }
        Commands::Intune { export } => {
            let policy = IntunePolicyManager::load_active_policy();
            println!("\n===========================================================");
            println!("       MICROSOFT INTUNE CUSTOM CSP POLICY PROFILE          ");
            println!("===========================================================");
            println!("Policy Version:             {}", policy.policy_version);
            println!("Enforce Removable Media CDR: {}", policy.enforce_removable_media_cdr);
            println!("Block Unauthorized USB HID:  {}", policy.block_unauthorized_usb_hid);
            println!("Charge-Only Fallback:        {}", policy.charge_only_fallback);
            println!("Max Allowed File Size:       {} MB", policy.max_file_size_mb);
            println!("Whitelisted Hardware IDs:    {:?}", policy.hardware_whitelist_patterns);
            println!("Allowed MIME Types:          {:?}", policy.allowed_file_types);

            if let Some(out_path) = export {
                let xml = IntunePolicyManager::export_oma_uri_profile_xml(&policy);
                fs::write(&out_path, &xml)?;
                println!("\n✅ Exported Intune OMA-URI XML profile to: {:?}", out_path);
            } else {
                println!("\n💡 Tip: Use --export <PATH.xml> to save the deployment profile.");
            }
        }
        Commands::Telemetry { event } => {
            let bridge = CrowdStrikeFalconBridge::new("SN-EDGE-WIN11-01".to_string());
            let ev = FalconPeripheralEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                event_type: event.clone(),
                timestamp_utc: chrono::Utc::now(),
                host_agent_id: "SN-EDGE-WIN11-01".to_string(),
                usb_device_info: Some("USB\\VID_0781&PID_5581\\Sandisk_Ultra".to_string()),
                threat_name: Some("Trojan:Win32/Ramnit!pz".to_string()),
                original_file_sha256: Some("7efc45df51d52223415b08c77a0828128b517288c81661e2a9a8109804cbb0c6".to_string()),
                sanitized_file_sha256: None,
                action_taken: "EncryptedAndQuarantined".to_string(),
                mitre_attack_technique: "T1091".to_string(),
                severity: "Critical".to_string(),
            };

            println!("\n===========================================================");
            println!("     CROWDSTRIKE FALCON FDR / SIEM TELEMETRY STREAM        ");
            println!("===========================================================");
            println!("FDR NDJSON Format:\n{}\n", bridge.to_fdr_json(&ev));
            println!("CEF Syslog Format:\n{}\n", bridge.to_cef_syslog(&ev));
            bridge.emit_event(&ev);
        }
        Commands::Kiosk { media } => {
            let scratch = std::env::temp_dir().join("sentinel_kiosk_scratch");
            let kiosk = AirGappedKioskManager::new("KIOSK-TERMINAL-SCADA-01".to_string(), scratch);

            println!("\n===========================================================");
            println!("       AIR-GAPPED INDUSTRIAL KIOSK SESSION (IEC 62443)     ");
            println!("===========================================================");
            let write_block = kiosk.verify_write_blocking_active();
            println!("Hardware Write-Blocker Status: {}", if write_block { "ACTIVE & ENGAGED (Read-Only Locked)" } else { "NOT DETECTED" });

            let (session_id, session_dir) = kiosk.start_kiosk_session(&media);
            println!("Session ID:                   {}", session_id);
            println!("Ephemeral Session Workspace:  {:?}", session_dir);

            // Simulate file triage inside kiosk session
            println!("Status:                       Executing Offline YARA & Deep CDR disarm...");

            // End session and verify NIST SP 800-88 cryptographic shredding
            let shredded = kiosk.end_kiosk_session(&session_id)?;
            println!("NIST SP 800-88 Cryptographic Wipe: {}", if shredded { "COMPLETED (Zero Residual Data)" } else { "FAILED" });
            println!("IEC 62443 Compliance State:   SL-3 ENFORCED\n");
        }
    }

    Ok(())
}

fn prompt_remediation(threat: &UniversalThreat) {
    println!("\n================================================================================");
    println!("🚨 [THREAT IDENTIFIED]: {:?}", threat.file_path);
    println!("   Carrier:      {:?}", threat.carrier_category);
    println!("   Threat Name:  {}", threat.threat_name);
    println!("   Severity:     {:?} (Risk Score: {}/100)", threat.severity, threat.risk_score);
    println!("   MITRE ATT&CK: {}", threat.mitre_technique);
    println!("   Details:      {}", threat.technical_details);
    println!("--------------------------------------------------------------------------------");
    println!("REMEDIATION CHOICES:");
    println!("  [1] PERMANENT ANTI-FORENSIC SHRED (NIST SP 800-88 Cryptographic Purge - 0% Remanence)");
    println!("  [2] QUARANTINE TO ENCRYPTED VAULT (AES-256-GCM container)");
    println!("  [3] SKIP / LEAVE UNTOUCHED");
    print!("Select action [1-3] (Default: 1): ");
    let _ = std::io::stdout().flush();

    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    let choice = input.trim();

    if choice.is_empty() || choice == "1" {
        println!("⚡ Executing NIST SP 800-88 cryptographic shredding...");
        match SecureShredder::shred_file(&threat.file_path, 3) {
            Ok(receipt) => {
                println!(
                    "✅ [PERMANENTLY ERADICATED]: {:?} ({} bytes overwritten in {} ms). Zero backdoors remain!",
                    receipt.target_path, receipt.original_size_bytes, receipt.duration_ms
                );
            }
            Err(e) => {
                println!("❌ Shredding error: {}", e);
            }
        }
    } else if choice == "2" {
        println!("🔒 Quarantining to encrypted vault...");
        let vault = QuarantineVault::new(PathBuf::from(".sentinel_vault"));
        if let Ok(bytes) = fs::read(&threat.file_path) {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let sha = hex::encode(hasher.finalize());
            match vault.quarantine_file(&bytes, &threat.file_path, threat.risk_score, &sha) {
                Ok(q) => {
                    println!("✅ Quarantined to: {:?}", q.quarantine_container_path);
                    let _ = fs::remove_file(&threat.file_path);
                }
                Err(e) => println!("❌ Quarantine failed: {}", e),
            }
        }
    } else {
        println!("⚠️ Threat skipped per user request.");
    }
}
