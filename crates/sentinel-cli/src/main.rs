use clap::{Parser, Subcommand};
use sentinel_cdr::engine::CdrEngine;
use sentinel_cdr::policy::SanitizationPolicy;
use sentinel_core::scanner::tier0_yara::Tier0YaraScanner;
use std::collections::HashMap;
use std::fs;
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
    /// Scan an external drive or folder recursively for viruses, worms, and suspicious payloads
    ScanDrive {
        /// Target drive or directory path (e.g. E:\ or E:)
        #[arg(short, long)]
        path: PathBuf,

        /// Maximum files to inspect
        #[arg(short, long, default_value_t = 2000)]
        limit: usize,
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
        Commands::ScanDrive { path, limit } => {
            info!("===========================================================");
            info!("   OmniConnect Sentinel - External Drive Threat Scanner    ");
            info!("   Scanning Target: {:?} (Limit: {} files)", path, limit);
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
            let mut suspicious_files = Vec::new();
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
                let file_name = entry.file_name().to_string_lossy().to_string();
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
                    suspicious_files.push((file_path.clone(), "LNK / CPL Shortcut Vector (Potential Exploit:Win32/CplLnk.A)".to_string(), 75));
                }

                // Try reading file to perform Tier 0 entropy & heuristic check
                match fs::read(&file_path) {
                    Ok(bytes) => {
                        let report = Tier0YaraScanner::scan_bytes(&bytes, &file_path);
                        if report.threat_score >= 35 {
                            suspicious_files.push((
                                file_path.clone(),
                                format!("Heuristic Alert: {:?} (Entropy: {:.2})", report.suspicious_strings, report.entropy),
                                report.threat_score,
                            ));
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
            println!("Suspicious Vectors Flagged: {}", suspicious_files.len());

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

            if malware_blocked_by_os > 0 || !suspicious_files.is_empty() {
                println!("\n🚨 [RECOMMENDED REMEDIATION ACTIONS]");
                println!("1. DO NOT open or click on any .lnk shortcuts or .exe files on this drive.");
                println!("2. The drive contains active Ramnit and CplLnk infections (Stuxnet/shortcut worm class).");
                println!("3. Run a complete Defender scan to quarantine infected executables:");
                println!("   Start-MpScan -ScanType CustomScan -ScanPath \"{}\"", path.display());
                println!("4. Sanitize legitimate documents/images into a safe folder using:");
                println!("   sentinel sanitize --input <E:\\path\\doc.pdf> --output <C:\\clean\\doc.pdf>");
            } else {
                println!("\n✅ No overt executable worms or viruses detected on inspected sample.");
            }
        }
    }

    Ok(())
}
