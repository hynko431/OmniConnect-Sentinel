use clap::{Parser, Subcommand};
use sentinel_cdr::engine::CdrEngine;
use sentinel_cdr::policy::SanitizationPolicy;
use std::fs;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    }

    Ok(())
}
