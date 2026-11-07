#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use sentinel_cdr::policy::SanitizationPolicy;
use sentinel_cdr::worker::{write_inspect_response_framed, WorkerCommand, WorkerLauncher};
use sentinel_cdr::WorkerResponse;

/// Local Pipe CDR Daemon (`sentinel-cdr-daemon`) (`BUG-CDR-10`, Master Plan v2 §0.2 & §2.1, Invariant I3)
///
/// Retires the legacy unauthenticated TCP `127.0.0.1:50051` listener so the CDR engine
/// never exposes a localhost TCP socket to untrusted local processes or browser SSRF.
/// Serves length-prefixed `prost::Message` (`DisarmRequest`/`DisarmResponse`/`InspectRequest`/`InspectResponse`)
/// frames over local pipes / stdio and dispatches every file to an isolated per-file
/// `sentinel-cdr-worker` process via `WorkerLauncher` (`Invariant I3`).
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(io::stderr)
        .with_target(false)
        .with_thread_ids(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let policy = SanitizationPolicy::default();
    info!("=========================================================");
    info!("OmniConnect Sentinel - Tier-1 CDR Engine");
    info!("Architecture: Hardened Option B (Local Pipe Service; TCP 50051 Retired)");
    info!(
        "Max Decompressed Budget: {} bytes",
        policy.max_decompressed_bytes
    );
    info!("=========================================================");

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--check" || a == "--health") {
        info!("CDR local-pipe service health check: OK");
        return Ok(());
    }

    let launcher = WorkerLauncher::new();
    let stdin = io::stdin();
    let stdout = io::stdout();

    while let Ok(cmd) = WorkerCommand::read_framed(stdin.lock()) {
        match cmd {
            WorkerCommand::Disarm(req) => {
                let resp = match launcher.sanitize_isolated(req) {
                    Ok(outcome) => WorkerResponse {
                        success: true,
                        outcome: Some(outcome),
                        error: None,
                    },
                    Err(e) => WorkerResponse {
                        success: false,
                        outcome: None,
                        error: Some(e.to_string()),
                    },
                };
                if resp.write_framed(stdout.lock()).is_err() {
                    break;
                }
            }
            WorkerCommand::Inspect {
                file_name,
                raw_bytes,
            } => match launcher.inspect_isolated(&raw_bytes, &file_name) {
                Ok(assessment) => {
                    if write_inspect_response_framed(stdout.lock(), &assessment).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
        }
    }

    Ok(())
}
