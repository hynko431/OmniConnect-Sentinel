#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use sentinel_cdr::policy::SanitizationPolicy;
use sentinel_cdr::worker::{serve_framed_ipc_io, serve_framed_ipc_stream, WorkerLauncher};
use sentinel_sys::LocalIpcServer;

/// Local IPC CDR Daemon (`sentinel-cdr-daemon`) (`CSE-22`, `BUG-CDR-10`, Invariant I3)
///
/// Binds an ACL-hardened Named Pipe (`\\.\pipe\OmniConnectSentinelCdr`, Windows SDDL
/// `D:P(A;;GA;;;SY)(A;;GA;;;BA)`) or mode-`0600` + `SO_PEERCRED` Unix Domain Socket
/// (`/run/omniconnect/cdr.sock`, Linux) serving framed `sentinel-proto` `DisarmRequest` /
/// `InspectRequest` messages dispatched to isolated per-file `sentinel-cdr-worker` processes
/// via `WorkerLauncher`. Retains `--stdio` strictly as an explicit flag for child-pipe harnesses.
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
    info!("Architecture: Hardened Option B (ACL Local IPC; TCP 50051 Retired)");
    info!(
        "Max Decompressed Budget: {} bytes",
        policy.max_decompressed_bytes
    );
    info!("=========================================================");

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--check" || a == "--health") {
        info!("CDR local-IPC service health check: OK");
        return Ok(());
    }

    let launcher = WorkerLauncher::new();
    if !launcher.has_worker_binary() {
        eprintln!(
            "FATAL: CDR_WORKER_FAILED: sentinel-cdr-worker binary not found adjacent to sentinel-cdr-daemon; refusing startup (Invariant I3)"
        );
        std::process::exit(1);
    }

    // Explicit `--stdio` child-pipe harness mode (`CSE-22`)
    if args.iter().any(|a| a == "--stdio") {
        info!("Serving framed sentinel-proto requests on explicit --stdio harness");
        let stdin = io::stdin();
        let stdout = io::stdout();
        if let Err(e) = serve_framed_ipc_io(stdin.lock(), stdout.lock(), &launcher) {
            error!("FATAL: Framed --stdio IPC error: {e}");
            eprintln!("FATAL: CDR_STDIO_IPC_ERROR: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    // Parse and strictly validate CLI flags (`--pipe` / `--socket` / `--max-requests`)
    let mut endpoint_override: Option<String> = None;
    let mut max_requests: Option<usize> = None;
    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            flag @ ("--pipe" | "--socket") => match args.get(idx + 1) {
                Some(val) if !val.trim().is_empty() && !val.starts_with("--") => {
                    endpoint_override = Some(val.clone());
                    idx += 2;
                    continue;
                }
                _ => {
                    eprintln!("FATAL: CLI_ARG_ERROR: {flag} requires a non-empty endpoint value");
                    std::process::exit(2);
                }
            },
            "--max-requests" => match args.get(idx + 1).and_then(|s| s.parse::<usize>().ok()) {
                Some(val) => {
                    max_requests = Some(val);
                    idx += 2;
                    continue;
                }
                None => {
                    eprintln!(
                        "FATAL: CLI_ARG_ERROR: --max-requests requires an unsigned integer value"
                    );
                    std::process::exit(2);
                }
            },
            unknown => {
                eprintln!("FATAL: CLI_ARG_ERROR: unrecognized argument '{unknown}'");
                std::process::exit(2);
            }
        }
    }

    if endpoint_override.is_none() {
        endpoint_override = std::env::var("SENTINEL_CDR_PIPE")
            .ok()
            .or_else(|| std::env::var("SENTINEL_CDR_SOCKET").ok());
    }

    let mut server = match LocalIpcServer::bind(endpoint_override.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            error!("FATAL: Failed binding ACL-hardened CDR IPC listener: {e}");
            eprintln!("FATAL: CDR_IPC_BIND_FAILED: {e}");
            std::process::exit(1);
        }
    };

    info!(
        "CDR IPC daemon listening on {} (ACL-hardened, zero TCP listeners)",
        server.endpoint()
    );

    let mut served_connections = 0usize;
    loop {
        if let Some(limit) = max_requests {
            if served_connections >= limit {
                break;
            }
        }
        match server.accept() {
            Ok((mut stream, peer)) => {
                served_connections += 1;
                info!(
                    pid = peer.pid,
                    exe = %peer.executable_path.display(),
                    signed = peer.signature_verified,
                    "Accepted verified local IPC peer on CDR daemon"
                );
                if let Err(e) = serve_framed_ipc_stream(&mut stream, &launcher) {
                    warn!("CDR IPC peer stream closed with error: {e}");
                }
            }
            Err(e) => {
                warn!("CDR IPC accept rejected/failed: {e}");
            }
        }
    }

    Ok(())
}
