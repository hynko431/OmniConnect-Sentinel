#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use sentinel_cdr::engine::CdrEngine;
use sentinel_cdr::worker::{write_inspect_response_framed, WorkerCommand};
use sentinel_cdr::WorkerResponse;
use sentinel_sys::apply_worker_process_mitigations;
use std::io;

/// Ephemeral Single-File CDR Worker Binary (`sentinel-cdr-worker`)
///
/// Applies in-process OS exploit mitigations (`SetProcessMitigationPolicy` on Windows,
/// `setrlimit(RLIMIT_AS, 256 MiB)` + `prctl(PR_SET_NO_NEW_PRIVS)` + `unshare(CLONE_NEWNET)`
/// on Linux) and exits immediately if mitigations fail. Reads a single length-prefixed
/// protobuf `WorkerCommand` (`DisarmRequest` or `InspectRequest`) from `stdin`, executes
/// structural CDR sanitization or inspection in-memory, writes a single framed protobuf
/// response to `stdout`, and immediately exits.
fn main() {
    if let Err(e) = apply_worker_process_mitigations() {
        eprintln!("FATAL: CDR worker process mitigations failed: {}", e);
        std::process::exit(2);
    }

    // Optional test hook for `worker_memory_cap` (`T7`): when the file name is
    // `"__TEST_ALLOC_300MB__.bin"`, attempt to allocate and touch 300 MiB on the heap so the
    // 256 MiB OS Job Object (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`) / `RLIMIT_AS` terminates the worker.
    let stdin = io::stdin();
    let stdout = io::stdout();

    let command = match WorkerCommand::read_framed(stdin.lock()) {
        Ok(cmd) => cmd,
        Err(e) => {
            let resp = WorkerResponse {
                success: false,
                outcome: None,
                error: Some(format!("Invalid worker protobuf request frame: {}", e)),
            };
            let _ = resp.write_framed(stdout.lock());
            std::process::exit(1);
        }
    };

    match command {
        WorkerCommand::Disarm(request) => {
            let fault_probes_enabled = std::env::var_os("SENTINEL_CDR_ENABLE_FAULT_PROBES")
                .is_some_and(|v| v == "1")
                || cfg!(debug_assertions);
            if fault_probes_enabled && request.file_name == "__TEST_ALLOC_300MB__.bin" {
                let target_bytes = 300 * 1024 * 1024usize;
                let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(300);
                for i in 0..300usize {
                    let mut page = vec![(i as u8).wrapping_add(1); 1024 * 1024];
                    std::hint::black_box(&mut page);
                    chunks.push(page);
                }
                std::hint::black_box(&chunks);
                let _ = target_bytes;
            }
            if fault_probes_enabled && request.file_name == "__TEST_HANG_60S__.bin" {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
            if fault_probes_enabled && request.file_name == "__TEST_SPAWN_CHILD__.bin" {
                let exe =
                    std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("cmd.exe"));
                match std::process::Command::new(exe).arg("--version").spawn() {
                    Ok(mut child) => {
                        let _ = child.kill();
                        let resp = WorkerResponse {
                            success: false,
                            outcome: None,
                            error: Some("UNEXPECTED_CHILD_SPAWN_SUCCEEDED".to_string()),
                        };
                        let _ = resp.write_framed(stdout.lock());
                        std::process::exit(3);
                    }
                    Err(e) => {
                        let resp = WorkerResponse {
                            success: false,
                            outcome: None,
                            error: Some(format!("CHILD_PROCESS_CREATION_BLOCKED: {}", e)),
                        };
                        let _ = resp.write_framed(stdout.lock());
                        std::process::exit(1);
                    }
                }
            }

            let engine = CdrEngine::new(request.policy.clone());
            let response = match engine.sanitize_with_hint(
                &request.raw_bytes,
                &request.file_name,
                &request.policy,
            ) {
                Ok(outcome) => WorkerResponse {
                    success: true,
                    outcome: Some(outcome),
                    error: None,
                },
                Err(err) => WorkerResponse {
                    success: false,
                    outcome: None,
                    error: Some(err.to_string()),
                },
            };

            let _ = response.write_framed(stdout.lock());
        }
        WorkerCommand::Inspect {
            file_name,
            raw_bytes,
        } => {
            let assessment = CdrEngine::inspect_bytes(&raw_bytes, &file_name);
            if write_inspect_response_framed(stdout.lock(), &assessment).is_err() {
                std::process::exit(1);
            }
        }
    }
}
