//! Test Gate T49: Hardened CDR Daemon Local IPC (Named Pipe / Unix Socket),
//! SDDL Removal of `AC` (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`), and Fail-Closed Sandbox Enforcement (`CSE-22`, `ADR-016`).

use sentinel_cdr::worker::{serve_framed_ipc_io, WorkerCommand, WorkerLauncher};
use sentinel_cdr::{SanitizationPolicy, WorkerRequest, WorkerResponse};
#[cfg(windows)]
use sentinel_sys::{
    close_raw_kernel_handle, create_acl_named_pipe_server, query_kernel_handle_dacl_sddl,
};
use sentinel_sys::{
    evaluate_sandbox_enforcement_failure, JobSandboxConfig, LocalIpcServer, LocalIpcStream,
    DEFAULT_CDR_NAMED_PIPE_ENDPOINT, DEFAULT_CDR_UNIX_SOCKET_PATH, NAMED_PIPE_SERVER_SDDL,
};
use std::io::{Cursor, Read, Write};

#[test]
fn t49_cdr_daemon_pipe_ipc_sddl_no_ac_and_fail_closed_sandbox() {
    // 1. Hardened Named Pipe SDDL MUST be strictly `D:P(A;;GA;;;SY)(A;;GA;;;BA)` with ZERO `AC`, `AU`, or `WD`.
    assert_eq!(NAMED_PIPE_SERVER_SDDL, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    assert!(
        !NAMED_PIPE_SERVER_SDDL.contains("AC"),
        "ALL APPLICATION PACKAGES (AC) MUST NOT appear in CDR Named Pipe SDDL"
    );
    assert!(!NAMED_PIPE_SERVER_SDDL.contains("AU"));
    assert!(!NAMED_PIPE_SERVER_SDDL.contains("WD"));
    assert_eq!(
        DEFAULT_CDR_NAMED_PIPE_ENDPOINT,
        r"\\.\pipe\OmniConnectSentinelCdr"
    );
    assert_eq!(DEFAULT_CDR_UNIX_SOCKET_PATH, "/run/omniconnect/cdr.sock");

    // 2. Default sandbox config MUST enforce AppContainer + CIG (`enforce_microsoft_signed_dlls`) fail-closed.
    let sandbox_cfg = JobSandboxConfig::default();
    assert!(sandbox_cfg.enable_appcontainer);
    assert!(sandbox_cfg.enforce_microsoft_signed_dlls);

    // 3. Fail-closed sandbox enforcement helper MUST reject CIG / Linux unshare / Landlock failures
    //    unless explicit dev opt-in (`unsafe_dev_opt_in = true`) is supplied.
    for component in [
        "windows_cig_process_signature_policy",
        "linux_unshare(CLONE_NEWNET|CLONE_NEWIPC)",
        "linux_landlock_abi",
    ] {
        let denied = evaluate_sandbox_enforcement_failure(
            component,
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "EPERM"),
            false,
        );
        assert!(
            denied.is_err(),
            "Sandbox component '{component}' MUST fail closed when unsafe_dev_opt_in=false"
        );
        let msg = denied.expect_err("expected error").to_string();
        assert!(
            msg.contains("SANDBOX_FAIL_CLOSED"),
            "Fail-closed error must carry SANDBOX_FAIL_CLOSED diagnostic: {msg}"
        );

        let dev_opt_in = evaluate_sandbox_enforcement_failure(
            component,
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "EPERM"),
            true,
        );
        assert!(
            dev_opt_in.is_ok(),
            "Explicit SENTINEL_UNSAFE_DEV_SANDBOX=1 opt-in should allow dev-only bypass with POSTURE_REDUCED_SANDBOX warning"
        );
    }

    // 4. Live OS Named Pipe / Unix Socket ACL & IPC Verification:
    #[cfg(windows)]
    {
        let unique_pipe = format!(
            r"\\.\pipe\OmniConnectSentinelCdr_T49_{}",
            uuid::Uuid::new_v4().simple()
        );
        let pipe_handle = create_acl_named_pipe_server(&unique_pipe)
            .expect("create_acl_named_pipe_server must bind protected first-instance pipe");

        // Inspect live OS kernel DACL on the created Named Pipe handle!
        let live_sddl = query_kernel_handle_dacl_sddl(pipe_handle)
            .expect("Querying live Named Pipe kernel DACL must succeed");
        assert!(
            live_sddl.contains("SY") && live_sddl.contains("BA"),
            "Live Named Pipe DACL must grant SY and BA: {live_sddl}"
        );
        assert!(
            !live_sddl.contains(";;;AC)")
                && !live_sddl.contains(";;;AU)")
                && !live_sddl.contains(";;;WD)")
                && !live_sddl.contains("S-1-15-2-1"),
            "Live Named Pipe kernel DACL MUST NOT grant AC/AU/WD/S-1-15-2-1: {live_sddl}"
        );

        // Verify squat-proofing (`FILE_FLAG_FIRST_PIPE_INSTANCE`)
        let squat_attempt = create_acl_named_pipe_server(&unique_pipe);
        assert!(
            squat_attempt.is_err(),
            "Second server instance on same pipe name must fail with ERROR_ACCESS_DENIED"
        );
        close_raw_kernel_handle(pipe_handle);

        // Bind live `LocalIpcServer` on a fresh pipe and verify client connection behavior:
        // - Under elevated Admin/SYSTEM, client connects and completes a live framed protobuf exchange.
        // - Under unprivileged/AppContainer sandbox, kernel rejects connect with ERROR_ACCESS_DENIED (5),
        //   proving AC removal is actively enforced by the Windows kernel!
        let live_pipe = format!(
            r"\\.\pipe\OmniConnectSentinelCdr_T49_Live_{}",
            uuid::Uuid::new_v4().simple()
        );
        let mut server = LocalIpcServer::bind(Some(&live_pipe))
            .expect("LocalIpcServer::bind must succeed on Windows Named Pipe");
        let server_sddl = server
            .kernel_dacl_sddl()
            .expect("LocalIpcServer::kernel_dacl_sddl");
        assert!(
            !server_sddl.contains(";;;AC)") && !server_sddl.contains("S-1-15-2-1"),
            "Bound LocalIpcServer DACL must exclude AC: {server_sddl}"
        );

        let pipe_for_client = live_pipe.clone();
        let client_probe = std::thread::spawn(move || LocalIpcStream::connect(&pipe_for_client));
        std::thread::sleep(std::time::Duration::from_millis(80));
        match client_probe.join().expect("client thread") {
            Ok(mut client_stream) => {
                // Elevated caller: accept on server thread, verify PeerCredentials, and serve framed DisarmRequest!
                let (mut server_stream, peer) = server
                    .accept()
                    .expect("Accepting authorized local pipe peer must succeed");
                assert_eq!(peer.pid, std::process::id());

                let req = WorkerRequest {
                    file_name: "notes.txt".to_string(),
                    policy: SanitizationPolicy::default(),
                    raw_bytes: b"hello ipc".to_vec(),
                };
                let client_handle = std::thread::spawn(move || {
                    req.write_framed(&mut client_stream)
                        .expect("write framed request over Named Pipe");
                    WorkerResponse::read_framed(&mut client_stream)
                        .expect("read framed response over Named Pipe")
                });
                let launcher = WorkerLauncher::new();
                let handled =
                    sentinel_cdr::worker::serve_framed_ipc_stream(&mut server_stream, &launcher);
                let _ = handled;
                drop(server_stream);
                let resp = client_handle.join().expect("client roundtrip");
                assert!(
                    resp.success || resp.error.is_some(),
                    "Framed response must be well-formed"
                );
            }
            Err(err) => {
                // Unprivileged / AppContainer sandbox: Windows kernel MUST reject with ERROR_ACCESS_DENIED (5)!
                assert_eq!(
                    err.raw_os_error(),
                    Some(5),
                    "Non-Admin/AppContainer client connecting to SY+BA pipe must be denied by OS kernel with ERROR_ACCESS_DENIED (5), got: {err}"
                );
            }
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let sock_path = std::env::temp_dir().join(format!(
            "sentinel_cdr_t49_{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let sock_str = sock_path.to_string_lossy().into_owned();
        let mut server = LocalIpcServer::bind(Some(&sock_str))
            .expect("LocalIpcServer::bind must create mode 0600 Unix socket");
        let mode = std::fs::metadata(&sock_path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "CDR Unix socket must be mode 0600");

        let client_sock = sock_str.clone();
        let client_thread = std::thread::spawn(move || {
            let mut client = LocalIpcStream::connect(&client_sock).expect("connect unix socket");
            let req = WorkerRequest {
                file_name: "notes.txt".to_string(),
                policy: SanitizationPolicy::default(),
                raw_bytes: b"hello unix ipc".to_vec(),
            };
            req.write_framed(&mut client).expect("write framed");
            WorkerResponse::read_framed(&mut client).expect("read framed")
        });

        let (mut server_stream, peer) = server.accept().expect("accept unix peer");
        assert!(peer.pid > 0 || cfg!(not(target_os = "linux")));
        let launcher = WorkerLauncher::new();
        let _ = sentinel_cdr::worker::serve_framed_ipc_stream(&mut server_stream, &launcher);
        drop(server_stream);
        let resp = client_thread.join().expect("client join");
        assert!(resp.success || resp.error.is_some());
    }

    // 5. Verify `sentinel-cdr-daemon` binary CLI contract (`--stdio` explicit harness + default IPC bind)
    let tmp_dir = std::env::temp_dir().join(format!(
        "sentinel_cdr_daemon_t49_{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
    let daemon_src = std::path::Path::new(env!("CARGO_BIN_EXE_sentinel-cdr-daemon"));
    let worker_src = std::path::Path::new(env!("CARGO_BIN_EXE_sentinel-cdr-worker"));
    let daemon_bin = tmp_dir.join(daemon_src.file_name().expect("daemon filename"));
    let worker_bin = tmp_dir.join(worker_src.file_name().expect("worker filename"));
    std::fs::copy(daemon_src, &daemon_bin).expect("copy daemon");
    std::fs::copy(worker_src, &worker_bin).expect("copy worker");

    // 5a. Explicit `--stdio` mode serves framed protobuf DisarmRequest and exits cleanly on EOF
    let mut stdio_child = std::process::Command::new(&daemon_bin)
        .arg("--stdio")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sentinel-cdr-daemon --stdio");

    let req = WorkerRequest {
        file_name: "memo.txt".to_string(),
        policy: SanitizationPolicy::default(),
        raw_bytes: b"Clean memo payload".to_vec(),
    };
    {
        let mut child_stdin = stdio_child.stdin.take().expect("child stdin");
        req.write_framed(&mut child_stdin)
            .expect("write framed request to daemon --stdio");
        child_stdin.flush().expect("flush stdin");
    }
    let mut stdout_bytes = Vec::new();
    stdio_child
        .stdout
        .take()
        .expect("child stdout")
        .read_to_end(&mut stdout_bytes)
        .expect("read daemon stdout");
    let exit_status = stdio_child.wait().expect("wait daemon --stdio");
    assert!(
        exit_status.success(),
        "sentinel-cdr-daemon --stdio must exit 0 after serving framed request"
    );
    let framed_resp = WorkerResponse::read_framed(Cursor::new(&stdout_bytes))
        .expect("daemon --stdio must return valid framed WorkerResponse");
    // In elevated/Linux CI, worker succeeds cleanly; in Windows AppContainer sandbox, worker fails closed with SandboxFailure.
    assert!(
        framed_resp.success || framed_resp.error.is_some(),
        "Daemon must return either clean outcome or explicit fail-closed error frame"
    );

    // 5b. Default mode (NO `--stdio`) binds real Named Pipe / Unix Socket IPC listener (does NOT exit on EOF stdin!)
    let daemon_ipc_endpoint = if cfg!(windows) {
        format!(
            r"\\.\pipe\OmniConnectSentinelCdr_Daemon_{}",
            uuid::Uuid::new_v4().simple()
        )
    } else {
        tmp_dir
            .join("cdr_daemon_t49.sock")
            .to_string_lossy()
            .into_owned()
    };
    let mut daemon_child = std::process::Command::new(&daemon_bin)
        .args(["--pipe", &daemon_ipc_endpoint, "--max-requests", "1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sentinel-cdr-daemon default IPC mode");

    // Wait briefly for daemon to bind IPC endpoint and verify it remains alive waiting for IPC peers
    // (proving it is NOT a dead stdin EOF reader anymore!).
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert!(
        daemon_child.try_wait().expect("try_wait").is_none(),
        "sentinel-cdr-daemon without --stdio MUST stay alive listening on local IPC even when stdin is closed/null"
    );

    // On Windows, verify the daemon truly holds the first-instance pipe (squat attempt fails with ERROR_ACCESS_DENIED)
    #[cfg(windows)]
    {
        let squat = create_acl_named_pipe_server(&daemon_ipc_endpoint);
        assert!(
            squat.is_err(),
            "Live sentinel-cdr-daemon must hold active first-instance Named Pipe"
        );
    }

    let _ = daemon_child.kill();
    let _ = daemon_child.wait();

    // Verify `serve_framed_ipc_io` fail-closed dispatch with nonexistent worker bin returns error frame (never panics or parses in-process)
    let bad_launcher = WorkerLauncher::new().with_worker_bin(tmp_dir.join("missing_worker.exe"));
    let mut req_buf = Vec::new();
    req.write_framed(&mut req_buf).expect("encode req");
    let mut resp_buf = Vec::new();
    let count = serve_framed_ipc_io(Cursor::new(&req_buf), &mut resp_buf, &bad_launcher)
        .expect("serve_framed_ipc_io");
    assert_eq!(count, 1);
    let err_resp = WorkerResponse::read_framed(Cursor::new(&resp_buf)).expect("decode err resp");
    assert!(!err_resp.success);
    assert!(err_resp
        .error
        .as_deref()
        .unwrap_or("")
        .contains("CDR_WORKER_FAILED"));
    let _ = WorkerCommand::read_framed(Cursor::new(&req_buf)).expect("decode cmd");

    // 6. Truncated mid-frame payload MUST return `Err(UnexpectedEof)` (NEVER silently `Ok(0)`)
    let truncated_frame = &req_buf[..req_buf.len().min(3)];
    let mut trunc_out = Vec::new();
    let trunc_res =
        serve_framed_ipc_io(Cursor::new(truncated_frame), &mut trunc_out, &bad_launcher);
    assert!(
        matches!(trunc_res, Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
        "Truncated mid-frame payload must propagate UnexpectedEof, got: {trunc_res:?}"
    );

    // 7. Malformed daemon CLI flags (`--pipe --max-requests 1`, `--max-requests bad`) MUST fail closed
    let bad_flag_out = std::process::Command::new(&daemon_bin)
        .args(["--pipe", "--max-requests", "1"])
        .output()
        .expect("run daemon with missing --pipe value");
    assert!(
        !bad_flag_out.status.success(),
        "sentinel-cdr-daemon must reject `--pipe --max-requests 1` fail-closed"
    );
    let bad_num_out = std::process::Command::new(&daemon_bin)
        .args(["--max-requests", "not_a_number"])
        .output()
        .expect("run daemon with invalid --max-requests");
    assert!(
        !bad_num_out.status.success(),
        "sentinel-cdr-daemon must reject `--max-requests not_a_number` fail-closed"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
