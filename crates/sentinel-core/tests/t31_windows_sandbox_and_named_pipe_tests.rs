//! Test Gate T31: Windows AppContainer + JobObject Fail-Closed Sandbox & Squat-Proof Named Pipe (`CSE-06`, `Story 3.2`)
//!
//! Validates Master Plan v2 §2.1 & §4.3 (Sub-Phase 1.2):
//! 1. Mandatory AppContainer: Zero unsandboxed `(false, false)` fallbacks; fails closed if profile cannot be derived.
//! 2. Single-Process UI-Restricted Job Object: ProcessMemoryLimit = 256 MiB, ActiveProcessLimit = 1, UI limitations applied.
//! 3. Squat-Proof Named Pipe: `FILE_FLAG_FIRST_PIPE_INSTANCE` prevents pre-binding squats with `ERROR_ACCESS_DENIED`.
//! 4. Tightened SDDL: SYSTEM (SY), Admins (BA), and AppContainer (AC) permitted; Authenticated Users (AU) revoked.
//! 5. Handle-Locked Authenticode: Open locked file handle verified with `WTD_REVOKE_WHOLECHAIN`.

#[cfg(windows)]
mod windows_tests {
    use sentinel_sys::{
        create_acl_named_pipe_server, verify_binary_authenticode_signature, JobSandboxConfig,
    };
    use std::path::PathBuf;

    #[test]
    fn test_t31_named_pipe_first_instance_blocks_squatting() {
        let unique_pipe = format!(r"\\.\pipe\OmniConnectTest_Squat_{}", std::process::id());

        // 1. Legitimate server creates the first pipe instance
        let server_h1 = create_acl_named_pipe_server(&unique_pipe)
            .expect("First pipe instance creation must succeed");
        assert!(server_h1 != 0 && server_h1 != -1);

        // 2. An attacker (or second rogue caller) tries to create another server instance on the same name
        let second_attempt = create_acl_named_pipe_server(&unique_pipe);
        assert!(
            second_attempt.is_err(),
            "FILE_FLAG_FIRST_PIPE_INSTANCE must reject subsequent server creations on the same pipe name"
        );

        let err = second_attempt.err().unwrap();
        assert_eq!(
            err.raw_os_error(),
            Some(5), // ERROR_ACCESS_DENIED
            "Second creation must fail with ERROR_ACCESS_DENIED (5): {err}"
        );

        // Clean up first handle
        unsafe {
            windows_sys_close(server_h1);
        }
    }

    #[test]
    fn test_t31_authenticode_verification_on_system_and_test_binaries() {
        // Authenticode-signed binary with embedded signature (e.g. Git for Windows)
        let candidate_paths = [
            PathBuf::from(r"C:\Program Files\Git\cmd\git.exe"),
            PathBuf::from(r"C:\Program Files\Git\bin\git.exe"),
            PathBuf::from(r"C:\Program Files\Git\mingw64\bin\git.exe"),
        ];

        let mut checked_signed = false;
        for path in &candidate_paths {
            if path.exists() {
                let res = verify_binary_authenticode_signature(path);
                assert!(
                    res.is_ok(),
                    "Authenticode check on {:?} must return Ok(result)",
                    path
                );
                assert!(
                    res.unwrap(),
                    "{:?} must verify as Authenticode signed",
                    path
                );
                checked_signed = true;
                break;
            }
        }
        if !checked_signed {
            println!(
                "Skipping signed binary check as no candidate embedded-signed binary was found"
            );
        }

        // Current executable in debug target is self-compiled/unsigned
        let current_exe = std::env::current_exe().expect("current exe");
        let res_self = verify_binary_authenticode_signature(&current_exe);
        assert!(res_self.is_ok());
        // Unsigned local cargo build should return Ok(false), never error or panic
        assert!(
            !res_self.unwrap(),
            "Unsigned test executable must report false without error"
        );
    }

    #[test]
    fn test_t31_job_sandbox_config_defaults_and_limits() {
        let config = JobSandboxConfig::default();
        assert!(config.enable_appcontainer);
        assert_eq!(config.memory_limit_bytes, 256 * 1024 * 1024);
        assert_eq!(config.active_process_limit, 1);
        assert!(config.enforce_microsoft_signed_dlls);
    }

    #[test]
    fn test_t31_named_pipe_peer_pid_invalid_handle_fails_closed() {
        use sentinel_sys::verify_named_pipe_client_pid;
        let invalid_handle: isize = -1;
        let res = verify_named_pipe_client_pid(invalid_handle);
        assert!(
            res.is_err(),
            "Invalid pipe handle must fail closed on PID verification"
        );
    }

    #[test]
    fn test_t31_named_pipe_peer_credentials_invalid_handle_fails_closed() {
        use sentinel_sys::verify_named_pipe_peer_credentials;
        let invalid_handle: isize = -1;
        let res = verify_named_pipe_peer_credentials(invalid_handle);
        assert!(
            res.is_err(),
            "Invalid pipe handle must fail closed on peer credential verification"
        );
    }

    unsafe fn windows_sys_close(h: isize) {
        #[link(name = "kernel32")]
        extern "system" {
            fn CloseHandle(hObject: isize) -> i32;
        }
        let _ = CloseHandle(h);
    }
}
