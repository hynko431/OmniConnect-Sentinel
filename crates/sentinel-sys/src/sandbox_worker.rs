use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Child;

/// Default Named Pipe IPC endpoint replacing the retired TCP `127.0.0.1:50051` listener (`Master Plan v2 §0.2`, Rows 25–28).
pub const DEFAULT_NAMED_PIPE_ENDPOINT: &str = r"\\.\pipe\OmniConnectSentinel";

/// Default ACL-hardened Named Pipe IPC endpoint for `sentinel-cdr-daemon` on Windows (`CSE-22`).
pub const DEFAULT_CDR_NAMED_PIPE_ENDPOINT: &str = r"\\.\pipe\OmniConnectSentinelCdr";

/// Default mode-`0600` Unix Domain Socket IPC endpoint for `sentinel-cdr-daemon` on Linux (`CSE-22`).
pub const DEFAULT_CDR_UNIX_SOCKET_PATH: &str = "/run/omniconnect/cdr.sock";

/// Hardened Named Pipe server SDDL (`CSE-22`, `ADR-016`):
/// Grants access strictly to `SYSTEM` (`SY`) and `Administrators` (`BA`).
/// `ALL APPLICATION PACKAGES` (`AC`), `Authenticated Users` (`AU`), and `Everyone` (`WD`)
/// are explicitly excluded so arbitrary Store/AppContainer processes cannot connect to the privileged CDR pipe.
pub const NAMED_PIPE_SERVER_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// Returns `true` ONLY when the operator explicitly sets `SENTINEL_UNSAFE_DEV_SANDBOX=1` (`CSE-22`).
/// Production builds NEVER silently downgrade CIG, Linux `unshare`, or Landlock sandboxing.
pub fn is_unsafe_dev_sandbox_opt_in() -> bool {
    std::env::var("SENTINEL_UNSAFE_DEV_SANDBOX")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Fail-closed evaluator for OS sandbox enforcement errors (`CSE-22`, `ADR-016`).
///
/// Always returns `Err(PermissionDenied)` unless `unsafe_dev_opt_in` is explicitly `true`
/// (`SENTINEL_UNSAFE_DEV_SANDBOX=1`), in which case it emits a loud `POSTURE_REDUCED_SANDBOX`
/// warning before allowing dev-only continuation.
pub fn evaluate_sandbox_enforcement_failure(
    component: &str,
    err: io::Error,
    unsafe_dev_opt_in: bool,
) -> io::Result<()> {
    if unsafe_dev_opt_in {
        tracing::warn!(
            "POSTURE_REDUCED_SANDBOX: {component} enforcement bypassed via SENTINEL_UNSAFE_DEV_SANDBOX=1 (error: {err})"
        );
        eprintln!(
            "POSTURE_REDUCED_SANDBOX: {component} enforcement bypassed via SENTINEL_UNSAFE_DEV_SANDBOX=1 (error: {err})"
        );
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "SANDBOX_FAIL_CLOSED: {component} failed ({err}); refusing to continue unsandboxed"
            ),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct JobSandboxConfig {
    pub memory_limit_bytes: usize,
    pub active_process_limit: u32,
    pub cpu_time_limit_ms: u64,
    pub enable_appcontainer: bool,
    pub enforce_microsoft_signed_dlls: bool,
}

impl Default for JobSandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit_bytes: 256 * 1024 * 1024, // 256 MB cap (Phase 2.1, Row 88)
            active_process_limit: 1,               // ACTIVE_PROCESS = 1 (Row 89)
            cpu_time_limit_ms: 30_000,             // 30 second CPU budget
            enable_appcontainer: true,             // Zero-capability AppContainer (Row 96)
            enforce_microsoft_signed_dlls: true,   // CIG Microsoft-signed DLLs only (Row 92)
        }
    }
}

pub struct JobSandboxGuard {
    #[cfg(windows)]
    job_handle: isize,
}

/// Handle to a sandboxed child worker spawned via `CreateProcessW` with `CREATE_SUSPENDED`
/// + `EXTENDED_STARTUPINFO_PRESENT` (`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`,
///   `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`, `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`),
///   assigned to a 256 MB Job Object BEFORE `ResumeThread` (`Critical #5`, Rows 88–97).
pub struct SandboxedChildProcess {
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub pid: u32,
    pub appcontainer_applied: bool,
    pub cig_applied: bool,
    #[cfg(windows)]
    process_handle: isize,
    #[cfg(windows)]
    thread_handle: isize,
    #[cfg(not(windows))]
    child: Option<Child>,
    _job_guard: JobSandboxGuard,
}

impl SandboxedChildProcess {
    /// Terminates the worker process immediately and waits for process exit.
    pub fn kill_and_wait(&mut self) -> io::Result<Option<i32>> {
        #[cfg(windows)]
        {
            if self.process_handle != 0 {
                unsafe {
                    let _ = TerminateProcess(self.process_handle, 1);
                    let _ = WaitForSingleObject(self.process_handle, 5_000);
                }
                let mut exit_code: u32 = 0;
                let ok = unsafe { GetExitCodeProcess(self.process_handle, &mut exit_code) };
                if ok != 0 {
                    return Ok(Some(exit_code as i32));
                }
            }
            Ok(None)
        }
        #[cfg(not(windows))]
        {
            if let Some(ref mut c) = self.child {
                let _ = c.kill();
                let status = c.wait()?;
                return Ok(status.code());
            }
            Ok(None)
        }
    }

    /// Waits synchronously for the worker process to exit and returns its exit code.
    pub fn wait(&mut self) -> io::Result<Option<i32>> {
        #[cfg(windows)]
        {
            if self.process_handle != 0 {
                unsafe {
                    let _ = WaitForSingleObject(self.process_handle, 30_000);
                }
                let mut exit_code: u32 = 0;
                let ok = unsafe { GetExitCodeProcess(self.process_handle, &mut exit_code) };
                if ok != 0 {
                    return Ok(Some(exit_code as i32));
                }
            }
            Ok(None)
        }
        #[cfg(not(windows))]
        {
            if let Some(ref mut c) = self.child {
                let status = c.wait()?;
                return Ok(status.code());
            }
            Ok(None)
        }
    }
}

impl Drop for SandboxedChildProcess {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            if self.thread_handle != 0 {
                let _ = CloseHandle(self.thread_handle);
                self.thread_handle = 0;
            }
            if self.process_handle != 0 {
                let _ = TerminateProcess(self.process_handle, 1);
                let _ = CloseHandle(self.process_handle);
                self.process_handle = 0;
            }
        }
        #[cfg(not(windows))]
        if let Some(ref mut c) = self.child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerCredentials {
    pub pid: u32,
    pub executable_path: PathBuf,
    pub signature_verified: bool,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct JobObjectBasicLimitInformation {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct JobObjectExtendedLimitInformation {
    basic_limit_information: JobObjectBasicLimitInformation,
    io_info: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[cfg(windows)]
#[repr(C)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut core::ffi::c_void,
    b_inherit_handle: i32,
}

#[cfg(windows)]
#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: isize,
    h_std_output: isize,
    h_std_error: isize,
}

#[cfg(windows)]
#[repr(C)]
struct StartupInfoExW {
    startup_info: StartupInfoW,
    lp_attribute_list: *mut core::ffi::c_void,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct ProcessInformation {
    h_process: isize,
    h_thread: isize,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[cfg(windows)]
#[repr(C)]
struct SecurityCapabilities {
    app_container_sid: *mut core::ffi::c_void,
    capabilities: *mut core::ffi::c_void,
    capability_count: u32,
    reserved: u32,
}

#[cfg(windows)]
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(windows)]
#[repr(C)]
struct WinTrustFileInfo {
    cb_struct: u32,
    pcwsz_file_path: *const u16,
    h_file: isize,
    pg_known_subject: *const Guid,
}

#[cfg(windows)]
#[repr(C)]
struct WinTrustData {
    cb_struct: u32,
    p_policy_callback_data: *mut core::ffi::c_void,
    p_sip_client_data: *mut core::ffi::c_void,
    dw_ui_choice: u32,
    fdw_revocation_checks: u32,
    dw_union_choice: u32,
    p_file: *const WinTrustFileInfo,
    dw_state_action: u32,
    h_vt_state_data: isize,
    pwsz_url_reference: *const u16,
    dw_prov_flags: u32,
    dw_ui_context: u32,
    p_signature_settings: *mut core::ffi::c_void,
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(lpJobAttributes: *const core::ffi::c_void, lpName: *const u16) -> isize;
    fn SetInformationJobObject(
        hJob: isize,
        JobObjectInformationClass: i32,
        lpJobObjectInformation: *const core::ffi::c_void,
        cbJobObjectInformationLength: u32,
    ) -> i32;
    fn AssignProcessToJobObject(hJob: isize, hProcess: isize) -> i32;
    fn SetProcessMitigationPolicy(
        MitigationPolicy: i32,
        lpBuffer: *const core::ffi::c_void,
        dwLength: usize,
    ) -> i32;
    fn GetNamedPipeClientProcessId(Pipe: isize, ClientProcessId: *mut u32) -> i32;
    fn CreateNamedPipeW(
        lpName: *const u16,
        dwOpenMode: u32,
        dwPipeMode: u32,
        nMaxInstances: u32,
        nOutBufferSize: u32,
        nInBufferSize: u32,
        nDefaultTimeOut: u32,
        lpSecurityAttributes: *const SecurityAttributes,
    ) -> isize;
    fn ConnectNamedPipe(hNamedPipe: isize, lpOverlapped: *mut core::ffi::c_void) -> i32;
    fn DisconnectNamedPipe(hNamedPipe: isize) -> i32;
    fn FlushFileBuffers(hFile: isize) -> i32;
    fn ReadFile(
        hFile: isize,
        lpBuffer: *mut u8,
        nNumberOfBytesToRead: u32,
        lpNumberOfBytesRead: *mut u32,
        lpOverlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn WriteFile(
        hFile: isize,
        lpBuffer: *const u8,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn CreatePipe(
        hReadPipe: *mut isize,
        hWritePipe: *mut isize,
        lpPipeAttributes: *const SecurityAttributes,
        nSize: u32,
    ) -> i32;
    fn SetHandleInformation(hObject: isize, dwMask: u32, dwFlags: u32) -> i32;
    fn InitializeProcThreadAttributeList(
        lpAttributeList: *mut core::ffi::c_void,
        dwAttributeCount: u32,
        dwFlags: u32,
        lpSize: *mut usize,
    ) -> i32;
    fn UpdateProcThreadAttribute(
        lpAttributeList: *mut core::ffi::c_void,
        dwFlags: u32,
        Attribute: usize,
        lpValue: *const core::ffi::c_void,
        cbSize: usize,
        lpPreviousValue: *mut core::ffi::c_void,
        lpReturnSize: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(lpAttributeList: *mut core::ffi::c_void);
    fn CreateProcessW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *const SecurityAttributes,
        lpThreadAttributes: *const SecurityAttributes,
        bInheritHandles: i32,
        dwCreationFlags: u32,
        lpEnvironment: *const core::ffi::c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *const StartupInfoExW,
        lpProcessInformation: *mut ProcessInformation,
    ) -> i32;
    fn ResumeThread(hThread: isize) -> u32;
    fn TerminateProcess(hProcess: isize, uExitCode: u32) -> i32;
    fn WaitForSingleObject(hHandle: isize, dwMilliseconds: u32) -> u32;
    fn GetExitCodeProcess(hProcess: isize, lpExitCode: *mut u32) -> i32;
    fn GetCurrentProcessId() -> u32;
    fn ProcessIdToSessionId(dwProcessId: u32, pSessionId: *mut u32) -> i32;
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> isize;
    fn QueryFullProcessImageNameW(
        hProcess: isize,
        dwFlags: u32,
        lpExeName: *mut u16,
        lpdwSize: *mut u32,
    ) -> i32;
    fn CloseHandle(hObject: isize) -> i32;
    fn LocalFree(hMem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const core::ffi::c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: isize,
    ) -> isize;
}

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        StringSecurityDescriptor: *const u16,
        StringSDRevision: u32,
        SecurityDescriptor: *mut *mut core::ffi::c_void,
        SecurityDescriptorSize: *mut u32,
    ) -> i32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        SecurityDescriptor: *const core::ffi::c_void,
        RequestedStringSDRevision: u32,
        SecurityInformation: u32,
        StringSecurityDescriptor: *mut *mut u16,
        StringSecurityDescriptorLen: *mut u32,
    ) -> i32;
    fn GetSecurityInfo(
        handle: isize,
        ObjectType: u32,
        SecurityInfo: u32,
        ppsidOwner: *mut *mut core::ffi::c_void,
        ppsidGroup: *mut *mut core::ffi::c_void,
        ppDacl: *mut *mut core::ffi::c_void,
        ppSacl: *mut *mut core::ffi::c_void,
        ppSecurityDescriptor: *mut *mut core::ffi::c_void,
    ) -> u32;
    fn FreeSid(pSid: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    fn IsValidSid(pSid: *mut core::ffi::c_void) -> i32;
}

#[cfg(windows)]
#[link(name = "userenv")]
extern "system" {
    fn CreateAppContainerProfile(
        pszAppContainerName: *const u16,
        pszDisplayName: *const u16,
        pszDescription: *const u16,
        pCapabilities: *mut core::ffi::c_void,
        dwCapabilityCount: u32,
        ppSidAppContainerSid: *mut *mut core::ffi::c_void,
    ) -> i32;
    fn DeriveAppContainerSidFromAppContainerName(
        pszAppContainerName: *const u16,
        ppsidAppContainerSid: *mut *mut core::ffi::c_void,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(hwnd: isize, pgActionID: *const Guid, pWVTData: *mut WinTrustData) -> i32;
}

/// Internal helper that creates a 256 MB Job Object (`ACTIVE_PROCESS=1`, `KILL_ON_JOB_CLOSE`,
/// `DIE_ON_UNHANDLED_EXCEPTION`) and assigns a raw process handle to it (`Rows 88–90`).
#[cfg(windows)]
fn assign_raw_handle_to_sandbox_job(
    proc_handle: isize,
    config: &JobSandboxConfig,
) -> io::Result<JobSandboxGuard> {
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
    const JOB_OBJECT_LIMIT_PROCESS_TIME: u32 = 0x0000_0002;
    const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
    const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x0000_0100;
    const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x0000_0400;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

    let job = unsafe { CreateJobObjectW(core::ptr::null(), core::ptr::null()) };
    if job == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ext_info = JobObjectExtendedLimitInformation::default();
    ext_info.basic_limit_information.per_process_user_time_limit =
        (config.cpu_time_limit_ms as i64) * 10_000;
    ext_info.basic_limit_information.active_process_limit = config.active_process_limit;
    ext_info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    ext_info.process_memory_limit = config.memory_limit_bytes;

    let ok_set = unsafe {
        SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            &ext_info as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<JobObjectExtendedLimitInformation>() as u32,
        )
    };
    if ok_set == 0 {
        let err = io::Error::last_os_error();
        unsafe {
            let _ = CloseHandle(job);
        }
        return Err(err);
    }

    // Apply strict UI restrictions (deny handles, clipboard, desktop, window hooks, global atoms)
    #[repr(C)]
    struct JobObjectBasicUiRestrictions {
        ui_restrictions_class: u32,
    }
    const JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS: i32 = 4;
    const JOB_OBJECT_UILIMIT_ALL: u32 = 0x0000_00FF; // Deny all 8 desktop UI interactions
    let ui_restrictions = JobObjectBasicUiRestrictions {
        ui_restrictions_class: JOB_OBJECT_UILIMIT_ALL,
    };
    let _ = unsafe {
        SetInformationJobObject(
            job,
            JOB_OBJECT_BASIC_UI_RESTRICTIONS_CLASS,
            &ui_restrictions as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<JobObjectBasicUiRestrictions>() as u32,
        )
    };

    let ok_assign = unsafe { AssignProcessToJobObject(job, proc_handle) };
    if ok_assign == 0 {
        let err = io::Error::last_os_error();
        unsafe {
            let _ = CloseHandle(job);
        }
        return Err(err);
    }

    Ok(JobSandboxGuard { job_handle: job })
}

/// Assigns a spawned worker child process to an OS-enforced Job Object sandbox
/// with a strict memory cap, active-process cap of 1, and kill-on-close semantics.
pub fn assign_child_to_sandbox_job(
    child: &Child,
    config: &JobSandboxConfig,
) -> io::Result<JobSandboxGuard> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let proc_handle = child.as_raw_handle() as isize;
        assign_raw_handle_to_sandbox_job(proc_handle, config)
    }
    #[cfg(not(windows))]
    {
        let _ = (child, config);
        Ok(JobSandboxGuard {})
    }
}

impl Drop for JobSandboxGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.job_handle != 0 {
            unsafe {
                let _ = CloseHandle(self.job_handle);
            }
        }
    }
}

/// AppContainer SID derivation strategy selected from the host Windows Session ID (`CSE-26`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppContainerSessionStrategy {
    /// Windows Session 0 (`NT AUTHORITY\SYSTEM` service): derive deterministic AppContainer SID
    /// directly via `DeriveAppContainerSidFromAppContainerName` without requiring an interactive
    /// `HKCU` user profile hive (which causes `CreateAppContainerProfile` to fail with
    /// `E_ACCESSDENIED` / missing profile errors under `LocalSystem`).
    DirectDeriveSessionZero,
    /// Interactive desktop session (Session >= 1): create/reuse profile via `CreateAppContainerProfile`
    /// and fall back to `DeriveAppContainerSidFromAppContainerName` on `ERROR_ALREADY_EXISTS` or
    /// restricted profile contexts.
    CreateOrDeriveInteractive,
}

/// Selects the appropriate AppContainer profile derivation strategy for a Windows Session ID (`CSE-26`).
pub fn resolve_appcontainer_strategy_for_session(session_id: u32) -> AppContainerSessionStrategy {
    if session_id == 0 {
        AppContainerSessionStrategy::DirectDeriveSessionZero
    } else {
        AppContainerSessionStrategy::CreateOrDeriveInteractive
    }
}

/// Returns the current Windows Session ID via `ProcessIdToSessionId(GetCurrentProcessId())`,
/// or `None` on non-Windows hosts (`CSE-26`).
pub fn current_process_session_id() -> Option<u32> {
    #[cfg(windows)]
    {
        let mut session_id: u32 = 0;
        let pid = unsafe { GetCurrentProcessId() };
        if unsafe { ProcessIdToSessionId(pid, &mut session_id) } != 0 {
            Some(session_id)
        } else {
            None
        }
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Verifies that the zero-capability AppContainer SID can be derived cleanly (including in
/// Windows Session 0 without an interactive user profile hive) and validates it via `IsValidSid` (`CSE-26`).
pub fn verify_appcontainer_sid_derivation() -> io::Result<bool> {
    #[cfg(windows)]
    {
        let Some(sid) = obtain_zero_capability_appcontainer_sid() else {
            return Ok(false);
        };
        let valid = unsafe { IsValidSid(sid) } != 0;
        unsafe {
            let _ = FreeSid(sid);
        }
        Ok(valid)
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

#[cfg(windows)]
fn obtain_zero_capability_appcontainer_sid() -> Option<*mut core::ffi::c_void> {
    use std::os::windows::ffi::OsStrExt;
    let name: Vec<u16> = std::ffi::OsStr::new("OmniConnect.Sentinel.CdrWorker")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let display: Vec<u16> = std::ffi::OsStr::new("OmniConnect Sentinel CDR Sandbox")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let desc: Vec<u16> = std::ffi::OsStr::new("Zero-capability AppContainer for CDR parsing")
        .encode_wide()
        .chain(Some(0))
        .collect();

    let session_id = current_process_session_id().unwrap_or(1);
    let strategy = resolve_appcontainer_strategy_for_session(session_id);

    let derive_direct = || -> Option<*mut core::ffi::c_void> {
        let mut sid: *mut core::ffi::c_void = core::ptr::null_mut();
        let hr_derive =
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if hr_derive == 0 && !sid.is_null() && unsafe { IsValidSid(sid) } != 0 {
            Some(sid)
        } else {
            if !sid.is_null() {
                unsafe {
                    let _ = FreeSid(sid);
                }
            }
            None
        }
    };

    let create_profile = || -> Option<*mut core::ffi::c_void> {
        let mut sid: *mut core::ffi::c_void = core::ptr::null_mut();
        let hr = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display.as_ptr(),
                desc.as_ptr(),
                core::ptr::null_mut(),
                0,
                &mut sid,
            )
        };
        if hr == 0 && !sid.is_null() && unsafe { IsValidSid(sid) } != 0 {
            Some(sid)
        } else {
            if !sid.is_null() {
                unsafe {
                    let _ = FreeSid(sid);
                }
            }
            None
        }
    };

    match strategy {
        AppContainerSessionStrategy::DirectDeriveSessionZero => {
            derive_direct().or_else(create_profile)
        }
        AppContainerSessionStrategy::CreateOrDeriveInteractive => {
            create_profile().or_else(derive_direct)
        }
    }
}

/// Spawns `sentinel-cdr-worker` using `CreateProcessW` with `CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW`:
/// 1. Configures `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` (DEP, ACG `PROHIBIT_DYNAMIC_CODE_ALWAYS_ON`,
///    `EXTENSION_POINT_DISABLE_ALWAYS_ON`, `IMAGE_LOAD_NO_REMOTE_ALWAYS_ON`, `IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON`,
///    and `BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` CIG).
/// 2. Configures `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` (`PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`).
/// 3. Configures `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (zero-capability AppContainer SID).
/// 4. Assigns the suspended process handle to the 256 MB Job Object (`AssignProcessToJobObject`) **before**
///    calling `ResumeThread`, failing closed and terminating the process if Job assignment fails (`Critical #5`, Rows 88–96).
pub fn spawn_sandboxed_worker_process(
    exe_path: &Path,
    config: &JobSandboxConfig,
) -> io::Result<SandboxedChildProcess> {
    if !exe_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("CDR worker binary not found at {}", exe_path.display()),
        ));
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;

        const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
        const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;

        const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
        const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x0002_0007;
        const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
        const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: usize = 0x0002_000E;

        const PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE: u64 = 0x0000_0001;
        const PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE: u64 = 0x0000_0002;
        const PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE: u64 = 0x0000_0004;
        const PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 =
            0x0000_0001u64 << 32;
        const PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON: u64 =
            0x0000_0001u64 << 36;
        const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 =
            0x0000_0001u64 << 44;
        const PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON: u64 =
            0x0000_0001u64 << 52;
        const PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON: u64 =
            0x0000_0001u64 << 56;

        const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: u32 = 0x0000_0001;

        let sa = SecurityAttributes {
            n_length: core::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: core::ptr::null_mut(),
            b_inherit_handle: 1,
        };

        let mut stdin_read: isize = 0;
        let mut stdin_write: isize = 0;
        if unsafe { CreatePipe(&mut stdin_read, &mut stdin_write, &sa, 64 * 1024) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0) } == 0 {
            let err = io::Error::last_os_error();
            unsafe {
                let _ = CloseHandle(stdin_read);
                let _ = CloseHandle(stdin_write);
            }
            return Err(err);
        }

        let mut stdout_read: isize = 0;
        let mut stdout_write: isize = 0;
        if unsafe { CreatePipe(&mut stdout_read, &mut stdout_write, &sa, 64 * 1024) } == 0 {
            let err = io::Error::last_os_error();
            unsafe {
                let _ = CloseHandle(stdin_read);
                let _ = CloseHandle(stdin_write);
            }
            return Err(err);
        }
        if unsafe { SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0) } == 0 {
            let err = io::Error::last_os_error();
            unsafe {
                let _ = CloseHandle(stdin_read);
                let _ = CloseHandle(stdin_write);
                let _ = CloseHandle(stdout_read);
                let _ = CloseHandle(stdout_write);
            }
            return Err(err);
        }

        let app_wide: Vec<u16> = exe_path.as_os_str().encode_wide().chain(Some(0)).collect();
        let cmd_str = format!("\"{}\"", exe_path.display());

        let appcontainer_sid = if config.enable_appcontainer {
            let sid_opt = obtain_zero_capability_appcontainer_sid();
            if sid_opt.is_none() {
                unsafe {
                    let _ = CloseHandle(stdin_read);
                    let _ = CloseHandle(stdin_write);
                    let _ = CloseHandle(stdout_read);
                    let _ = CloseHandle(stdout_write);
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Fail-closed: AppContainer profile creation or derivation failed",
                ));
            }
            sid_opt
        } else {
            None
        };

        // Strict fail-closed single-tier launch (`CSE-22`, `ADR-016`):
        // NEVER silently retry without CIG (`enforce_microsoft_signed_dlls`) or AppContainer.
        // Relaxing CIG requires explicit operator opt-in via `SENTINEL_UNSAFE_DEV_SANDBOX=1`,
        // which logs `POSTURE_REDUCED_SANDBOX`.
        let use_appcontainer = appcontainer_sid.is_some();
        let use_cig = if config.enforce_microsoft_signed_dlls {
            if is_unsafe_dev_sandbox_opt_in() {
                tracing::warn!(
                    "POSTURE_REDUCED_SANDBOX: Windows CIG disabled for worker launch via SENTINEL_UNSAFE_DEV_SANDBOX=1"
                );
                eprintln!(
                    "POSTURE_REDUCED_SANDBOX: Windows CIG disabled for worker launch via SENTINEL_UNSAFE_DEV_SANDBOX=1"
                );
                false
            } else {
                true
            }
        } else {
            false
        };
        let tiers: [(bool, bool); 1] = [(use_appcontainer, use_cig)];

        let mut spawned_pi: Option<(ProcessInformation, JobSandboxGuard, bool, bool)> = None;
        let mut last_spawn_err: Option<io::Error> = None;
        const WAIT_TIMEOUT: u32 = 0x0000_0102;

        for (use_appcontainer, use_cig) in tiers {
            let mut cmd_wide: Vec<u16> = std::ffi::OsStr::new(&cmd_str)
                .encode_wide()
                .chain(Some(0))
                .collect();

            let attr_count: u32 = if use_appcontainer { 4 } else { 3 };
            let mut attr_list_size: usize = 0;
            unsafe {
                let _ = InitializeProcThreadAttributeList(
                    core::ptr::null_mut(),
                    attr_count,
                    0,
                    &mut attr_list_size,
                );
            }
            let mut attr_buf = vec![0u8; attr_list_size.max(64)];
            let attr_ptr = attr_buf.as_mut_ptr() as *mut core::ffi::c_void;
            if unsafe {
                InitializeProcThreadAttributeList(attr_ptr, attr_count, 0, &mut attr_list_size)
            } == 0
            {
                last_spawn_err = Some(io::Error::last_os_error());
                continue;
            }

            let mut mitigation_flags: u64 = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE
                | PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE
                | PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE
                | PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
                | PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
                | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
                | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON;
            if use_cig {
                mitigation_flags |=
                    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
            }

            let child_policy: u32 = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
            let mut sec_caps = SecurityCapabilities {
                app_container_sid: appcontainer_sid.unwrap_or(core::ptr::null_mut()),
                capabilities: core::ptr::null_mut(),
                capability_count: 0,
                reserved: 0,
            };

            let mut handles_to_inherit: [isize; 2] = [stdin_read, stdout_write];
            let ok_h = unsafe {
                UpdateProcThreadAttribute(
                    attr_ptr,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handles_to_inherit.as_mut_ptr() as *mut core::ffi::c_void,
                    handles_to_inherit.len() * core::mem::size_of::<isize>(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };

            let ok_m = unsafe {
                UpdateProcThreadAttribute(
                    attr_ptr,
                    0,
                    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                    &mitigation_flags as *const _ as *const core::ffi::c_void,
                    core::mem::size_of::<u64>(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            let ok_c = unsafe {
                UpdateProcThreadAttribute(
                    attr_ptr,
                    0,
                    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                    &child_policy as *const _ as *const core::ffi::c_void,
                    core::mem::size_of::<u32>(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            let ok_ac = if use_appcontainer {
                unsafe {
                    UpdateProcThreadAttribute(
                        attr_ptr,
                        0,
                        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                        &mut sec_caps as *mut _ as *const core::ffi::c_void,
                        core::mem::size_of::<SecurityCapabilities>(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                }
            } else {
                1
            };

            if ok_m == 0 || ok_c == 0 || ok_h == 0 || ok_ac == 0 {
                last_spawn_err = Some(io::Error::last_os_error());
                unsafe {
                    DeleteProcThreadAttributeList(attr_ptr);
                }
                continue;
            }

            let si_ex = StartupInfoExW {
                startup_info: StartupInfoW {
                    cb: core::mem::size_of::<StartupInfoExW>() as u32,
                    lp_reserved: core::ptr::null_mut(),
                    lp_desktop: core::ptr::null_mut(),
                    lp_title: core::ptr::null_mut(),
                    dw_x: 0,
                    dw_y: 0,
                    dw_x_size: 0,
                    dw_y_size: 0,
                    dw_x_count_chars: 0,
                    dw_y_count_chars: 0,
                    dw_fill_attribute: 0,
                    dw_flags: STARTF_USESTDHANDLES,
                    w_show_window: 0,
                    cb_reserved2: 0,
                    lp_reserved2: core::ptr::null_mut(),
                    h_std_input: stdin_read,
                    h_std_output: stdout_write,
                    h_std_error: stdout_write,
                },
                lp_attribute_list: attr_ptr,
            };

            let mut pi = ProcessInformation::default();
            // Do NOT pass CREATE_NO_WINDOW here: on Windows, CREATE_NO_WINDOW forces kernelbase.dll
            // DllMain to spawn a new conhost.exe instance during LdrInitializeThunk, which is blocked
            // by PROCESS_CREATION_CHILD_PROCESS_RESTRICTED and active_process_limit=1, causing
            // 0xC0000142 (STATUS_DLL_INIT_FAILED). With STARTF_USESTDHANDLES and without CREATE_NO_WINDOW,
            // no new conhost.exe is spawned.
            let created = unsafe {
                CreateProcessW(
                    app_wide.as_ptr(),
                    cmd_wide.as_mut_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                    1,
                    CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                    core::ptr::null(),
                    core::ptr::null(),
                    &si_ex,
                    &mut pi,
                )
            };

            unsafe {
                DeleteProcThreadAttributeList(attr_ptr);
            }

            if created == 0 {
                last_spawn_err = Some(io::Error::last_os_error());
                continue;
            }

            // Fail-closed: assign suspended child to 256 MB Job Object BEFORE ResumeThread!
            let job_guard = match assign_raw_handle_to_sandbox_job(pi.h_process, config) {
                Ok(g) => g,
                Err(e) => {
                    if let Some(sid) = appcontainer_sid {
                        unsafe {
                            let _ = FreeSid(sid);
                        }
                    }
                    unsafe {
                        let _ = TerminateProcess(pi.h_process, 1);
                        let _ = CloseHandle(pi.h_thread);
                        let _ = CloseHandle(pi.h_process);
                        let _ = CloseHandle(stdin_read);
                        let _ = CloseHandle(stdout_write);
                        let _ = CloseHandle(stdin_write);
                        let _ = CloseHandle(stdout_read);
                    }
                    return Err(e);
                }
            };

            // Resume suspended worker thread only after Job Object and mitigations are active
            let prev_suspend = unsafe { ResumeThread(pi.h_thread) };
            if prev_suspend == u32::MAX {
                last_spawn_err = Some(io::Error::last_os_error());
                unsafe {
                    let _ = TerminateProcess(pi.h_process, 1);
                    let _ = CloseHandle(pi.h_thread);
                    let _ = CloseHandle(pi.h_process);
                }
                drop(job_guard);
                continue;
            }

            // If AppContainer or CIG was requested on a binary located in a user directory where
            // S-1-15-2-1 lacks DLL init permissions (`STATUS_DLL_INIT_FAILED` = 0xC0000142),
            // verify the worker stays alive waiting on `stdin` after `LdrInitializeThunk`.
            if use_appcontainer || use_cig {
                let wait_rc = unsafe { WaitForSingleObject(pi.h_process, 15) };
                if wait_rc != WAIT_TIMEOUT {
                    let mut exit_code: u32 = 0;
                    unsafe {
                        let _ = GetExitCodeProcess(pi.h_process, &mut exit_code);
                        let _ = CloseHandle(pi.h_thread);
                        let _ = CloseHandle(pi.h_process);
                    }
                    drop(job_guard);
                    last_spawn_err = Some(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("AppContainer/CIG loader init exited with 0x{exit_code:08X}"),
                    ));
                    continue;
                }
            }

            spawned_pi = Some((pi, job_guard, use_appcontainer, use_cig));
            break;
        }

        if let Some(sid) = appcontainer_sid {
            unsafe {
                let _ = FreeSid(sid);
            }
        }

        // Close child pipe ends in the parent process immediately
        unsafe {
            let _ = CloseHandle(stdin_read);
            let _ = CloseHandle(stdout_write);
        }

        let (pi, job_guard, appcontainer_applied, cig_applied) = match spawned_pi {
            Some(t) => t,
            None => {
                unsafe {
                    let _ = CloseHandle(stdin_write);
                    let _ = CloseHandle(stdout_read);
                }
                return Err(last_spawn_err
                    .unwrap_or_else(|| io::Error::other("CreateProcessW failed for CDR worker")));
            }
        };

        let stdin_file = unsafe { File::from_raw_handle(stdin_write as *mut core::ffi::c_void) };
        let stdout_file = unsafe { File::from_raw_handle(stdout_read as *mut core::ffi::c_void) };

        Ok(SandboxedChildProcess {
            stdin: Some(stdin_file),
            stdout: Some(stdout_file),
            pid: pi.dw_process_id,
            appcontainer_applied,
            cig_applied,
            process_handle: pi.h_process,
            thread_handle: pi.h_thread,
            _job_guard: job_guard,
        })
    }
    #[cfg(not(windows))]
    {
        use std::process::{Command, Stdio};
        let mut child = Command::new(exe_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();
        let job_guard = assign_child_to_sandbox_job(&child, config)?;
        let stdin_pipe = child.stdin.take();
        let stdout_pipe = child.stdout.take();
        // Convert ChildStdin/ChildStdout into std::fs::File via OwnedFd
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        let stdin_file = stdin_pipe.map(|s| unsafe { File::from_raw_fd(s.into_raw_fd()) });
        let stdout_file = stdout_pipe.map(|s| unsafe { File::from_raw_fd(s.into_raw_fd()) });

        Ok(SandboxedChildProcess {
            stdin: stdin_file,
            stdout: stdout_file,
            pid,
            appcontainer_applied: false,
            cig_applied: false,
            child: Some(child),
            _job_guard: job_guard,
        })
    }
}

/// Applies in-process OS exploit mitigations to the ephemeral `sentinel-cdr-worker` process
/// (`Master Plan v2 §2.1`, Rows 91, 92, 97):
/// - On Windows: Dynamic-Code (ACG) prohibition, Extension-Point disablement, Binary Signature
///   Policy (`MicrosoftSignedOnly`), Remote/Low-Mandatory image load prohibition, and Child-Process
///   creation prohibition (`ProcessChildProcessPolicy`), checking return codes.
/// - On Linux: `setrlimit(RLIMIT_AS, 256 MiB)`, `prctl(PR_SET_NO_NEW_PRIVS, 1)`, and `unshare(CLONE_NEWNET)`.
pub fn apply_worker_process_mitigations() -> io::Result<()> {
    #[cfg(windows)]
    {
        // ProcessDynamicCodePolicy = 2 (ProhibitDynamicCode = bit 0)
        const PROCESS_DYNAMIC_CODE_POLICY: i32 = 2;
        // ProcessExtensionPointDisablePolicy = 6 (DisableExtensionPoints = bit 0)
        const PROCESS_EXTENSION_POINT_DISABLE_POLICY: i32 = 6;
        // ProcessSignaturePolicy = 8 (MicrosoftSignedOnly = bit 0)
        const PROCESS_SIGNATURE_POLICY: i32 = 8;
        // ProcessImageLoadPolicy = 10 (NoRemoteImages = bit 0, NoLowMandatoryLabelImages = bit 1)
        const PROCESS_IMAGE_LOAD_POLICY: i32 = 10;
        // ProcessChildProcessPolicy = 13 (NoChildProcessCreation = bit 0)
        const PROCESS_CHILD_PROCESS_POLICY: i32 = 13;
        const ERROR_ACCESS_DENIED: i32 = 5;

        let flag_one: u32 = 0x1;
        let flag_three: u32 = 0x3;

        unsafe {
            // Note: if the parent already enabled a mitigation via PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            // SetProcessMitigationPolicy may return ERROR_ACCESS_DENIED (5) because the policy is locked on.
            let check_mitigation = |rc: i32| -> io::Result<()> {
                if rc != 0 {
                    return Ok(());
                }
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
                    // Already locked on at process creation via STARTUPINFOEXW
                    return Ok(());
                }
                Err(err)
            };

            check_mitigation(SetProcessMitigationPolicy(
                PROCESS_DYNAMIC_CODE_POLICY,
                &flag_one as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<u32>(),
            ))?;
            check_mitigation(SetProcessMitigationPolicy(
                PROCESS_EXTENSION_POINT_DISABLE_POLICY,
                &flag_one as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<u32>(),
            ))?;
            check_mitigation(SetProcessMitigationPolicy(
                PROCESS_IMAGE_LOAD_POLICY,
                &flag_three as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<u32>(),
            ))?;
            check_mitigation(SetProcessMitigationPolicy(
                PROCESS_CHILD_PROCESS_POLICY,
                &flag_one as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<u32>(),
            ))?;
            // Apply ProcessSignaturePolicy (CIG MicrosoftSignedOnly = 1) fail-closed (`CSE-22`).
            if let Err(err) = check_mitigation(SetProcessMitigationPolicy(
                PROCESS_SIGNATURE_POLICY,
                &flag_one as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<u32>(),
            )) {
                evaluate_sandbox_enforcement_failure(
                    "windows_cig_process_signature_policy",
                    err,
                    is_unsafe_dev_sandbox_opt_in(),
                )?;
            }
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        crate::bpf_sandbox::apply_linux_worker_sandbox()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Ok(())
    }
}

/// Internal helper creating an ACL-hardened Windows Named Pipe instance using
/// `NAMED_PIPE_SERVER_SDDL` (`D:P(A;;GA;;;SY)(A;;GA;;;BA)` — zero `AC`/`AU`/`WD`)
/// and `PIPE_REJECT_REMOTE_CLIENTS` (`CSE-22`, `ADR-016`).
#[cfg(windows)]
fn create_acl_named_pipe_server_instance(
    pipe_name: &str,
    first_instance: bool,
) -> io::Result<isize> {
    use std::os::windows::ffi::OsStrExt;
    const SDDL_REVISION_1: u32 = 1;
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
    const INVALID_HANDLE_VALUE: isize = -1;

    let sddl_wide: Vec<u16> = std::ffi::OsStr::new(NAMED_PIPE_SERVER_SDDL)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut sd_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut sd_size: u32 = 0;
    let ok_sddl = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr,
            &mut sd_size,
        )
    };
    if ok_sddl == 0 || sd_ptr.is_null() {
        return Err(io::Error::last_os_error());
    }

    let sa = SecurityAttributes {
        n_length: core::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: sd_ptr,
        b_inherit_handle: 0,
    };
    let pipe_wide: Vec<u16> = std::ffi::OsStr::new(pipe_name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let open_mode = if first_instance {
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        PIPE_ACCESS_DUPLEX
    };
    let handle = unsafe {
        CreateNamedPipeW(
            pipe_wide.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            8, // Max instances bound to 8
            64 * 1024,
            64 * 1024,
            5_000,
            &sa,
        )
    };
    unsafe {
        let _ = LocalFree(sd_ptr);
    }
    if handle == INVALID_HANDLE_VALUE || handle == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}

/// Creates a local Named Pipe server handle (`\\.\pipe\OmniConnectSentinelCdr`) protected by the
/// hardened SDDL DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (zero `AC`/`AU`/`WD`),
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` (anti-squatting), and `PIPE_REJECT_REMOTE_CLIENTS`
/// (`CSE-22`, `ADR-016`, `Row 26, 27`).
pub fn create_acl_named_pipe_server(pipe_name: &str) -> io::Result<isize> {
    #[cfg(windows)]
    {
        create_acl_named_pipe_server_instance(pipe_name, true)
    }
    #[cfg(not(windows))]
    {
        let _ = pipe_name;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows Named Pipe creation is only supported on Windows",
        ))
    }
}

/// Queries the live OS kernel DACL SDDL string of an open kernel object handle (such as a Windows
/// Named Pipe handle) via `GetSecurityInfo(SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION)` (`CSE-22`).
pub fn query_kernel_handle_dacl_sddl(handle: isize) -> io::Result<String> {
    #[cfg(windows)]
    {
        const SE_KERNEL_OBJECT: u32 = 6;
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
        const SDDL_REVISION_1: u32 = 1;

        let mut sd_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let rc = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut sd_ptr,
            )
        };
        if rc != 0 || sd_ptr.is_null() {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }

        let mut sddl_ptr: *mut u16 = core::ptr::null_mut();
        let mut sddl_len: u32 = 0;
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd_ptr,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl_ptr,
                &mut sddl_len,
            )
        };
        unsafe {
            let _ = LocalFree(sd_ptr);
        }
        if ok == 0 || sddl_ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        let slice = unsafe { core::slice::from_raw_parts(sddl_ptr, sddl_len as usize) };
        let sddl = String::from_utf16_lossy(slice)
            .trim_end_matches('\0')
            .to_string();
        unsafe {
            let _ = LocalFree(sddl_ptr as *mut core::ffi::c_void);
        }
        Ok(sddl)
    }
    #[cfg(not(windows))]
    {
        let _ = handle;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Kernel handle SDDL inspection is Windows-specific",
        ))
    }
}

/// Closes a raw Windows kernel handle safely across crate boundaries without exposing `unsafe`.
pub fn close_raw_kernel_handle(handle: isize) {
    #[cfg(windows)]
    {
        if handle != 0 && handle != -1 {
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = handle;
    }
}

/// Connected local IPC stream (`\\.\pipe\...` on Windows or Unix Domain Socket on Linux) (`CSE-22`).
pub struct LocalIpcStream {
    #[cfg(windows)]
    handle: isize,
    #[cfg(windows)]
    is_server_side: bool,
    #[cfg(unix)]
    stream: std::os::unix::net::UnixStream,
}

impl LocalIpcStream {
    /// Connects as a local client to an ACL-hardened Named Pipe (`Windows`) or Unix Domain Socket (`Unix`).
    pub fn connect(endpoint: &str) -> io::Result<Self> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            const GENERIC_READ: u32 = 0x8000_0000;
            const GENERIC_WRITE: u32 = 0x4000_0000;
            const OPEN_EXISTING: u32 = 3;
            const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
            const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
            const INVALID_HANDLE_VALUE: isize = -1;

            let wide: Vec<u16> = std::ffi::OsStr::new(endpoint)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    0,
                )
            };
            if handle == INVALID_HANDLE_VALUE || handle == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                handle,
                is_server_side: false,
            })
        }
        #[cfg(unix)]
        {
            let stream = std::os::unix::net::UnixStream::connect(endpoint)?;
            Ok(Self { stream })
        }
    }
}

impl io::Read for LocalIpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        #[cfg(windows)]
        {
            const ERROR_BROKEN_PIPE: i32 = 109;
            let to_read = buf.len().min(u32::MAX as usize) as u32;
            let mut bytes_read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    buf.as_mut_ptr(),
                    to_read,
                    &mut bytes_read,
                    core::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(ERROR_BROKEN_PIPE) {
                    return Ok(0);
                }
                return Err(err);
            }
            Ok(bytes_read as usize)
        }
        #[cfg(unix)]
        {
            self.stream.read(buf)
        }
    }
}

impl io::Write for LocalIpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        #[cfg(windows)]
        {
            let to_write = buf.len().min(u32::MAX as usize) as u32;
            let mut written: u32 = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle,
                    buf.as_ptr(),
                    to_write,
                    &mut written,
                    core::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(written as usize)
        }
        #[cfg(unix)]
        {
            self.stream.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        {
            let _ = unsafe { FlushFileBuffers(self.handle) };
            Ok(())
        }
        #[cfg(unix)]
        {
            self.stream.flush()
        }
    }
}

impl Drop for LocalIpcStream {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.handle != 0 && self.handle != -1 {
                unsafe {
                    if self.is_server_side {
                        let _ = FlushFileBuffers(self.handle);
                        let _ = DisconnectNamedPipe(self.handle);
                    }
                    let _ = CloseHandle(self.handle);
                }
                self.handle = 0;
            }
        }
    }
}

/// ACL-hardened local IPC server listener (`\\.\pipe\OmniConnectSentinelCdr` on Windows or
/// mode-`0600` + `SO_PEERCRED` Unix Domain Socket `/run/omniconnect/cdr.sock` on Linux) (`CSE-22`).
pub struct LocalIpcServer {
    endpoint: String,
    #[cfg(windows)]
    next_pipe_handle: isize,
    #[cfg(unix)]
    listener: std::os::unix::net::UnixListener,
    #[cfg(unix)]
    socket_path: PathBuf,
}

impl LocalIpcServer {
    /// Binds an ACL-hardened local IPC listener on the given endpoint (or the OS default CDR endpoint).
    pub fn bind(endpoint_override: Option<&str>) -> io::Result<Self> {
        #[cfg(windows)]
        {
            let endpoint = endpoint_override
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_CDR_NAMED_PIPE_ENDPOINT)
                .to_string();
            let first_handle = create_acl_named_pipe_server_instance(&endpoint, true)?;
            Ok(Self {
                endpoint,
                next_pipe_handle: first_handle,
            })
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let endpoint = endpoint_override
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_CDR_UNIX_SOCKET_PATH)
                .to_string();
            let socket_path = PathBuf::from(&endpoint);
            if let Some(parent) = socket_path.parent() {
                if !parent.as_os_str().is_empty() {
                    crate::fs_lowlevel::ensure_not_symlink_or_reparse_point(parent)?;
                    if std::fs::symlink_metadata(parent).is_err() {
                        crate::fs_lowlevel::create_restricted_dir_atomic(parent)?;
                    }
                }
            }
            // Unconditionally reject symlinked parents OR dangling/existing symlinks at socket_path
            crate::fs_lowlevel::ensure_not_symlink_or_reparse_point(&socket_path)?;
            if std::fs::symlink_metadata(&socket_path).is_ok() {
                let _ = std::fs::remove_file(&socket_path);
            }
            let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
            if let Err(err) =
                std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            {
                let _ = std::fs::remove_file(&socket_path);
                return Err(err);
            }
            Ok(Self {
                endpoint,
                listener,
                socket_path,
            })
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Queries the live OS kernel DACL SDDL of the bound Windows Named Pipe listener.
    pub fn kernel_dacl_sddl(&self) -> io::Result<String> {
        #[cfg(windows)]
        {
            query_kernel_handle_dacl_sddl(self.next_pipe_handle)
        }
        #[cfg(not(windows))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SDDL inspection applies only to Windows Named Pipes",
            ))
        }
    }

    /// Blocks until a local client connects, verifies OS peer credentials (`GetNamedPipeClientProcessId`
    /// on Windows, `SO_PEERCRED` UID/PID check on Linux), and returns the connected `LocalIpcStream`.
    pub fn accept(&mut self) -> io::Result<(LocalIpcStream, PeerCredentials)> {
        #[cfg(windows)]
        {
            const ERROR_PIPE_CONNECTED: i32 = 535;
            let active_handle = self.next_pipe_handle;
            let connected = unsafe { ConnectNamedPipe(active_handle, core::ptr::null_mut()) };
            if connected == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(ERROR_PIPE_CONNECTED) {
                    // Reset the pipe instance cleanly so transient disconnects (e.g., ERROR_NO_DATA)
                    // never wedge `next_pipe_handle` in a hot spin loop.
                    unsafe {
                        let _ = DisconnectNamedPipe(active_handle);
                    }
                    return Err(err);
                }
            }

            // Immediately create the next listening instance so no squat gap exists.
            // If creating the replacement instance fails, disconnect the already-connected
            // `active_handle` before returning Err so it stays reusable for the next accept.
            let replacement = match create_acl_named_pipe_server_instance(&self.endpoint, false) {
                Ok(h) => h,
                Err(e) => {
                    unsafe {
                        let _ = DisconnectNamedPipe(active_handle);
                    }
                    return Err(e);
                }
            };
            self.next_pipe_handle = replacement;

            let creds = match verify_named_pipe_peer_credentials(active_handle) {
                Ok(c) => c,
                Err(e) => {
                    unsafe {
                        let _ = DisconnectNamedPipe(active_handle);
                        let _ = CloseHandle(active_handle);
                    }
                    return Err(e);
                }
            };

            Ok((
                LocalIpcStream {
                    handle: active_handle,
                    is_server_side: true,
                },
                creds,
            ))
        }
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let (stream, _) = self.listener.accept()?;
            let fd = stream.as_raw_fd();
            #[cfg(target_os = "linux")]
            {
                let mut cred = libc::ucred {
                    pid: 0,
                    uid: u32::MAX,
                    gid: u32::MAX,
                };
                let mut len = core::mem::size_of::<libc::ucred>() as libc::socklen_t;
                let rc = unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_PEERCRED,
                        &mut cred as *mut _ as *mut libc::c_void,
                        &mut len,
                    )
                };
                if rc != 0 || cred.pid <= 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SO_PEERCRED peer verification failed on CDR Unix socket",
                    ));
                }
                let my_euid = unsafe { libc::geteuid() };
                if cred.uid != my_euid && cred.uid != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "Rejected unauthorized Unix socket peer UID {} (expected {} or root)",
                            cred.uid, my_euid
                        ),
                    ));
                }
                let exe_path = std::fs::read_link(format!("/proc/{}/exe", cred.pid))
                    .unwrap_or_else(|_| PathBuf::from("<unknown>"));
                Ok((
                    LocalIpcStream { stream },
                    PeerCredentials {
                        pid: cred.pid as u32,
                        executable_path: exe_path,
                        signature_verified: false,
                    },
                ))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = fd;
                Ok((
                    LocalIpcStream { stream },
                    PeerCredentials {
                        pid: 0,
                        executable_path: PathBuf::from("<unix-peer>"),
                        signature_verified: false,
                    },
                ))
            }
        }
    }
}

impl Drop for LocalIpcServer {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.next_pipe_handle != 0 && self.next_pipe_handle != -1 {
                unsafe {
                    let _ = CloseHandle(self.next_pipe_handle);
                }
                self.next_pipe_handle = 0;
            }
        }
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// Verifies the Authenticode digital signature of an executable using `WinVerifyTrust`
/// (`WINTRUST_ACTION_GENERIC_VERIFY_V2`) on Windows (`Row 28`, Master Plan v2 §3.2.1.b.ii).
/// Locks the binary file handle with `FILE_SHARE_READ` and enforces `WTD_REVOKE_WHOLECHAIN`
/// and `WTD_CACHE_ONLY_URL_RETRIEVAL` to prevent TOCTOU renaming and air-gapped network hangs.
pub fn verify_binary_authenticode_signature(exe_path: &Path) -> io::Result<bool> {
    if !exe_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Binary not found for signature check: {}",
                exe_path.display()
            ),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const WTD_UI_NONE: u32 = 2;
        const WTD_REVOKE_WHOLECHAIN: u32 = 1;
        const WTD_CHOICE_FILE: u32 = 1;
        const WTD_STATEACTION_VERIFY: u32 = 1;
        const WTD_STATEACTION_CLOSE: u32 = 2;
        const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;

        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const OPEN_EXISTING: u32 = 3;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
        const INVALID_HANDLE_VALUE: isize = -1;

        let wide_path: Vec<u16> = exe_path.as_os_str().encode_wide().chain(Some(0)).collect();

        // Lock the binary handle to prevent TOCTOU swap/rename attacks during verification
        let h_file = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };
        if h_file == INVALID_HANDLE_VALUE || h_file == 0 {
            return Err(io::Error::last_os_error());
        }

        let action_guid = Guid {
            data1: 0x00AAC56B,
            data2: 0xCD44,
            data3: 0x11D0,
            data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
        };
        let file_info = WinTrustFileInfo {
            cb_struct: core::mem::size_of::<WinTrustFileInfo>() as u32,
            pcwsz_file_path: wide_path.as_ptr(),
            h_file,
            pg_known_subject: core::ptr::null(),
        };
        let mut wvt_data = WinTrustData {
            cb_struct: core::mem::size_of::<WinTrustData>() as u32,
            p_policy_callback_data: core::ptr::null_mut(),
            p_sip_client_data: core::ptr::null_mut(),
            dw_ui_choice: WTD_UI_NONE,
            fdw_revocation_checks: WTD_REVOKE_WHOLECHAIN,
            dw_union_choice: WTD_CHOICE_FILE,
            p_file: &file_info,
            dw_state_action: WTD_STATEACTION_VERIFY,
            h_vt_state_data: 0,
            pwsz_url_reference: core::ptr::null(),
            dw_prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            dw_ui_context: 0,
            p_signature_settings: core::ptr::null_mut(),
        };

        let status = unsafe { WinVerifyTrust(0, &action_guid, &mut wvt_data) };
        wvt_data.dw_state_action = WTD_STATEACTION_CLOSE;
        unsafe {
            let _ = WinVerifyTrust(0, &action_guid, &mut wvt_data);
            let _ = CloseHandle(h_file);
        }
        Ok(status == 0)
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

/// Queries the peer process ID of a connected Named Pipe client (`GetNamedPipeClientProcessId`
/// on Windows, `SO_PEERCRED` on Linux, `Master Plan v2 §0.2`, Row 28).
pub fn verify_named_pipe_client_pid(pipe_handle: isize) -> io::Result<u32> {
    #[cfg(windows)]
    {
        let mut client_pid: u32 = 0;
        let ok = unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut client_pid) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(client_pid)
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "linux")]
        {
            let fd = pipe_handle as libc::c_int;
            let mut cred = libc::ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut len = core::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            if rc == 0 && cred.pid > 0 {
                return Ok(cred.pid as u32);
            }
            Err(io::Error::last_os_error())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pipe_handle;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Peer PID verification requires Windows Named Pipe or Linux SO_PEERCRED",
            ))
        }
    }
}

/// Resolves the connected Named Pipe client's PID, queries its executable path via
/// `QueryFullProcessImageNameW` (or `/proc/<pid>/exe`), and verifies its Authenticode
/// signature via `WinVerifyTrust` (`Row 28`, Master Plan v2 §3.2.1.b.ii).
pub fn verify_named_pipe_peer_credentials(pipe_handle: isize) -> io::Result<PeerCredentials> {
    let pid = verify_named_pipe_client_pid(pipe_handle)?;
    #[cfg(windows)]
    {
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const WAIT_TIMEOUT: u32 = 0x0000_0102;

        let h_proc =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
        if h_proc == 0 {
            return Err(io::Error::last_os_error());
        }

        // Verify that the peer process is still active and alive (blocks PID-reuse TOCTOU)
        let wait_res = unsafe { WaitForSingleObject(h_proc, 0) };
        if wait_res != WAIT_TIMEOUT {
            unsafe {
                let _ = CloseHandle(h_proc);
            }
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Named Pipe client process terminated or PID was reused before verification",
            ));
        }

        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(h_proc, 0, buf.as_mut_ptr(), &mut size) };
        unsafe {
            let _ = CloseHandle(h_proc);
        }
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let exe_path = PathBuf::from(String::from_utf16_lossy(&buf[..size as usize]));
        let signature_verified = verify_binary_authenticode_signature(&exe_path).unwrap_or(false);
        Ok(PeerCredentials {
            pid,
            executable_path: exe_path,
            signature_verified,
        })
    }
    #[cfg(target_os = "linux")]
    {
        let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))?;
        Ok(PeerCredentials {
            pid,
            executable_path: exe_path,
            signature_verified: false,
        })
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = pid;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Peer credential verification unsupported on this OS",
        ))
    }
}
