//! Windows Service Control Manager (SCM) entrypoint (`StartServiceCtrlDispatcherW`)
//! for `sentinel-agent --service` (`CSE-26`).

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Canonical Windows Service Name registered with Windows Service Control Manager (`CSE-26`).
pub const SENTINEL_WINDOWS_SERVICE_NAME: &str = "OmniConnectSentinel";

pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
pub const SERVICE_STOPPED: u32 = 0x0000_0001;
pub const SERVICE_START_PENDING: u32 = 0x0000_0002;
pub const SERVICE_STOP_PENDING: u32 = 0x0000_0003;
pub const SERVICE_RUNNING: u32 = 0x0000_0004;
pub const SERVICE_ACCEPT_STOP: u32 = 0x0000_0001;
pub const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x0000_0004;

pub const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
pub const SERVICE_CONTROL_INTERROGATE: u32 = 0x0000_0004;
pub const SERVICE_CONTROL_SHUTDOWN: u32 = 0x0000_0005;

pub const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;

/// Pure-Rust representation of a Win32 `SERVICE_STATUS` report for deterministic verification (`CSE-26`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScmServiceStatusSnapshot {
    pub service_type: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub check_point: u32,
    pub wait_hint_ms: u32,
}

/// Returns `true` when an SCM control code commands graceful daemon termination (`CSE-26`).
pub fn scm_control_triggers_shutdown(control_code: u32) -> bool {
    matches!(
        control_code,
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN
    )
}

/// Builds a canonical Win32 `SERVICE_STATUS` transition snapshot for `START_PENDING`, `RUNNING`,
/// `STOP_PENDING`, or `STOPPED` (`CSE-26`).
pub fn build_scm_status(
    current_state: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint_ms: u32,
) -> ScmServiceStatusSnapshot {
    let controls_accepted = if current_state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else {
        0
    };
    ScmServiceStatusSnapshot {
        service_type: SERVICE_WIN32_OWN_PROCESS,
        current_state,
        controls_accepted,
        win32_exit_code,
        service_specific_exit_code,
        check_point,
        wait_hint_ms,
    }
}

#[cfg(windows)]
mod win_scm {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicIsize, Ordering};
    use std::sync::{Mutex, OnceLock};

    const NO_ERROR: u32 = 0;
    const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
    const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

    type ServiceMainFn = unsafe extern "system" fn(u32, *mut *mut u16);
    type HandlerExFn =
        unsafe extern "system" fn(u32, u32, *mut core::ffi::c_void, *mut core::ffi::c_void) -> u32;

    #[repr(C)]
    struct ServiceTableEntryW {
        lp_service_name: *const u16,
        lp_service_proc: Option<ServiceMainFn>,
    }

    #[repr(C)]
    struct RawWin32ServiceStatus {
        dw_service_type: u32,
        dw_current_state: u32,
        dw_controls_accepted: u32,
        dw_win32_exit_code: u32,
        dw_service_specific_exit_code: u32,
        dw_check_point: u32,
        dw_wait_hint: u32,
    }

    impl From<ScmServiceStatusSnapshot> for RawWin32ServiceStatus {
        fn from(s: ScmServiceStatusSnapshot) -> Self {
            Self {
                dw_service_type: s.service_type,
                dw_current_state: s.current_state,
                dw_controls_accepted: s.controls_accepted,
                dw_win32_exit_code: s.win32_exit_code,
                dw_service_specific_exit_code: s.service_specific_exit_code,
                dw_check_point: s.check_point,
                dw_wait_hint: s.wait_hint_ms,
            }
        }
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn StartServiceCtrlDispatcherW(lpServiceStartTable: *const ServiceTableEntryW) -> i32;
        fn RegisterServiceCtrlHandlerExW(
            lpServiceName: *const u16,
            lpHandlerProc: Option<HandlerExFn>,
            lpContext: *mut core::ffi::c_void,
        ) -> isize;
        fn SetServiceStatus(
            hServiceStatus: isize,
            lpServiceStatus: *const RawWin32ServiceStatus,
        ) -> i32;
    }

    type ServiceBodyFn = Box<dyn FnOnce(Arc<AtomicBool>) -> io::Result<()> + Send + 'static>;

    struct ScmRuntimeHandoff {
        service_name_wide: Vec<u16>,
        shutdown_flag: Arc<AtomicBool>,
        body: Option<ServiceBodyFn>,
        body_result: Option<io::Result<()>>,
    }

    static SCM_HANDOFF: OnceLock<Mutex<Option<ScmRuntimeHandoff>>> = OnceLock::new();
    static SCM_STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

    fn report_status(handle: isize, snap: ScmServiceStatusSnapshot) {
        if handle != 0 {
            let raw = RawWin32ServiceStatus::from(snap);
            unsafe {
                let _ = SetServiceStatus(handle, &raw);
            }
        }
    }

    unsafe extern "system" fn service_ctrl_handler(
        dw_control: u32,
        _dw_event_type: u32,
        _lp_event_data: *mut core::ffi::c_void,
        _lp_context: *mut core::ffi::c_void,
    ) -> u32 {
        let status_handle = SCM_STATUS_HANDLE.load(Ordering::Acquire);
        if scm_control_triggers_shutdown(dw_control) {
            report_status(
                status_handle,
                build_scm_status(SERVICE_STOP_PENDING, 0, 0, 1, 10_000),
            );
            if let Some(lock) = SCM_HANDOFF.get() {
                if let Ok(guard) = lock.lock() {
                    if let Some(ref handoff) = *guard {
                        handoff.shutdown_flag.store(true, Ordering::Release);
                    }
                }
            }
            return NO_ERROR;
        }
        if dw_control == SERVICE_CONTROL_INTERROGATE {
            return NO_ERROR;
        }
        ERROR_CALL_NOT_IMPLEMENTED
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let (service_name_wide, shutdown_flag, body_opt) = {
            let Some(lock) = SCM_HANDOFF.get() else {
                return;
            };
            let Ok(mut guard) = lock.lock() else {
                return;
            };
            let Some(ref mut handoff) = *guard else {
                return;
            };
            (
                handoff.service_name_wide.clone(),
                handoff.shutdown_flag.clone(),
                handoff.body.take(),
            )
        };

        let status_handle = RegisterServiceCtrlHandlerExW(
            service_name_wide.as_ptr(),
            Some(service_ctrl_handler),
            core::ptr::null_mut(),
        );
        if status_handle == 0 {
            return;
        }
        SCM_STATUS_HANDLE.store(status_handle, Ordering::Release);

        report_status(
            status_handle,
            build_scm_status(SERVICE_START_PENDING, 0, 0, 1, 10_000),
        );
        report_status(status_handle, build_scm_status(SERVICE_RUNNING, 0, 0, 0, 0));

        let run_result = match body_opt {
            Some(body) => body(shutdown_flag),
            None => Err(io::Error::other("Windows SCM service body missing")),
        };

        let (win32_code, specific_code) = match &run_result {
            Ok(()) => (0, 0),
            Err(_) => (ERROR_SERVICE_SPECIFIC_ERROR, 1),
        };

        if let Some(lock) = SCM_HANDOFF.get() {
            if let Ok(mut guard) = lock.lock() {
                if let Some(ref mut handoff) = *guard {
                    handoff.body_result = Some(run_result);
                }
            }
        }

        report_status(
            status_handle,
            build_scm_status(SERVICE_STOPPED, win32_code, specific_code, 0, 0),
        );
        SCM_STATUS_HANDLE.store(0, Ordering::Release);
    }

    pub fn dispatch_windows_service<F>(service_name: &str, service_body: F) -> io::Result<()>
    where
        F: FnOnce(Arc<AtomicBool>) -> io::Result<()> + Send + 'static,
    {
        let trimmed = service_name.trim();
        if trimmed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows SCM service name must not be empty",
            ));
        }

        let wide_name: Vec<u16> = std::ffi::OsStr::new(trimmed)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let lock = SCM_HANDOFF.get_or_init(|| Mutex::new(None));
        {
            let mut guard = lock.lock().map_err(|_| {
                io::Error::other("Windows SCM service dispatcher state lock poisoned")
            })?;
            *guard = Some(ScmRuntimeHandoff {
                service_name_wide: wide_name.clone(),
                shutdown_flag: Arc::new(AtomicBool::new(false)),
                body: Some(Box::new(service_body)),
                body_result: None,
            });
        }

        let table = [
            ServiceTableEntryW {
                lp_service_name: wide_name.as_ptr(),
                lp_service_proc: Some(service_main),
            },
            ServiceTableEntryW {
                lp_service_name: core::ptr::null(),
                lp_service_proc: None,
            },
        ];

        let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        let body_res = lock
            .lock()
            .ok()
            .and_then(|mut g| g.take())
            .and_then(|h| h.body_result);

        if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "StartServiceCtrlDispatcherW failed (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT=1063): \
                         --service must be launched by Windows Service Control Manager (services.exe) for service '{trimmed}'"
                    ),
                ));
            }
            return Err(err);
        }

        body_res.unwrap_or(Ok(()))
    }
}

/// Connects the current process to the Windows Service Control Manager via
/// `StartServiceCtrlDispatcherW`, reporting `SERVICE_START_PENDING` -> `SERVICE_RUNNING` ->
/// `SERVICE_STOP_PENDING` -> `SERVICE_STOPPED` and signaling `shutdown_flag` on `SERVICE_CONTROL_STOP`
/// or `SERVICE_CONTROL_SHUTDOWN` (`CSE-26`).
pub fn run_windows_service<F>(service_name: &str, service_body: F) -> io::Result<()>
where
    F: FnOnce(Arc<AtomicBool>) -> io::Result<()> + Send + 'static,
{
    #[cfg(windows)]
    {
        win_scm::dispatch_windows_service(service_name, service_body)
    }
    #[cfg(not(windows))]
    {
        let _ = (service_name, service_body);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows SCM --service mode is only supported on Windows; run sentinel-agent under systemd on Linux",
        ))
    }
}
