use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use tracing::{debug, info};

/// Exact `mountmgr.h` & `winioctl.h` IOCTL control codes:
/// - `IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT = CTL_CODE(0x6D, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)` = `0x006D003C`
/// - `IOCTL_MOUNTMGR_SET_AUTO_MOUNT   = CTL_CODE(0x6D, 16, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)` = `0x006DC040`
pub const IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT: u32 = 0x006D003C;
pub const IOCTL_MOUNTMGR_SET_AUTO_MOUNT: u32 = 0x006DC040;
pub const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x00560000;
pub const IOCTL_VOLUME_ONLINE: u32 = 0x0056C008;
pub const IOCTL_VOLUME_OFFLINE: u32 = 0x0056C00C;
pub const IOCTL_VOLUME_IS_OFFLINE: u32 = 0x00560010;
pub const IOCTL_DISK_GET_DISK_ATTRIBUTES: u32 = 0x000700F0;
pub const IOCTL_DISK_SET_DISK_ATTRIBUTES: u32 = 0x0007C0F4;
pub const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;
pub const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D1080;
pub const BUS_TYPE_USB: u32 = 0x07;
/// Linux kernel block-device read-only ioctl (`_IO(0x12, 93)` from `<linux/fs.h>`) (`CSE-25`).
pub const LINUX_BLKROSET_IOCTL: u64 = 0x125D;
/// Linux systemd-udevd class-scoped USB storage policy rules path (`CSE-25`).
pub const LINUX_UDEV_RULES_PATH: &str = "/etc/udev/rules.d/99-omniconnect-sentinel.rules";
/// Maximum PnP/sysfs parent hops walked during volume-to-USB topology attribution (`CSE-24`).
pub const MAX_USB_TOPOLOGY_HOPS: usize = 12;

/// Class-scoped Windows Device Installation Restriction hardware/compatible IDs (`CSE-24`).
/// Blocks ONLY USB Mass Storage (`USBSTOR`, `USB\Class_08`) and Windows Portable Devices (`WPD`, MTP)
/// so USB-C docks, webcams, YubiKeys, headsets, and HMI touchscreens are never disrupted.
pub const SCOPED_STORAGE_DENY_DEVICE_IDS: &[&str] =
    &[r"USBSTOR\*", r"USB\Class_08", r"WPD\*", r"USB\MS_COMP_MTP"];
/// Windows Device Setup Class GUID for Windows Portable Devices (WPD / MTP / PTP).
pub const WPD_DEVICE_SETUP_CLASS_GUID: &str = "{eec5ad98-8080-425f-922a-dabf3de3f69a}";
/// Class-scoped Windows Device Setup Class GUIDs denied under `DeviceInstall\Restrictions\DenyDeviceClasses`.
pub const SCOPED_STORAGE_DENY_CLASS_GUIDS: &[&str] = &[WPD_DEVICE_SETUP_CLASS_GUID];
/// Windows `RemovableStorageDevices` policy class GUIDs (Removable Disks + WPD Devices).
pub const REMOVABLE_STORAGE_POLICY_CLASS_GUIDS: &[&str] = &[
    "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}", // Removable Disks
    "{6AC27878-A6FA-4155-BA85-F98F491D4F33}", // WPD Devices
    "{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}", // WPD Devices (secondary)
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbTopologyAttribution {
    pub instance_id: String,
    pub vid: u16,
    pub pid: u16,
    pub serial: String,
    pub device_desc: Option<String>,
    pub hops: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedStorageInstallPolicySpec {
    pub deny_unspecified: bool,
    pub deny_device_ids: Vec<String>,
    pub deny_device_class_guids: Vec<String>,
    pub removable_storage_class_guids: Vec<String>,
    pub allow_device_ids: Vec<String>,
}

/// Constructs the deterministic class-scoped Windows storage restriction policy (`CSE-24`):
/// explicitly sets `deny_unspecified = false` so non-storage USB peripherals (docks, webcams,
/// YubiKeys, headsets, HMI touchscreens) remain operational while scoping install/access blocks
/// strictly to `USBSTOR` / `USB\Class_08` / `WPD` classes and allowing `allowed_hardware_ids`.
pub fn build_windows_scoped_storage_install_policy(
    allowed_hardware_ids: &[String],
) -> ScopedStorageInstallPolicySpec {
    ScopedStorageInstallPolicySpec {
        deny_unspecified: false,
        deny_device_ids: SCOPED_STORAGE_DENY_DEVICE_IDS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        deny_device_class_guids: SCOPED_STORAGE_DENY_CLASS_GUIDS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        removable_storage_class_guids: REMOVABLE_STORAGE_POLICY_CLASS_GUIDS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        allow_device_ids: allowed_hardware_ids
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    }
}

/// Evaluates whether the live Windows `DeviceInstall\Restrictions` toggles AND subkey lists
/// genuinely enforce class-scoped `USBSTOR`/`WPD` restrictions without global `DenyUnspecified=1`
/// (eliminating false-positive posture compliance when toggles are `1` but subkeys are empty) (`CSE-24`).
pub fn verify_scoped_storage_registry_lists(
    deny_unspecified: bool,
    deny_device_ids_enabled: bool,
    deny_device_classes_enabled: bool,
    deny_device_ids_values: &[String],
    deny_device_classes_values: &[String],
) -> bool {
    if deny_unspecified || !deny_device_ids_enabled || !deny_device_classes_enabled {
        return false;
    }
    let all_ids_present = SCOPED_STORAGE_DENY_DEVICE_IDS.iter().all(|req| {
        deny_device_ids_values
            .iter()
            .any(|v| v.trim().eq_ignore_ascii_case(req))
    });
    let all_classes_present = SCOPED_STORAGE_DENY_CLASS_GUIDS.iter().all(|req| {
        deny_device_classes_values
            .iter()
            .any(|v| v.trim().eq_ignore_ascii_case(req))
    });
    all_ids_present && all_classes_present
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbVolumeInfo {
    pub volume_guid_path: String,
    pub mount_points: Vec<PathBuf>,
    pub physical_drive_number: Option<u32>,
    pub bus_type: u32,
    pub is_removable_media: bool,
    pub is_offline: bool,
    pub is_readonly: bool,
    #[serde(default)]
    pub usb_device_instance_id: Option<String>,
    #[serde(default)]
    pub usb_device_desc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbPnpDeviceInfo {
    pub instance_id: String,
    pub vid: u16,
    pub pid: u16,
    pub serial: String,
    pub interface_classes: Vec<u8>,
    pub child_instance_ids: Vec<String>,
    pub has_mass_storage: bool,
    pub has_hid_input: bool,
    pub is_composite_hid_storage: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtpSyncStatus {
    pub ntp_synchronized: bool,
    pub clock_source: String,
    pub stratum: Option<u8>,
    pub max_error_us: Option<u64>,
}

/// Environment variable specifying the physical Bay-1 (Read-Only Intake) hardware write-blocker
/// volume GUID, USB instance ID, or mount point for Pivot A OT Kiosk stations (`CSE-27`).
pub const SENTINEL_KIOSK_BAY1_RO_DEVICE_ENV: &str = "SENTINEL_KIOSK_BAY1_RO_DEVICE";

/// Environment variable specifying the physical Bay-2 (Read-Write Sanitized Export) device
/// volume GUID, USB instance ID, or mount point for Pivot A OT Kiosk stations (`CSE-27`).
pub const SENTINEL_KIOSK_BAY2_RW_DEVICE_ENV: &str = "SENTINEL_KIOSK_BAY2_RW_DEVICE";

/// Physical dual-bay hardware write-blocker telemetry state for Pivot A OT Kiosk deployments (`CSE-27`).
///
/// Defaults honestly to `NotDetected` unless physical Bay-1 (RO intake) and optional Bay-2 (RW export)
/// states are verified against enumerated USB volumes. A `Faulted` state (e.g., Bay-1 intake volume
/// reporting writable or Bay-1/Bay-2 colliding on the same device) fails `PostureReport::is_compliant()`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HardwareWriteBlockerState {
    #[default]
    NotDetected,
    Bay1RoOnly {
        bay1_device: String,
        bay1_readonly_verified: bool,
    },
    DualBayVerified {
        bay1_ro_device: String,
        bay2_rw_device: String,
    },
    Faulted {
        reason: String,
    },
}

fn volume_matches_bay_hint(vol: &UsbVolumeInfo, hint: &str) -> bool {
    let trimmed = hint.trim();
    if trimmed.is_empty() {
        return false;
    }
    if vol.volume_guid_path.eq_ignore_ascii_case(trimmed) {
        return true;
    }
    if vol
        .usb_device_instance_id
        .as_deref()
        .is_some_and(|id| id.eq_ignore_ascii_case(trimmed))
    {
        return true;
    }
    vol.mount_points
        .iter()
        .any(|mp| mp.to_string_lossy().eq_ignore_ascii_case(trimmed))
}

/// Evaluates physical Bay-1 RO / Bay-2 RW hardware write-blocker state against enumerated USB
/// volumes (`CSE-27`). Defaults honestly to `NotDetected` when no bay hints are configured or
/// attached; returns `Faulted` if Bay-1 is writable, Bay-2 is read-only, or both bays alias.
pub fn detect_hardware_write_blocker_state(
    bay1_hint: Option<&str>,
    bay2_hint: Option<&str>,
    volumes: &[UsbVolumeInfo],
) -> HardwareWriteBlockerState {
    let Some(b1) = bay1_hint.map(str::trim).filter(|s| !s.is_empty()) else {
        return HardwareWriteBlockerState::NotDetected;
    };
    let Some(vol1) = volumes.iter().find(|v| volume_matches_bay_hint(v, b1)) else {
        return HardwareWriteBlockerState::NotDetected;
    };
    if !vol1.is_readonly {
        return HardwareWriteBlockerState::Faulted {
            reason: format!(
                "Bay-1 intake device '{}' is writable (hardware write-blocker disengaged or bypassed)",
                vol1.volume_guid_path
            ),
        };
    }

    if let Some(b2) = bay2_hint.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(vol2) = volumes.iter().find(|v| volume_matches_bay_hint(v, b2)) {
            if vol2
                .volume_guid_path
                .eq_ignore_ascii_case(&vol1.volume_guid_path)
            {
                return HardwareWriteBlockerState::Faulted {
                    reason: format!(
                        "Bay-1 RO and Bay-2 RW hints resolved to identical physical volume '{}'",
                        vol1.volume_guid_path
                    ),
                };
            }
            if vol2.is_readonly {
                return HardwareWriteBlockerState::Faulted {
                    reason: format!(
                        "Bay-2 export device '{}' is read-only (expected writable clean export media)",
                        vol2.volume_guid_path
                    ),
                };
            }
            return HardwareWriteBlockerState::DualBayVerified {
                bay1_ro_device: vol1.volume_guid_path.clone(),
                bay2_rw_device: vol2.volume_guid_path.clone(),
            };
        }
    }

    HardwareWriteBlockerState::Bay1RoOnly {
        bay1_device: vol1.volume_guid_path.clone(),
        bay1_readonly_verified: true,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReport {
    pub automount_disabled: bool,
    pub removable_volumes_offline: Vec<(String, bool)>,
    pub user_deny_policy_present: bool,
    pub install_restrictions_active: bool,
    pub write_protect_active: bool,
    pub autoplay_suppressed: bool,
    pub linux_authorized_default_zero: Option<bool>,
    #[serde(default)]
    pub hardware_write_blocker: HardwareWriteBlockerState,
}

impl PostureReport {
    /// Strict fail-closed compliance evaluation for Linux hosts (`CSE-25`, `CSE-27`): requires USB
    /// automount suppression (`authorized_default=0`), active `/etc/udev/rules.d/99-omniconnect-sentinel.rules`
    /// storage/block policy (`user_deny_policy_present && install_restrictions_active`), all
    /// enumerated removable/USB volumes offline, and no faulted hardware write-blocker.
    pub fn is_compliant_for_linux(&self) -> bool {
        let all_volumes_offline = self
            .removable_volumes_offline
            .iter()
            .all(|(_, offline)| *offline);
        let hw_wb_ok = !matches!(
            self.hardware_write_blocker,
            HardwareWriteBlockerState::Faulted { .. }
        );
        self.automount_disabled
            && self.linux_authorized_default_zero == Some(true)
            && self.user_deny_policy_present
            && self.install_restrictions_active
            && all_volumes_offline
            && hw_wb_ok
    }

    /// Strict fail-closed compliance evaluation (`Master Plan v2 §0.1`, Row 21, `CSE-24`, `CSE-25`, `CSE-27`):
    /// Requires every OS control field to hold (`automount_disabled`, `user_deny_policy_present`,
    /// `install_restrictions_active`, `write_protect_active`, `autoplay_suppressed`, every
    /// enumerated USB/removable volume GUID offline, and no faulted hardware write-blocker).
    pub fn is_compliant(&self) -> bool {
        let all_volumes_offline = self
            .removable_volumes_offline
            .iter()
            .all(|(_, offline)| *offline);
        let hw_wb_ok = !matches!(
            self.hardware_write_blocker,
            HardwareWriteBlockerState::Faulted { .. }
        );

        #[cfg(windows)]
        {
            self.automount_disabled
                && self.user_deny_policy_present
                && self.install_restrictions_active
                && self.write_protect_active
                && self.autoplay_suppressed
                && all_volumes_offline
                && hw_wb_ok
        }
        #[cfg(not(windows))]
        {
            let _ = (all_volumes_offline, hw_wb_ok);
            self.is_compliant_for_linux()
        }
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetLogicalDrives() -> u32;
    fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;
    fn DeleteVolumeMountPointW(lpszVolumeMountPoint: *const u16) -> i32;
    fn FindFirstVolumeW(lpszVolumeName: *mut u16, cchBufferLength: u32) -> isize;
    fn FindNextVolumeW(hFindVolume: isize, lpszVolumeName: *mut u16, cchBufferLength: u32) -> i32;
    fn FindVolumeClose(hFindVolume: isize) -> i32;
    fn GetVolumePathNamesForVolumeNameW(
        lpszVolumeName: *const u16,
        lpszVolumePathNames: *mut u16,
        cchBufferLength: u32,
        lpcchReturnLength: *mut u32,
    ) -> i32;
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const core::ffi::c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: isize,
    ) -> isize;
    fn DeviceIoControl(
        hDevice: isize,
        dwIoControlCode: u32,
        lpInBuffer: *const core::ffi::c_void,
        nInBufferSize: u32,
        lpOutBuffer: *mut core::ffi::c_void,
        nOutBufferSize: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn CloseHandle(hObject: isize) -> i32;
    fn GetSystemTimeAdjustment(
        lpTimeAdjustment: *mut u32,
        lpTimeIncrement: *mut u32,
        lpTimeAdjustmentDisabled: *mut i32,
    ) -> i32;
    fn GetTimeZoneInformation(lpTimeZoneInformation: *mut Win32TimeZoneInformation) -> u32;
}

#[cfg(windows)]
#[repr(C)]
struct Win32SystemTime {
    w_year: u16,
    w_month: u16,
    w_day_of_week: u16,
    w_day: u16,
    w_hour: u16,
    w_minute: u16,
    w_second: u16,
    w_milliseconds: u16,
}

#[cfg(windows)]
#[repr(C)]
struct Win32TimeZoneInformation {
    bias: i32,
    standard_name: [u16; 32],
    standard_date: Win32SystemTime,
    standard_bias: i32,
    daylight_name: [u16; 32],
    daylight_date: Win32SystemTime,
    daylight_bias: i32,
}

#[cfg(windows)]
#[repr(C)]
struct Win32ServiceStatus {
    dw_service_type: u32,
    dw_current_state: u32,
    dw_controls_accepted: u32,
    dw_win32_exit_code: u32,
    dw_service_specific_exit_code: u32,
    dw_check_point: u32,
    dw_wait_hint: u32,
}

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn RegGetValueW(
        hkey: isize,
        lpSubKey: *const u16,
        lpValue: *const u16,
        dwFlags: u32,
        pdwType: *mut u32,
        pvData: *mut core::ffi::c_void,
        pcbData: *mut u32,
    ) -> i32;
    fn RegSetKeyValueW(
        hKey: isize,
        lpSubKey: *const u16,
        lpValueName: *const u16,
        dwType: u32,
        lpData: *const core::ffi::c_void,
        cbData: u32,
    ) -> i32;
    fn RegDeleteKeyValueW(hKey: isize, lpSubKey: *const u16, lpValueName: *const u16) -> i32;
    fn RegDeleteTreeW(hKey: isize, lpSubKey: *const u16) -> i32;
    fn RegOpenKeyExW(
        hKey: isize,
        lpSubKey: *const u16,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut isize,
    ) -> i32;
    fn RegEnumValueW(
        hKey: isize,
        dwIndex: u32,
        lpValueName: *mut u16,
        lpcchValueName: *mut u32,
        lpReserved: *mut u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> i32;
    fn RegCloseKey(hKey: isize) -> i32;
    fn OpenSCManagerW(
        lpMachineName: *const u16,
        lpDatabaseName: *const u16,
        dwDesiredAccess: u32,
    ) -> isize;
    fn OpenServiceW(hSCManager: isize, lpServiceName: *const u16, dwDesiredAccess: u32) -> isize;
    fn QueryServiceStatus(hService: isize, lpServiceStatus: *mut Win32ServiceStatus) -> i32;
    fn CloseServiceHandle(hSCObject: isize) -> i32;
}

#[cfg(windows)]
#[link(name = "cfgmgr32")]
extern "system" {
    fn CM_Locate_DevNodeW(pdnDevInst: *mut u32, pDeviceID: *const u16, ulFlags: u32) -> u32;
    fn CM_Disable_DevNode(dnDevInst: u32, ulFlags: u32) -> u32;
    fn CM_Enable_DevNode(dnDevInst: u32, ulFlags: u32) -> u32;
    fn CM_Get_Parent(pdnDevInst: *mut u32, dnDevInst: u32, ulFlags: u32) -> u32;
    fn CM_Get_Device_ID_Size(pulLen: *mut u32, dnDevInst: u32, ulFlags: u32) -> u32;
    fn CM_Get_Device_IDW(dnDevInst: u32, Buffer: *mut u16, BufferLen: u32, ulFlags: u32) -> u32;
    fn CM_Get_Device_ID_List_SizeW(pulLen: *mut u32, pszFilter: *const u16, ulFlags: u32) -> u32;
    fn CM_Get_Device_ID_ListW(
        pszFilter: *const u16,
        Buffer: *mut u16,
        BufferLen: u32,
        ulFlags: u32,
    ) -> u32;
    fn CM_Get_DevNode_Registry_PropertyW(
        dnDevInst: u32,
        ulProperty: u32,
        pulRegDataType: *mut u32,
        Buffer: *mut core::ffi::c_void,
        pulLength: *mut u32,
        ulFlags: u32,
    ) -> u32;
    fn CM_Register_Notification(
        pFilter: *const CmNotifyFilter,
        pContext: *mut core::ffi::c_void,
        pCallback: unsafe extern "system" fn(
            h_notify: isize,
            context: *mut core::ffi::c_void,
            action: u32,
            event_data: *const core::ffi::c_void,
            event_data_size: u32,
        ) -> u32,
        pNotifyContext: *mut isize,
    ) -> u32;
    fn CM_Unregister_Notification(hNotify: isize) -> u32;
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct WinGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(windows)]
#[repr(C)]
struct SpDeviceInterfaceData {
    cb_size: u32,
    interface_class_guid: WinGuid,
    flags: u32,
    reserved: usize,
}

#[cfg(windows)]
#[repr(C)]
struct SpDevinfoData {
    cb_size: u32,
    class_guid: WinGuid,
    dev_inst: u32,
    reserved: usize,
}

#[cfg(windows)]
#[repr(C)]
struct StorageDeviceNumber {
    device_type: u32,
    device_number: u32,
    partition_number: u32,
}

#[cfg(windows)]
#[link(name = "setupapi")]
extern "system" {
    fn SetupDiGetClassDevsW(
        class_guid: *const WinGuid,
        enumerator: *const u16,
        hwnd_parent: isize,
        flags: u32,
    ) -> isize;
    fn SetupDiEnumDeviceInterfaces(
        device_info_set: isize,
        device_info_data: *const SpDevinfoData,
        interface_class_guid: *const WinGuid,
        member_index: u32,
        device_interface_data: *mut SpDeviceInterfaceData,
    ) -> i32;
    fn SetupDiGetDeviceInterfaceDetailW(
        device_info_set: isize,
        device_interface_data: *const SpDeviceInterfaceData,
        device_interface_detail_data: *mut core::ffi::c_void,
        device_interface_detail_data_size: u32,
        required_size: *mut u32,
        device_info_data: *mut SpDevinfoData,
    ) -> i32;
    fn SetupDiGetDeviceRegistryPropertyW(
        device_info_set: isize,
        device_info_data: *const SpDevinfoData,
        property: u32,
        property_reg_data_type: *mut u32,
        property_buffer: *mut u8,
        property_buffer_size: u32,
        required_size: *mut u32,
    ) -> i32;
    fn SetupDiDestroyDeviceInfoList(device_info_set: isize) -> i32;
}

#[cfg(windows)]
#[repr(C)]
pub struct CmNotifyFilter {
    pub cb_size: u32,
    pub flags: u32,
    pub filter_type: u32,
    pub reserved: u32,
    pub u_data: [u8; 400],
}

#[cfg(windows)]
const HKEY_CURRENT_USER: isize = -2147483647i32 as isize; // 0x80000001
#[cfg(windows)]
const HKEY_LOCAL_MACHINE: isize = -2147483646i32 as isize; // 0x80000002
#[cfg(windows)]
const RRF_RT_REG_DWORD: u32 = 0x00000010;
#[cfg(windows)]
const RRF_RT_REG_SZ: u32 = 0x00000002;
#[cfg(windows)]
const REG_SZ: u32 = 1;
#[cfg(windows)]
const REG_DWORD: u32 = 4;

#[cfg(windows)]
#[repr(C)]
struct StoragePropertyQuery {
    property_id: u32,
    query_type: u32,
    additional_parameters: [u8; 4],
}

#[cfg(windows)]
#[repr(C)]
struct StorageDeviceDescriptorHeader {
    version: u32,
    size: u32,
    device_type: u8,
    device_type_modifier: u8,
    removable_media: u8,
    command_queueing: u8,
    vendor_id_offset: u32,
    product_id_offset: u32,
    product_revision_offset: u32,
    serial_number_offset: u32,
    bus_type: u32,
}

#[cfg(windows)]
#[repr(C)]
struct DiskExtent {
    disk_number: u32,
    starting_offset: i64,
    extent_length: i64,
}

#[cfg(windows)]
#[repr(C)]
struct VolumeDiskExtents {
    number_of_disk_extents: u32,
    extents: [DiskExtent; 1],
}

/// Parses a Windows USB PnP instance ID (`USB\VID_xxxx&PID_yyyy\<serial>`) into `(vid, pid, serial)` (`CSE-24`).
pub fn parse_windows_usb_vid_pid_serial(instance_id: &str) -> Option<(u16, u16, String)> {
    let upper = instance_id.to_ascii_uppercase();
    let vid_pos = upper.find("VID_")?;
    let pid_pos = upper.find("PID_")?;
    let vid_hex = upper.get(vid_pos + 4..vid_pos + 8)?;
    let pid_hex = upper.get(pid_pos + 4..pid_pos + 8)?;
    let vid = u16::from_str_radix(vid_hex, 16).ok()?;
    let pid = u16::from_str_radix(pid_hex, 16).ok()?;
    let serial = instance_id
        .rsplit('\\')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("UNKNOWN")
        .to_string();
    Some((vid, pid, serial))
}

/// Validates a canonical Linux sysfs USB bus-port identifier matching `^[0-9]+-[0-9]+(\.[0-9]+)*$`
/// (e.g. `1-2`, `1-2.3`, `2-1.4.2`), rejecting root hubs (`usb1`), interface nodes (`1-2:1.0`),
/// Windows `USB\VID_...` strings, and path-traversal tokens (`CSE-24`, `CSE-25`).
pub fn is_valid_linux_usb_bus_port(candidate: &str) -> bool {
    let Some((bus, ports)) = candidate.split_once('-') else {
        return false;
    };
    if bus.is_empty() || !bus.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if ports.is_empty() {
        return false;
    }
    ports
        .split('.')
        .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()))
}

/// Validates a canonical Linux sysfs USB interface identifier matching
/// `^[0-9]+-[0-9]+(\.[0-9]+)*:[0-9]+\.[0-9]+$` (e.g. `1-2.3:1.0`) (`CSE-25`).
pub fn is_valid_linux_usb_interface_id(candidate: &str) -> bool {
    let Some((bus_port, cfg_intf)) = candidate.split_once(':') else {
        return false;
    };
    if !is_valid_linux_usb_bus_port(bus_port) {
        return false;
    }
    let Some((cfg, intf)) = cfg_intf.split_once('.') else {
        return false;
    };
    !cfg.is_empty()
        && !intf.is_empty()
        && cfg.bytes().all(|b| b.is_ascii_digit())
        && intf.bytes().all(|b| b.is_ascii_digit())
}

/// Validates a Linux USB sysfs node ID and returns its exact `/sys/bus/usb/devices/<id>/authorized`
/// path, failing closed with `InvalidInput` on Windows `USB\VID_...` strings, path traversal (`..`),
/// or malformed tokens (`CSE-25`).
pub fn resolve_linux_usb_authorized_sysfs_path(
    device_id: &str,
    allow_interface: bool,
) -> io::Result<PathBuf> {
    let trimmed = device_id.trim();
    let valid = is_valid_linux_usb_bus_port(trimmed)
        || (allow_interface && is_valid_linux_usb_interface_id(trimmed));
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Invalid Linux sysfs USB bus-port identifier '{trimmed}': expected ^[0-9]+-[0-9]+(\\.[0-9]+)*${}",
                if allow_interface { " (or :<cfg>.<intf>)" } else { "" }
            ),
        ));
    }
    Ok(PathBuf::from(format!(
        "/sys/bus/usb/devices/{trimmed}/authorized"
    )))
}

/// Collects all active Linux mount points from `/proc/mounts` backed by `volume_path` (either a
/// block device node `/dev/sdX` / `/dev/sdX1` or a mounted directory), sorted deepest-path first
/// so nested mounts can be detached cleanly via `umount2(MNT_DETACH)` (`CSE-25`).
pub fn collect_linux_mount_points_for_target(
    volume_path: &Path,
    proc_mounts: &str,
) -> Vec<PathBuf> {
    let raw = volume_path.to_string_lossy();
    let norm = if raw == "/" {
        "/"
    } else {
        raw.trim_end_matches('/')
    };
    if norm.is_empty() {
        return Vec::new();
    }
    let mut mounts = Vec::new();
    for line in proc_mounts.lines() {
        let mut parts = line.split_whitespace();
        let Some(raw_dev) = parts.next() else {
            continue;
        };
        let Some(raw_mnt) = parts.next() else {
            continue;
        };
        let dev = unescape_proc_mounts_field(raw_dev);
        let mnt_unescaped = unescape_proc_mounts_field(raw_mnt);
        let mnt = if mnt_unescaped == "/" {
            "/"
        } else {
            mnt_unescaped.trim_end_matches('/')
        };
        let dev_matches = if norm.starts_with("/dev/") {
            if dev == norm {
                true
            } else if let Some(suffix) = dev.strip_prefix(norm) {
                let norm_ends_digit = norm.ends_with(|c: char| c.is_ascii_digit());
                if norm_ends_digit {
                    // Partitioned disk whose base name ends in a digit (`nvme0n1` -> `nvme0n1p1`,
                    // `loop0` -> `loop0p1`); prevents `/dev/sdb1` from matching `/dev/sdb10`.
                    suffix
                        .strip_prefix('p')
                        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                } else {
                    // Base SCSI/USB block device (`sdb` -> `sdb1`, `sdb12`)
                    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                }
            } else {
                false
            }
        } else {
            false
        };
        let mnt_matches = mnt == norm
            || (norm != "/"
                && mnt.starts_with(norm)
                && mnt.as_bytes().get(norm.len()) == Some(&b'/'));
        if dev_matches || mnt_matches {
            let p = PathBuf::from(mnt);
            if !mounts.contains(&p) {
                mounts.push(p);
            }
        }
    }
    mounts.sort_by_key(|a| std::cmp::Reverse(a.as_os_str().len()));
    mounts
}

/// Collects and deduplicates all active Linux mount points for BOTH a raw caller path (e.g. a udev
/// `/dev/disk/by-id/...` symlink or mount directory) AND its canonical `/dev/<block>` node, sorted
/// deepest-path first so bind-mounts and symlink-referenced volumes are always unmounted (`CSE-25`).
pub fn collect_linux_mount_points_for_volume_and_dev(
    volume_path: &Path,
    canonical_dev: Option<&Path>,
    proc_mounts: &str,
) -> Vec<PathBuf> {
    let mut mounts = collect_linux_mount_points_for_target(volume_path, proc_mounts);
    if let Some(dev_path) = canonical_dev {
        for mp in collect_linux_mount_points_for_target(dev_path, proc_mounts) {
            if !mounts.contains(&mp) {
                mounts.push(mp);
            }
        }
    }
    mounts.sort_by_key(|a| std::cmp::Reverse(a.as_os_str().len()));
    mounts
}

fn is_valid_udev_usb_serial(serial: &str) -> bool {
    !serial.is_empty()
        && serial.len() <= 128
        && serial
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

fn parse_allowlisted_usb_vid_pid_for_udev(
    raw: &str,
) -> Option<(String, Option<String>, Option<String>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed.is_ascii()
        || trimmed
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | ',' | ';' | '=' | '|' | '$' | '`'))
    {
        return None;
    }
    let upper = trimmed.to_ascii_uppercase();
    if let Some(vid_pos) = upper.find("VID_") {
        let vid_hex = upper.get(vid_pos + 4..vid_pos + 8)?;
        if !vid_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if let Some(next_b) = upper.as_bytes().get(vid_pos + 8) {
            if next_b.is_ascii_alphanumeric() {
                return None;
            }
        }

        let (pid_opt, tail_start) = if let Some(pid_pos) = upper.find("PID_") {
            let pid_hex = upper.get(pid_pos + 4..pid_pos + 8)?;
            if !pid_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            if let Some(next_b) = upper.as_bytes().get(pid_pos + 8) {
                if next_b.is_ascii_alphanumeric() {
                    return None;
                }
            }
            (Some(pid_hex.to_ascii_lowercase()), pid_pos + 8)
        } else {
            (None, vid_pos + 8)
        };

        let tail = trimmed.get(tail_start..).unwrap_or("");
        let serial_opt = if let Some(bs_pos) = tail.find('\\') {
            let raw_serial = &tail[bs_pos + 1..];
            if raw_serial.is_empty() || raw_serial == "*" {
                None
            } else if is_valid_udev_usb_serial(raw_serial) {
                Some(raw_serial.to_string())
            } else {
                // Fail closed on malformed/globbed/injected serials rather than widening to model/vendor-wide allow
                return None;
            }
        } else {
            None
        };

        return Some((vid_hex.to_ascii_lowercase(), pid_opt, serial_opt));
    }

    let mut parts = trimmed.splitn(3, ':');
    if let (Some(v), Some(p)) = (parts.next(), parts.next()) {
        if v.len() != 4 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let pid_opt = if p == "*" {
            None
        } else if p.len() == 4 && p.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(p.to_ascii_lowercase())
        } else {
            return None;
        };
        let serial_opt = match parts.next() {
            None | Some("*") => None,
            Some(s) if is_valid_udev_usb_serial(s) => Some(s.to_string()),
            Some(_) => return None,
        };
        return Some((v.to_ascii_lowercase(), pid_opt, serial_opt));
    }
    None
}

/// Validates that a canonicalized Linux sysfs attribute's parent directory resides strictly under
/// `/sys/devices/` (permitting kernel sysfs device-directory symlinks under `/sys/bus/usb/devices`
/// and `/sys/block/<dev>/device`) while strictly rejecting a symlinked leaf attribute (`CSE-25`).
pub fn validate_linux_sysfs_leaf_target(
    canonical_parent: &Path,
    leaf_is_symlink: bool,
) -> io::Result<()> {
    if leaf_is_symlink {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Refusing symlinked Linux sysfs leaf attribute",
        ));
    }
    let parent_str = canonical_parent.to_string_lossy().replace('\\', "/");
    let under_sys_devices = parent_str == "/sys/devices" || parent_str.starts_with("/sys/devices/");
    if !under_sys_devices {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Linux sysfs attribute parent '{parent_str}' escaped /sys/devices/ boundary"),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn write_linux_sysfs_leaf_attr(sysfs_leaf: &Path, value: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = sysfs_leaf.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid Linux sysfs path '{}'", sysfs_leaf.display()),
        )
    })?;
    let leaf_name = sysfs_leaf.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Missing sysfs leaf filename '{}'", sysfs_leaf.display()),
        )
    })?;
    let canonical_parent = std::fs::canonicalize(parent)?;
    let target_leaf = canonical_parent.join(leaf_name);
    let meta = std::fs::symlink_metadata(&target_leaf)?;
    validate_linux_sysfs_leaf_target(&canonical_parent, meta.file_type().is_symlink())?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&target_leaf)?;
    file.write_all(value.as_bytes())
}

/// Renders deterministic, class-scoped Linux `udev` rules for `/etc/udev/rules.d/99-omniconnect-sentinel.rules`
/// (`CSE-24`, `CSE-25`):
/// - Matches allowlisted hardware across `usb_device`, child `usb_interface`, and child `block`
///   uevents using parent-walking `SUBSYSTEMS=="usb", ATTRS{idVendor}=="...", ATTRS{idProduct}=="..."`
///   so allowlisted USB devices are NOT blocked by child interface/block rules.
/// - Restricts ONLY unapproved USB Mass Storage (`bInterfaceClass=="08"`), MTP/WPD
///   (`ID_MTP_DEVICE=="1"`), and USB block devices (`RUN+="/sbin/blockdev --setro $devnode"`,
///   `UDISKS_IGNORE="1"`, `UDISKS_AUTO="0"` — never writing to kernel-RO `ATTR{ro}`), leaving
///   HID, docks, webcams, audio, and YubiKeys operational.
pub fn render_linux_udev_usb_storage_rules(allowed_hardware_ids: &[String]) -> String {
    let mut out = String::from(
        "# Managed by OmniConnect-Sentinel (CSE-24 / CSE-25): Class-Scoped USB Storage & WPD Policy\n",
    );
    for hw_id in allowed_hardware_ids {
        if let Some((vid, pid_opt, serial_opt)) = parse_allowlisted_usb_vid_pid_for_udev(hw_id) {
            let mut match_clause = format!("SUBSYSTEMS==\"usb\", ATTRS{{idVendor}}==\"{vid}\"");
            if let Some(pid) = pid_opt {
                match_clause.push_str(&format!(", ATTRS{{idProduct}}==\"{pid}\""));
            }
            if let Some(serial) = serial_opt {
                match_clause.push_str(&format!(", ATTRS{{serial}}==\"{serial}\""));
            }
            out.push_str(&format!(
                "ACTION==\"add|change\", SUBSYSTEM==\"usb\", {match_clause}, ENV{{OMNICONNECT_ALLOWED}}=\"1\", ATTR{{authorized}}=\"1\", GOTO=\"omniconnect_sentinel_end\"\n"
            ));
            out.push_str(&format!(
                "ACTION==\"add|change\", SUBSYSTEM==\"block\", {match_clause}, ENV{{OMNICONNECT_ALLOWED}}=\"1\", GOTO=\"omniconnect_sentinel_end\"\n"
            ));
        }
    }
    out.push_str(
        "ACTION==\"add|change\", SUBSYSTEM==\"usb\", ENV{DEVTYPE}==\"usb_interface\", ATTR{bInterfaceClass}==\"08\", ENV{OMNICONNECT_ALLOWED}!=\"1\", ATTR{authorized}=\"0\", ENV{UDISKS_IGNORE}=\"1\", ENV{UDISKS_AUTO}=\"0\"\n",
    );
    out.push_str(
        "ACTION==\"add|change\", SUBSYSTEM==\"usb\", ENV{ID_MTP_DEVICE}==\"1\", ENV{OMNICONNECT_ALLOWED}!=\"1\", ENV{UDISKS_IGNORE}=\"1\", ENV{UDISKS_AUTO}=\"0\"\n",
    );
    out.push_str(
        "ACTION==\"add|change\", SUBSYSTEM==\"block\", ENV{ID_BUS}==\"usb\", ENV{OMNICONNECT_ALLOWED}!=\"1\", ENV{UDISKS_IGNORE}=\"1\", ENV{UDISKS_AUTO}=\"0\", RUN+=\"/sbin/blockdev --setro $devnode\"\n",
    );
    out.push_str("LABEL=\"omniconnect_sentinel_end\"\n");
    out
}

/// Verifies that Linux `/etc/udev/rules.d/99-omniconnect-sentinel.rules` genuinely contains the
/// required class-scoped USB storage and `blockdev --setro` controls (and rejects broken
/// unwritable `ATTR{ro}="1"` rules) (`CSE-25`).
pub fn verify_linux_udev_rules_content(rules_text: &str) -> bool {
    if rules_text.contains("ATTR{ro}=\"1\"") {
        return false;
    }
    let has_storage_iface_block = rules_text.contains("ATTR{bInterfaceClass}==\"08\"")
        && rules_text.contains("ATTR{authorized}=\"0\"");
    let has_usb_block_ro = rules_text.contains("SUBSYSTEM==\"block\"")
        && rules_text.contains("ENV{ID_BUS}==\"usb\"")
        && rules_text.contains("blockdev --setro")
        && rules_text.contains("ENV{UDISKS_IGNORE}=\"1\"");
    let has_mtp_block = rules_text.contains("ENV{ID_MTP_DEVICE}==\"1\"");
    has_storage_iface_block && has_usb_block_ro && has_mtp_block
}

#[cfg(target_os = "linux")]
fn linux_umount_detach(mount_point: &str) -> io::Result<()> {
    let trimmed = mount_point.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux mount point path must not be empty",
        ));
    }
    let c_path = std::ffi::CString::new(trimmed).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Linux mount point contains NUL byte: {e}"),
        )
    })?;
    let rc = unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_apply_blkroset(dev_node: &Path, readonly: bool) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new().read(true).open(dev_node)?;
    let ro_flag: libc::c_int = i32::from(readonly);
    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            LINUX_BLKROSET_IOCTL as libc::Ioctl,
            &ro_flag as *const libc::c_int,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Resolves the owning parent `USB\VID_xxxx&PID_yyyy\<serial>` device from a child-to-root
/// Windows PnP ancestor chain (`O(depth)`, bounded to `MAX_USB_TOPOLOGY_HOPS`, skipping `&MI_xx`
/// composite sub-interfaces so attribution targets the exact physical USB device) (`CSE-24`).
pub fn resolve_windows_ancestor_usb_instance(
    ancestor_chain: &[String],
    device_desc: Option<String>,
) -> Option<UsbTopologyAttribution> {
    let mut fallback_mi: Option<UsbTopologyAttribution> = None;
    for (hop_idx, inst) in ancestor_chain
        .iter()
        .take(MAX_USB_TOPOLOGY_HOPS)
        .enumerate()
    {
        let upper = inst.to_ascii_uppercase();
        if !upper.starts_with("USB\\VID_") {
            continue;
        }
        let Some((vid, pid, serial)) = parse_windows_usb_vid_pid_serial(inst) else {
            continue;
        };
        let candidate = UsbTopologyAttribution {
            instance_id: inst.clone(),
            vid,
            pid,
            serial,
            device_desc: device_desc.clone(),
            hops: hop_idx,
        };
        if !upper.contains("&MI_") {
            return Some(candidate);
        }
        if fallback_mi.is_none() {
            fallback_mi = Some(candidate);
        }
    }
    fallback_mi
}

/// Normalizes a Linux block device or partition path (`/dev/sdb1`, `nvme0n1p2`, `mmcblk0p1`) to
/// its base `/sys/block/<base>` device name (`CSE-24`, `CSE-25`).
pub fn normalize_linux_block_device_name(dev_name: &str) -> Option<String> {
    let trimmed = dev_name.trim();
    let base = trimmed.strip_prefix("/dev/").unwrap_or(trimmed);
    if base.is_empty()
        || base.contains('/')
        || base.contains('\\')
        || base.contains("..")
        || !base
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return None;
    }
    // Partitioned devices using `<digits>p<digits>` suffix (`nvme0n1p1`, `mmcblk0p2`, `loop0p1`).
    // Requiring the character before `p` to be an ASCII digit guarantees unpartitioned `loop0`
    // is NEVER mangled into `loo` (`CSE-24`).
    if (base.starts_with("nvme") || base.starts_with("mmcblk") || base.starts_with("loop"))
        && base.contains('p')
    {
        if let Some((prefix, suffix)) = base.rsplit_once('p') {
            if prefix.as_bytes().last().is_some_and(u8::is_ascii_digit)
                && !suffix.is_empty()
                && suffix.bytes().all(|b| b.is_ascii_digit())
            {
                return Some(prefix.to_string());
            }
        }
    }
    // Traditional SCSI/USB/VirtIO partitions (`sdb1`, `sda12`, `vdb1`)
    let stripped = base.trim_end_matches(|c: char| c.is_ascii_digit());
    if !stripped.is_empty()
        && (stripped.starts_with("sd")
            || stripped.starts_with("hd")
            || stripped.starts_with("vd")
            || stripped.starts_with("xvd"))
    {
        return Some(stripped.to_string());
    }
    Some(base.to_string())
}

fn unescape_proc_mounts_field(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let d1 = bytes[i + 1];
            let d2 = bytes[i + 2];
            let d3 = bytes[i + 3];
            if (b'0'..=b'3').contains(&d1)
                && (b'0'..=b'7').contains(&d2)
                && (b'0'..=b'7').contains(&d3)
            {
                let val = ((d1 - b'0') << 6) | ((d2 - b'0') << 3) | (d3 - b'0');
                out.push(val as char);
                i += 4;
                continue;
            }
        }
        if let Some(ch) = raw[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

/// Resolves the backing `/dev/...` block device node for a Linux mount point from `/proc/mounts`
/// contents, preferring an exact mount-point match or the deepest ancestor mount (`CSE-24`, `CSE-25`).
pub fn resolve_linux_mount_block_device_from_proc_mounts(
    mount_point: &Path,
    proc_mounts: &str,
) -> Option<String> {
    let target = mount_point.to_string_lossy();
    let norm_target = if target == "/" {
        "/"
    } else {
        target.trim_end_matches('/')
    };
    if norm_target.is_empty() {
        return None;
    }
    let mut best_match: Option<(usize, String)> = None;
    for line in proc_mounts.lines() {
        let mut parts = line.split_whitespace();
        let Some(raw_dev) = parts.next() else {
            continue;
        };
        let Some(raw_mnt) = parts.next() else {
            continue;
        };
        let dev = unescape_proc_mounts_field(raw_dev);
        if !dev.starts_with("/dev/") {
            continue;
        }
        let mnt_unescaped = unescape_proc_mounts_field(raw_mnt);
        let mnt = if mnt_unescaped == "/" {
            "/"
        } else {
            mnt_unescaped.trim_end_matches('/')
        };
        let matches = mnt == norm_target
            || (mnt != "/"
                && norm_target.starts_with(mnt)
                && norm_target.as_bytes().get(mnt.len()) == Some(&b'/'));
        if matches {
            let score = mnt.len();
            // `>=` ensures a later topmost overmount at the identical path wins over a buried mount.
            if best_match
                .as_ref()
                .map(|(best_len, _)| score >= *best_len)
                .unwrap_or(true)
            {
                best_match = Some((score, dev));
            }
        }
    }
    best_match.map(|(_, dev)| dev)
}

/// Extracts the exact (deepest) Linux sysfs USB bus-port identifier (`1-2.3`) from a canonical
/// `/sys/block/<dev>/device` sysfs path (`CSE-24`, `CSE-25`).
pub fn extract_linux_usb_bus_port_from_sysfs_path(canonical_sysfs_path: &Path) -> Option<String> {
    let raw = canonical_sysfs_path.to_string_lossy();
    let segments: Vec<&str> = raw
        .split(['/', '\\'])
        .filter(|seg| !seg.is_empty())
        .collect();
    for seg in segments.iter().rev() {
        if is_valid_linux_usb_bus_port(seg) {
            return Some((*seg).to_string());
        }
    }
    None
}

/// Matches a `UsbVolumeInfo` strictly against its topology-attributed `UsbPnpDeviceInfo`
/// (NEVER guessing via `.first()`), returning `None` when no exact topology match exists (`CSE-24`).
pub fn attribute_volume_to_pnp_device(
    vol: &UsbVolumeInfo,
    pnp_devices: &[UsbPnpDeviceInfo],
) -> Option<UsbPnpDeviceInfo> {
    let target_id = vol.usb_device_instance_id.as_deref()?;
    let trimmed = target_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(exact) = pnp_devices
        .iter()
        .find(|d| d.instance_id.eq_ignore_ascii_case(trimmed))
    {
        return Some(exact.clone());
    }
    pnp_devices
        .iter()
        .find(|d| {
            d.child_instance_ids
                .iter()
                .any(|c| c.eq_ignore_ascii_case(trimmed))
        })
        .cloned()
}

#[cfg(windows)]
fn read_cm_device_id(dev_inst: u32) -> Option<String> {
    let mut len: u32 = 0;
    if unsafe { CM_Get_Device_ID_Size(&mut len, dev_inst, 0) } != 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u16; (len as usize) + 1];
    if unsafe { CM_Get_Device_IDW(dev_inst, buf.as_mut_ptr(), buf.len() as u32, 0) } != 0 {
        return None;
    }
    let nul_pos = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..nul_pos]))
}

#[cfg(windows)]
fn read_cm_device_desc(dev_inst: u32) -> Option<String> {
    const CM_DRP_DEVICEDESC: u32 = 0x0000_0001;
    let mut reg_type: u32 = 0;
    let mut prop_len: u32 = 0;
    let _ = unsafe {
        CM_Get_DevNode_Registry_PropertyW(
            dev_inst,
            CM_DRP_DEVICEDESC,
            &mut reg_type,
            core::ptr::null_mut(),
            &mut prop_len,
            0,
        )
    };
    if !(2..=65_536).contains(&prop_len) {
        return None;
    }
    let mut buf = vec![0u16; (prop_len as usize).div_ceil(2)];
    let mut actual_len = (buf.len() * 2) as u32;
    if unsafe {
        CM_Get_DevNode_Registry_PropertyW(
            dev_inst,
            CM_DRP_DEVICEDESC,
            &mut reg_type,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut actual_len,
            0,
        )
    } != 0
    {
        return None;
    }
    let u16_count = (actual_len as usize / 2).min(buf.len());
    let nul_pos = buf[..u16_count]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(u16_count);
    let desc = String::from_utf16_lossy(&buf[..nul_pos]).trim().to_string();
    if desc.is_empty() {
        None
    } else {
        Some(desc)
    }
}

#[cfg(windows)]
fn resolve_windows_disk_number_to_usb_topology(
    target_disk_number: u32,
) -> Option<UsbTopologyAttribution> {
    const DIGCF_PRESENT: u32 = 0x0000_0002;
    const DIGCF_DEVICEINTERFACE: u32 = 0x0000_0010;
    const INVALID_HANDLE_VALUE: isize = -1;
    const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
    const OPEN_EXISTING: u32 = 3;
    const FILE_DEVICE_DISK: u32 = 0x0000_0007;
    const SPDRP_DEVICEDESC: u32 = 0x0000_0000;
    const GUID_DEVINTERFACE_DISK: WinGuid = WinGuid {
        data1: 0x53F5_6307,
        data2: 0xB6BF,
        data3: 0x11D0,
        data4: [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
    };

    let dev_info_set = unsafe {
        SetupDiGetClassDevsW(
            &GUID_DEVINTERFACE_DISK,
            core::ptr::null(),
            0,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if dev_info_set == INVALID_HANDLE_VALUE || dev_info_set == 0 {
        return None;
    }

    let mut matched: Option<(u32, Option<String>)> = None;
    let mut member_index: u32 = 0;

    loop {
        let mut iface_data = SpDeviceInterfaceData {
            cb_size: core::mem::size_of::<SpDeviceInterfaceData>() as u32,
            interface_class_guid: WinGuid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            flags: 0,
            reserved: 0,
        };
        let enum_ok = unsafe {
            SetupDiEnumDeviceInterfaces(
                dev_info_set,
                core::ptr::null(),
                &GUID_DEVINTERFACE_DISK,
                member_index,
                &mut iface_data,
            )
        };
        if enum_ok == 0 {
            break;
        }
        member_index = member_index.saturating_add(1);

        let mut required_size: u32 = 0;
        let _ = unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info_set,
                &iface_data,
                core::ptr::null_mut(),
                0,
                &mut required_size,
                core::ptr::null_mut(),
            )
        };
        if !(8..=65_536).contains(&required_size) {
            continue;
        }

        let mut detail_words = vec![0u32; (required_size as usize).div_ceil(4).max(2)];
        // SP_DEVICE_INTERFACE_DETAIL_DATA_W.cbSize is 8 on 64-bit Windows, 6 on 32-bit Windows
        detail_words[0] = if cfg!(target_pointer_width = "64") {
            8
        } else {
            6
        };

        let mut devinfo_data = SpDevinfoData {
            cb_size: core::mem::size_of::<SpDevinfoData>() as u32,
            class_guid: WinGuid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            dev_inst: 0,
            reserved: 0,
        };

        let detail_ok = unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info_set,
                &iface_data,
                detail_words.as_mut_ptr() as *mut core::ffi::c_void,
                (detail_words.len() * 4) as u32,
                core::ptr::null_mut(),
                &mut devinfo_data,
            )
        };
        if detail_ok == 0 {
            continue;
        }

        // DevicePath starts at byte offset 4 (detail_words[1..])
        let path_ptr = unsafe { (detail_words.as_ptr() as *const u16).add(2) };
        let h_disk = unsafe {
            CreateFileW(
                path_ptr,
                0,
                FILE_SHARE_READ_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if h_disk == INVALID_HANDLE_VALUE || h_disk == 0 {
            continue;
        }

        let mut sdn = StorageDeviceNumber {
            device_type: 0,
            device_number: u32::MAX,
            partition_number: 0,
        };
        let mut bytes_ret: u32 = 0;
        let ok_sdn = unsafe {
            DeviceIoControl(
                h_disk,
                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                core::ptr::null(),
                0,
                &mut sdn as *mut _ as *mut core::ffi::c_void,
                core::mem::size_of::<StorageDeviceNumber>() as u32,
                &mut bytes_ret,
                core::ptr::null_mut(),
            )
        };
        unsafe {
            let _ = CloseHandle(h_disk);
        }

        if ok_sdn != 0
            && sdn.device_type == FILE_DEVICE_DISK
            && sdn.device_number == target_disk_number
        {
            let mut desc_buf = [0u8; 512];
            let mut desc_req: u32 = 0;
            let mut reg_type: u32 = 0;
            let desc = if unsafe {
                SetupDiGetDeviceRegistryPropertyW(
                    dev_info_set,
                    &devinfo_data,
                    SPDRP_DEVICEDESC,
                    &mut reg_type,
                    desc_buf.as_mut_ptr(),
                    desc_buf.len() as u32,
                    &mut desc_req,
                )
            } != 0
            {
                let u16_len = (desc_req as usize / 2).min(desc_buf.len() / 2);
                let mut wide = Vec::with_capacity(u16_len);
                let (pairs, _) = desc_buf[..(u16_len * 2)].as_chunks::<2>();
                for &[lo, hi] in pairs {
                    let w = u16::from_le_bytes([lo, hi]);
                    if w == 0 {
                        break;
                    }
                    wide.push(w);
                }
                let s = String::from_utf16_lossy(&wide).trim().to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            } else {
                None
            };
            matched = Some((devinfo_data.dev_inst, desc));
            break;
        }
    }

    unsafe {
        let _ = SetupDiDestroyDeviceInfoList(dev_info_set);
    }

    let (disk_dev_inst, disk_desc) = matched?;
    let mut ancestor_chain = Vec::with_capacity(MAX_USB_TOPOLOGY_HOPS);
    let mut current = disk_dev_inst;
    let mut usb_desc = disk_desc;

    for _ in 0..MAX_USB_TOPOLOGY_HOPS {
        if let Some(id) = read_cm_device_id(current) {
            if id.to_ascii_uppercase().starts_with("USB\\VID_")
                && !id.to_ascii_uppercase().contains("&MI_")
            {
                if let Some(d) = read_cm_device_desc(current) {
                    usb_desc = Some(d);
                }
            }
            ancestor_chain.push(id);
        }
        let mut parent: u32 = 0;
        if unsafe { CM_Get_Parent(&mut parent, current, 0) } != 0
            || parent == 0
            || parent == current
        {
            break;
        }
        current = parent;
    }

    resolve_windows_ancestor_usb_instance(&ancestor_chain, usb_desc)
}

/// Resolves the exact physical USB device owning `volume_path` via OS hardware topology (`CSE-24`):
/// - **Windows:** `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` -> `DiskNumber` -> SetupAPI
///   `GUID_DEVINTERFACE_DISK` + `IOCTL_STORAGE_GET_DEVICE_NUMBER` + `SPDRP_DEVICEDESC` ->
///   `CM_Get_Parent` ancestor walk (`O(depth)`) to `USB\VID_xxxx&PID_yyyy\<serial>`.
/// - **Linux:** `/proc/mounts` (if mount path) -> `/sys/block/<dev>/device` canonical sysfs path ->
///   exact USB bus-port (`^[0-9]+-[0-9]+(\.[0-9]+)*$`) -> sysfs `idVendor`/`idProduct`/`serial`/`product`.
pub fn resolve_volume_usb_topology(volume_path: &Path) -> Option<UsbTopologyAttribution> {
    #[cfg(windows)]
    {
        let phys = resolve_physical_drive_path(volume_path)?;
        let disk_num: u32 = phys
            .to_ascii_lowercase()
            .strip_prefix(r"\\.\physicaldrive")?
            .parse()
            .ok()?;
        resolve_windows_disk_number_to_usb_topology(disk_num)
    }
    #[cfg(not(windows))]
    {
        let raw_str = volume_path.to_string_lossy();
        let dev_node = if raw_str.starts_with("/dev/") {
            raw_str.to_string()
        } else {
            let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
            resolve_linux_mount_block_device_from_proc_mounts(volume_path, &mounts)?
        };
        let resolved_dev = std::fs::canonicalize(&dev_node)
            .unwrap_or_else(|_| PathBuf::from(&dev_node))
            .to_string_lossy()
            .into_owned();
        let base_dev = normalize_linux_block_device_name(&resolved_dev)?;
        let sys_dev_link = Path::new("/sys/block").join(&base_dev).join("device");
        let canonical = std::fs::canonicalize(&sys_dev_link).ok()?;
        let bus_port = extract_linux_usb_bus_port_from_sysfs_path(&canonical)?;
        let usb_sys_dir = Path::new("/sys/bus/usb/devices").join(&bus_port);
        let vid = std::fs::read_to_string(usb_sys_dir.join("idVendor"))
            .ok()
            .and_then(|s| u16::from_str_radix(s.trim(), 16).ok())
            .unwrap_or(0);
        let pid = std::fs::read_to_string(usb_sys_dir.join("idProduct"))
            .ok()
            .and_then(|s| u16::from_str_radix(s.trim(), 16).ok())
            .unwrap_or(0);
        let serial = std::fs::read_to_string(usb_sys_dir.join("serial"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| bus_port.clone());
        let device_desc = std::fs::read_to_string(usb_sys_dir.join("product"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Some(UsbTopologyAttribution {
            instance_id: bus_port,
            vid,
            pid,
            serial,
            device_desc,
            hops: 1,
        })
    }
}

/// Resolves a volume path (`E:\`, `\\.\E:`, or `\\?\Volume{GUID}\`) to its underlying physical disk
/// device path (`\\.\PhysicalDriveN`) via `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` (`Row 16, 20`).
pub fn resolve_physical_drive_path(volume_path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        let raw = volume_path.to_string_lossy();
        let trimmed = raw.trim_end_matches('\\');
        if trimmed
            .to_ascii_lowercase()
            .starts_with(r"\\.\physicaldrive")
        {
            return Some(trimmed.to_string());
        }
        let device_path = if trimmed.starts_with(r"\\.\") || trimmed.starts_with(r"\\?\") {
            trimmed.to_string()
        } else {
            format!(r"\\.\{trimmed}")
        };
        let wide: Vec<u16> = std::ffi::OsStr::new(&device_path)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0, // FILE_ANY_ACCESS
                FILE_SHARE_READ_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return None;
        }
        let mut extents = VolumeDiskExtents {
            number_of_disk_extents: 0,
            extents: [DiskExtent {
                disk_number: 0,
                starting_offset: 0,
                extent_length: 0,
            }],
        };
        let mut bytes_ret: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                core::ptr::null(),
                0,
                &mut extents as *mut _ as *mut core::ffi::c_void,
                core::mem::size_of::<VolumeDiskExtents>() as u32,
                &mut bytes_ret,
                core::ptr::null_mut(),
            )
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        if ok != 0 && extents.number_of_disk_extents > 0 {
            return Some(format!(
                r"\\.\PhysicalDrive{}",
                extents.extents[0].disk_number
            ));
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = volume_path;
        None
    }
}

/// Enumerates all USB-attached and removable volumes by Volume GUID (`FindFirstVolumeW` /
/// `FindNextVolumeW`, `\\?\Volume{GUID}\`) and `IOCTL_STORAGE_QUERY_PROPERTY` (`BusTypeUsb = 0x07`),
/// capturing both `DRIVE_REMOVABLE` flash drives and `DRIVE_FIXED` external USB SSDs/HDDs even when
/// auto-mount is disabled and no drive letter is assigned (`Critical #2`, `High #12`, Rows 20, 138).
pub fn enumerate_usb_volumes() -> Vec<UsbVolumeInfo> {
    let mut volumes = Vec::new();

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const INVALID_HANDLE_VALUE: isize = -1;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const DRIVE_REMOVABLE: u32 = 2;

        let mut vol_buf = [0u16; 260];
        let find_handle = unsafe { FindFirstVolumeW(vol_buf.as_mut_ptr(), vol_buf.len() as u32) };
        if find_handle != INVALID_HANDLE_VALUE && find_handle != 0 {
            loop {
                let len = vol_buf.iter().position(|&c| c == 0).unwrap_or(0);
                let vol_guid_path = String::from_utf16_lossy(&vol_buf[..len]);
                let vol_no_slash = vol_guid_path.trim_end_matches('\\').to_string();

                let mut mp_buf = vec![0u16; 512];
                let mut ret_len: u32 = 0;
                let mut mount_points = Vec::new();
                let ok_mp = unsafe {
                    GetVolumePathNamesForVolumeNameW(
                        vol_buf.as_ptr(),
                        mp_buf.as_mut_ptr(),
                        mp_buf.len() as u32,
                        &mut ret_len,
                    )
                };
                if ok_mp != 0 {
                    let mut start = 0usize;
                    while start < mp_buf.len() && mp_buf[start] != 0 {
                        let end = mp_buf[start..]
                            .iter()
                            .position(|&c| c == 0)
                            .map(|p| start + p)
                            .unwrap_or(mp_buf.len());
                        let mp_str = String::from_utf16_lossy(&mp_buf[start..end]);
                        if !mp_str.is_empty() {
                            mount_points.push(PathBuf::from(mp_str));
                        }
                        start = end + 1;
                    }
                }

                let mut is_removable_drive_type = false;
                let wide_guid_root: Vec<u16> = std::ffi::OsStr::new(&vol_guid_path)
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                if unsafe { GetDriveTypeW(wide_guid_root.as_ptr()) } == DRIVE_REMOVABLE {
                    is_removable_drive_type = true;
                }
                for mp in &mount_points {
                    let wide_mp: Vec<u16> = mp.as_os_str().encode_wide().chain(Some(0)).collect();
                    if unsafe { GetDriveTypeW(wide_mp.as_ptr()) } == DRIVE_REMOVABLE {
                        is_removable_drive_type = true;
                    }
                }

                let wide_dev: Vec<u16> = std::ffi::OsStr::new(&vol_no_slash)
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                let h_vol = unsafe {
                    CreateFileW(
                        wide_dev.as_ptr(),
                        0,
                        FILE_SHARE_READ_WRITE,
                        core::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        0,
                    )
                };

                let mut bus_type = 0u32;
                let mut removable_media = is_removable_drive_type;
                let mut physical_drive_number = None;

                if h_vol != INVALID_HANDLE_VALUE && h_vol != 0 {
                    let query = StoragePropertyQuery {
                        property_id: 0,
                        query_type: 0,
                        additional_parameters: [0; 4],
                    };
                    let mut dev_hdr = StorageDeviceDescriptorHeader {
                        version: 0,
                        size: 0,
                        device_type: 0,
                        device_type_modifier: 0,
                        removable_media: 0,
                        command_queueing: 0,
                        vendor_id_offset: 0,
                        product_id_offset: 0,
                        product_revision_offset: 0,
                        serial_number_offset: 0,
                        bus_type: 0,
                    };
                    let mut bytes_ret: u32 = 0;
                    let ok_prop = unsafe {
                        DeviceIoControl(
                            h_vol,
                            IOCTL_STORAGE_QUERY_PROPERTY,
                            &query as *const _ as *const core::ffi::c_void,
                            core::mem::size_of::<StoragePropertyQuery>() as u32,
                            &mut dev_hdr as *mut _ as *mut core::ffi::c_void,
                            core::mem::size_of::<StorageDeviceDescriptorHeader>() as u32,
                            &mut bytes_ret,
                            core::ptr::null_mut(),
                        )
                    };
                    if ok_prop != 0 {
                        bus_type = dev_hdr.bus_type;
                        if dev_hdr.removable_media != 0 {
                            removable_media = true;
                        }
                    }

                    let mut extents = VolumeDiskExtents {
                        number_of_disk_extents: 0,
                        extents: [DiskExtent {
                            disk_number: 0,
                            starting_offset: 0,
                            extent_length: 0,
                        }],
                    };
                    let ok_ext = unsafe {
                        DeviceIoControl(
                            h_vol,
                            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                            core::ptr::null(),
                            0,
                            &mut extents as *mut _ as *mut core::ffi::c_void,
                            core::mem::size_of::<VolumeDiskExtents>() as u32,
                            &mut bytes_ret,
                            core::ptr::null_mut(),
                        )
                    };
                    if ok_ext != 0 && extents.number_of_disk_extents > 0 {
                        physical_drive_number = Some(extents.extents[0].disk_number);
                    }

                    unsafe {
                        let _ = CloseHandle(h_vol);
                    }
                }

                if bus_type == BUS_TYPE_USB || removable_media {
                    let vol_path = Path::new(&vol_guid_path);
                    let is_offline = is_volume_offline(vol_path);
                    let is_readonly = is_volume_readonly(vol_path);
                    let topo =
                        physical_drive_number.and_then(resolve_windows_disk_number_to_usb_topology);
                    let (usb_device_instance_id, usb_device_desc) = match topo {
                        Some(attr) => (Some(attr.instance_id), attr.device_desc),
                        None => (None, None),
                    };
                    volumes.push(UsbVolumeInfo {
                        volume_guid_path: vol_guid_path,
                        mount_points,
                        physical_drive_number,
                        bus_type,
                        is_removable_media: removable_media,
                        is_offline,
                        is_readonly,
                        usb_device_instance_id,
                        usb_device_desc,
                    });
                }

                vol_buf.fill(0);
                if unsafe {
                    FindNextVolumeW(find_handle, vol_buf.as_mut_ptr(), vol_buf.len() as u32)
                } == 0
                {
                    break;
                }
            }
            unsafe {
                let _ = FindVolumeClose(find_handle);
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                let dev_name = entry.file_name().to_string_lossy().to_string();
                let sys_path = entry.path();
                let is_rem = std::fs::read_to_string(sys_path.join("removable"))
                    .map(|s| s.trim() == "1")
                    .unwrap_or(false);
                let is_usb = std::fs::canonicalize(&sys_path)
                    .map(|p| p.to_string_lossy().contains("/usb"))
                    .unwrap_or(false);
                if !is_rem && !is_usb {
                    continue;
                }
                let is_ro = std::fs::read_to_string(sys_path.join("ro"))
                    .map(|s| s.trim() == "1")
                    .unwrap_or(false);
                let dev_node = format!("/dev/{dev_name}");
                let is_off = is_volume_offline(Path::new(&dev_node));
                let mut mount_points = Vec::new();
                if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
                    for line in mounts.lines() {
                        let mut parts = line.split_whitespace();
                        let m_dev = parts
                            .next()
                            .map(unescape_proc_mounts_field)
                            .unwrap_or_default();
                        let m_mnt = parts
                            .next()
                            .map(unescape_proc_mounts_field)
                            .unwrap_or_default();
                        if m_dev == dev_node
                            || (m_dev.starts_with(&dev_node)
                                && m_dev
                                    .as_bytes()
                                    .get(dev_node.len())
                                    .map(|b| b.is_ascii_digit() || *b == b'p')
                                    .unwrap_or(false))
                        {
                            let p = PathBuf::from(m_mnt);
                            if !mount_points.contains(&p) {
                                mount_points.push(p);
                            }
                        }
                    }
                }
                let topo = resolve_volume_usb_topology(Path::new(&dev_node));
                let (usb_device_instance_id, usb_device_desc) = match topo {
                    Some(attr) => (Some(attr.instance_id), attr.device_desc),
                    None => (None, None),
                };
                volumes.push(UsbVolumeInfo {
                    volume_guid_path: dev_node,
                    mount_points,
                    physical_drive_number: None,
                    bus_type: if is_usb { BUS_TYPE_USB } else { 0 },
                    is_removable_media: is_rem,
                    is_offline: is_off,
                    is_readonly: is_ro,
                    usb_device_instance_id,
                    usb_device_desc,
                });
            }
        }
    }

    volumes
}

/// Enumerates USB and removable drives (`enumerate_usb_volumes()` on Windows — covering both
/// `DRIVE_REMOVABLE` flash drives and `BusTypeUsb` external SSDs/HDDs even without drive letters —
/// plus `/media` & `/run/media` on Linux) (`BUG-CORE-12`, Rows 20, 138).
pub fn get_removable_drives() -> Vec<PathBuf> {
    let mut drives = Vec::new();
    for vol in enumerate_usb_volumes() {
        if !vol.mount_points.is_empty() {
            for mp in vol.mount_points {
                if !drives.contains(&mp) {
                    drives.push(mp);
                }
            }
        } else {
            let p = PathBuf::from(vol.volume_guid_path);
            if !drives.contains(&p) {
                drives.push(p);
            }
        }
    }

    #[cfg(not(windows))]
    {
        for mount_root in &["/media", "/run/media", "/Volumes"] {
            let p = std::path::Path::new(mount_root);
            if p.is_dir() {
                if let Ok(entries) = std::fs::read_dir(p) {
                    for entry in entries.flatten() {
                        let ep = entry.path();
                        if ep.is_dir() && !drives.contains(&ep) {
                            drives.push(ep);
                        }
                    }
                }
            }
        }
    }

    drives
}

/// Reads a `REG_DWORD` value from `HKEY_LOCAL_MACHINE` (or `HKEY_CURRENT_USER` when `use_hkcu` is true).
pub fn read_registry_dword(use_hkcu: bool, subkey: &str, value_name: &str) -> Option<u32> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let hive = if use_hkcu {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        };
        let wide_subkey: Vec<u16> = std::ffi::OsStr::new(subkey)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let wide_val: Vec<u16> = std::ffi::OsStr::new(value_name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut data: u32 = 0;
        let mut cb_data: u32 = core::mem::size_of::<u32>() as u32;
        let status = unsafe {
            RegGetValueW(
                hive,
                wide_subkey.as_ptr(),
                wide_val.as_ptr(),
                RRF_RT_REG_DWORD,
                core::ptr::null_mut(),
                &mut data as *mut _ as *mut core::ffi::c_void,
                &mut cb_data,
            )
        };
        if status == 0 {
            return Some(data);
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = (use_hkcu, subkey, value_name);
        None
    }
}

/// Maximum permitted registry `REG_SZ` string payload size (1 MiB, lifting the old 1,024-char cap
/// while preventing unbounded OOM allocation from adversarial registry values) (`CSE-26`).
pub const MAX_REGISTRY_STRING_BYTES: u32 = 1024 * 1024;

/// Decodes a UTF-16LE `REG_SZ` buffer bounded by `cb_data` bytes, stopping at the first NUL terminator.
pub fn decode_utf16_reg_sz_bytes(buf: &[u16], cb_data: u32) -> String {
    let max_units = ((cb_data as usize) / 2).min(buf.len());
    let slice = &buf[..max_units];
    let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16_lossy(&slice[..len])
}

/// Executes the two-call Win32 `RegGetValueW` sizing protocol:
/// 1. Queries exact byte length with `buf = None` (`pvData = NULL`).
/// 2. Rejects zero-length or `> MAX_REGISTRY_STRING_BYTES` (1 MiB) payloads fail-closed.
/// 3. Allocates exact `Vec<u16>` capacity and fills the payload (retrying once on `ERROR_MORE_DATA = 234`
///    if the registry value grew concurrently between Call 1 and Call 2).
#[cfg(any(windows, test))]
pub(crate) fn read_registry_string_two_call<F>(mut query_fn: F) -> Option<String>
where
    F: FnMut(Option<&mut [u16]>, &mut u32) -> i32,
{
    const ERROR_MORE_DATA: i32 = 234;
    let mut cb_data: u32 = 0;
    let size_status = query_fn(None, &mut cb_data);
    if size_status != 0 || cb_data == 0 || cb_data > MAX_REGISTRY_STRING_BYTES {
        return None;
    }

    for _ in 0..2 {
        if cb_data == 0 || cb_data > MAX_REGISTRY_STRING_BYTES {
            return None;
        }
        let unit_count = (cb_data as usize).div_ceil(2).saturating_add(1);
        let mut buf = vec![0u16; unit_count];
        let mut actual_bytes: u32 = (buf.len().saturating_mul(2)) as u32;
        let read_status = query_fn(Some(&mut buf), &mut actual_bytes);
        if read_status == 0 {
            return Some(decode_utf16_reg_sz_bytes(&buf, actual_bytes));
        }
        if read_status == ERROR_MORE_DATA {
            cb_data = actual_bytes;
            continue;
        }
        return None;
    }
    None
}

/// Reads a dynamically sized `REG_SZ` string value via two-call `RegGetValueW` (first querying the
/// exact byte length with a `NULL` buffer, then allocating the exact `Vec<u16>` capped at
/// `MAX_REGISTRY_STRING_BYTES`) (`CSE-26`).
pub fn read_registry_string_from_hive(
    use_hkcu: bool,
    subkey: &str,
    value_name: &str,
) -> Option<String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let hive = if use_hkcu {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        };
        let wide_subkey: Vec<u16> = std::ffi::OsStr::new(subkey)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let wide_val: Vec<u16> = std::ffi::OsStr::new(value_name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        read_registry_string_two_call(|buf_opt, cb_data| {
            let ptr = match buf_opt {
                Some(b) => b.as_mut_ptr() as *mut core::ffi::c_void,
                None => core::ptr::null_mut(),
            };
            unsafe {
                RegGetValueW(
                    hive,
                    wide_subkey.as_ptr(),
                    wide_val.as_ptr(),
                    RRF_RT_REG_SZ,
                    core::ptr::null_mut(),
                    ptr,
                    cb_data,
                )
            }
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (use_hkcu, subkey, value_name);
        None
    }
}

/// Reads a dynamically sized `REG_SZ` string value from `HKEY_LOCAL_MACHINE` (`CSE-26`).
pub fn read_registry_string(subkey: &str, value_name: &str) -> Option<String> {
    read_registry_string_from_hive(false, subkey, value_name)
}

#[cfg(windows)]
fn write_registry_dword(
    use_hkcu: bool,
    subkey: &str,
    value_name: &str,
    val: u32,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let hive = if use_hkcu {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    };
    let wide_subkey: Vec<u16> = std::ffi::OsStr::new(subkey)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let wide_val: Vec<u16> = std::ffi::OsStr::new(value_name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let status = unsafe {
        RegSetKeyValueW(
            hive,
            wide_subkey.as_ptr(),
            wide_val.as_ptr(),
            REG_DWORD,
            &val as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<u32>() as u32,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(())
}

#[cfg(windows)]
fn clear_registry_subkey(subkey: &str) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;

    let wide_subkey: Vec<u16> = std::ffi::OsStr::new(subkey)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide_subkey.as_ptr()) };
    if status == 0 || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

#[cfg(windows)]
fn enumerate_registry_string_values(subkey: &str) -> Vec<String> {
    use std::os::windows::ffi::OsStrExt;
    const KEY_READ: u32 = 0x0002_0019;
    const ERROR_NO_MORE_ITEMS: i32 = 259;

    let wide_subkey: Vec<u16> = std::ffi::OsStr::new(subkey)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut hkey: isize = 0;
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide_subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    } != 0
        || hkey == 0
    {
        return Vec::new();
    }

    let mut values = Vec::new();
    let mut index: u32 = 0;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len: u32 = name_buf.len() as u32;
        let mut val_type: u32 = 0;
        let mut data_buf = [0u8; 2048];
        let mut data_len: u32 = data_buf.len() as u32;
        let status = unsafe {
            RegEnumValueW(
                hkey,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                core::ptr::null_mut(),
                &mut val_type,
                data_buf.as_mut_ptr(),
                &mut data_len,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        index = index.saturating_add(1);
        if status == 0 && val_type == REG_SZ {
            let u16_count = (data_len as usize / 2).min(data_buf.len() / 2);
            let mut wide = Vec::with_capacity(u16_count);
            let (pairs, _) = data_buf[..(u16_count * 2)].as_chunks::<2>();
            for &[lo, hi] in pairs {
                let w = u16::from_le_bytes([lo, hi]);
                if w == 0 {
                    break;
                }
                wide.push(w);
            }
            let s = String::from_utf16_lossy(&wide).trim().to_string();
            if !s.is_empty() {
                values.push(s);
            }
        }
        if index >= 4096 {
            break;
        }
    }
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    values
}

#[cfg(windows)]
fn write_registry_sz(subkey: &str, value_name: &str, val: &str) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let wide_subkey: Vec<u16> = std::ffi::OsStr::new(subkey)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let wide_val: Vec<u16> = std::ffi::OsStr::new(value_name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let wide_data: Vec<u16> = std::ffi::OsStr::new(val)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            wide_subkey.as_ptr(),
            wide_val.as_ptr(),
            REG_SZ,
            wide_data.as_ptr() as *const core::ffi::c_void,
            (wide_data.len() * 2) as u32,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(())
}

/// Queries whether Mount Manager automount is disabled (`NoAutoMount == 1`).
pub fn query_automount_disabled() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const GENERIC_READ: u32 = 0x80000000;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        let mgr_wide: Vec<u16> = std::ffi::OsStr::new(r"\\.\MountPointManager")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let h_mgr = unsafe {
            CreateFileW(
                mgr_wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if h_mgr != INVALID_HANDLE_VALUE && h_mgr != 0 {
            let mut auto_mount_state: i32 = 1; // 0 = Disabled, 1 = Enabled
            let mut bytes_ret: u32 = 0;
            let ok = unsafe {
                DeviceIoControl(
                    h_mgr,
                    IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT,
                    core::ptr::null(),
                    0,
                    &mut auto_mount_state as *mut _ as *mut core::ffi::c_void,
                    core::mem::size_of::<i32>() as u32,
                    &mut bytes_ret,
                    core::ptr::null_mut(),
                )
            };
            unsafe {
                let _ = CloseHandle(h_mgr);
            }
            if ok != 0 && auto_mount_state == 0 {
                return true;
            }
        }

        read_registry_dword(
            false,
            r"SYSTEM\CurrentControlSet\Services\mountmgr",
            "NoAutoMount",
        ) == Some(1)
    }
    #[cfg(not(windows))]
    {
        check_linux_usb_authorized_default() == Some(true)
    }
}

/// Configures Mount Manager automount (`IOCTL_MOUNTMGR_SET_AUTO_MOUNT` = `0x006DC040` + `NoAutoMount`
/// registry persistence) or Linux `/sys/bus/usb/devices/usb*/authorized_default` (`Master Plan v2 §0.1`,
/// Rows 11–13). Checks and propagates all OS errors.
pub fn set_automount_disabled(disable: bool) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const GENERIC_READ_WRITE: u32 = 0xC0000000;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        let mgr_wide: Vec<u16> = std::ffi::OsStr::new(r"\\.\MountPointManager")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let h_mgr = unsafe {
            CreateFileW(
                mgr_wide.as_ptr(),
                GENERIC_READ_WRITE,
                FILE_SHARE_READ_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if h_mgr == INVALID_HANDLE_VALUE || h_mgr == 0 {
            return Err(io::Error::last_os_error());
        }

        let new_state: i32 = if disable { 0 } else { 1 };
        let mut bytes_ret: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                h_mgr,
                IOCTL_MOUNTMGR_SET_AUTO_MOUNT,
                &new_state as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<i32>() as u32,
                core::ptr::null_mut(),
                0,
                &mut bytes_ret,
                core::ptr::null_mut(),
            )
        };
        let ioctl_err = if ok == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe {
            let _ = CloseHandle(h_mgr);
        }
        if let Some(err) = ioctl_err {
            return Err(err);
        }

        if disable {
            purge_stale_mounted_devices()?;
        }

        write_registry_dword(
            false,
            r"SYSTEM\CurrentControlSet\Services\mountmgr",
            "NoAutoMount",
            if disable { 1 } else { 0 },
        )?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let val = if disable { "0\n" } else { "1\n" };
        let entries = std::fs::read_dir("/sys/bus/usb/devices")?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("usb") {
                let p = entry.path().join("authorized_default");
                write_linux_sysfs_leaf_attr(&p, val)?;
            }
        }
        Ok(())
    }
}

/// Removes stale unmounted removable-media drive-letter entries (`\DosDevices\D:`..`\DosDevices\Z:`)
/// under `HKLM\SYSTEM\MountedDevices` while inspecting `REG_BINARY` value data (`RegGetValueW`)
/// to preserve `DMIO:ID:` GPT fixed partition signatures and all currently mounted fixed, remote,
/// CD-ROM, RAMDisk, and active drives (`Master Plan v2 §0.1`, Row 13).
pub fn purge_stale_mounted_devices() -> io::Result<usize> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const DRIVE_REMOVABLE: u32 = 2;
        const DRIVE_FIXED: u32 = 3;
        const DRIVE_REMOTE: u32 = 4;
        const DRIVE_CDROM: u32 = 5;
        const DRIVE_RAMDISK: u32 = 6;
        const RRF_RT_ANY: u32 = 0x0000FFFF;
        const ERROR_FILE_NOT_FOUND: i32 = 2;

        let bitmask = unsafe { GetLogicalDrives() };
        let subkey_wide: Vec<u16> = std::ffi::OsStr::new(r"SYSTEM\MountedDevices")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut purged = 0usize;

        for i in 3..26u32 {
            let letter = (b'A' + i as u8) as char;
            let root = format!("{letter}:\\");
            let root_wide: Vec<u16> = std::ffi::OsStr::new(&root)
                .encode_wide()
                .chain(Some(0))
                .collect();
            if (bitmask & (1 << i)) != 0 {
                let dtype = unsafe { GetDriveTypeW(root_wide.as_ptr()) };
                if matches!(
                    dtype,
                    DRIVE_FIXED | DRIVE_REMOTE | DRIVE_CDROM | DRIVE_RAMDISK | DRIVE_REMOVABLE
                ) {
                    continue;
                }
            }
            let dos_dev = format!("\\DosDevices\\{letter}:");
            let val_wide: Vec<u16> = std::ffi::OsStr::new(&dos_dev)
                .encode_wide()
                .chain(Some(0))
                .collect();

            // Inspect the binary registry value data (`REG_BINARY`) before deleting:
            // skip fixed GPT/dynamic disk signatures starting with ASCII `DMIO:ID:` (`[0x44, 0x4D, 0x49, 0x4F, ...]`).
            let mut val_buf = [0u8; 512];
            let mut val_size: u32 = val_buf.len() as u32;
            let get_status = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    subkey_wide.as_ptr(),
                    val_wide.as_ptr(),
                    RRF_RT_ANY,
                    core::ptr::null_mut(),
                    val_buf.as_mut_ptr() as *mut core::ffi::c_void,
                    &mut val_size,
                )
            };
            if get_status == ERROR_FILE_NOT_FOUND {
                continue;
            }
            if get_status != 0 {
                return Err(io::Error::from_raw_os_error(get_status));
            }
            let data_slice = &val_buf[..(val_size as usize).min(val_buf.len())];
            if data_slice.starts_with(b"DMIO:ID:") {
                continue;
            }

            let status = unsafe {
                RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, subkey_wide.as_ptr(), val_wide.as_ptr())
            };
            if status == 0 {
                purged += 1;
            } else if status != ERROR_FILE_NOT_FOUND {
                return Err(io::Error::from_raw_os_error(status));
            }
        }
        Ok(purged)
    }
    #[cfg(not(windows))]
    {
        Ok(0)
    }
}

/// Places a volume offline (`IOCTL_VOLUME_OFFLINE`) or online (`IOCTL_VOLUME_ONLINE`) (`Master Plan v2 §0.1`, Rows 15, 16).
pub fn set_volume_offline(volume_path: &Path, offline: bool) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const GENERIC_READ_WRITE: u32 = 0xC0000000;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        let raw = volume_path.to_string_lossy();
        let trimmed = raw.trim_end_matches('\\');
        let device_path = if trimmed.starts_with(r"\\.\") || trimmed.starts_with(r"\\?\") {
            trimmed.to_string()
        } else {
            format!(r"\\.\{trimmed}")
        };
        let wide: Vec<u16> = std::ffi::OsStr::new(&device_path)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ_WRITE,
                FILE_SHARE_READ_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return Err(io::Error::last_os_error());
        }
        let ioctl = if offline {
            IOCTL_VOLUME_OFFLINE
        } else {
            IOCTL_VOLUME_ONLINE
        };
        let mut bytes_ret: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                ioctl,
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                0,
                &mut bytes_ret,
                core::ptr::null_mut(),
            )
        };
        let err = if ok == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        if let Some(e) = err {
            return Err(e);
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let proc_mounts = std::fs::read_to_string("/proc/mounts")?;
        let raw_str = volume_path.to_string_lossy();
        let dev_node = if raw_str.starts_with("/dev/") {
            let trimmed = raw_str.trim_end_matches('/');
            Some(
                std::fs::canonicalize(trimmed)
                    .unwrap_or_else(|_| PathBuf::from(trimmed))
                    .to_string_lossy()
                    .into_owned(),
            )
        } else {
            resolve_linux_mount_block_device_from_proc_mounts(volume_path, &proc_mounts).map(|d| {
                std::fs::canonicalize(&d)
                    .unwrap_or_else(|_| PathBuf::from(&d))
                    .to_string_lossy()
                    .into_owned()
            })
        };

        if offline {
            let active_mounts = collect_linux_mount_points_for_volume_and_dev(
                volume_path,
                dev_node.as_deref().map(Path::new),
                &proc_mounts,
            );
            for mp in &active_mounts {
                linux_umount_detach(&mp.to_string_lossy())?;
            }
            if let Some(ref dev) = dev_node {
                let dev_path = Path::new(dev);
                linux_apply_blkroset(dev_path, true)?;
                if let Some(base_dev) = normalize_linux_block_device_name(dev) {
                    let base_dev_path = PathBuf::from(format!("/dev/{base_dev}"));
                    if base_dev_path != dev_path && base_dev_path.exists() {
                        linux_apply_blkroset(&base_dev_path, true)?;
                    }
                    let state_path = Path::new("/sys/block").join(&base_dev).join("device/state");
                    if state_path.exists() {
                        write_linux_sysfs_leaf_attr(&state_path, "offline\n")?;
                    }
                }
                Ok(())
            } else if !active_mounts.is_empty() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Cannot offline Linux volume '{}': no matching mount or /dev block device found",
                        volume_path.display()
                    ),
                ))
            }
        } else {
            let dev = dev_node.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Cannot online Linux volume '{}': backing /dev block device not found",
                        volume_path.display()
                    ),
                )
            })?;
            let dev_path = Path::new(&dev);
            if !dev_path.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Linux block device '{dev}' does not exist"),
                ));
            }
            if let Some(base_dev) = normalize_linux_block_device_name(&dev) {
                let state_path = Path::new("/sys/block").join(&base_dev).join("device/state");
                if state_path.exists() {
                    write_linux_sysfs_leaf_attr(&state_path, "running\n")?;
                }
            }
            Ok(())
        }
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let _ = (volume_path, offline);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "set_volume_offline is not implemented on this OS",
        ))
    }
}

/// Resolves the physical disk (`\\.\PhysicalDriveN`) for `volume_path` via
/// `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` and applies `IOCTL_DISK_SET_DISK_ATTRIBUTES`
/// (`DISK_ATTRIBUTE_READ_ONLY`) during the agent's read window (`Master Plan v2 §0.1`, Row 16).
pub fn set_volume_online_readonly(volume_path: &Path, readonly: bool) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const DISK_ATTRIBUTE_OFFLINE: u64 = 0x0000_0000_0000_0001;
        const DISK_ATTRIBUTE_READ_ONLY: u64 = 0x0000_0000_0000_0002;
        const GENERIC_READ_WRITE: u32 = 0xC0000000;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        #[repr(C)]
        struct SetDiskAttributes {
            version: u32,
            persist: u8,
            relinquish_ownership: u8,
            reserved1: [u8; 2],
            attributes: u64,
            attributes_mask: u64,
            caller: [u8; 16],
        }

        // Resolve `\\.\PhysicalDriveN` from the volume handle first (`Critical #2`, Row 16)
        let target_disk_path = resolve_physical_drive_path(volume_path).unwrap_or_else(|| {
            let raw = volume_path.to_string_lossy();
            let trimmed = raw.trim_end_matches('\\');
            if trimmed.starts_with(r"\\.\") || trimmed.starts_with(r"\\?\") {
                trimmed.to_string()
            } else {
                format!(r"\\.\{trimmed}")
            }
        });

        let wide: Vec<u16> = std::ffi::OsStr::new(&target_disk_path)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ_WRITE,
                FILE_SHARE_READ_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return Err(io::Error::last_os_error());
        }
        let attrs = SetDiskAttributes {
            version: core::mem::size_of::<SetDiskAttributes>() as u32,
            persist: 0,
            relinquish_ownership: 0,
            reserved1: [0; 2],
            attributes: if readonly {
                DISK_ATTRIBUTE_READ_ONLY
            } else {
                0
            },
            attributes_mask: DISK_ATTRIBUTE_OFFLINE | DISK_ATTRIBUTE_READ_ONLY,
            caller: [0; 16],
        };
        let mut bytes_ret: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_SET_DISK_ATTRIBUTES,
                &attrs as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<SetDiskAttributes>() as u32,
                core::ptr::null_mut(),
                0,
                &mut bytes_ret,
                core::ptr::null_mut(),
            )
        };
        let err = if ok == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        if let Some(e) = err {
            return Err(e);
        }
        if readonly {
            set_volume_offline(volume_path, false)?;
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let raw_str = volume_path.to_string_lossy();
        let resolved_raw = if raw_str.starts_with("/dev/") {
            raw_str.trim_end_matches('/').to_string()
        } else {
            let proc_mounts = std::fs::read_to_string("/proc/mounts")?;
            resolve_linux_mount_block_device_from_proc_mounts(volume_path, &proc_mounts)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "Cannot resolve Linux block device for '{}' to apply BLKROSET",
                            volume_path.display()
                        ),
                    )
                })?
        };
        let dev_node = std::fs::canonicalize(&resolved_raw)
            .unwrap_or_else(|_| PathBuf::from(&resolved_raw))
            .to_string_lossy()
            .into_owned();
        let dev_path = Path::new(&dev_node);
        let base_dev_opt = normalize_linux_block_device_name(&dev_node);
        let mut transitioned_from_offline = false;
        let state_path_opt = base_dev_opt
            .as_ref()
            .map(|b| Path::new("/sys/block").join(b).join("device/state"));

        // On Linux (`drivers/scsi/sd.c::sd_open`), opening `/dev/sdX*` while `device/state == offline`
        // returns `-ENXIO`. When transitioning to online read-only, bring `device/state` to `running`
        // first (retaining kernel `BLKROSET(1)` set during offline/udev), then re-assert `BLKROSET`,
        // rolling `device/state` back to `offline` fail-closed if `BLKROSET` fails (`CSE-25`).
        if readonly {
            if let Some(ref state_path) = state_path_opt {
                if state_path.exists() {
                    let cur_state = std::fs::read_to_string(state_path).unwrap_or_default();
                    if cur_state.trim().eq_ignore_ascii_case("offline") {
                        write_linux_sysfs_leaf_attr(state_path, "running\n")?;
                        transitioned_from_offline = true;
                    }
                }
            }
        }

        let ro_res = (|| -> io::Result<()> {
            linux_apply_blkroset(dev_path, readonly)?;
            if let Some(ref base_dev) = base_dev_opt {
                let base_dev_path = PathBuf::from(format!("/dev/{base_dev}"));
                if base_dev_path != dev_path && base_dev_path.exists() {
                    linux_apply_blkroset(&base_dev_path, readonly)?;
                }
            }
            Ok(())
        })();

        if let Err(err) = ro_res {
            if transitioned_from_offline {
                if let Some(ref state_path) = state_path_opt {
                    let _ = write_linux_sysfs_leaf_attr(state_path, "offline\n");
                }
            }
            return Err(err);
        }
        Ok(())
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let _ = (volume_path, readonly);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "set_volume_online_readonly is not implemented on this OS",
        ))
    }
}

/// Executes a closure `f` inside a scoped read-only online window for `volume_path`:
/// 1. Strips any unapproved drive-letter mount points (`delete_volume_mount_point`).
/// 2. Brings the disk/volume online read-only (`set_volume_online_readonly(volume_path, true)`).
/// 3. Executes `f()`.
/// 4. Immediately takes the volume back offline (`set_volume_offline(volume_path, true)`), even if `f` fails (`Rows 4, 14–16`).
pub fn with_readonly_volume_window<F, T>(volume_path: &Path, f: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T>,
{
    let raw = volume_path.to_string_lossy();
    for vol in enumerate_usb_volumes() {
        if vol.volume_guid_path.eq_ignore_ascii_case(&raw)
            || vol.mount_points.iter().any(|mp| mp == volume_path)
        {
            for mp in &vol.mount_points {
                let _ = delete_volume_mount_point(&mp.to_string_lossy());
            }
        }
    }
    set_volume_online_readonly(volume_path, true)?;
    let result = f();
    let offline_res = set_volume_offline(volume_path, true);
    match result {
        Ok(val) => {
            offline_res?;
            Ok(val)
        }
        Err(err) => Err(err),
    }
}

/// Queries whether a volume or its physical disk is read-only (`IOCTL_DISK_GET_DISK_ATTRIBUTES`).
pub fn is_volume_readonly(volume_path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const DISK_ATTRIBUTE_READ_ONLY: u64 = 0x0000_0000_0000_0002;
        const GENERIC_READ: u32 = 0x80000000;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        #[repr(C)]
        struct GetDiskAttributes {
            version: u32,
            reserved1: u32,
            attributes: u64,
        }

        let target = resolve_physical_drive_path(volume_path).unwrap_or_else(|| {
            let raw = volume_path.to_string_lossy();
            let trimmed = raw.trim_end_matches('\\');
            if trimmed.starts_with(r"\\.\") || trimmed.starts_with(r"\\?\") {
                trimmed.to_string()
            } else {
                format!(r"\\.\{trimmed}")
            }
        });
        let wide: Vec<u16> = std::ffi::OsStr::new(&target)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return false;
        }
        let mut disk_attrs = GetDiskAttributes {
            version: core::mem::size_of::<GetDiskAttributes>() as u32,
            reserved1: 0,
            attributes: 0,
        };
        let mut bytes_ret: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DISK_ATTRIBUTES,
                core::ptr::null(),
                0,
                &mut disk_attrs as *mut _ as *mut core::ffi::c_void,
                core::mem::size_of::<GetDiskAttributes>() as u32,
                &mut bytes_ret,
                core::ptr::null_mut(),
            )
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        ok != 0 && (disk_attrs.attributes & DISK_ATTRIBUTE_READ_ONLY) != 0
    }
    #[cfg(not(windows))]
    {
        let target = volume_path.to_string_lossy();
        let trimmed = target.trim_end_matches('/');
        if trimmed.is_empty() {
            return false;
        }
        // 1. Check `/sys/block/<dev>/ro` when given `/dev/<block>` or a partition `/dev/sdX1`
        if let Some(dev_name) = trimmed.strip_prefix("/dev/") {
            let base_dev = dev_name.trim_end_matches(|c: char| c.is_ascii_digit());
            for candidate in [dev_name, base_dev] {
                let ro_path = Path::new("/sys/block").join(candidate).join("ro");
                if let Ok(val) = std::fs::read_to_string(&ro_path) {
                    if val.trim() == "1" {
                        return true;
                    }
                }
            }
        }
        // 2. Check `/proc/mounts` for `ro` mount option
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let mut parts = line.split_whitespace();
                let dev = parts.next().unwrap_or("");
                let mnt = parts.next().unwrap_or("");
                let _fstype = parts.next().unwrap_or("");
                let opts = parts.next().unwrap_or("");
                let dev_matches =
                    dev == trimmed || (trimmed.starts_with("/dev/") && dev.starts_with(trimmed));
                let mnt_matches = mnt == trimmed || mnt.starts_with(&format!("{trimmed}/"));
                if dev_matches || mnt_matches {
                    return opts.split(',').any(|o| o == "ro");
                }
            }
        }
        false
    }
}

/// Queries whether a volume or its underlying physical disk is offline (`IOCTL_VOLUME_IS_OFFLINE`
/// and `IOCTL_DISK_GET_DISK_ATTRIBUTES` on `\\.\PhysicalDriveN`) (`Master Plan v2 §0.1`, Row 20).
pub fn is_volume_offline(volume_path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const DISK_ATTRIBUTE_OFFLINE: u64 = 0x0000_0000_0000_0001;
        const GENERIC_READ: u32 = 0x80000000;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        #[repr(C)]
        struct GetDiskAttributes {
            version: u32,
            reserved1: u32,
            attributes: u64,
        }

        let raw = volume_path.to_string_lossy();
        let trimmed = raw.trim_end_matches('\\');
        let device_path = if trimmed.starts_with(r"\\.\") || trimmed.starts_with(r"\\?\") {
            trimmed.to_string()
        } else {
            format!(r"\\.\{trimmed}")
        };
        let wide: Vec<u16> = std::ffi::OsStr::new(&device_path)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if handle != INVALID_HANDLE_VALUE && handle != 0 {
            let mut bytes_ret: u32 = 0;
            let vol_offline = unsafe {
                DeviceIoControl(
                    handle,
                    IOCTL_VOLUME_IS_OFFLINE,
                    core::ptr::null(),
                    0,
                    core::ptr::null_mut(),
                    0,
                    &mut bytes_ret,
                    core::ptr::null_mut(),
                )
            };
            unsafe {
                let _ = CloseHandle(handle);
            }
            if vol_offline != 0 {
                return true;
            }
        }

        if let Some(phys_path) = resolve_physical_drive_path(volume_path) {
            let wide_phys: Vec<u16> = std::ffi::OsStr::new(&phys_path)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let h_phys = unsafe {
                CreateFileW(
                    wide_phys.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ_WRITE,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    0,
                )
            };
            if h_phys != INVALID_HANDLE_VALUE && h_phys != 0 {
                let mut disk_attrs = GetDiskAttributes {
                    version: core::mem::size_of::<GetDiskAttributes>() as u32,
                    reserved1: 0,
                    attributes: 0,
                };
                let mut bytes_ret: u32 = 0;
                let ok_disk = unsafe {
                    DeviceIoControl(
                        h_phys,
                        IOCTL_DISK_GET_DISK_ATTRIBUTES,
                        core::ptr::null(),
                        0,
                        &mut disk_attrs as *mut _ as *mut core::ffi::c_void,
                        core::mem::size_of::<GetDiskAttributes>() as u32,
                        &mut bytes_ret,
                        core::ptr::null_mut(),
                    )
                };
                unsafe {
                    let _ = CloseHandle(h_phys);
                }
                if ok_disk != 0 && (disk_attrs.attributes & DISK_ATTRIBUTE_OFFLINE) != 0 {
                    return true;
                }
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        let target = volume_path.to_string_lossy();
        let trimmed = target.trim_end_matches('/');
        if trimmed.is_empty() {
            return false;
        }
        let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
            return false;
        };
        for line in mounts.lines() {
            let mut parts = line.split_whitespace();
            let dev = parts.next().unwrap_or("");
            let mnt = parts.next().unwrap_or("");
            let _fstype = parts.next().unwrap_or("");
            let opts = parts.next().unwrap_or("");
            let dev_matches =
                dev == trimmed || (trimmed.starts_with("/dev/") && dev.starts_with(trimmed));
            let mnt_matches = mnt == trimmed || mnt.starts_with(&format!("{trimmed}/"));
            if dev_matches || mnt_matches {
                // Any read-write mount means the volume is NOT offline.
                // Even if mounted read-only, a mounted volume in `/proc/mounts` is online unless `/sys/block/<dev>/ro` is enforced and unmounted.
                let _ = opts;
                return false;
            }
        }
        // Also inspect `/sys/block/<dev>/ro` and `/sys/block/<dev>/device/state` when a `/dev/` node is passed
        if let Some(dev_name) = trimmed.strip_prefix("/dev/") {
            let base_dev = dev_name.trim_end_matches(|c: char| c.is_ascii_digit());
            let sys_block = Path::new("/sys/block").join(base_dev);
            if sys_block.exists() {
                if let Ok(state) = std::fs::read_to_string(sys_block.join("device/state")) {
                    if state.trim().eq_ignore_ascii_case("offline") {
                        return true;
                    }
                }
                if let Ok(ro) = std::fs::read_to_string(sys_block.join("ro")) {
                    // Unmounted block device with ro=1 or unmounted block device not present in /proc/mounts
                    let _ = ro.trim();
                }
            }
        }
        true
    }
}

/// Removes an unapproved drive letter or volume mount point (`DeleteVolumeMountPointW`).
pub fn delete_volume_mount_point(mount_point: &str) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let normalized = if mount_point.ends_with('\\') {
            mount_point.to_string()
        } else {
            format!("{mount_point}\\")
        };
        let wide: Vec<u16> = std::ffi::OsStr::new(&normalized)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let ok = unsafe { DeleteVolumeMountPointW(wide.as_ptr()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        linux_umount_detach(mount_point)
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let _ = mount_point;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "delete_volume_mount_point is not implemented on this OS",
        ))
    }
}

/// Applies `NoDriveTypeAutoRun = 0xFF` under **`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`**
/// AND `AutoRun = 0` under **`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom`** (plus `HKCU`),
/// propagating registry errors (`High #13`, Rows 143, 226).
pub fn apply_autoplay_suppression_policy() -> io::Result<()> {
    #[cfg(windows)]
    {
        write_registry_dword(
            false,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun",
            0xFF,
        )?;
        write_registry_dword(
            false,
            r"SYSTEM\CurrentControlSet\Services\cdrom",
            "AutoRun",
            0,
        )?;
        let _ = write_registry_dword(
            true,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun",
            0xFF,
        );
        info!("Applied HKLM NoDriveTypeAutoRun = 0xFF and cdrom AutoRun = 0");
    }
    Ok(())
}

/// Applies class-scoped Windows removable storage restrictions (`CSE-24`):
/// - `RemovableStorageDevices` (`Deny_All = 1`, `Deny_Execute = 1`, `Deny_Write = 1`, plus scoped
///   Removable Disk `{53f5630d-...}` & WPD `{6AC27878-...}` / `{F33FDC04-...}` class subkeys)
/// - `StorageDevicePolicies` (`WriteProtect = 1`)
/// - `DeviceInstall\Restrictions`: explicitly sets `DenyUnspecified = 0` (so USB-C docks,
///   webcams, YubiKeys, headsets, and HMI touchscreens are NEVER bricked), enforces class-scoped
///   `DenyDeviceIDs = 1` (`USBSTOR\*`, `USB\Class_08`, `WPD\*`, `USB\MS_COMP_MTP`) and
///   `DenyDeviceClasses = 1` (`WPD` setup class GUID `{eec5ad98-...}`), and populates
///   `AllowDeviceIDs = 1` with operator-approved `allowed_hardware_ids` (`Rows 17, 140`, `CSE-24`).
pub fn apply_usb_storage_and_install_policies(allowed_hardware_ids: &[String]) -> io::Result<()> {
    let spec = build_windows_scoped_storage_install_policy(allowed_hardware_ids);
    #[cfg(windows)]
    {
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
            "Deny_All",
            1,
        )?;
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
            "Deny_Execute",
            1,
        )?;
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
            "Deny_Write",
            1,
        )?;
        for class_guid in &spec.removable_storage_class_guids {
            let subkey = format!(
                r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{class_guid}"
            );
            write_registry_dword(false, &subkey, "Deny_Read", 1)?;
            write_registry_dword(false, &subkey, "Deny_Write", 1)?;
            write_registry_dword(false, &subkey, "Deny_Execute", 1)?;
        }
        write_registry_dword(
            false,
            r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
            "WriteProtect",
            1,
        )?;
        // CSE-24: NEVER enforce global `DenyUnspecified=1`; scope installation blocks strictly to
        // USB mass storage (`USBSTOR` / `USB\Class_08`) and WPD portable devices.
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyUnspecified",
            u32::from(spec.deny_unspecified),
        )?;
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceIDs",
            1,
        )?;
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceIDsRetroactive",
            1,
        )?;
        // Purge stale higher-numbered entries before repopulating exact scoped lists (`CSE-24`)
        clear_registry_subkey(
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs",
        )?;
        for (idx, deny_id) in spec.deny_device_ids.iter().enumerate() {
            let name = (idx + 1).to_string();
            write_registry_sz(
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs",
                &name,
                deny_id,
            )?;
        }
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceClasses",
            1,
        )?;
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceClassesRetroactive",
            1,
        )?;
        clear_registry_subkey(
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses",
        )?;
        for (idx, class_guid) in spec.deny_device_class_guids.iter().enumerate() {
            let name = (idx + 1).to_string();
            write_registry_sz(
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses",
                &name,
                class_guid,
            )?;
        }
        clear_registry_subkey(
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs",
        )?;
        if spec.allow_device_ids.is_empty() {
            write_registry_dword(
                false,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
                "AllowDeviceIDs",
                0,
            )?;
            write_registry_dword(
                false,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
                "AllowDenyLayered",
                0,
            )?;
        } else {
            write_registry_dword(
                false,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
                "AllowDeviceIDs",
                1,
            )?;
            // Enable layered evaluation so explicit AllowDeviceIDs exceptions take precedence
            // over scoped DenyDeviceIDs / DenyDeviceClasses rules on Windows (`CSE-24`).
            write_registry_dword(
                false,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
                "AllowDenyLayered",
                1,
            )?;
            for (idx, hw_id) in spec.allow_device_ids.iter().enumerate() {
                let name = (idx + 1).to_string();
                write_registry_sz(
                    r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs",
                    &name,
                    hw_id,
                )?;
            }
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use rand::RngCore;
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let _ = spec;
        let rules = render_linux_udev_usb_storage_rules(allowed_hardware_ids);
        let rules_path = Path::new(LINUX_UDEV_RULES_PATH);
        let parent = rules_path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid udev rules path")
        })?;
        if !parent.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("udev rules directory '{}' not found", parent.display()),
            ));
        }
        // Check symlink_metadata (not .exists()) so dangling symlinks at rules_path fail closed.
        match std::fs::symlink_metadata(rules_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Refusing symlink at Linux udev rules target '{}'",
                        rules_path.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let nonce_hex = u64::from_le_bytes(nonce);
        let tmp_path = parent.join(format!(
            ".99-omniconnect-sentinel.rules.{}.{nonce_hex:016x}.tmp",
            std::process::id()
        ));
        let mut tmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp_path)?;
        let write_res = (|| -> io::Result<()> {
            tmp_file.write_all(rules.as_bytes())?;
            tmp_file.sync_all()?;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o644))?;
            Ok(())
        })();
        drop(tmp_file);
        if let Err(e) = write_res {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp_path, rules_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
        let _ = crate::fs_lowlevel::sync_directory(parent);

        let status = std::process::Command::new("udevadm")
            .args(["control", "--reload-rules"])
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "udevadm control --reload-rules exited with status {status}"
            )));
        }
        Ok(())
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let _ = spec;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "apply_usb_storage_and_install_policies is not implemented on this OS",
        ))
    }
}

/// Enumerates real USB PnP device nodes via `CM_Get_Device_ID_ListW` (`cfgmgr32.dll`) on Windows
/// and `/sys/bus/usb/devices` on Linux, keyed per physical device instance (so two identical
/// `VID`/`PID` devices on different ports/serials never collide) and inspecting compatible IDs /
/// services / interface classes to detect composite HID (`0x03`) + Mass Storage (`0x08`) BadUSB
/// devices (`Row 142`, `CSE-24`).
pub fn enumerate_usb_pnp_devices() -> Vec<UsbPnpDeviceInfo> {
    let mut grouped: HashMap<String, UsbPnpDeviceInfo> = HashMap::new();

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const CM_GETIDLIST_FILTER_ENUMERATOR: u32 = 0x0000_0004;
        const CM_GETIDLIST_FILTER_PRESENT: u32 = 0x0000_0100;
        const CM_DRP_COMPATIBLEIDS: u32 = 0x0000_0003;
        const CM_DRP_SERVICE: u32 = 0x0000_0005;
        const CM_DRP_CLASS: u32 = 0x0000_0008;

        let filter: Vec<u16> = std::ffi::OsStr::new("USB")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let flags = CM_GETIDLIST_FILTER_ENUMERATOR | CM_GETIDLIST_FILTER_PRESENT;
        let mut list_chars: u32 = 0;
        if unsafe { CM_Get_Device_ID_List_SizeW(&mut list_chars, filter.as_ptr(), flags) } == 0
            && list_chars > 1
        {
            let mut buf = vec![0u16; list_chars as usize];
            if unsafe {
                CM_Get_Device_ID_ListW(filter.as_ptr(), buf.as_mut_ptr(), list_chars, flags)
            } == 0
            {
                let mut start = 0usize;
                while start < buf.len() && buf[start] != 0 {
                    let end = buf[start..]
                        .iter()
                        .position(|&c| c == 0)
                        .map(|p| start + p)
                        .unwrap_or(buf.len());
                    let id_str = String::from_utf16_lossy(&buf[start..end]);
                    start = end + 1;

                    let Some((vid, pid, serial)) = parse_windows_usb_vid_pid_serial(&id_str) else {
                        continue;
                    };

                    let mut is_storage = false;
                    let mut is_hid = false;
                    let is_child_mi = id_str.to_ascii_uppercase().contains("&MI_");
                    let mut canonical_parent_id = id_str.clone();

                    let wide_id: Vec<u16> = std::ffi::OsStr::new(&id_str)
                        .encode_wide()
                        .chain(Some(0))
                        .collect();
                    let mut dev_inst: u32 = 0;
                    if unsafe { CM_Locate_DevNodeW(&mut dev_inst, wide_id.as_ptr(), 0) } == 0 {
                        if is_child_mi {
                            let mut cur = dev_inst;
                            for _ in 0..MAX_USB_TOPOLOGY_HOPS {
                                let mut parent_inst: u32 = 0;
                                if unsafe { CM_Get_Parent(&mut parent_inst, cur, 0) } != 0
                                    || parent_inst == 0
                                    || parent_inst == cur
                                {
                                    break;
                                }
                                if let Some(parent_id) = read_cm_device_id(parent_inst) {
                                    let p_upper = parent_id.to_ascii_uppercase();
                                    if p_upper.starts_with("USB\\VID_") && !p_upper.contains("&MI_")
                                    {
                                        canonical_parent_id = parent_id;
                                        break;
                                    }
                                }
                                cur = parent_inst;
                            }
                        }
                        for prop_id in [CM_DRP_COMPATIBLEIDS, CM_DRP_SERVICE, CM_DRP_CLASS] {
                            let mut reg_type: u32 = 0;
                            let mut prop_buf = [0u16; 512];
                            let mut prop_len: u32 = (prop_buf.len() * 2) as u32;
                            if unsafe {
                                CM_Get_DevNode_Registry_PropertyW(
                                    dev_inst,
                                    prop_id,
                                    &mut reg_type,
                                    prop_buf.as_mut_ptr() as *mut core::ffi::c_void,
                                    &mut prop_len,
                                    0,
                                )
                            } == 0
                            {
                                let u16_count = (prop_len as usize / 2).min(prop_buf.len());
                                let text = String::from_utf16_lossy(&prop_buf[..u16_count])
                                    .to_ascii_uppercase();
                                if text.contains("CLASS_08")
                                    || text.contains("USBSTOR")
                                    || text.contains("UASPSTOR")
                                    || text.contains("DISKDRIVE")
                                {
                                    is_storage = true;
                                }
                                if text.contains("CLASS_03")
                                    || text.contains("HIDUSB")
                                    || text.contains("HIDCLASS")
                                    || text.contains("KBDHID")
                                    || text.contains("KEYBOARD")
                                {
                                    is_hid = true;
                                }
                            }
                        }
                    }

                    let group_key = canonical_parent_id.to_ascii_uppercase();
                    let parent_serial = parse_windows_usb_vid_pid_serial(&canonical_parent_id)
                        .map(|(_, _, s)| s)
                        .unwrap_or_else(|| serial.clone());
                    let entry = grouped
                        .entry(group_key)
                        .or_insert_with(|| UsbPnpDeviceInfo {
                            instance_id: canonical_parent_id.clone(),
                            vid,
                            pid,
                            serial: parent_serial,
                            interface_classes: Vec::new(),
                            child_instance_ids: Vec::new(),
                            has_mass_storage: false,
                            has_hid_input: false,
                            is_composite_hid_storage: false,
                        });
                    if !is_child_mi {
                        entry.instance_id = id_str.clone();
                        entry.serial = serial;
                    } else if !entry.child_instance_ids.contains(&id_str) {
                        entry.child_instance_ids.push(id_str);
                    }
                    if is_storage {
                        entry.has_mass_storage = true;
                        if !entry.interface_classes.contains(&0x08) {
                            entry.interface_classes.push(0x08);
                        }
                    }
                    if is_hid {
                        entry.has_hid_input = true;
                        if !entry.interface_classes.contains(&0x03) {
                            entry.interface_classes.push(0x03);
                        }
                    }
                    entry.is_composite_hid_storage = entry.has_mass_storage && entry.has_hid_input;
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
            for entry in entries.flatten() {
                let p = entry.path();
                let dev_name = entry.file_name().to_string_lossy().to_string();
                if !is_valid_linux_usb_bus_port(&dev_name) {
                    continue;
                }
                let Ok(vid_str) = std::fs::read_to_string(p.join("idVendor")) else {
                    continue;
                };
                let Ok(pid_str) = std::fs::read_to_string(p.join("idProduct")) else {
                    continue;
                };
                let Ok(vid) = u16::from_str_radix(vid_str.trim(), 16) else {
                    continue;
                };
                let Ok(pid) = u16::from_str_radix(pid_str.trim(), 16) else {
                    continue;
                };
                let serial = std::fs::read_to_string(p.join("serial"))
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| dev_name.clone());

                let mut classes = Vec::new();
                let mut children = Vec::new();
                if let Ok(sub_entries) = std::fs::read_dir(&p) {
                    for sub in sub_entries.flatten() {
                        let sub_name = sub.file_name().to_string_lossy().to_string();
                        if sub_name.starts_with(&format!("{dev_name}:")) {
                            children.push(sub_name);
                            if let Ok(cls_str) =
                                std::fs::read_to_string(sub.path().join("bInterfaceClass"))
                            {
                                if let Ok(cls) = u8::from_str_radix(cls_str.trim(), 16) {
                                    if !classes.contains(&cls) {
                                        classes.push(cls);
                                    }
                                }
                            }
                        }
                    }
                }
                let has_storage = classes.contains(&0x08);
                let has_hid = classes.contains(&0x03);
                grouped.insert(
                    dev_name.clone(),
                    UsbPnpDeviceInfo {
                        instance_id: dev_name,
                        vid,
                        pid,
                        serial,
                        interface_classes: classes,
                        child_instance_ids: children,
                        has_mass_storage: has_storage,
                        has_hid_input: has_hid,
                        is_composite_hid_storage: has_storage && has_hid,
                    },
                );
            }
        }
    }

    let mut devices: Vec<UsbPnpDeviceInfo> = grouped.into_values().collect();
    devices.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
    devices
}

/// Checks if a USB device instance ID or `USB\VID_xxxx&PID_yyyy...` string matches any entry in
/// `allowed_hardware_ids` (supporting `*` suffix wildcards such as `USB\VID_0781&*`).
pub fn is_hardware_id_allowed(device_id: &str, allowed_hardware_ids: &[String]) -> bool {
    let candidate = device_id.to_ascii_uppercase();
    for pattern in allowed_hardware_ids {
        let pat = pattern.trim().to_ascii_uppercase();
        if pat.is_empty() {
            continue;
        }
        if let Some(prefix) = pat.strip_suffix('*') {
            if candidate.starts_with(prefix) || candidate.contains(prefix) {
                return true;
            }
        } else if candidate == pat || candidate.starts_with(&format!("{pat}\\")) {
            return true;
        }
    }
    false
}

/// One-time cleanup of previously installed, unapproved USB storage/composite devices and unapproved
/// mounted USB volumes (`Master Plan v2 §3.1`, Rows 14, 15, 141).
pub fn cleanup_unapproved_usb_devices(allowed_hardware_ids: &[String]) -> io::Result<Vec<String>> {
    let mut disabled = Vec::new();
    for dev in enumerate_usb_pnp_devices() {
        let hw_key = format!("USB\\VID_{:04X}&PID_{:04X}", dev.vid, dev.pid);
        if (dev.has_mass_storage || dev.is_composite_hid_storage)
            && !is_hardware_id_allowed(&hw_key, allowed_hardware_ids)
            && !is_hardware_id_allowed(&dev.instance_id, allowed_hardware_ids)
            && disable_device_node(&dev.instance_id).is_ok()
        {
            disabled.push(dev.instance_id);
        }
    }
    for vol in enumerate_usb_volumes() {
        for mp in &vol.mount_points {
            let _ = delete_volume_mount_point(&mp.to_string_lossy());
        }
        if !vol.is_offline {
            let _ = set_volume_offline(Path::new(&vol.volume_guid_path), true);
        }
    }
    Ok(disabled)
}

/// Disables a PnP device node via Configuration Manager (`CM_Locate_DevNodeW` + `CM_Disable_DevNode`)
/// or writes `0` to `/sys/bus/usb/devices/<id>/authorized` on Linux (`BUG-CORE-13`, Rows 142, 144).
pub fn disable_device_node(device_instance_id: &str) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = std::ffi::OsStr::new(device_instance_id)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut dev_inst: u32 = 0;
        let cr_locate = unsafe { CM_Locate_DevNodeW(&mut dev_inst, wide.as_ptr(), 0) };
        if cr_locate != 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("CM_Locate_DevNodeW({device_instance_id}) returned CR={cr_locate:#x}"),
            ));
        }
        let cr_disable = unsafe { CM_Disable_DevNode(dev_inst, 0) };
        if cr_disable != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("CM_Disable_DevNode({device_instance_id}) returned CR={cr_disable:#x}"),
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let sysfs_path = resolve_linux_usb_authorized_sysfs_path(device_instance_id, false)?;
        write_linux_sysfs_leaf_attr(&sysfs_path, "0\n")
    }
}

/// Disables a specific USB interface on a composite device (`CM_Disable_DevNode` on child `MI_xx`
/// node on Windows, or writing `0` to `/sys/bus/usb/devices/<bus-port>:<cfg>.<intf>/authorized` on Linux) (`Row 144`, `CSE-25`).
pub fn disable_usb_interface(device_id: &str, interface_id: &str) -> io::Result<()> {
    #[cfg(windows)]
    {
        let _ = device_id;
        disable_device_node(interface_id)
    }
    #[cfg(not(windows))]
    {
        let target = if interface_id.contains(':') {
            interface_id.trim().to_string()
        } else {
            format!("{}:{}", device_id.trim(), interface_id.trim())
        };
        let sysfs_path = resolve_linux_usb_authorized_sysfs_path(&target, true)?;
        write_linux_sysfs_leaf_attr(&sysfs_path, "0\n")
    }
}

/// Re-enables a PnP device node after explicit user-presence confirmation (`CM_Locate_DevNodeW` +
/// `CM_Enable_DevNode` on Windows, or writing `1` to `/sys/bus/usb/devices/<id>/authorized` on Linux) (`Rows 3, 142, 144`, `CSE-25`).
pub fn enable_device_node(device_instance_id: &str) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = std::ffi::OsStr::new(device_instance_id)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut dev_inst: u32 = 0;
        let cr_locate = unsafe { CM_Locate_DevNodeW(&mut dev_inst, wide.as_ptr(), 0) };
        if cr_locate != 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("CM_Locate_DevNodeW({device_instance_id}) returned CR={cr_locate:#x}"),
            ));
        }
        let cr_enable = unsafe { CM_Enable_DevNode(dev_inst, 0) };
        if cr_enable != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("CM_Enable_DevNode({device_instance_id}) returned CR={cr_enable:#x}"),
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let sysfs_path = resolve_linux_usb_authorized_sysfs_path(device_instance_id, false)?;
        write_linux_sysfs_leaf_attr(&sysfs_path, "1\n")
    }
}

/// RAII handle for an active OS PnP notification subscription (`CM_Register_Notification` on Windows).
pub struct PnpNotificationGuard {
    #[cfg(windows)]
    notify_handle: isize,
    #[cfg(windows)]
    context_ptr: *mut Box<dyn Fn() + Send + Sync>,
}

unsafe impl Send for PnpNotificationGuard {}
unsafe impl Sync for PnpNotificationGuard {}

#[cfg(windows)]
unsafe extern "system" fn cm_pnp_notify_callback(
    _h_notify: isize,
    context: *mut core::ffi::c_void,
    _action: u32,
    _event_data: *const core::ffi::c_void,
    _event_data_size: u32,
) -> u32 {
    if !context.is_null() {
        let cb = &*(context as *const Box<dyn Fn() + Send + Sync>);
        cb();
    }
    0 // ERROR_SUCCESS
}

/// Registers an OS PnP device-arrival notification callback via `CM_Register_Notification` on Windows
/// or spawns a `NETLINK_KOBJECT_UEVENT` listener thread on Linux (`Master Plan v2 §3.1`, Row 137).
pub fn register_pnp_notification_watcher<F>(on_device_event: F) -> io::Result<PnpNotificationGuard>
where
    F: Fn() + Send + Sync + 'static,
{
    #[cfg(windows)]
    {
        const CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES: u32 = 0x0000_0002;
        const CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE: u32 = 1;

        let filter = CmNotifyFilter {
            cb_size: core::mem::size_of::<CmNotifyFilter>() as u32,
            flags: CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES,
            filter_type: CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE,
            reserved: 0,
            u_data: [0u8; 400],
        };
        let boxed_cb: Box<Box<dyn Fn() + Send + Sync>> = Box::new(Box::new(on_device_event));
        let ctx_ptr = Box::into_raw(boxed_cb);
        let mut notify_handle: isize = 0;

        let cr = unsafe {
            CM_Register_Notification(
                &filter,
                ctx_ptr as *mut core::ffi::c_void,
                cm_pnp_notify_callback,
                &mut notify_handle,
            )
        };
        if cr != 0 {
            unsafe {
                let _ = Box::from_raw(ctx_ptr);
            }
            return Err(io::Error::other(format!(
                "CM_Register_Notification failed with CR={cr:#x}"
            )));
        }
        debug!(
            "Registered CM_Register_Notification PnP handle {}",
            notify_handle
        );
        Ok(PnpNotificationGuard {
            notify_handle,
            context_ptr: ctx_ptr,
        })
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "linux")]
        {
            std::thread::spawn(move || {
                const NETLINK_KOBJECT_UEVENT: libc::c_int = 15;
                let sock = unsafe {
                    libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)
                };
                if sock >= 0 {
                    let mut addr: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
                    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
                    addr.nl_pid = std::process::id();
                    addr.nl_groups = 1;
                    if unsafe {
                        libc::bind(
                            sock,
                            &addr as *const _ as *const libc::sockaddr,
                            core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                        )
                    } == 0
                    {
                        let mut buf = [0u8; 4096];
                        loop {
                            let n = unsafe {
                                libc::recv(
                                    sock,
                                    buf.as_mut_ptr() as *mut libc::c_void,
                                    buf.len(),
                                    0,
                                )
                            };
                            if n <= 0 {
                                break;
                            }
                            on_device_event();
                        }
                    }
                    unsafe {
                        let _ = libc::close(sock);
                    }
                }
            });
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = on_device_event;
        }
        Ok(PnpNotificationGuard {})
    }
}

impl Drop for PnpNotificationGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.notify_handle != 0 {
                unsafe {
                    let _ = CM_Unregister_Notification(self.notify_handle);
                }
            }
            if !self.context_ptr.is_null() {
                unsafe {
                    let _ = Box::from_raw(self.context_ptr);
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn check_linux_usb_authorized_default() -> Option<bool> {
    let usb_dir = std::path::Path::new("/sys/bus/usb/devices");
    if !usb_dir.exists() {
        return None;
    }
    let mut found_any = false;
    if let Ok(entries) = std::fs::read_dir(usb_dir) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("usb") {
                found_any = true;
                let p = entry.path().join("authorized_default");
                if let Ok(s) = std::fs::read_to_string(p) {
                    if s.trim() != "0" {
                        return Some(false);
                    }
                }
            }
        }
    }
    Some(found_any)
}

/// Queries the actual host OS controls for Phase 0.1 `verify_posture()` (`BUG-CORE-13`, Rows 19–21).
/// Uses `enumerate_usb_volumes()` keyed by Volume GUID (`\\?\Volume{GUID}\`) so letterless and
/// `BusTypeUsb` volumes are always checked.
pub fn verify_system_posture() -> PostureReport {
    let automount_disabled = query_automount_disabled();
    #[cfg(windows)]
    let (
        user_deny_policy_present,
        install_restrictions_active,
        write_protect_active,
        autoplay_suppressed,
    ) = {
        let user_deny_all = read_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
            "Deny_All",
        ) == Some(1);
        let scoped_removable_classes_denied =
            REMOVABLE_STORAGE_POLICY_CLASS_GUIDS.iter().all(|guid| {
                let subkey =
                    format!(r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{guid}");
                read_registry_dword(false, &subkey, "Deny_Read") == Some(1)
                    && read_registry_dword(false, &subkey, "Deny_Write") == Some(1)
                    && read_registry_dword(false, &subkey, "Deny_Execute") == Some(1)
            });
        let deny_unspecified = read_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyUnspecified",
        ) == Some(1);
        let deny_device_ids = read_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceIDs",
        ) == Some(1);
        let deny_device_classes = read_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceClasses",
        ) == Some(1);
        let deny_id_vals = enumerate_registry_string_values(
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs",
        );
        let deny_class_vals = enumerate_registry_string_values(
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses",
        );
        let scoped_ok = verify_scoped_storage_registry_lists(
            deny_unspecified,
            deny_device_ids,
            deny_device_classes,
            &deny_id_vals,
            &deny_class_vals,
        );
        let wp = read_registry_dword(
            false,
            r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
            "WriteProtect",
        ) == Some(1);
        let ap = read_registry_dword(
            false,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun",
        ) == Some(0xFF)
            && read_registry_dword(false, r"SYSTEM\CurrentControlSet\Services\cdrom", "AutoRun")
                .unwrap_or(0)
                == 0;
        (
            user_deny_all && scoped_removable_classes_denied,
            scoped_ok,
            wp,
            ap,
        )
    };
    #[cfg(not(windows))]
    let (
        user_deny_policy_present,
        install_restrictions_active,
        write_protect_active,
        autoplay_suppressed,
    ) = {
        let udev_rules_ok = std::fs::read_to_string(LINUX_UDEV_RULES_PATH)
            .map(|text| verify_linux_udev_rules_content(&text))
            .unwrap_or(false);
        (udev_rules_ok, udev_rules_ok, udev_rules_ok, udev_rules_ok)
    };

    let usb_volumes = enumerate_usb_volumes();
    let bay1_hint = std::env::var(SENTINEL_KIOSK_BAY1_RO_DEVICE_ENV).ok();
    let bay2_hint = std::env::var(SENTINEL_KIOSK_BAY2_RW_DEVICE_ENV).ok();
    let hardware_write_blocker = detect_hardware_write_blocker_state(
        bay1_hint.as_deref(),
        bay2_hint.as_deref(),
        &usb_volumes,
    );
    let removable_volumes_offline = usb_volumes
        .into_iter()
        .map(|v| (v.volume_guid_path, v.is_offline))
        .collect();

    #[cfg(windows)]
    let linux_auth = None;
    #[cfg(not(windows))]
    let linux_auth = check_linux_usb_authorized_default();

    PostureReport {
        automount_disabled,
        removable_volumes_offline,
        user_deny_policy_present,
        install_restrictions_active,
        write_protect_active,
        autoplay_suppressed,
        linux_authorized_default_zero: linux_auth,
        hardware_write_blocker,
    }
}

#[cfg(windows)]
fn query_w32time_service_running() -> Option<bool> {
    use std::os::windows::ffi::OsStrExt;
    const SC_MANAGER_CONNECT: u32 = 0x0001;
    const SERVICE_QUERY_STATUS: u32 = 0x0004;
    const SERVICE_RUNNING: u32 = 0x0000_0004;

    let svc_name: Vec<u16> = std::ffi::OsStr::new("W32Time")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let scm = unsafe { OpenSCManagerW(core::ptr::null(), core::ptr::null(), SC_MANAGER_CONNECT) };
    if scm == 0 {
        return None;
    }
    let svc = unsafe { OpenServiceW(scm, svc_name.as_ptr(), SERVICE_QUERY_STATUS) };
    if svc == 0 {
        unsafe {
            let _ = CloseServiceHandle(scm);
        }
        return None;
    }
    let mut status = Win32ServiceStatus {
        dw_service_type: 0,
        dw_current_state: 0,
        dw_controls_accepted: 0,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: 0,
    };
    let ok = unsafe { QueryServiceStatus(svc, &mut status) };
    unsafe {
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }
    if ok != 0 {
        Some(status.dw_current_state == SERVICE_RUNNING)
    } else {
        None
    }
}

/// Maximum permitted elapsed sync age (24 hours) before NTP or hardware clock status is
/// classified as stale (`ntp_synchronized: false`, `stratum: None`) (`CSE-26`).
pub const NTP_MAX_STALE_AGE_SECS: i64 = 24 * 60 * 60;

/// Environment variable containing an explicit inline air-gapped `IRIG-B`/`PTP` hardware clock
/// attestation payload (flat JSON object or `key=value` pairs) (`CSE-26`).
pub const SENTINEL_AIRGAP_CLOCK_ATTESTATION_ENV: &str = "SENTINEL_AIRGAP_CLOCK_ATTESTATION";

/// Environment variable pointing to a symlink-checked local configuration file containing an
/// air-gapped `IRIG-B`/`PTP` hardware clock attestation payload (`CSE-26`).
pub const SENTINEL_AIRGAP_CLOCK_CONFIG_ENV: &str = "SENTINEL_AIRGAP_CLOCK_CONFIG";

/// Explicit air-gapped hardware clock attestation configuration (`IRIG-B` or IEEE-1588 `PTP`)
/// for disconnected OT/ICS kiosks without external NTP reachability (`CSE-26`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AirgapHardwareClockAttestation {
    /// Supported hardware timing protocol: `"IRIG-B"` or `"PTP"`.
    pub protocol: String,
    /// Hardware time-receiver identifier (e.g., `"Meinberg-IRIG-B0"`, `"ptp0"`).
    pub device_id: String,
    /// Hardware stratum (`1..=4`).
    pub stratum: u8,
    /// Whether the hardware timing receiver holds active lock.
    pub locked: bool,
    /// Unix timestamp (seconds, UTC) of the last verified receiver lock heartbeat.
    pub last_locked_unix: i64,
    /// Maximum timing uncertainty bound in microseconds.
    pub max_error_us: u64,
}

/// Evaluates an air-gapped `IRIG-B` / `PTP` hardware clock attestation at `now_unix` (`CSE-26`).
///
/// Returns `None` if `protocol` is not `IRIG-B`/`PTP`, `device_id` is empty, or `stratum` is
/// outside `1..=4`. Returns `Some(NtpSyncStatus)` with `ntp_synchronized: false` and
/// `stratum: None` when unlocked, future-skewed (`> 60s`), or stale (`> 24h`).
pub fn evaluate_airgap_hardware_clock_attestation(
    cfg: &AirgapHardwareClockAttestation,
    now_unix: i64,
) -> Option<NtpSyncStatus> {
    let proto_norm = match cfg.protocol.trim().to_ascii_uppercase().as_str() {
        "IRIG-B" | "IRIGB" => "IRIG-B",
        "PTP" | "IEEE-1588" | "IEEE1588" => "PTP",
        _ => return None,
    };
    let device_id = cfg.device_id.trim();
    if device_id.is_empty()
        || device_id.len() > 128
        || device_id.chars().any(|c| c.is_control())
        || !(1..=4).contains(&cfg.stratum)
    {
        return None;
    }

    let fresh_lock = cfg.locked
        && cfg.last_locked_unix > 0
        && cfg.last_locked_unix <= now_unix.saturating_add(60)
        && now_unix.saturating_sub(cfg.last_locked_unix) <= NTP_MAX_STALE_AGE_SECS;

    if fresh_lock {
        Some(NtpSyncStatus {
            ntp_synchronized: true,
            clock_source: format!("HardwareClock({proto_norm}):{device_id}"),
            stratum: Some(cfg.stratum),
            max_error_us: Some(cfg.max_error_us),
        })
    } else {
        Some(NtpSyncStatus {
            ntp_synchronized: false,
            clock_source: format!("HardwareClock({proto_norm},unlocked_or_stale):{device_id}"),
            stratum: None,
            max_error_us: Some(cfg.max_error_us),
        })
    }
}

/// Zero-dependency parser for flat JSON objects or `key=value` lines/semicolon pairs representing
/// `AirgapHardwareClockAttestation` (`CSE-26`).
pub fn parse_airgap_clock_config_str(raw: &str) -> Option<AirgapHardwareClockAttestation> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 {
        return None;
    }
    let mut fields: HashMap<String, String> = HashMap::new();
    let is_json = trimmed.starts_with('{') && trimmed.ends_with('}');
    let body = if is_json {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    let entries: Vec<&str> = if is_json {
        body.split(',').collect()
    } else {
        body.split(['\n', '\r', ';']).collect()
    };
    for entry in entries {
        let part = entry.trim();
        if part.is_empty() || part.starts_with('#') {
            continue;
        }
        let (raw_k, raw_v) = if is_json {
            part.split_once(':')?
        } else {
            part.split_once('=')?
        };
        let k = raw_k.trim().trim_matches('"').trim();
        let v = raw_v.trim().trim_matches('"').trim();
        if k.is_empty() {
            return None;
        }
        // Deny unknown fields strictly (`CSE-26`)
        if !matches!(
            k,
            "protocol" | "device_id" | "stratum" | "locked" | "last_locked_unix" | "max_error_us"
        ) {
            return None;
        }
        fields.insert(k.to_string(), v.to_string());
    }
    Some(AirgapHardwareClockAttestation {
        protocol: fields.get("protocol")?.clone(),
        device_id: fields.get("device_id")?.clone(),
        stratum: fields.get("stratum")?.parse::<u8>().ok()?,
        locked: match fields.get("locked")?.to_ascii_lowercase().as_str() {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => return None,
        },
        last_locked_unix: fields.get("last_locked_unix")?.parse::<i64>().ok()?,
        max_error_us: fields.get("max_error_us")?.parse::<u64>().ok()?,
    })
}

fn civil_to_unix_secs(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
) -> Option<i64> {
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || min > 59
        || sec > 60
    {
        return None;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if day > max_day {
        return None;
    }
    // Howard Hinnant's exact civil-from-days inverse algorithm (days since 1970-01-01)
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m_adj = if month > 2 {
        (month - 3) as i64
    } else {
        (month + 9) as i64
    };
    let doy = (153 * m_adj + 2) / 5 + (day as i64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days
        .checked_mul(86_400)?
        .checked_add((hour as i64) * 3_600)?
        .checked_add((min as i64) * 60)?
        .checked_add(sec.min(59) as i64)?;
    Some(secs)
}

fn parse_w32tm_sync_timestamp_unix(
    raw: &str,
    now_unix_utc: i64,
    local_utc_offset_secs: i64,
) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("unspecified") || lower == "n/a" || lower == "none" || lower == "never" {
        return None;
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 2 {
        return None;
    }
    let date_part = tokens[0].trim_end_matches(',');
    let time_part = tokens[1].trim_end_matches(',');
    let am_pm = tokens.get(2).map(|s| s.to_ascii_uppercase());

    let time_clean = time_part.split('.').next().unwrap_or(time_part);
    let time_nums: Vec<u32> = time_clean
        .split(':')
        .map(|p| p.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()?;
    if time_nums.len() < 2 || time_nums.len() > 3 {
        return None;
    }
    let mut hour = time_nums[0];
    let min = time_nums[1];
    let sec = time_nums.get(2).copied().unwrap_or(0);
    if let Some(ref mer) = am_pm {
        if mer == "AM" || mer == "A.M." {
            if hour == 12 {
                hour = 0;
            } else if hour == 0 || hour > 12 {
                return None;
            }
        } else if mer == "PM" || mer == "P.M." {
            if (1..=11).contains(&hour) {
                hour += 12;
            } else if hour != 12 {
                return None;
            }
        }
    }

    let sep = if date_part.contains('-') {
        '-'
    } else if date_part.contains('/') {
        '/'
    } else if date_part.contains('.') {
        '.'
    } else {
        return None;
    };
    let dnums: Vec<i64> = date_part
        .split(sep)
        .map(|p| p.parse::<i64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if dnums.len() != 3 {
        return None;
    }

    let candidates: Vec<i64> = if dnums[0] >= 1970 {
        // ISO YYYY-MM-DD
        civil_to_unix_secs(dnums[0], dnums[1] as u32, dnums[2] as u32, hour, min, sec)
            .into_iter()
            .collect()
    } else if dnums[2] >= 1970 {
        let a = dnums[0] as u32;
        let b = dnums[1] as u32;
        let y = dnums[2];
        let mut out = Vec::new();
        if a > 12 {
            // Unambiguously DD-MM-YYYY / DD/MM/YYYY
            if let Some(ts) = civil_to_unix_secs(y, b, a, hour, min, sec) {
                out.push(ts);
            }
        } else if b > 12 {
            // Unambiguously MM/DD/YYYY
            if let Some(ts) = civil_to_unix_secs(y, a, b, hour, min, sec) {
                out.push(ts);
            }
        } else {
            // Both a, b <= 12: evaluate MDY and DMY and select the non-future timestamp closest to now
            if let Some(ts) = civil_to_unix_secs(y, a, b, hour, min, sec) {
                out.push(ts);
            }
            if let Some(ts) = civil_to_unix_secs(y, b, a, hour, min, sec) {
                if !out.contains(&ts) {
                    out.push(ts);
                }
            }
        }
        out
    } else {
        return None;
    };

    // Convert parsed local wall-clock seconds to UTC using `local_utc_offset_secs`
    let mut best: Option<i64> = None;
    for local_ts in candidates {
        let utc_ts = local_ts.saturating_sub(local_utc_offset_secs);
        let not_future = utc_ts <= now_unix_utc.saturating_add(300);
        if not_future {
            let delta = now_unix_utc.saturating_sub(utc_ts).abs();
            let replace = match best {
                None => true,
                Some(prev) => delta < now_unix_utc.saturating_sub(prev).abs(),
            };
            if replace {
                best = Some(utc_ts);
            }
        } else if best.is_none() {
            best = Some(utc_ts);
        }
    }
    best
}

fn parse_w32tm_root_dispersion_us(raw: &str) -> Option<u64> {
    let trimmed = raw.trim().trim_end_matches('s').trim();
    let secs: f64 = trimmed.parse().ok()?;
    if !secs.is_finite() || secs < 0.0 {
        return None;
    }
    Some((secs * 1_000_000.0).round() as u64)
}

/// Parses real `w32tm /query /status` output at `now_unix_utc` (converting local wall-clock
/// timestamps using `local_utc_offset_secs`) (`CSE-26`).
///
/// Strictly marks `Local CMOS Clock`, `Free-running System Clock`, `Stratum: 0` / `>= 16`,
/// `Last Successful Sync Time: unspecified`, or stale sync age `> 24h` as
/// `ntp_synchronized: false` with `stratum: None` — NEVER fabricating `stratum: Some(2)`.
pub fn parse_w32tm_status_output_with_tz_offset(
    stdout: &str,
    now_unix_utc: i64,
    local_utc_offset_secs: i64,
) -> Option<NtpSyncStatus> {
    let mut parsed_stratum: Option<u8> = None;
    let mut source: Option<String> = None;
    let mut last_sync_raw: Option<String> = None;
    let mut root_dispersion_us: Option<u64> = None;

    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if let Some((key, val)) = line.split_once(':') {
            let k = key.trim().to_ascii_lowercase();
            let v = val.trim();
            if k == "stratum" {
                let first_tok = v.split_whitespace().next().unwrap_or("");
                if let Ok(s) = first_tok.parse::<u8>() {
                    parsed_stratum = Some(s);
                }
            } else if k == "source" {
                source = Some(v.to_string());
            } else if k == "last successful sync time" {
                last_sync_raw = Some(v.to_string());
            } else if k == "root dispersion" {
                root_dispersion_us = parse_w32tm_root_dispersion_us(v);
            }
        }
    }

    let source_str = source?;
    let source_trimmed = source_str.trim();
    let source_lower = source_trimmed.to_ascii_lowercase();
    let is_unsynced_source = source_trimmed.is_empty()
        || source_lower.contains("local cmos clock")
        || source_lower.contains("free-running system clock")
        || source_lower == "unspecified";

    let valid_stratum = parsed_stratum.filter(|&s| (1..=15).contains(&s));
    let sync_unix_opt = last_sync_raw
        .as_deref()
        .and_then(|raw| parse_w32tm_sync_timestamp_unix(raw, now_unix_utc, local_utc_offset_secs));
    let sync_fresh = sync_unix_opt.is_some_and(|ts| {
        ts <= now_unix_utc.saturating_add(300)
            && now_unix_utc.saturating_sub(ts) <= NTP_MAX_STALE_AGE_SECS
    });

    let ntp_synchronized = !is_unsynced_source && valid_stratum.is_some() && sync_fresh;
    let stratum = if ntp_synchronized {
        valid_stratum
    } else {
        None
    };

    let status_tag = if ntp_synchronized {
        "synced"
    } else if is_unsynced_source {
        "unsynced"
    } else {
        "stale"
    };
    let clock_source = if source_trimmed.is_empty() {
        format!("W32Time({status_tag}):Local CMOS Clock")
    } else {
        format!("W32Time({status_tag}):{source_trimmed}")
    };

    Some(NtpSyncStatus {
        ntp_synchronized,
        clock_source,
        stratum,
        max_error_us: root_dispersion_us,
    })
}

/// Parses real `w32tm /query /status` output assuming UTC timestamps (`local_utc_offset_secs = 0`) (`CSE-26`).
pub fn parse_w32tm_status_output(stdout: &str, now_unix_utc: i64) -> Option<NtpSyncStatus> {
    parse_w32tm_status_output_with_tz_offset(stdout, now_unix_utc, 0)
}

fn current_unix_timestamp_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn load_airgap_clock_attestation_from_env(now_unix: i64) -> Option<NtpSyncStatus> {
    if let Ok(inline) = std::env::var(SENTINEL_AIRGAP_CLOCK_ATTESTATION_ENV) {
        if !inline.trim().is_empty() {
            return parse_airgap_clock_config_str(&inline)
                .and_then(|cfg| evaluate_airgap_hardware_clock_attestation(&cfg, now_unix))
                .or_else(|| {
                    Some(NtpSyncStatus {
                        ntp_synchronized: false,
                        clock_source: "HardwareClock(invalid_config)".to_string(),
                        stratum: None,
                        max_error_us: None,
                    })
                });
        }
    }
    if let Ok(cfg_path_raw) = std::env::var(SENTINEL_AIRGAP_CLOCK_CONFIG_ENV) {
        let trimmed = cfg_path_raw.trim();
        if !trimmed.is_empty() {
            let p = Path::new(trimmed);
            let ok = crate::fs_lowlevel::ensure_not_symlink_or_reparse_point(p)
                .ok()
                .and_then(|()| std::fs::read_to_string(p).ok())
                .and_then(|text| parse_airgap_clock_config_str(&text))
                .and_then(|cfg| evaluate_airgap_hardware_clock_attestation(&cfg, now_unix));
            return Some(ok.unwrap_or(NtpSyncStatus {
                ntp_synchronized: false,
                clock_source: "HardwareClock(unreadable_or_invalid_config)".to_string(),
                stratum: None,
                max_error_us: None,
            }));
        }
    }
    None
}

#[cfg(windows)]
fn query_windows_local_utc_offset_secs() -> i64 {
    const TIME_ZONE_ID_STANDARD: u32 = 1;
    const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
    let mut tzi: Win32TimeZoneInformation = unsafe { core::mem::zeroed() };
    let id = unsafe { GetTimeZoneInformation(&mut tzi) };
    let total_bias_mins = match id {
        TIME_ZONE_ID_STANDARD => tzi.bias.saturating_add(tzi.standard_bias),
        TIME_ZONE_ID_DAYLIGHT => tzi.bias.saturating_add(tzi.daylight_bias),
        _ => tzi.bias,
    };
    // Win32 `Bias` is defined as `UTC = local_time + Bias` (minutes), so `local - UTC = -Bias * 60`
    -(total_bias_mins as i64).saturating_mul(60)
}

#[cfg(windows)]
fn query_w32tm_status_stdout() -> Option<String> {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let w32tm_path = Path::new(&sys_root).join("System32").join("w32tm.exe");
    let output = std::process::Command::new(&w32tm_path)
        .args(["/query", "/status"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Queries live OS NTP / ICT clock-synchronization health (`CERT-In Apr 2022` Directions, `CSE-14`, `CSE-26`).
///
/// - **Air-Gapped Hardware Clocks (`IRIG-B` / `PTP`):** If `SENTINEL_AIRGAP_CLOCK_ATTESTATION` or
///   `SENTINEL_AIRGAP_CLOCK_CONFIG` is configured, evaluates receiver lock & 24 h freshness honestly.
/// - **Windows:** Runs `%SystemRoot%\System32\w32tm.exe /query /status` and inspects actual
///   `Source`, `Stratum`, `Last Successful Sync Time` (`<= 24 h`), and `Root Dispersion`. Marks
///   `Local CMOS Clock`, `Free-running System Clock`, `Stratum: 0`, stale syncs (`> 24 h`), or
///   stopped/unavailable `W32Time` honestly as `ntp_synchronized: false` with `stratum: None`.
/// - **Linux:** Invokes `libc::adjtimex` (`modes = 0` read-only) and checks `(status & STA_UNSYNC) == 0`
///   plus `maxerror` in microseconds.
pub fn query_ntp_sync_status() -> NtpSyncStatus {
    let now_unix = current_unix_timestamp_secs();
    if let Some(hw_status) = load_airgap_clock_attestation_from_env(now_unix) {
        return hw_status;
    }

    #[cfg(windows)]
    {
        let tz_offset = query_windows_local_utc_offset_secs();
        if let Some(stdout) = query_w32tm_status_stdout() {
            if let Some(parsed) =
                parse_w32tm_status_output_with_tz_offset(&stdout, now_unix, tz_offset)
            {
                return parsed;
            }
        }

        // Honest fail-closed fallback when `w32tm /query /status` is unavailable or unparseable:
        // NEVER fabricate `ntp_synchronized: true` or `stratum: Some(2)` from registry settings alone!
        let svc_running = query_w32time_service_running();
        let svc_tag = match svc_running {
            Some(true) => "running_unverified",
            Some(false) => "stopped",
            None => "unavailable",
        };
        let mut time_adj: u32 = 0;
        let mut time_inc: u32 = 0;
        let mut adj_disabled: i32 = 1;
        let adj_ok =
            unsafe { GetSystemTimeAdjustment(&mut time_adj, &mut time_inc, &mut adj_disabled) }
                != 0;
        let max_error_us = if adj_ok && time_inc > 0 {
            Some((time_inc as u64) / 10)
        } else {
            None
        };

        NtpSyncStatus {
            ntp_synchronized: false,
            clock_source: format!("W32Time({svc_tag}):Local CMOS Clock"),
            stratum: None,
            max_error_us,
        }
    }

    #[cfg(target_os = "linux")]
    {
        let mut tx: libc::timex = unsafe { core::mem::zeroed() };
        tx.modes = 0; // Read-only kernel clock state query
        let rc = unsafe { libc::adjtimex(&mut tx) };
        let synced = rc >= 0 && rc != libc::TIME_ERROR && (tx.status & libc::STA_UNSYNC) == 0;
        let max_error_us = if rc >= 0 && tx.maxerror >= 0 {
            Some(tx.maxerror as u64)
        } else {
            None
        };
        let clock_source = if synced {
            "linux_adjtimex_STA_SYNC".to_string()
        } else {
            "linux_adjtimex_STA_UNSYNC".to_string()
        };
        NtpSyncStatus {
            ntp_synchronized: synced,
            clock_source,
            stratum: None,
            max_error_us,
        }
    }

    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let chrony_active = Path::new("/var/run/chrony/chronyd.pid").exists()
            || Path::new("/run/chrony/chronyd.pid").exists();
        let ntpd_active = Path::new("/var/run/ntpd.pid").exists();
        let synced = chrony_active || ntpd_active;
        let clock_source = if chrony_active {
            "unix_chronyd".to_string()
        } else if ntpd_active {
            "unix_ntpd".to_string()
        } else {
            "unix_unsynchronized".to_string()
        };
        NtpSyncStatus {
            ntp_synchronized: synced,
            clock_source,
            stratum: None,
            max_error_us: None,
        }
    }
}

#[cfg(test)]
mod registry_dynamic_read_tests {
    use super::*;

    #[test]
    fn read_registry_string_two_call_protocol_exceeds_1024_utf16_chars_and_enforces_cap() {
        // 1. Verify exact two-call protocol reads 6,144 UTF-16 chars (> 1,024 cap) without truncation
        let large_payload = "S".repeat(6144);
        let mut encoded: Vec<u16> = large_payload.encode_utf16().collect();
        encoded.push(0);
        let required_bytes = (encoded.len() * 2) as u32;
        let mut calls = 0usize;
        let read_back = read_registry_string_two_call(|buf_opt, cb_data| {
            calls += 1;
            match buf_opt {
                None => {
                    *cb_data = required_bytes;
                    0
                }
                Some(buf) => {
                    if (buf.len() * 2) < required_bytes as usize {
                        *cb_data = required_bytes;
                        234 // ERROR_MORE_DATA
                    } else {
                        buf[..encoded.len()].copy_from_slice(&encoded);
                        *cb_data = required_bytes;
                        0
                    }
                }
            }
        });
        assert_eq!(calls, 2);
        assert_eq!(read_back.as_deref(), Some(large_payload.as_str()));

        // 2. Verify concurrent growth (`ERROR_MORE_DATA = 234` on Call 2) retries cleanly
        let mut retry_calls = 0usize;
        let retried = read_registry_string_two_call(|buf_opt, cb_data| {
            retry_calls += 1;
            match (retry_calls, buf_opt) {
                (1, None) => {
                    *cb_data = 128; // initial smaller size
                    0
                }
                (2, Some(_)) => {
                    *cb_data = required_bytes; // value grew concurrently before Call 2
                    234 // ERROR_MORE_DATA
                }
                (3, Some(buf)) => {
                    buf[..encoded.len()].copy_from_slice(&encoded);
                    *cb_data = required_bytes;
                    0
                }
                _ => 1,
            }
        });
        assert_eq!(retry_calls, 3);
        assert_eq!(retried.as_deref(), Some(large_payload.as_str()));

        // 3. Verify oversized > MAX_REGISTRY_STRING_BYTES (1 MiB) fails closed without allocating
        let oversized = read_registry_string_two_call(|buf_opt, cb_data| {
            assert!(
                buf_opt.is_none(),
                "Must reject oversized value after Call 1"
            );
            *cb_data = MAX_REGISTRY_STRING_BYTES + 2;
            0
        });
        assert!(oversized.is_none());

        // 4. On live Windows hosts, verify real two-call RegGetValueW reads HKLM ProductName
        #[cfg(windows)]
        {
            let prod = read_registry_string(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "ProductName",
            );
            assert!(
                prod.as_deref().is_some_and(|s| !s.trim().is_empty()),
                "Live Windows two-call RegGetValueW must read HKLM ProductName"
            );
        }
    }
}
