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
pub const BUS_TYPE_USB: u32 = 0x07;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbVolumeInfo {
    pub volume_guid_path: String,
    pub mount_points: Vec<PathBuf>,
    pub physical_drive_number: Option<u32>,
    pub bus_type: u32,
    pub is_removable_media: bool,
    pub is_offline: bool,
    pub is_readonly: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReport {
    pub automount_disabled: bool,
    pub removable_volumes_offline: Vec<(String, bool)>,
    pub user_deny_policy_present: bool,
    pub install_restrictions_active: bool,
    pub write_protect_active: bool,
    pub autoplay_suppressed: bool,
    pub linux_authorized_default_zero: Option<bool>,
}

impl PostureReport {
    /// Strict fail-closed compliance evaluation (`Master Plan v2 §0.1`, Row 21):
    /// Requires every OS control field to hold (`automount_disabled`, `user_deny_policy_present`,
    /// `install_restrictions_active`, `write_protect_active`, `autoplay_suppressed`, and every
    /// enumerated USB/removable volume GUID offline).
    pub fn is_compliant(&self) -> bool {
        let all_volumes_offline = self
            .removable_volumes_offline
            .iter()
            .all(|(_, offline)| *offline);

        #[cfg(windows)]
        {
            self.automount_disabled
                && self.user_deny_policy_present
                && self.install_restrictions_active
                && self.write_protect_active
                && self.autoplay_suppressed
                && all_volumes_offline
        }
        #[cfg(not(windows))]
        {
            self.automount_disabled
                && self.linux_authorized_default_zero == Some(true)
                && all_volumes_offline
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
}

#[cfg(windows)]
#[link(name = "cfgmgr32")]
extern "system" {
    fn CM_Locate_DevNodeW(pdnDevInst: *mut u32, pDeviceID: *const u16, ulFlags: u32) -> u32;
    fn CM_Disable_DevNode(dnDevInst: u32, ulFlags: u32) -> u32;
    fn CM_Enable_DevNode(dnDevInst: u32, ulFlags: u32) -> u32;
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
                    volumes.push(UsbVolumeInfo {
                        volume_guid_path: vol_guid_path,
                        mount_points,
                        physical_drive_number,
                        bus_type,
                        is_removable_media: removable_media,
                        is_offline,
                        is_readonly,
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
                let dev_node = format!("/dev/{}", dev_name);
                let is_off = is_volume_offline(Path::new(&dev_node));
                volumes.push(UsbVolumeInfo {
                    volume_guid_path: dev_node,
                    mount_points: Vec::new(),
                    physical_drive_number: None,
                    bus_type: if is_usb { BUS_TYPE_USB } else { 0 },
                    is_removable_media: is_rem,
                    is_offline: is_off,
                    is_readonly: is_ro,
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

/// Reads a `REG_SZ` string value from `HKEY_LOCAL_MACHINE`.
pub fn read_registry_string(subkey: &str, value_name: &str) -> Option<String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide_subkey: Vec<u16> = std::ffi::OsStr::new(subkey)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let wide_val: Vec<u16> = std::ffi::OsStr::new(value_name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut buf = vec![0u16; 1024];
        let mut cb_data: u32 = (buf.len() * 2) as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                wide_subkey.as_ptr(),
                wide_val.as_ptr(),
                RRF_RT_REG_SZ,
                core::ptr::null_mut(),
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                &mut cb_data,
            )
        };
        if status == 0 {
            let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
            return Some(String::from_utf16_lossy(&buf[..len]));
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = (subkey, value_name);
        None
    }
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
                std::fs::write(&p, val)?;
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
    #[cfg(not(windows))]
    {
        let _ = (volume_path, offline);
        Ok(())
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
    #[cfg(not(windows))]
    {
        let _ = (volume_path, readonly);
        Ok(())
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
                let mnt_matches = mnt == trimmed || mnt.starts_with(&format!("{}/", trimmed));
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
            let mnt_matches = mnt == trimmed || mnt.starts_with(&format!("{}/", trimmed));
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
    #[cfg(not(windows))]
    {
        let _ = mount_point;
        Ok(())
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

/// Applies Windows Group Policy `RemovableStorageDevices` (`Deny_All = 1`, `Deny_Execute = 1`, `Deny_Write = 1`),
/// `StorageDevicePolicies` (`WriteProtect = 1`), and `DeviceInstall\Restrictions` (`DenyUnspecified = 1` +
/// `AllowDeviceIDs` from the Intune hardware allowlist) (`Rows 17, 140`).
pub fn apply_usb_storage_and_install_policies(allowed_hardware_ids: &[String]) -> io::Result<()> {
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
        write_registry_dword(
            false,
            r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
            "WriteProtect",
            1,
        )?;
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyUnspecified",
            1,
        )?;
        write_registry_dword(
            false,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "AllowDeviceIDs",
            1,
        )?;
        for (idx, hw_id) in allowed_hardware_ids.iter().enumerate() {
            let name = (idx + 1).to_string();
            write_registry_sz(
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs",
                &name,
                hw_id,
            )?;
        }
    }
    #[cfg(not(windows))]
    {
        let _ = allowed_hardware_ids;
    }
    Ok(())
}

#[cfg(windows)]
fn parse_vid_pid_serial(instance_id: &str) -> Option<(u16, u16, String)> {
    let upper = instance_id.to_ascii_uppercase();
    let vid_pos = upper.find("VID_")?;
    let pid_pos = upper.find("PID_")?;
    if vid_pos + 8 > upper.len() || pid_pos + 8 > upper.len() {
        return None;
    }
    let vid = u16::from_str_radix(&upper[vid_pos + 4..vid_pos + 8], 16).ok()?;
    let pid = u16::from_str_radix(&upper[pid_pos + 4..pid_pos + 8], 16).ok()?;
    let serial = instance_id
        .rsplit('\\')
        .next()
        .unwrap_or("UNKNOWN")
        .to_string();
    Some((vid, pid, serial))
}

/// Enumerates real USB PnP device nodes via `CM_Get_Device_ID_ListW` (`cfgmgr32.dll`) on Windows
/// and `/sys/bus/usb/devices` on Linux, inspecting compatible IDs / services / interface classes
/// to detect composite HID (`0x03`) + Mass Storage (`0x08`) BadUSB devices (`Row 142`).
pub fn enumerate_usb_pnp_devices() -> Vec<UsbPnpDeviceInfo> {
    let mut grouped: HashMap<(u16, u16), UsbPnpDeviceInfo> = HashMap::new();

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

                    let Some((vid, pid, serial)) = parse_vid_pid_serial(&id_str) else {
                        continue;
                    };

                    let mut is_storage = false;
                    let mut is_hid = false;

                    let wide_id: Vec<u16> = std::ffi::OsStr::new(&id_str)
                        .encode_wide()
                        .chain(Some(0))
                        .collect();
                    let mut dev_inst: u32 = 0;
                    if unsafe { CM_Locate_DevNodeW(&mut dev_inst, wide_id.as_ptr(), 0) } == 0 {
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

                    let entry = grouped
                        .entry((vid, pid))
                        .or_insert_with(|| UsbPnpDeviceInfo {
                            instance_id: id_str.clone(),
                            vid,
                            pid,
                            serial: serial.clone(),
                            interface_classes: Vec::new(),
                            child_instance_ids: Vec::new(),
                            has_mass_storage: false,
                            has_hid_input: false,
                            is_composite_hid_storage: false,
                        });
                    if !id_str.to_ascii_uppercase().contains("&MI_") {
                        entry.instance_id = id_str.clone();
                        entry.serial = serial;
                    } else {
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
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| entry.file_name().to_string_lossy().to_string());
                let dev_name = entry.file_name().to_string_lossy().to_string();

                let mut classes = Vec::new();
                let mut children = Vec::new();
                if let Ok(sub_entries) = std::fs::read_dir(&p) {
                    for sub in sub_entries.flatten() {
                        let sub_name = sub.file_name().to_string_lossy().to_string();
                        if sub_name.starts_with(&format!("{}:", dev_name)) {
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
                    (vid, pid),
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

    grouped.into_values().collect()
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
        let sanitized_id = device_instance_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':' | '_'))
            .collect::<String>();
        if sanitized_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Empty USB device ID",
            ));
        }
        let sysfs_path = format!("/sys/bus/usb/devices/{}/authorized", sanitized_id);
        std::fs::write(&sysfs_path, "0")
    }
}

/// Disables a specific USB interface on a composite device (`CM_Disable_DevNode` on child `MI_xx`
/// node on Windows, or writing `0` to `/sys/bus/usb/devices/<bus-port>:<cfg>.<intf>/authorized` on Linux) (`Row 144`).
pub fn disable_usb_interface(device_id: &str, interface_id: &str) -> io::Result<()> {
    #[cfg(windows)]
    {
        let _ = device_id;
        disable_device_node(interface_id)
    }
    #[cfg(not(windows))]
    {
        let target = if interface_id.contains(':') {
            interface_id.to_string()
        } else {
            format!("{}:{}", device_id, interface_id)
        };
        disable_device_node(&target)
    }
}

/// Re-enables a PnP device node after explicit user-presence confirmation (`CM_Locate_DevNodeW` +
/// `CM_Enable_DevNode` on Windows, or writing `1` to `/sys/bus/usb/devices/<id>/authorized` on Linux) (`Rows 3, 142, 144`).
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
        let sanitized_id = device_instance_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':' | '_'))
            .collect::<String>();
        if sanitized_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Empty USB device ID",
            ));
        }
        let sysfs_path = format!("/sys/bus/usb/devices/{}/authorized", sanitized_id);
        std::fs::write(&sysfs_path, "1")
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
    let user_deny_policy_present = read_registry_dword(
        false,
        r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices",
        "Deny_All",
    ) == Some(1);
    let install_restrictions_active = read_registry_dword(
        false,
        r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
        "DenyUnspecified",
    ) == Some(1);
    let write_protect_active = read_registry_dword(
        false,
        r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
        "WriteProtect",
    ) == Some(1);
    let autoplay_suppressed = read_registry_dword(
        false,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoDriveTypeAutoRun",
    ) == Some(0xFF)
        && read_registry_dword(false, r"SYSTEM\CurrentControlSet\Services\cdrom", "AutoRun")
            .unwrap_or(0)
            == 0;

    let usb_volumes = enumerate_usb_volumes();
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
    }
}
