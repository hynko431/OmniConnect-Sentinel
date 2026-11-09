use serde::{Deserialize, Serialize};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
#[cfg(windows)]
use std::io::Write;
use std::path::{Component, Path, PathBuf};
#[cfg(windows)]
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    Hdd,
    SsdOrFlash,
    UsbFlash,
    UnknownOrVirtual,
}

impl MediaType {
    pub fn label(&self) -> &'static str {
        match self {
            MediaType::Hdd => "HDD (Magnetic Rotational)",
            MediaType::SsdOrFlash => "SSD / NVMe (Flash-Wear-Leveled — Purge not guaranteed by overwrite alone)",
            MediaType::UsbFlash => "USB Flash Media (Controller-Wear-Leveled — Purge not guaranteed by overwrite alone)",
            MediaType::UnknownOrVirtual => "Filesystem Volume (Standard)",
        }
    }
}

/// 4096-byte page-aligned 64 KiB buffer for `FILE_FLAG_NO_BUFFERING` sector-aligned I/O (Phase 1.2).
#[repr(C, align(4096))]
pub struct AlignedSectorBuffer {
    pub data: [u8; 65536],
}

impl Default for AlignedSectorBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl AlignedSectorBuffer {
    pub fn new() -> Self {
        Self { data: [0u8; 65536] }
    }
}

#[cfg(windows)]
#[repr(C)]
struct Win32FindStreamData {
    stream_size: i64,
    c_stream_name: [u16; 296],
}

#[cfg(windows)]
#[repr(C)]
struct StoragePropertyQuery {
    property_id: u32,
    query_type: u32,
    additional_parameters: [u8; 4],
}

#[cfg(windows)]
#[repr(C)]
struct StorageAccessAlignmentDescriptor {
    version: u32,
    size: u32,
    bytes_per_cache_line: u32,
    bytes_offset_for_cache_alignment: u32,
    bytes_per_logical_sector: u32,
    bytes_per_physical_sector: u32,
    bytes_offset_for_sector_alignment: u32,
}

#[cfg(windows)]
#[repr(C)]
struct DeviceSeekPenaltyDescriptor {
    version: u32,
    size: u32,
    incurs_seek_penalty: u8,
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
struct FileLevelTrimRange {
    offset: u64,
    length: u64,
}

#[cfg(windows)]
#[repr(C)]
struct FileLevelTrim {
    key: u32,
    num_ranges: u32,
    ranges: [FileLevelTrimRange; 1],
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
    fn FlushFileBuffers(hFile: isize) -> i32;
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const core::ffi::c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: isize,
    ) -> isize;
    fn CloseHandle(hObject: isize) -> i32;
    fn LocalFree(hMem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
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
    fn FindFirstStreamW(
        lpFileName: *const u16,
        InfoLevelId: i32,
        lpFindStreamData: *mut core::ffi::c_void,
        dwFlags: u32,
    ) -> isize;
    fn FindNextStreamW(hFindStream: isize, lpFindStreamData: *mut core::ffi::c_void) -> i32;
    fn FindClose(hFindFile: isize) -> i32;
    fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;
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
    fn GetSecurityDescriptorDacl(
        pSecurityDescriptor: *const core::ffi::c_void,
        lpbDaclPresent: *mut i32,
        pDacl: *mut *mut core::ffi::c_void,
        lpbDaclDefaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        pObjectName: *const u16,
        ObjectType: i32,
        SecurityInfo: u32,
        psidOwner: *const core::ffi::c_void,
        psidGroup: *const core::ffi::c_void,
        pDacl: *const core::ffi::c_void,
        pSacl: *const core::ffi::c_void,
    ) -> u32;
}

/// Lexically normalizes `.` and `..` components and converts a Path to a Windows `\\?\`
/// extended-length verbatim path so that reserved DOS device names (`CON.txt`, `NUL.exe`,
/// `PRN`, `AUX`, `COM1..9`, `LPT1..9`) and long paths (>260 chars) address the filesystem
/// entry directly without following symlinks (`Master Plan v2 §1.2`).
pub fn to_verbatim_path(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };

    let mut normalized = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::Prefix(p) => normalized.push(p.as_os_str()),
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(c) => normalized.push(c),
        }
    }

    #[cfg(windows)]
    {
        let s = normalized.to_string_lossy().replace('/', "\\");
        if s.starts_with(r"\\?\") {
            PathBuf::from(s)
        } else if let Some(stripped) = s.strip_prefix(r"\\") {
            PathBuf::from(format!(r"\\?\UNC\{stripped}"))
        } else {
            PathBuf::from(format!(r"\\?\{s}"))
        }
    }
    #[cfg(not(windows))]
    {
        normalized
    }
}

/// Normalizes file attributes (clears READONLY, HIDDEN, SYSTEM) on the verbatim path,
/// refusing to touch symlinks or NTFS reparse points.
pub fn normalize_file_attributes(path: &Path) -> io::Result<()> {
    let verbatim = to_verbatim_path(path);
    if let Ok(sym_meta) = fs::symlink_metadata(&verbatim) {
        if is_reparse_point_or_symlink(&sym_meta) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Refusing to normalize attributes on symlink or NTFS reparse point",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();
        unsafe {
            // FILE_ATTRIBUTE_NORMAL = 0x80
            let ret = SetFileAttributesW(wide.as_ptr(), 0x80);
            if ret == 0 {
                debug!("SetFileAttributesW returned 0 for {:?}", verbatim);
            }
        }
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::symlink_metadata(&verbatim) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&verbatim, perms);
        }
    }
    Ok(())
}

/// Verifies that a target path (or host path for an NTFS `:stream`) is NOT a symlink or reparse point.
pub fn ensure_not_symlink_or_reparse_point(path: &Path) -> io::Result<()> {
    let s = path.to_string_lossy();
    // If path is an NTFS Alternate Data Stream `C:\dir\file.txt:stream`, check the host file too
    let without_verbatim = s.strip_prefix(r"\\?\").unwrap_or(&s);
    if without_verbatim.len() > 3 {
        if let Some(colon_rel) = without_verbatim[2..].find(':') {
            let host_str = &without_verbatim[..2 + colon_rel];
            let host_verbatim = to_verbatim_path(Path::new(host_str));
            if let Ok(host_meta) = fs::symlink_metadata(&host_verbatim) {
                if is_reparse_point_or_symlink(&host_meta) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Refusing operation: host path '{host_str}' is a symlink or reparse point"
                        ),
                    ));
                }
            }
        }
    }

    let verbatim = to_verbatim_path(path);
    if let Ok(meta) = fs::symlink_metadata(&verbatim) {
        if is_reparse_point_or_symlink(&meta) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Refusing operation: '{}' is a symlink or reparse point",
                    path.display()
                ),
            ));
        }
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if is_reparse_point_or_symlink(&meta) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Refusing operation: '{}' is a symlink or reparse point",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Opens a file with OS write-through flags (`FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT`
/// on Windows, `O_DSYNC | O_NOFOLLOW` on Unix) using a `\\?\` verbatim path, refusing symlinks/reparse points.
pub fn open_write_through(path: &Path) -> io::Result<File> {
    ensure_not_symlink_or_reparse_point(path)?;
    let verbatim = to_verbatim_path(path);
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_WRITE_THROUGH (0x80000000) | FILE_FLAG_OPEN_REPARSE_POINT (0x00200000)
        opts.custom_flags(0x8000_0000 | 0x0020_0000);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_DSYNC | libc::O_NOFOLLOW);
    }

    let file = opts.open(&verbatim)?;
    if let Ok(meta) = file.metadata() {
        if is_reparse_point_or_symlink(&meta) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Opened handle is a reparse point or symlink; aborting write-through open",
            ));
        }
    }
    Ok(file)
}

/// Opens an existing file with `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT`
/// on Windows (or `O_DSYNC | O_NOFOLLOW` on Unix) for sector-aligned unbuffered overwrites (Phase 1.2).
pub fn open_no_buffering_write_through(path: &Path) -> io::Result<File> {
    ensure_not_symlink_or_reparse_point(path)?;
    let verbatim = to_verbatim_path(path);
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_WRITE_THROUGH (0x80000000) | FILE_FLAG_NO_BUFFERING (0x20000000) | FILE_FLAG_OPEN_REPARSE_POINT (0x00200000)
        opts.custom_flags(0x8000_0000 | 0x2000_0000 | 0x0020_0000);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_DSYNC | libc::O_NOFOLLOW);
    }

    let file = opts.open(&verbatim)?;
    if let Ok(meta) = file.metadata() {
        if is_reparse_point_or_symlink(&meta) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Opened handle is a reparse point or symlink; aborting unbuffered open",
            ));
        }
    }
    Ok(file)
}

/// Queries physical/logical sector alignment via `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageAccessAlignmentProperty`),
/// defaulting to 4096 bytes when the underlying volume does not expose raw storage descriptors.
pub fn query_sector_alignment(file: &File) -> u32 {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;
        const STORAGE_ACCESS_ALIGNMENT_PROPERTY: u32 = 6;
        const PROPERTY_STANDARD_QUERY: u32 = 0;

        let query = StoragePropertyQuery {
            property_id: STORAGE_ACCESS_ALIGNMENT_PROPERTY,
            query_type: PROPERTY_STANDARD_QUERY,
            additional_parameters: [0; 4],
        };
        let mut desc = StorageAccessAlignmentDescriptor {
            version: 0,
            size: 0,
            bytes_per_cache_line: 0,
            bytes_offset_for_cache_alignment: 0,
            bytes_per_logical_sector: 0,
            bytes_per_physical_sector: 0,
            bytes_offset_for_sector_alignment: 0,
        };
        let mut returned: u32 = 0;
        let handle = file.as_raw_handle() as isize;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &query as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<StoragePropertyQuery>() as u32,
                &mut desc as *mut _ as *mut core::ffi::c_void,
                core::mem::size_of::<StorageAccessAlignmentDescriptor>() as u32,
                &mut returned,
                core::ptr::null_mut(),
            )
        };
        if ok != 0
            && desc.bytes_per_physical_sector >= 512
            && desc.bytes_per_physical_sector <= 4096
            && desc.bytes_per_physical_sector.is_power_of_two()
        {
            return desc.bytes_per_physical_sector;
        }
    }
    let _ = file;
    4096
}

/// Queries the volume handle `\\.\X:` (with `FILE_ANY_ACCESS`) for `StorageAccessAlignmentProperty`,
/// falling back to `query_sector_alignment(file)` (or 4096).
pub fn query_sector_alignment_for_path(path: &Path, fallback_file: Option<&File>) -> u32 {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;
        const STORAGE_ACCESS_ALIGNMENT_PROPERTY: u32 = 6;
        const PROPERTY_STANDARD_QUERY: u32 = 0;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        let abs = to_verbatim_path(path);
        let s = abs.to_string_lossy();
        let trimmed = s.strip_prefix(r"\\?\").unwrap_or(&s);
        if trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':' {
            let vol_dev = format!(r"\\.\{}", &trimmed[..2]);
            let wide_vol: Vec<u16> = std::ffi::OsStr::new(&vol_dev)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let handle = unsafe {
                CreateFileW(
                    wide_vol.as_ptr(),
                    0,
                    FILE_SHARE_READ_WRITE,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    0,
                )
            };
            if handle != INVALID_HANDLE_VALUE && handle != 0 {
                let query = StoragePropertyQuery {
                    property_id: STORAGE_ACCESS_ALIGNMENT_PROPERTY,
                    query_type: PROPERTY_STANDARD_QUERY,
                    additional_parameters: [0; 4],
                };
                let mut desc = StorageAccessAlignmentDescriptor {
                    version: 0,
                    size: 0,
                    bytes_per_cache_line: 0,
                    bytes_offset_for_cache_alignment: 0,
                    bytes_per_logical_sector: 0,
                    bytes_per_physical_sector: 0,
                    bytes_offset_for_sector_alignment: 0,
                };
                let mut returned: u32 = 0;
                let ok = unsafe {
                    DeviceIoControl(
                        handle,
                        IOCTL_STORAGE_QUERY_PROPERTY,
                        &query as *const _ as *const core::ffi::c_void,
                        core::mem::size_of::<StoragePropertyQuery>() as u32,
                        &mut desc as *mut _ as *mut core::ffi::c_void,
                        core::mem::size_of::<StorageAccessAlignmentDescriptor>() as u32,
                        &mut returned,
                        core::ptr::null_mut(),
                    )
                };
                unsafe {
                    let _ = CloseHandle(handle);
                }
                let sector = if desc.bytes_per_logical_sector >= 512
                    && desc.bytes_per_logical_sector <= 4096
                    && desc.bytes_per_logical_sector.is_power_of_two()
                {
                    desc.bytes_per_logical_sector.max(
                        if desc.bytes_per_physical_sector <= 4096
                            && desc.bytes_per_physical_sector.is_power_of_two()
                        {
                            desc.bytes_per_physical_sector
                        } else {
                            512
                        },
                    )
                } else {
                    desc.bytes_per_physical_sector
                };
                if ok != 0 && (512..=4096).contains(&sector) && sector.is_power_of_two() {
                    return sector;
                }
            }
        }
    }
    let _ = path;
    if let Some(f) = fallback_file {
        query_sector_alignment(f)
    } else {
        4096
    }
}

/// Classifies media type from seek-penalty and USB bus properties.
pub fn classify_media_characteristics(
    is_usb_bus: bool,
    incurs_seek_penalty: Option<bool>,
) -> MediaType {
    if is_usb_bus {
        return MediaType::UsbFlash;
    }
    match incurs_seek_penalty {
        Some(true) => MediaType::Hdd,
        Some(false) => MediaType::SsdOrFlash,
        None => MediaType::UnknownOrVirtual,
    }
}

/// Queries the hardware media classification (`HDD`, `SsdOrFlash`, `UsbFlash`) using
/// `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceProperty` for `BusTypeUsb` and
/// `StorageDeviceSeekPenaltyProperty` for rotational HDD vs SSD detection) (`Master Plan v2 §1.2`).
pub fn query_media_type(path: &Path) -> MediaType {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;
        const STORAGE_DEVICE_PROPERTY: u32 = 0;
        const STORAGE_DEVICE_SEEK_PENALTY_PROPERTY: u32 = 7;
        const PROPERTY_STANDARD_QUERY: u32 = 0;
        const BUS_TYPE_USB: u32 = 0x07;
        const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        let abs = to_verbatim_path(path);
        let s = abs.to_string_lossy();
        let trimmed = s.strip_prefix(r"\\?\").unwrap_or(&s);
        if trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':' {
            let drive_prefix = &trimmed[..2];
            let root = format!("{drive_prefix}\\");
            let wide_root: Vec<u16> = std::ffi::OsStr::new(&root)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let drive_type = unsafe { GetDriveTypeW(wide_root.as_ptr()) };
            // DRIVE_REMOVABLE = 2
            if drive_type == 2 {
                return MediaType::UsbFlash;
            }

            // Open volume device `\\.\X:` with dwDesiredAccess = 0 (FILE_ANY_ACCESS)
            let vol_dev = format!(r"\\.\{drive_prefix}");
            let wide_vol: Vec<u16> = std::ffi::OsStr::new(&vol_dev)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let handle = unsafe {
                CreateFileW(
                    wide_vol.as_ptr(),
                    0, // FILE_ANY_ACCESS allows unprivileged IOCTL_STORAGE_QUERY_PROPERTY
                    FILE_SHARE_READ_WRITE,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    0,
                )
            };
            if handle != INVALID_HANDLE_VALUE && handle != 0 {
                let mut is_usb = false;
                let dev_query = StoragePropertyQuery {
                    property_id: STORAGE_DEVICE_PROPERTY,
                    query_type: PROPERTY_STANDARD_QUERY,
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
                let mut ret_bytes: u32 = 0;
                let ok_dev = unsafe {
                    DeviceIoControl(
                        handle,
                        IOCTL_STORAGE_QUERY_PROPERTY,
                        &dev_query as *const _ as *const core::ffi::c_void,
                        core::mem::size_of::<StoragePropertyQuery>() as u32,
                        &mut dev_hdr as *mut _ as *mut core::ffi::c_void,
                        core::mem::size_of::<StorageDeviceDescriptorHeader>() as u32,
                        &mut ret_bytes,
                        core::ptr::null_mut(),
                    )
                };
                if ok_dev != 0 && (dev_hdr.bus_type == BUS_TYPE_USB || dev_hdr.removable_media != 0)
                {
                    is_usb = true;
                }

                let seek_query = StoragePropertyQuery {
                    property_id: STORAGE_DEVICE_SEEK_PENALTY_PROPERTY,
                    query_type: PROPERTY_STANDARD_QUERY,
                    additional_parameters: [0; 4],
                };
                let mut seek_desc = DeviceSeekPenaltyDescriptor {
                    version: 0,
                    size: 0,
                    incurs_seek_penalty: 0,
                };
                let ok_seek = unsafe {
                    DeviceIoControl(
                        handle,
                        IOCTL_STORAGE_QUERY_PROPERTY,
                        &seek_query as *const _ as *const core::ffi::c_void,
                        core::mem::size_of::<StoragePropertyQuery>() as u32,
                        &mut seek_desc as *mut _ as *mut core::ffi::c_void,
                        core::mem::size_of::<DeviceSeekPenaltyDescriptor>() as u32,
                        &mut ret_bytes,
                        core::ptr::null_mut(),
                    )
                };
                unsafe {
                    let _ = CloseHandle(handle);
                }

                let penalty_opt = if ok_seek != 0 {
                    Some(seek_desc.incurs_seek_penalty != 0)
                } else if drive_type == 3 {
                    Some(false)
                } else {
                    None
                };
                return classify_media_characteristics(is_usb, penalty_opt);
            }

            if drive_type == 3 {
                return MediaType::SsdOrFlash;
            }
        }
    }
    let _ = path;
    MediaType::UnknownOrVirtual
}

/// Flushes a directory's metadata entry to disk (`FlushFileBuffers` with `FILE_FLAG_BACKUP_SEMANTICS`
/// on Windows, `File::open(dir)?.sync_all()` on Unix) after an atomic rename (`Master Plan v2 §1.1`).
pub fn sync_directory(dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_SHARE_ALL: u32 = 0x0000_0007;
        const OPEN_EXISTING: u32 = 3;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const INVALID_HANDLE_VALUE: isize = -1;

        let verbatim = to_verbatim_path(dir);
        let wide: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_ALL,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                0,
            )
        };
        if handle != INVALID_HANDLE_VALUE && handle != 0 {
            let _ = unsafe { FlushFileBuffers(handle) };
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let f = File::open(dir)?;
        f.sync_all()
    }
}

/// Applies a strict ACL (`SY` SYSTEM, `BA` Built-in Administrators, and `OW` Owner Rights)
/// to a directory or file so unprivileged standard users cannot read/tamper with vault keys,
/// shadow caches, or audit ledgers (`Master Plan v2 §1.1, §3.2, §4.2`).
pub fn apply_system_admin_dacl(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const SDDL_REVISION_1: u32 = 1;
        const SE_FILE_OBJECT: i32 = 1;
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
        const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

        // Grant full control to SYSTEM (SY), Administrators (BA), and Creator/Owner (CO/OW) so
        // both elevated SYSTEM services and current process owners can access while blocking other users.
        let sddl = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;OW)";
        let wide_sddl: Vec<u16> = std::ffi::OsStr::new(sddl)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut sd_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut sd_size: u32 = 0;

        let ok_sddl = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd_ptr,
                &mut sd_size,
            )
        };
        if ok_sddl == 0 || sd_ptr.is_null() {
            return Err(io::Error::last_os_error());
        }

        let mut dacl_present: i32 = 0;
        let mut dacl_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut dacl_defaulted: i32 = 0;
        let ok_dacl = unsafe {
            GetSecurityDescriptorDacl(
                sd_ptr,
                &mut dacl_present,
                &mut dacl_ptr,
                &mut dacl_defaulted,
            )
        };
        if ok_dacl == 0 {
            let err = io::Error::last_os_error();
            unsafe {
                let _ = LocalFree(sd_ptr);
            }
            return Err(err);
        }

        let verbatim = to_verbatim_path(path);
        let wide_path: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide_path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                core::ptr::null(),
                core::ptr::null(),
                dacl_ptr,
                core::ptr::null(),
            )
        };
        unsafe {
            let _ = LocalFree(sd_ptr);
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(path)?;
        let mut perms = meta.permissions();
        if meta.is_dir() {
            perms.set_mode(0o700);
        } else {
            perms.set_mode(0o600);
        }
        fs::set_permissions(path, perms)
    }
}

/// Flushes OS and device buffers, returning the actual measured success status.
pub fn flush_hardware_buffers(file: &File) -> bool {
    if file.sync_all().is_err() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let raw_handle = file.as_raw_handle() as isize;
        let ok = unsafe { FlushFileBuffers(raw_handle) };
        ok != 0
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Best-effort `FSCTL_FILE_LEVEL_TRIM` hint before truncation on Windows.
pub fn issue_file_level_trim(file: &File, len: u64) -> bool {
    if len == 0 {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        const FSCTL_FILE_LEVEL_TRIM: u32 = 0x00098208;
        let trim = FileLevelTrim {
            key: 0,
            num_ranges: 1,
            ranges: [FileLevelTrimRange {
                offset: 0,
                length: len,
            }],
        };
        let mut returned: u32 = 0;
        let handle = file.as_raw_handle() as isize;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_FILE_LEVEL_TRIM,
                &trim as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<FileLevelTrim>() as u32,
                core::ptr::null_mut(),
                0,
                &mut returned,
                core::ptr::null_mut(),
            )
        };
        ok != 0
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        false
    }
}

/// Enumerates NTFS Alternate Data Streams (`FindFirstStreamW` / `FindNextStreamW`) safely.
/// Returns `(stream_name, stream_size)` pairs excluding the default `::$DATA` stream.
pub fn enumerate_ntfs_ads(path: &Path) -> Vec<(String, u64)> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut results = Vec::new();
        let verbatim = to_verbatim_path(path);
        let wide_path: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut stream_data = Win32FindStreamData {
            stream_size: 0,
            c_stream_name: [0u16; 296],
        };
        let handle = unsafe {
            FindFirstStreamW(
                wide_path.as_ptr(),
                0,
                &mut stream_data as *mut _ as *mut core::ffi::c_void,
                0,
            )
        };
        if handle != -1_isize && handle != 0 {
            loop {
                let len = stream_data
                    .c_stream_name
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(stream_data.c_stream_name.len());
                let stream_name = String::from_utf16_lossy(&stream_data.c_stream_name[..len]);
                let stream_size = stream_data.stream_size.max(0) as u64;

                if !stream_name.is_empty() && stream_name != "::$DATA" {
                    results.push((stream_name, stream_size));
                }

                if unsafe {
                    FindNextStreamW(handle, &mut stream_data as *mut _ as *mut core::ffi::c_void)
                } == 0
                {
                    break;
                }
            }
            unsafe {
                let _ = FindClose(handle);
            }
        }
        results
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Vec::new()
    }
}

/// Checks if a `Metadata` object represents a symlink or a Windows NTFS reparse point / junction (`FILE_ATTRIBUTE_REPARSE_POINT`).
pub fn is_reparse_point_or_symlink(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

/// Attaches Mark-of-the-Web (`Zone.Identifier` stream with `ZoneId=3` on Windows;
/// `.Zone.Identifier` metadata attribute on non-Windows) to a released file (Phase 2.6, Row 136).
pub fn write_mark_of_the_web(path: &Path, zone_id: u8) -> io::Result<()> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Cannot attach Mark-of-the-Web to non-existent file '{}'",
                path.display()
            ),
        ));
    }
    #[cfg(windows)]
    {
        let verbatim = to_verbatim_path(path);
        let ads_path = PathBuf::from(format!("{}:Zone.Identifier", verbatim.display()));
        let mut f = File::create(ads_path)?;
        write!(
            f,
            "[ZoneTransfer]\r\nZoneId={zone_id}\r\nHostUrl=about:internet\r\n"
        )?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let payload = format!("[ZoneTransfer]\r\nZoneId={zone_id}\r\nHostUrl=about:internet\r\n");
        if let (Ok(c_path), Ok(c_name)) = (
            CString::new(path.as_os_str().as_bytes()),
            CString::new("user.xdg.origin.url"),
        ) {
            unsafe {
                let _ = libc::setxattr(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    payload.as_ptr() as *const libc::c_void,
                    payload.len(),
                    0,
                );
            }
        }
        Ok(())
    }
}

/// Handle to an active Windows Projected File System (`ProjectedFSLib.dll`) virtualization instance (`Row 148`).
pub struct ProjFsInstanceHandle {
    namespace_ctx: isize,
    #[cfg(windows)]
    lib_handle: isize,
}

unsafe impl Send for ProjFsInstanceHandle {}
unsafe impl Sync for ProjFsInstanceHandle {}

impl ProjFsInstanceHandle {
    pub fn raw_context(&self) -> isize {
        self.namespace_ctx
    }
}

impl Drop for ProjFsInstanceHandle {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.namespace_ctx != 0 && self.lib_handle != 0 {
                #[link(name = "kernel32")]
                extern "system" {
                    fn GetProcAddress(h_module: isize, lp_proc_name: *const u8) -> isize;
                    fn FreeLibrary(h_lib_module: isize) -> i32;
                }
                type PrjStopVirtualizingFn = unsafe extern "system" fn(isize);
                unsafe {
                    let proc_addr = GetProcAddress(
                        self.lib_handle,
                        c"PrjStopVirtualizing".as_ptr().cast::<u8>(),
                    );
                    if proc_addr != 0 {
                        let stop_fn: PrjStopVirtualizingFn = core::mem::transmute(proc_addr);
                        stop_fn(self.namespace_ctx);
                    }
                    let _ = FreeLibrary(self.lib_handle);
                }
                self.namespace_ctx = 0;
                self.lib_handle = 0;
            }
        }
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct PrjGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(windows)]
#[repr(C)]
struct PrjCallbackData {
    size: u32,
    flags: u32,
    namespace_virtualization_context: isize,
    command_id: i32,
    file_id: PrjGuid,
    data_stream_id: PrjGuid,
    file_path_name: *const u16,
    version_info: *const core::ffi::c_void,
    triggering_process_id: u32,
    triggering_process_image_file_name: *const u16,
    instance_context: *mut core::ffi::c_void,
}

#[cfg(windows)]
#[repr(C)]
struct PrjCallbacks {
    start_directory_enumeration_cb:
        unsafe extern "system" fn(*const PrjCallbackData, *const PrjGuid) -> i32,
    end_directory_enumeration_cb:
        unsafe extern "system" fn(*const PrjCallbackData, *const PrjGuid) -> i32,
    get_directory_enumeration_cb:
        unsafe extern "system" fn(*const PrjCallbackData, *const PrjGuid, *const u16, isize) -> i32,
    get_placeholder_info_cb: unsafe extern "system" fn(*const PrjCallbackData) -> i32,
    get_file_data_cb: unsafe extern "system" fn(*const PrjCallbackData, u64, u32) -> i32,
    query_file_name_cb: usize,
    notification_cb: usize,
    cancel_command_cb: usize,
}

#[cfg(windows)]
unsafe extern "system" fn prj_start_dir_enum_cb(
    _callback_data: *const PrjCallbackData,
    _enumeration_id: *const PrjGuid,
) -> i32 {
    0 // S_OK
}

#[cfg(windows)]
unsafe extern "system" fn prj_end_dir_enum_cb(
    _callback_data: *const PrjCallbackData,
    _enumeration_id: *const PrjGuid,
) -> i32 {
    0 // S_OK
}

#[cfg(windows)]
unsafe extern "system" fn prj_get_dir_enum_cb(
    _callback_data: *const PrjCallbackData,
    _enumeration_id: *const PrjGuid,
    _search_expression: *const u16,
    _dir_entry_buffer_handle: isize,
) -> i32 {
    0 // S_OK
}

#[cfg(windows)]
unsafe extern "system" fn prj_get_placeholder_info_cb(
    _callback_data: *const PrjCallbackData,
) -> i32 {
    0 // S_OK
}

#[cfg(windows)]
unsafe extern "system" fn prj_get_file_data_cb(
    callback_data: *const PrjCallbackData,
    byte_offset: u64,
    length: u32,
) -> i32 {
    if callback_data.is_null() {
        return -2147024809; // E_INVALIDARG
    }
    let cb = unsafe { &*callback_data };
    let mut guid_bytes = [0u8; 16];
    guid_bytes[0..4].copy_from_slice(&cb.data_stream_id.data1.to_le_bytes());
    guid_bytes[4..6].copy_from_slice(&cb.data_stream_id.data2.to_le_bytes());
    guid_bytes[6..8].copy_from_slice(&cb.data_stream_id.data3.to_le_bytes());
    guid_bytes[8..16].copy_from_slice(&cb.data_stream_id.data4);
    let zero_buf = vec![0u8; length as usize];
    match prj_write_file_data(
        cb.namespace_virtualization_context,
        &guid_bytes,
        &zero_buf,
        byte_offset,
    ) {
        Ok(()) => 0,
        Err(_) => -2147467259, // E_FAIL
    }
}

/// Checks whether Windows Projected File System (`ProjectedFSLib.dll` and `prjflt.sys`)
/// is installed and operational on this endpoint (`Row 148, 151`).
pub fn is_projfs_available() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryW(lp_lib_file_name: *const u16) -> isize;
            fn GetProcAddress(h_module: isize, lp_proc_name: *const u8) -> isize;
            fn FreeLibrary(h_lib_module: isize) -> i32;
        }
        let dll_wide: Vec<u16> = std::ffi::OsStr::new("ProjectedFSLib.dll")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let h_lib = unsafe { LoadLibraryW(dll_wide.as_ptr()) };
        if h_lib == 0 {
            return false;
        }
        let has_start =
            unsafe { GetProcAddress(h_lib, c"PrjStartVirtualizing".as_ptr().cast::<u8>()) != 0 };
        let has_stop =
            unsafe { GetProcAddress(h_lib, c"PrjStopVirtualizing".as_ptr().cast::<u8>()) != 0 };
        let has_write =
            unsafe { GetProcAddress(h_lib, c"PrjWriteFileData".as_ptr().cast::<u8>()) != 0 };
        let has_mark = unsafe {
            GetProcAddress(
                h_lib,
                c"PrjMarkDirectoryAsPlaceholder".as_ptr().cast::<u8>(),
            ) != 0
        };
        unsafe {
            let _ = FreeLibrary(h_lib);
        }
        has_start && has_stop && has_write && has_mark
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Marks `root_path` as a ProjFS virtualization root (`PrjMarkDirectoryAsPlaceholder`) and
/// starts a ProjFS virtualization instance (`PrjStartVirtualizing`) (`Row 148`).
pub fn prj_start_virtualizing_root(root_path: &Path) -> io::Result<ProjFsInstanceHandle> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryW(lp_lib_file_name: *const u16) -> isize;
            fn GetProcAddress(h_module: isize, lp_proc_name: *const u8) -> isize;
            fn FreeLibrary(h_lib_module: isize) -> i32;
        }
        type PrjMarkDirectoryAsPlaceholderFn = unsafe extern "system" fn(
            *const u16,
            *const u16,
            *const core::ffi::c_void,
            *const PrjGuid,
        ) -> i32;
        type PrjStartVirtualizingFn = unsafe extern "system" fn(
            *const u16,
            *const PrjCallbacks,
            *const core::ffi::c_void,
            *const core::ffi::c_void,
            *mut isize,
        ) -> i32;

        fs::create_dir_all(root_path)?;
        let dll_wide: Vec<u16> = std::ffi::OsStr::new("ProjectedFSLib.dll")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let h_lib = unsafe { LoadLibraryW(dll_wide.as_ptr()) };
        if h_lib == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ProjectedFSLib.dll is not available on this Windows host (POSTURE_REDUCED_NO_PROJFS)",
            ));
        }

        let mark_addr = unsafe {
            GetProcAddress(
                h_lib,
                c"PrjMarkDirectoryAsPlaceholder".as_ptr().cast::<u8>(),
            )
        };
        let start_addr =
            unsafe { GetProcAddress(h_lib, c"PrjStartVirtualizing".as_ptr().cast::<u8>()) };
        if mark_addr == 0 || start_addr == 0 {
            unsafe {
                let _ = FreeLibrary(h_lib);
            }
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ProjectedFSLib.dll missing PrjStartVirtualizing entry point",
            ));
        }

        let mark_fn: PrjMarkDirectoryAsPlaceholderFn = unsafe { core::mem::transmute(mark_addr) };
        let start_fn: PrjStartVirtualizingFn = unsafe { core::mem::transmute(start_addr) };

        let root_wide: Vec<u16> = root_path.as_os_str().encode_wide().chain(Some(0)).collect();
        let instance_guid = PrjGuid {
            data1: 0x534E_544C,
            data2: 0x5052,
            data3: 0x4A46,
            data4: *b"SENTINEL",
        };
        let hr_mark = unsafe {
            mark_fn(
                root_wide.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                &instance_guid,
            )
        };
        if hr_mark < 0 {
            unsafe {
                let _ = FreeLibrary(h_lib);
            }
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "PrjMarkDirectoryAsPlaceholder failed with HRESULT 0x{:08X} (POSTURE_REDUCED_NO_PROJFS)",
                    hr_mark as u32
                ),
            ));
        }

        let callbacks = Box::new(PrjCallbacks {
            start_directory_enumeration_cb: prj_start_dir_enum_cb,
            end_directory_enumeration_cb: prj_end_dir_enum_cb,
            get_directory_enumeration_cb: prj_get_dir_enum_cb,
            get_placeholder_info_cb: prj_get_placeholder_info_cb,
            get_file_data_cb: prj_get_file_data_cb,
            query_file_name_cb: 0,
            notification_cb: 0,
            cancel_command_cb: 0,
        });
        let mut namespace_ctx: isize = 0;
        let hr_start = unsafe {
            start_fn(
                root_wide.as_ptr(),
                &*callbacks,
                core::ptr::null(),
                core::ptr::null(),
                &mut namespace_ctx,
            )
        };
        if hr_start < 0 || namespace_ctx == 0 {
            unsafe {
                let _ = FreeLibrary(h_lib);
            }
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "PrjStartVirtualizing failed with HRESULT 0x{:08X} (POSTURE_REDUCED_NO_PROJFS)",
                    hr_start as u32
                ),
            ));
        }

        Ok(ProjFsInstanceHandle {
            namespace_ctx,
            lib_handle: h_lib,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = root_path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ProjFS is only supported on Windows hosts",
        ))
    }
}

/// Streams decrypted, hash-verified file bytes into a ProjFS placeholder via
/// `PrjAllocateAlignedBuffer` + `PrjWriteFileData` + `PrjFreeAlignedBuffer` (`Row 148`).
pub fn prj_write_file_data(
    namespace_ctx: isize,
    data_stream_id: &[u8; 16],
    data: &[u8],
    byte_offset: u64,
) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryW(lp_lib_file_name: *const u16) -> isize;
            fn GetProcAddress(h_module: isize, lp_proc_name: *const u8) -> isize;
            fn FreeLibrary(h_lib_module: isize) -> i32;
        }
        type PrjAllocateAlignedBufferFn = unsafe extern "system" fn(isize, usize) -> *mut u8;
        type PrjFreeAlignedBufferFn = unsafe extern "system" fn(*mut u8);
        type PrjWriteFileDataFn =
            unsafe extern "system" fn(isize, *const PrjGuid, *const u8, u64, u32) -> i32;

        if namespace_ctx == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid ProjFS namespace_virtualization_context",
            ));
        }

        let dll_wide: Vec<u16> = std::ffi::OsStr::new("ProjectedFSLib.dll")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let h_lib = unsafe { LoadLibraryW(dll_wide.as_ptr()) };
        if h_lib == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ProjectedFSLib.dll not found",
            ));
        }

        let alloc_addr =
            unsafe { GetProcAddress(h_lib, c"PrjAllocateAlignedBuffer".as_ptr().cast::<u8>()) };
        let free_addr =
            unsafe { GetProcAddress(h_lib, c"PrjFreeAlignedBuffer".as_ptr().cast::<u8>()) };
        let write_addr =
            unsafe { GetProcAddress(h_lib, c"PrjWriteFileData".as_ptr().cast::<u8>()) };

        if alloc_addr == 0 || free_addr == 0 || write_addr == 0 {
            unsafe {
                let _ = FreeLibrary(h_lib);
            }
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ProjectedFSLib.dll missing PrjWriteFileData symbols",
            ));
        }

        let alloc_fn: PrjAllocateAlignedBufferFn = unsafe { core::mem::transmute(alloc_addr) };
        let free_fn: PrjFreeAlignedBufferFn = unsafe { core::mem::transmute(free_addr) };
        let write_fn: PrjWriteFileDataFn = unsafe { core::mem::transmute(write_addr) };

        let buf_len = data.len().max(1);
        let aligned_ptr = unsafe { alloc_fn(namespace_ctx, buf_len) };
        if aligned_ptr.is_null() {
            unsafe {
                let _ = FreeLibrary(h_lib);
            }
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "PrjAllocateAlignedBuffer returned null",
            ));
        }

        let mut d4 = [0u8; 8];
        d4.copy_from_slice(&data_stream_id[8..16]);
        let stream_guid = PrjGuid {
            data1: u32::from_le_bytes([
                data_stream_id[0],
                data_stream_id[1],
                data_stream_id[2],
                data_stream_id[3],
            ]),
            data2: u16::from_le_bytes([data_stream_id[4], data_stream_id[5]]),
            data3: u16::from_le_bytes([data_stream_id[6], data_stream_id[7]]),
            data4: d4,
        };

        let hr = unsafe {
            if !data.is_empty() {
                core::ptr::copy_nonoverlapping(data.as_ptr(), aligned_ptr, data.len());
            }
            let res = write_fn(
                namespace_ctx,
                &stream_guid,
                aligned_ptr,
                byte_offset,
                data.len() as u32,
            );
            free_fn(aligned_ptr);
            let _ = FreeLibrary(h_lib);
            res
        };

        if hr < 0 {
            return Err(io::Error::other(format!(
                "PrjWriteFileData failed with HRESULT 0x{:08X}",
                hr as u32
            )));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (namespace_ctx, data_stream_id, data, byte_offset);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "PrjWriteFileData is only supported on Windows",
        ))
    }
}
