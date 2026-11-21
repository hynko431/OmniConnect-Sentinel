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
    fn CreateDirectoryW(
        lpPathName: *const u16,
        lpSecurityAttributes: *const core::ffi::c_void,
    ) -> i32;
    fn GetFileInformationByHandle(hFile: isize, lpFileInformation: *mut core::ffi::c_void) -> i32;
    fn GetFileType(hFile: isize) -> u32;
    fn FindFirstFileW(lpFileName: *const u16, lpFindFileData: *mut core::ffi::c_void) -> isize;
}

#[cfg(windows)]
#[repr(C)]
struct Win32FindDataW {
    dw_file_attributes: u32,
    ft_creation_time_low: u32,
    ft_creation_time_high: u32,
    ft_last_access_time_low: u32,
    ft_last_access_time_high: u32,
    ft_last_write_time_low: u32,
    ft_last_write_time_high: u32,
    n_file_size_high: u32,
    n_file_size_low: u32,
    dw_reserved0: u32,
    dw_reserved1: u32,
    c_file_name: [u16; 260],
    c_alternate_file_name: [u16; 14],
}

#[cfg(windows)]
#[repr(C)]
struct ByHandleFileInformation {
    dw_file_attributes: u32,
    ft_creation_time_dw_low_datetime: u32,
    ft_creation_time_dw_high_datetime: u32,
    ft_last_access_time_dw_low_datetime: u32,
    ft_last_access_time_dw_high_datetime: u32,
    ft_last_write_time_dw_low_datetime: u32,
    ft_last_write_time_dw_high_datetime: u32,
    dw_volume_serial_number: u32,
    n_file_size_high: u32,
    n_file_size_low: u32,
    n_number_of_links: u32,
    n_file_index_high: u32,
    n_file_index_low: u32,
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
    fn SetKernelObjectSecurity(
        Handle: isize,
        SecurityInformation: u32,
        SecurityDescriptor: *const core::ffi::c_void,
    ) -> i32;
    fn GetNamedSecurityInfoW(
        pObjectName: *const u16,
        ObjectType: i32,
        SecurityInfo: u32,
        ppsidOwner: *mut *mut core::ffi::c_void,
        ppsidGroup: *mut *mut core::ffi::c_void,
        ppDacl: *mut *mut core::ffi::c_void,
        ppSacl: *mut *mut core::ffi::c_void,
        ppSecurityDescriptor: *mut *mut core::ffi::c_void,
    ) -> u32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        SecurityDescriptor: *const core::ffi::c_void,
        RequestedStringSDRevision: u32,
        SecurityInformation: u32,
        StringSecurityDescriptor: *mut *mut u16,
        StringSecurityDescriptorLen: *mut u32,
    ) -> i32;
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

/// Verifies that `path` AND every existing ancestor component (plus host path for an NTFS `:stream`)
/// is NOT a symlink or NTFS reparse point / junction.
pub fn ensure_not_symlink_or_reparse_point(path: &Path) -> io::Result<()> {
    let s = path.to_string_lossy();
    let without_verbatim = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let base_target: PathBuf = if without_verbatim.len() > 3 {
        if let Some(colon_rel) = without_verbatim[2..].find(':') {
            let host_str = &without_verbatim[..2 + colon_rel];
            PathBuf::from(host_str)
        } else {
            PathBuf::from(without_verbatim)
        }
    } else {
        PathBuf::from(without_verbatim)
    };

    let abs_target = if base_target.is_absolute() {
        base_target
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&base_target))
            .unwrap_or(base_target)
    };

    // Walk every prefix component without collapsing `..` first so intermediate NTFS junctions
    // or symlinks (`junc/existing_sub/file.txt` or `junc/../foo`) are caught before OS traversal.
    let mut cur = PathBuf::new();
    for comp in abs_target.components() {
        match comp {
            Component::Prefix(p) => cur.push(p.as_os_str()),
            Component::RootDir => cur.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                cur.push("..");
            }
            Component::Normal(c) => {
                cur.push(c);
                let cur_verbatim = to_verbatim_path(&cur);
                if let Ok(meta) = fs::symlink_metadata(&cur_verbatim) {
                    if is_reparse_point_or_symlink(&meta) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "Refusing operation: path component '{}' (in '{}') is a symlink or reparse point",
                                cur.display(),
                                path.display()
                            ),
                        ));
                    }
                }
                if let Ok(meta) = fs::symlink_metadata(&cur) {
                    if is_reparse_point_or_symlink(&meta) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "Refusing operation: path component '{}' (in '{}') is a symlink or reparse point",
                                cur.display(),
                                path.display()
                            ),
                        ));
                    }
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

/// Opens an untrusted file (e.g. from removable USB media) strictly without following symlinks
/// or NTFS reparse points, verifying on the open handle that the target is a regular file.
/// Rejects symlinks, reparse points, directories, device nodes, pipes, and FIFOs.
pub fn open_untrusted_readonly_nofollow(path: &Path) -> io::Result<File> {
    ensure_not_symlink_or_reparse_point(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;

        let verbatim = to_verbatim_path(path);
        let wide: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: isize = -1;

        let h_file = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };

        if h_file == INVALID_HANDLE_VALUE || h_file == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut info: ByHandleFileInformation = unsafe { core::mem::zeroed() };
        let ok = unsafe {
            GetFileInformationByHandle(h_file, &mut info as *mut _ as *mut core::ffi::c_void)
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            unsafe {
                let _ = CloseHandle(h_file);
            }
            return Err(err);
        }

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
        const FILE_TYPE_DISK: u32 = 0x0001;

        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            unsafe {
                let _ = CloseHandle(h_file);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Untrusted path '{}' is an NTFS reparse point or symlink",
                    path.display()
                ),
            ));
        }

        if (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            unsafe {
                let _ = CloseHandle(h_file);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Untrusted path '{}' is a directory", path.display()),
            ));
        }

        let file_type = unsafe { GetFileType(h_file) };
        if file_type != FILE_TYPE_DISK {
            unsafe {
                let _ = CloseHandle(h_file);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Untrusted path '{}' is not a regular disk file (file_type={file_type})",
                    path.display()
                ),
            ));
        }

        Ok(unsafe { File::from_raw_handle(h_file as *mut core::ffi::c_void) })
    }
    #[cfg(not(windows))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } < 0 {
            let err = io::Error::last_os_error();
            unsafe {
                let _ = libc::close(fd);
            }
            return Err(err);
        }

        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            unsafe {
                let _ = libc::close(fd);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Untrusted path '{}' is not a regular file", path.display()),
            ));
        }

        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/// Reads an untrusted stream into a buffer with strict quota enforcement via `Read::take(budget + 1)`.
/// Guaranteed to prevent memory exhaustion by failing closed if the stream exceeds `max_bytes`.
pub fn read_untrusted_to_end_bounded<R: io::Read>(
    reader: &mut R,
    max_bytes: u64,
) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut take_reader = reader.take(max_bytes.saturating_add(1));
    let mut buffer = Vec::new();
    take_reader.read_to_end(&mut buffer)?;
    if buffer.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Untrusted stream exceeded byte quota limit of {max_bytes} bytes"),
        ));
    }
    Ok(buffer)
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
    ensure_not_symlink_or_reparse_point(path)?;
    let verbatim = to_verbatim_path(path);
    let meta = fs::symlink_metadata(&verbatim).or_else(|_| fs::symlink_metadata(path))?;
    if is_reparse_point_or_symlink(&meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Refusing DACL application on symlink or reparse point '{}'",
                path.display()
            ),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const SDDL_REVISION_1: u32 = 1;
        const SE_FILE_OBJECT: i32 = 1;
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
        const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

        // Grant full control to SYSTEM (SY), Administrators (BA), and Owner Rights (OW) so
        // both elevated SYSTEM services and current process owners can access while blocking other users.
        let sddl = if meta.is_dir() {
            "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;OW)"
        } else {
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"
        };
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
        let mut perms = meta.permissions();
        if meta.is_dir() {
            perms.set_mode(0o700);
        } else {
            perms.set_mode(0o600);
        }
        fs::set_permissions(path, perms)
    }
}

/// Creates or truncates a file atomically with strict SYSTEM + Administrators DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`)
/// on Windows, or `0o600` on Unix, at handle creation time, completely eliminating post-creation DACL race windows.
pub fn create_restricted_file_handle_atomic(path: &Path) -> io::Result<File> {
    ensure_not_symlink_or_reparse_point(path)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_not_symlink_or_reparse_point(parent)?;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;

        const SDDL_REVISION_1: u32 = 1;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        const CREATE_NEW: u32 = 1;
        const OPEN_EXISTING: u32 = 3;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
        const INVALID_HANDLE_VALUE: isize = -1;

        // Grant full control to SYSTEM (SY), Administrators (BA), and Owner (OW) so
        // elevated services, administrator tools, and current process owners can access
        // while strictly denying untrusted users (Authenticated Users, Everyone).
        let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";
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

        #[repr(C)]
        struct SecurityAttributes {
            n_length: u32,
            lp_security_descriptor: *mut core::ffi::c_void,
            b_inherit_handle: i32,
        }

        let sa = SecurityAttributes {
            n_length: core::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: sd_ptr,
            b_inherit_handle: 0,
        };

        let verbatim = to_verbatim_path(path);
        let wide_path: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();

        // Attempt atomic `CREATE_NEW` first (never follows live or dangling symlinks/junctions).
        let h_new = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &sa as *const _ as *const core::ffi::c_void,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };

        unsafe {
            let _ = LocalFree(sd_ptr);
        }

        if h_new != INVALID_HANDLE_VALUE && h_new != 0 {
            return Ok(unsafe { File::from_raw_handle(h_new as *mut core::ffi::c_void) });
        }

        let create_err = io::Error::last_os_error();
        if create_err.raw_os_error() != Some(80) && create_err.raw_os_error() != Some(183) {
            return Err(create_err);
        }

        // File entry already exists: open strictly with `FILE_FLAG_OPEN_REPARSE_POINT` (no traversal),
        // verify on the kernel handle that it is a single-link regular file, remediate its DACL, then truncate.
        ensure_not_symlink_or_reparse_point(path)?;
        let h_existing = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };
        if h_existing == INVALID_HANDLE_VALUE || h_existing == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut info: ByHandleFileInformation = unsafe { core::mem::zeroed() };
        let ok_info = unsafe {
            GetFileInformationByHandle(h_existing, &mut info as *mut _ as *mut core::ffi::c_void)
        };
        if ok_info == 0 {
            let err = io::Error::last_os_error();
            unsafe {
                let _ = CloseHandle(h_existing);
            }
            return Err(err);
        }
        if (info.dw_file_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
            != 0
        {
            unsafe {
                let _ = CloseHandle(h_existing);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Refusing restricted file open: '{}' is a reparse point or directory",
                    path.display()
                ),
            ));
        }
        if info.n_number_of_links > 1 {
            unsafe {
                let _ = CloseHandle(h_existing);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Refusing restricted file open: hardlink squatting detected on '{}' (links={})",
                    path.display(),
                    info.n_number_of_links
                ),
            ));
        }

        let file = unsafe { File::from_raw_handle(h_existing as *mut core::ffi::c_void) };
        apply_system_admin_dacl(path)?;
        file.set_len(0)?;
        Ok(file)
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path)?;
        let fd = file.as_raw_fd();
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Restricted target '{}' is not a regular file",
                    path.display()
                ),
            ));
        }
        if st.st_nlink > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Refusing restricted file open: hardlink squatting detected on '{}'",
                    path.display()
                ),
            ));
        }
        if unsafe { libc::fchmod(fd, 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        file.set_len(0)?;
        Ok(file)
    }
}

/// Creates a file atomically with restricted permissions and writes `content` to it.
pub fn create_restricted_file_atomic(path: &Path, content: &[u8]) -> io::Result<()> {
    ensure_not_symlink_or_reparse_point(path)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_not_symlink_or_reparse_point(parent)?;
            let parent_verbatim = to_verbatim_path(parent);
            match fs::symlink_metadata(&parent_verbatim).or_else(|_| fs::symlink_metadata(parent)) {
                Ok(pm) => {
                    if is_reparse_point_or_symlink(&pm) || !pm.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "Parent path '{}' is a reparse point or non-directory",
                                parent.display()
                            ),
                        ));
                    }
                }
                Err(_) => {
                    create_restricted_dir_atomic(parent)?;
                }
            }
        }
    }
    use std::io::Write;
    let mut file = create_restricted_file_handle_atomic(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

/// Creates a directory atomically with strict SYSTEM + Administrators DACL (`D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)`)
/// on Windows, or `0o700` on Unix, at creation time.
pub fn create_restricted_dir_atomic(path: &Path) -> io::Result<()> {
    ensure_not_symlink_or_reparse_point(path)?;
    let verbatim = to_verbatim_path(path);
    if let Ok(meta) = fs::symlink_metadata(&verbatim).or_else(|_| fs::symlink_metadata(path)) {
        if is_reparse_point_or_symlink(&meta) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Refusing operation: '{}' is a symlink or reparse point",
                    path.display()
                ),
            ));
        }
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Target restricted directory '{}' already exists as a non-directory",
                    path.display()
                ),
            ));
        }
        apply_system_admin_dacl(path)?;
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_not_symlink_or_reparse_point(parent)?;
            let parent_verbatim = to_verbatim_path(parent);
            match fs::symlink_metadata(&parent_verbatim).or_else(|_| fs::symlink_metadata(parent)) {
                Ok(pm) => {
                    if is_reparse_point_or_symlink(&pm) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "Refusing operation: parent '{}' is a symlink or reparse point",
                                parent.display()
                            ),
                        ));
                    }
                    if !pm.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!(
                                "Parent path '{}' already exists as a non-directory",
                                parent.display()
                            ),
                        ));
                    }
                }
                Err(_) => {
                    create_restricted_dir_atomic(parent)?;
                }
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        const SDDL_REVISION_1: u32 = 1;
        // Grant full control to SYSTEM (SY), Administrators (BA), and Owner (OW) with container/object inheritance.
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

        #[repr(C)]
        struct SecurityAttributes {
            n_length: u32,
            lp_security_descriptor: *mut core::ffi::c_void,
            b_inherit_handle: i32,
        }

        let sa = SecurityAttributes {
            n_length: core::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: sd_ptr,
            b_inherit_handle: 0,
        };

        let wide_path: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();

        let res = unsafe {
            CreateDirectoryW(
                wide_path.as_ptr(),
                &sa as *const _ as *const core::ffi::c_void,
            )
        };

        unsafe {
            let _ = LocalFree(sd_ptr);
        }

        if res == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(183) {
                // ERROR_ALREADY_EXISTS — re-validate non-reparse directory AND enforce restricted DACL
                ensure_not_symlink_or_reparse_point(path)?;
                let meta =
                    fs::symlink_metadata(&verbatim).or_else(|_| fs::symlink_metadata(path))?;
                if is_reparse_point_or_symlink(&meta) || !meta.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Concurrent creation check failed: '{}' is a symlink/reparse point or non-directory",
                            path.display()
                        ),
                    ));
                }
                apply_system_admin_dacl(path)?;
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                ensure_not_symlink_or_reparse_point(path)?;
                let meta = fs::symlink_metadata(path)?;
                if is_reparse_point_or_symlink(&meta) || !meta.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Concurrent creation check failed: '{}' is a symlink or non-directory",
                            path.display()
                        ),
                    ));
                }
                apply_system_admin_dacl(path)?;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

/// Windows SDDL for materialized sanitized staging directories (`CSE-18`):
/// `SY`/`BA`/`OW` hold full control for service lifecycle/teardown, while `AU`
/// (Authenticated Users) receives strictly read+traverse (`FRFX`) on directories
/// and read-only (`FR`, zero write/delete/execute) inherited onto files.
pub const STAGING_DIR_READONLY_USER_SDDL: &str =
    "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;OW)(A;CI;FRFX;;;AU)(A;OIIO;FR;;;AU)";

/// Windows SDDL for materialized sanitized staging files (`CSE-18`):
/// `SY`/`BA`/`OW` hold full control for hydration/MOTW/teardown, while `AU`
/// (Authenticated Users) receives strictly `FILE_GENERIC_READ` (`FR`, zero write/delete/execute).
pub const STAGING_FILE_READONLY_USER_SDDL: &str =
    "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;FR;;;AU)";

/// Applies the read-only interactive-user staging ACL (`SY`/`BA`/`OW` full control + `AU` read-only)
/// to a materialized sanitized staging directory or file (`CSE-18`).
///
/// Must NEVER be used on `ShadowCache`, `Quarantine`, `AuditLedger`, or key material.
pub fn apply_readonly_staging_dacl(path: &Path) -> io::Result<()> {
    ensure_not_symlink_or_reparse_point(path)?;
    let verbatim = to_verbatim_path(path);
    let meta = fs::symlink_metadata(&verbatim).or_else(|_| fs::symlink_metadata(path))?;
    if is_reparse_point_or_symlink(&meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Refusing staging DACL application on symlink or reparse point '{}'",
                path.display()
            ),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const SDDL_REVISION_1: u32 = 1;
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
        const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
        const WRITE_DAC: u32 = 0x0004_0000;
        const READ_CONTROL: u32 = 0x0002_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        const OPEN_EXISTING: u32 = 3;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        const INVALID_HANDLE_VALUE: isize = -1;

        let sddl = if meta.is_dir() {
            STAGING_DIR_READONLY_USER_SDDL
        } else {
            STAGING_FILE_READONLY_USER_SDDL
        };
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

        // Open handle directly with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`
        // and apply the protected DACL via `SetKernelObjectSecurity` (zero path-swap TOCTOU and
        // reliable handling of `\\?\` verbatim paths).
        let wide_path: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                WRITE_DAC | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            let err = io::Error::last_os_error();
            unsafe {
                let _ = LocalFree(sd_ptr);
            }
            return Err(err);
        }

        let mut info: ByHandleFileInformation = unsafe { core::mem::zeroed() };
        let ok_info = unsafe {
            GetFileInformationByHandle(handle, &mut info as *mut _ as *mut core::ffi::c_void)
        };
        if ok_info == 0 || (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            let err = if ok_info == 0 {
                io::Error::last_os_error()
            } else {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Refusing staging DACL application on reparse point '{}'",
                        path.display()
                    ),
                )
            };
            unsafe {
                let _ = CloseHandle(handle);
                let _ = LocalFree(sd_ptr);
            }
            return Err(err);
        }

        let status = unsafe {
            SetKernelObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd_ptr,
            )
        };
        let kernel_err = if status == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe {
            let _ = CloseHandle(handle);
            let _ = LocalFree(sd_ptr);
        }
        if let Some(err) = kernel_err {
            return Err(err);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = meta.permissions();
        if meta.is_dir() {
            perms.set_mode(0o755);
        } else {
            perms.set_mode(0o444);
        }
        fs::set_permissions(path, perms)
    }
}

/// Atomically creates (or updates) a sanitized staging directory with `STAGING_DIR_READONLY_USER_SDDL`
/// on Windows or `0o755` on Unix (`CSE-18`), refusing symlinks/reparse points.
pub fn create_readonly_staging_dir_atomic(path: &Path) -> io::Result<()> {
    ensure_not_symlink_or_reparse_point(path)?;
    let verbatim = to_verbatim_path(path);
    if let Ok(meta) = fs::symlink_metadata(&verbatim).or_else(|_| fs::symlink_metadata(path)) {
        if is_reparse_point_or_symlink(&meta) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Refusing staging directory operation: '{}' is a symlink or reparse point",
                    path.display()
                ),
            ));
        }
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Target staging directory '{}' already exists as a non-directory",
                    path.display()
                ),
            ));
        }
        apply_readonly_staging_dacl(path)?;
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_not_symlink_or_reparse_point(parent)?;
            let parent_verbatim = to_verbatim_path(parent);
            match fs::symlink_metadata(&parent_verbatim).or_else(|_| fs::symlink_metadata(parent)) {
                Ok(pm) => {
                    if is_reparse_point_or_symlink(&pm) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "Refusing staging directory operation: parent '{}' is a symlink or reparse point",
                                parent.display()
                            ),
                        ));
                    }
                    if !pm.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!(
                                "Parent path '{}' already exists as a non-directory",
                                parent.display()
                            ),
                        ));
                    }
                }
                Err(_) => {
                    create_readonly_staging_dir_atomic(parent)?;
                }
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const SDDL_REVISION_1: u32 = 1;
        let wide_sddl: Vec<u16> = std::ffi::OsStr::new(STAGING_DIR_READONLY_USER_SDDL)
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

        #[repr(C)]
        struct SecurityAttributes {
            n_length: u32,
            lp_security_descriptor: *mut core::ffi::c_void,
            b_inherit_handle: i32,
        }

        let sa = SecurityAttributes {
            n_length: core::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: sd_ptr,
            b_inherit_handle: 0,
        };

        let wide_path: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();
        let res = unsafe {
            CreateDirectoryW(
                wide_path.as_ptr(),
                &sa as *const _ as *const core::ffi::c_void,
            )
        };
        unsafe {
            let _ = LocalFree(sd_ptr);
        }

        if res == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(183) {
                ensure_not_symlink_or_reparse_point(path)?;
                let meta =
                    fs::symlink_metadata(&verbatim).or_else(|_| fs::symlink_metadata(path))?;
                if is_reparse_point_or_symlink(&meta) || !meta.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Concurrent staging directory check failed: '{}' is a symlink/reparse point or non-directory",
                            path.display()
                        ),
                    ));
                }
                apply_readonly_staging_dacl(path)?;
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o755);
        match builder.create(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                ensure_not_symlink_or_reparse_point(path)?;
                let meta = fs::symlink_metadata(path)?;
                if is_reparse_point_or_symlink(&meta) || !meta.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Concurrent staging directory check failed: '{}' is a symlink or non-directory",
                            path.display()
                        ),
                    ));
                }
                apply_readonly_staging_dacl(path)?;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

/// Atomically writes a materialized sanitized staging file with `STAGING_FILE_READONLY_USER_SDDL`
/// on Windows (`SY`/`BA`/`OW` full control + `AU` strictly `FILE_GENERIC_READ`, zero write/delete/execute)
/// or `0o644` on Unix (caller finishes with MOTW + `set_readonly(true)` -> `0o444`), rejecting
/// symlinks, reparse points, and hardlink squatting (`CSE-18`).
pub fn create_readonly_staging_file_atomic(path: &Path, content: &[u8]) -> io::Result<()> {
    ensure_not_symlink_or_reparse_point(path)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_not_symlink_or_reparse_point(parent)?;
            let parent_verbatim = to_verbatim_path(parent);
            match fs::symlink_metadata(&parent_verbatim).or_else(|_| fs::symlink_metadata(parent)) {
                Ok(pm) => {
                    if is_reparse_point_or_symlink(&pm) || !pm.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "Staging parent path '{}' is a reparse point or non-directory",
                                parent.display()
                            ),
                        ));
                    }
                }
                Err(_) => {
                    create_readonly_staging_dir_atomic(parent)?;
                }
            }
        }
    }

    #[cfg(windows)]
    let mut file = {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;

        const SDDL_REVISION_1: u32 = 1;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        const CREATE_NEW: u32 = 1;
        const OPEN_EXISTING: u32 = 3;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
        const INVALID_HANDLE_VALUE: isize = -1;

        let wide_sddl: Vec<u16> = std::ffi::OsStr::new(STAGING_FILE_READONLY_USER_SDDL)
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

        #[repr(C)]
        struct SecurityAttributes {
            n_length: u32,
            lp_security_descriptor: *mut core::ffi::c_void,
            b_inherit_handle: i32,
        }

        let sa = SecurityAttributes {
            n_length: core::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: sd_ptr,
            b_inherit_handle: 0,
        };

        let verbatim = to_verbatim_path(path);
        let wide_path: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();

        let h_new = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &sa as *const _ as *const core::ffi::c_void,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };
        unsafe {
            let _ = LocalFree(sd_ptr);
        }

        if h_new != INVALID_HANDLE_VALUE && h_new != 0 {
            unsafe { File::from_raw_handle(h_new as *mut core::ffi::c_void) }
        } else {
            let create_err = io::Error::last_os_error();
            if create_err.raw_os_error() != Some(80) && create_err.raw_os_error() != Some(183) {
                return Err(create_err);
            }
            ensure_not_symlink_or_reparse_point(path)?;
            let h_existing = unsafe {
                CreateFileW(
                    wide_path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
                    0,
                )
            };
            if h_existing == INVALID_HANDLE_VALUE || h_existing == 0 {
                return Err(io::Error::last_os_error());
            }

            let mut info: ByHandleFileInformation = unsafe { core::mem::zeroed() };
            let ok_info = unsafe {
                GetFileInformationByHandle(
                    h_existing,
                    &mut info as *mut _ as *mut core::ffi::c_void,
                )
            };
            if ok_info == 0 {
                let err = io::Error::last_os_error();
                unsafe {
                    let _ = CloseHandle(h_existing);
                }
                return Err(err);
            }
            if (info.dw_file_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
                != 0
            {
                unsafe {
                    let _ = CloseHandle(h_existing);
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Refusing staging file open: '{}' is a reparse point or directory",
                        path.display()
                    ),
                ));
            }
            if info.n_number_of_links > 1 {
                unsafe {
                    let _ = CloseHandle(h_existing);
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Refusing staging file open: hardlink squatting detected on '{}' (links={})",
                        path.display(),
                        info.n_number_of_links
                    ),
                ));
            }

            let existing = unsafe { File::from_raw_handle(h_existing as *mut core::ffi::c_void) };
            apply_readonly_staging_dacl(path)?;
            existing.set_len(0)?;
            existing
        }
    };

    #[cfg(not(windows))]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        options.mode(0o644);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let f = options.open(path)?;
        let fd = f.as_raw_fd();
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Staging target '{}' is not a regular file", path.display()),
            ));
        }
        if st.st_nlink > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Refusing staging file open: hardlink squatting detected on '{}'",
                    path.display()
                ),
            ));
        }
        if unsafe { libc::fchmod(fd, 0o644) } != 0 {
            return Err(io::Error::last_os_error());
        }
        f.set_len(0)?;
        f
    };

    {
        use std::io::Write as _;
        file.write_all(content)?;
        file.sync_all()?;
        Ok(())
    }
}

/// Queries the active NTFS DACL SDDL string for `path` on Windows (or octal mode on Unix).
/// Rejects symlinks and NTFS reparse points.
pub fn query_path_dacl_sddl(path: &Path) -> io::Result<String> {
    ensure_not_symlink_or_reparse_point(path)?;
    let verbatim = to_verbatim_path(path);
    let meta = fs::symlink_metadata(&verbatim).or_else(|_| fs::symlink_metadata(path))?;
    if is_reparse_point_or_symlink(&meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Refusing DACL query on symlink or reparse point '{}'",
                path.display()
            ),
        ));
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const SE_FILE_OBJECT: i32 = 1;
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
        const SDDL_REVISION_1: u32 = 1;

        let wide_path: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut dacl_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut sd_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide_path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut dacl_ptr,
                core::ptr::null_mut(),
                &mut sd_ptr,
            )
        };
        if status != 0 || sd_ptr.is_null() {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let mut wide_sddl_ptr: *mut u16 = core::ptr::null_mut();
        let mut wide_sddl_len: u32 = 0;
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd_ptr,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut wide_sddl_ptr,
                &mut wide_sddl_len,
            )
        };
        unsafe {
            let _ = LocalFree(sd_ptr);
        }
        if ok == 0 || wide_sddl_ptr.is_null() {
            return Err(io::Error::last_os_error());
        }

        let slice = unsafe { core::slice::from_raw_parts(wide_sddl_ptr, wide_sddl_len as usize) };
        let trimmed_len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        let sddl = String::from_utf16_lossy(&slice[..trimmed_len]);
        unsafe {
            let _ = LocalFree(wide_sddl_ptr as *mut core::ffi::c_void);
        }
        Ok(sddl)
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(format!(
            "unix_mode:0o{:04o}",
            meta.permissions().mode() & 0o7777
        ))
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

/// Windows Projected File System (`ProjFS`) NTFS reparse tag (`0x9000_001C`).
pub const IO_REPARSE_TAG_PROJFS: u32 = 0x9000_001C;

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

/// Returns `true` strictly when `path` is a Windows NTFS reparse point tagged with
/// `IO_REPARSE_TAG_PROJFS` (`0x9000_001C`) rather than a symlink or NTFS junction.
pub fn is_projfs_reparse_point(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        const INVALID_HANDLE_VALUE: isize = -1;

        let verbatim = to_verbatim_path(path);
        let wide: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut find_data: Win32FindDataW = unsafe { core::mem::zeroed() };
        let h = unsafe {
            FindFirstFileW(
                wide.as_ptr(),
                (&mut find_data as *mut Win32FindDataW).cast::<core::ffi::c_void>(),
            )
        };
        if h == INVALID_HANDLE_VALUE || h == 0 {
            return false;
        }
        unsafe {
            let _ = FindClose(h);
        }
        (find_data.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            && find_data.dw_reserved0 == IO_REPARSE_TAG_PROJFS
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
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

/// Metadata for an entry projected through Windows Projected File System (`ProjFS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjFsProjectedEntry {
    pub relative_path: PathBuf,
    pub is_directory: bool,
    pub file_size: u64,
    pub content_sha256: [u8; 32],
}

/// Backend data source invoked by Windows `ProjectedFSLib.dll` callbacks (`Row 148`).
pub trait ProjFsVirtualizerBackend: Send + Sync + 'static {
    fn list_entries(&self) -> Vec<ProjFsProjectedEntry>;
    fn read_verified_range(
        &self,
        relative_path: &Path,
        byte_offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, String>;
}

/// Handle to an active Windows Projected File System (`ProjectedFSLib.dll`) virtualization instance (`Row 148`).
pub struct ProjFsInstanceHandle {
    namespace_ctx: isize,
    #[cfg(windows)]
    lib_handle: isize,
    #[cfg(windows)]
    state: Option<Box<ProjFsInstanceState>>,
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
            if self.namespace_ctx != 0 {
                if let Some(ref state) = self.state {
                    unsafe {
                        (state.stop_fn)(self.namespace_ctx);
                    }
                }
                self.namespace_ctx = 0;
            }
            drop(self.state.take());
            if self.lib_handle != 0 {
                #[link(name = "kernel32")]
                extern "system" {
                    fn FreeLibrary(h_lib_module: isize) -> i32;
                }
                unsafe {
                    let _ = FreeLibrary(self.lib_handle);
                }
                self.lib_handle = 0;
            }
        }
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PrjGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PrjFileBasicInfo {
    is_directory: u8,
    _pad0: [u8; 7],
    file_size: i64,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
    _pad1: u32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PrjPlaceholderInfo {
    file_basic_info: PrjFileBasicInfo,
    ea_buffer_size: u32,
    offset_to_first_ea: u32,
    security_buffer_size: u32,
    offset_to_security_descriptor: u32,
    streams_info_buffer_size: u32,
    offset_to_first_stream_info: u32,
    provider_id: [u8; 128],
    content_id: [u8; 128],
    variable_data: [u8; 1],
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
type PrjMarkDirectoryAsPlaceholderFn = unsafe extern "system" fn(
    *const u16,
    *const u16,
    *const core::ffi::c_void,
    *const PrjGuid,
) -> i32;
#[cfg(windows)]
type PrjStartVirtualizingFn = unsafe extern "system" fn(
    *const u16,
    *const PrjCallbacks,
    *const core::ffi::c_void,
    *const core::ffi::c_void,
    *mut isize,
) -> i32;
#[cfg(windows)]
type PrjStopVirtualizingFn = unsafe extern "system" fn(isize);
#[cfg(windows)]
type PrjFillDirEntryBufferFn =
    unsafe extern "system" fn(*const u16, *const PrjFileBasicInfo, isize) -> i32;
#[cfg(windows)]
type PrjWritePlaceholderInfoFn =
    unsafe extern "system" fn(isize, *const u16, *const PrjPlaceholderInfo, u32) -> i32;
#[cfg(windows)]
type PrjAllocateAlignedBufferFn = unsafe extern "system" fn(isize, usize) -> *mut u8;
#[cfg(windows)]
type PrjFreeAlignedBufferFn = unsafe extern "system" fn(*mut u8);
#[cfg(windows)]
type PrjWriteFileDataFn =
    unsafe extern "system" fn(isize, *const PrjGuid, *const u8, u64, u32) -> i32;
#[cfg(windows)]
type PrjFileNameCompareFn = unsafe extern "system" fn(*const u16, *const u16) -> i32;
#[cfg(windows)]
type PrjFileNameMatchFn = unsafe extern "system" fn(*const u16, *const u16) -> u8;

#[cfg(windows)]
struct DirEnumSession {
    cursor: usize,
    search_expr: Option<String>,
}

#[cfg(windows)]
struct ProjFsInstanceState {
    callbacks: PrjCallbacks,
    backend: Box<dyn ProjFsVirtualizerBackend>,
    dir_enums: std::sync::Mutex<std::collections::HashMap<PrjGuid, DirEnumSession>>,
    fill_dir_fn: PrjFillDirEntryBufferFn,
    write_placeholder_fn: PrjWritePlaceholderInfoFn,
    alloc_buf_fn: PrjAllocateAlignedBufferFn,
    free_buf_fn: PrjFreeAlignedBufferFn,
    write_data_fn: PrjWriteFileDataFn,
    compare_fn: PrjFileNameCompareFn,
    match_fn: PrjFileNameMatchFn,
    stop_fn: PrjStopVirtualizingFn,
}

#[cfg(windows)]
const PRJ_S_OK: i32 = 0;
#[cfg(windows)]
const PRJ_E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
#[cfg(windows)]
const PRJ_E_OUTOFMEMORY: i32 = 0x8007_000Eu32 as i32;
#[cfg(windows)]
const PRJ_E_FAIL: i32 = 0x8000_4005u32 as i32;
#[cfg(windows)]
const PRJ_HRESULT_ERROR_FILE_NOT_FOUND: i32 = 0x8007_0002u32 as i32;
#[cfg(windows)]
const PRJ_HRESULT_ERROR_ACCESS_DENIED: i32 = 0x8007_0005u32 as i32;
#[cfg(windows)]
const PRJ_HRESULT_ERROR_INSUFFICIENT_BUFFER: i32 = 0x8007_007Au32 as i32;
#[cfg(windows)]
const PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN: u32 = 0x1;

#[cfg(windows)]
unsafe fn wide_ptr_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < 65_536 {
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf16_lossy(slice))
}

#[cfg(windows)]
fn normalize_projfs_rel_components(raw: &str) -> Option<Vec<String>> {
    if raw.contains('\0') || raw.contains(':') {
        return None;
    }
    let trimmed = raw.trim_matches(|c| c == '\\' || c == '/');
    if trimmed.is_empty() {
        return Some(Vec::new());
    }
    let mut parts = Vec::new();
    for seg in trimmed.split(['\\', '/']) {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        parts.push(seg.to_string());
    }
    Some(parts)
}

#[cfg(windows)]
fn build_prj_basic_info(entry: &ProjFsProjectedEntry) -> PrjFileBasicInfo {
    let file_size = if entry.is_directory {
        0
    } else {
        i64::try_from(entry.file_size).unwrap_or(i64::MAX)
    };
    PrjFileBasicInfo {
        is_directory: if entry.is_directory { 1 } else { 0 },
        _pad0: [0u8; 7],
        file_size,
        creation_time: 0,
        last_access_time: 0,
        last_write_time: 0,
        change_time: 0,
        file_attributes: if entry.is_directory { 0x10 } else { 0x01 },
        _pad1: 0,
    }
}

#[cfg(windows)]
unsafe fn recover_instance_state<'a>(cb: &PrjCallbackData) -> Result<&'a ProjFsInstanceState, i32> {
    if cb.instance_context.is_null() {
        return Err(PRJ_E_INVALIDARG);
    }
    Ok(unsafe { &*(cb.instance_context.cast::<ProjFsInstanceState>()) })
}

#[cfg(windows)]
unsafe extern "system" fn prj_start_dir_enum_cb(
    callback_data: *const PrjCallbackData,
    enumeration_id: *const PrjGuid,
) -> i32 {
    if callback_data.is_null() || enumeration_id.is_null() {
        return PRJ_E_INVALIDARG;
    }
    let cb = unsafe { &*callback_data };
    let state = match unsafe { recover_instance_state(cb) } {
        Ok(s) => s,
        Err(hr) => return hr,
    };
    let mut enums = match state.dir_enums.lock() {
        Ok(g) => g,
        Err(_) => return PRJ_E_FAIL,
    };
    enums.insert(
        unsafe { *enumeration_id },
        DirEnumSession {
            cursor: 0,
            search_expr: None,
        },
    );
    PRJ_S_OK
}

#[cfg(windows)]
unsafe extern "system" fn prj_end_dir_enum_cb(
    callback_data: *const PrjCallbackData,
    enumeration_id: *const PrjGuid,
) -> i32 {
    if callback_data.is_null() || enumeration_id.is_null() {
        return PRJ_E_INVALIDARG;
    }
    let cb = unsafe { &*callback_data };
    let state = match unsafe { recover_instance_state(cb) } {
        Ok(s) => s,
        Err(hr) => return hr,
    };
    let mut enums = match state.dir_enums.lock() {
        Ok(g) => g,
        Err(_) => return PRJ_E_FAIL,
    };
    enums.remove(unsafe { &*enumeration_id });
    PRJ_S_OK
}

#[cfg(windows)]
unsafe extern "system" fn prj_get_dir_enum_cb(
    callback_data: *const PrjCallbackData,
    enumeration_id: *const PrjGuid,
    search_expression: *const u16,
    dir_entry_buffer_handle: isize,
) -> i32 {
    if callback_data.is_null() || enumeration_id.is_null() || dir_entry_buffer_handle == 0 {
        return PRJ_E_INVALIDARG;
    }
    let cb = unsafe { &*callback_data };
    let state = match unsafe { recover_instance_state(cb) } {
        Ok(s) => s,
        Err(hr) => return hr,
    };

    let raw_dir = match unsafe { wide_ptr_to_string(cb.file_path_name) } {
        Some(s) => s,
        None => return PRJ_E_INVALIDARG,
    };
    let parent_comps = match normalize_projfs_rel_components(&raw_dir) {
        Some(c) => c,
        None => return PRJ_HRESULT_ERROR_FILE_NOT_FOUND,
    };

    let restart_scan = (cb.flags & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN) != 0;
    let incoming_expr = unsafe { wide_ptr_to_string(search_expression) }.filter(|s| !s.is_empty());

    let (start_cursor, active_expr) = {
        let mut enums = match state.dir_enums.lock() {
            Ok(g) => g,
            Err(_) => return PRJ_E_FAIL,
        };
        let Some(session) = enums.get_mut(unsafe { &*enumeration_id }) else {
            return PRJ_E_INVALIDARG;
        };
        if restart_scan {
            session.cursor = 0;
            session.search_expr = incoming_expr;
        } else if session.search_expr.is_none() && incoming_expr.is_some() {
            session.search_expr = incoming_expr;
        }
        (session.cursor, session.search_expr.clone())
    };

    struct ChildItem {
        child_name: String,
        entry: ProjFsProjectedEntry,
    }

    let entries = state.backend.list_entries();
    let mut children_map: std::collections::HashMap<String, ChildItem> =
        std::collections::HashMap::new();

    for entry in entries {
        let entry_str = entry.relative_path.to_string_lossy();
        let Some(entry_comps) = normalize_projfs_rel_components(&entry_str) else {
            continue;
        };
        if entry_comps.len() != parent_comps.len() + 1 {
            continue;
        }
        let parent_matches = entry_comps[..parent_comps.len()]
            .iter()
            .zip(parent_comps.iter())
            .all(|(a, b)| {
                let a_wide: Vec<u16> = a.encode_utf16().chain(Some(0)).collect();
                let b_wide: Vec<u16> = b.encode_utf16().chain(Some(0)).collect();
                unsafe { (state.compare_fn)(a_wide.as_ptr(), b_wide.as_ptr()) == 0 }
            });
        if !parent_matches {
            continue;
        }
        let child_name = entry_comps[parent_comps.len()].clone();
        let key = child_name.to_lowercase();
        children_map
            .entry(key)
            .and_modify(|existing| {
                if !existing.entry.is_directory && entry.is_directory {
                    existing.child_name = child_name.clone();
                    existing.entry = entry.clone();
                }
            })
            .or_insert(ChildItem { child_name, entry });
    }

    let mut children: Vec<ChildItem> = children_map.into_values().collect();
    if let Some(ref expr) = active_expr {
        if !expr.is_empty() && expr != "*" {
            let expr_wide: Vec<u16> = expr.encode_utf16().chain(Some(0)).collect();
            children.retain(|child| {
                let child_wide: Vec<u16> = child.child_name.encode_utf16().chain(Some(0)).collect();
                unsafe { (state.match_fn)(child_wide.as_ptr(), expr_wide.as_ptr()) != 0 }
            });
        }
    }

    children.sort_by(|a, b| {
        let a_wide: Vec<u16> = a.child_name.encode_utf16().chain(Some(0)).collect();
        let b_wide: Vec<u16> = b.child_name.encode_utf16().chain(Some(0)).collect();
        let cmp = unsafe { (state.compare_fn)(a_wide.as_ptr(), b_wide.as_ptr()) };
        cmp.cmp(&0)
    });

    let mut cursor = start_cursor;
    let mut return_hr = PRJ_S_OK;

    for (entries_added, child) in children.iter().skip(start_cursor).enumerate() {
        let child_wide: Vec<u16> = child.child_name.encode_utf16().chain(Some(0)).collect();
        let basic_info = build_prj_basic_info(&child.entry);
        let hr = unsafe {
            (state.fill_dir_fn)(child_wide.as_ptr(), &basic_info, dir_entry_buffer_handle)
        };
        if hr == PRJ_HRESULT_ERROR_INSUFFICIENT_BUFFER {
            if entries_added == 0 {
                return_hr = PRJ_HRESULT_ERROR_INSUFFICIENT_BUFFER;
            }
            break;
        }
        if hr < 0 {
            return_hr = hr;
            break;
        }
        cursor += 1;
    }

    if let Ok(mut enums) = state.dir_enums.lock() {
        if let Some(session) = enums.get_mut(unsafe { &*enumeration_id }) {
            session.cursor = cursor;
        }
    }

    return_hr
}

#[cfg(windows)]
unsafe extern "system" fn prj_get_placeholder_info_cb(
    callback_data: *const PrjCallbackData,
) -> i32 {
    if callback_data.is_null() {
        return PRJ_E_INVALIDARG;
    }
    let cb = unsafe { &*callback_data };
    let state = match unsafe { recover_instance_state(cb) } {
        Ok(s) => s,
        Err(hr) => return hr,
    };
    let raw_path = match unsafe { wide_ptr_to_string(cb.file_path_name) } {
        Some(s) => s,
        None => return PRJ_E_INVALIDARG,
    };
    let Some(req_comps) = normalize_projfs_rel_components(&raw_path) else {
        return PRJ_HRESULT_ERROR_FILE_NOT_FOUND;
    };
    if req_comps.is_empty() {
        return PRJ_HRESULT_ERROR_FILE_NOT_FOUND;
    }

    let entries = state.backend.list_entries();
    let matched = entries.into_iter().find_map(|entry| {
        let entry_str = entry.relative_path.to_string_lossy();
        let entry_comps = normalize_projfs_rel_components(&entry_str)?;
        if entry_comps.len() == req_comps.len()
            && entry_comps.iter().zip(req_comps.iter()).all(|(a, b)| {
                let a_wide: Vec<u16> = a.encode_utf16().chain(Some(0)).collect();
                let b_wide: Vec<u16> = b.encode_utf16().chain(Some(0)).collect();
                unsafe { (state.compare_fn)(a_wide.as_ptr(), b_wide.as_ptr()) == 0 }
            })
        {
            Some((entry, entry_comps))
        } else {
            None
        }
    });

    let Some((entry, entry_comps)) = matched else {
        return PRJ_HRESULT_ERROR_FILE_NOT_FOUND;
    };

    let mut provider_id = [0u8; 128];
    provider_id[..16].copy_from_slice(b"OMNISENTINEL_V2\0");
    let mut content_id = [0u8; 128];
    content_id[..32].copy_from_slice(&entry.content_sha256);

    let placeholder_info = PrjPlaceholderInfo {
        file_basic_info: build_prj_basic_info(&entry),
        ea_buffer_size: 0,
        offset_to_first_ea: 0,
        security_buffer_size: 0,
        offset_to_security_descriptor: 0,
        streams_info_buffer_size: 0,
        offset_to_first_stream_info: 0,
        provider_id,
        content_id,
        variable_data: [0u8; 1],
    };

    let canonical_rel = entry_comps.join("\\");
    let dest_wide: Vec<u16> = canonical_rel.encode_utf16().chain(Some(0)).collect();
    unsafe {
        (state.write_placeholder_fn)(
            cb.namespace_virtualization_context,
            dest_wide.as_ptr(),
            &placeholder_info,
            core::mem::size_of::<PrjPlaceholderInfo>() as u32,
        )
    }
}

#[cfg(windows)]
unsafe extern "system" fn prj_get_file_data_cb(
    callback_data: *const PrjCallbackData,
    byte_offset: u64,
    length: u32,
) -> i32 {
    if callback_data.is_null() {
        return PRJ_E_INVALIDARG;
    }
    let cb = unsafe { &*callback_data };
    let state = match unsafe { recover_instance_state(cb) } {
        Ok(s) => s,
        Err(hr) => return hr,
    };
    let raw_path = match unsafe { wide_ptr_to_string(cb.file_path_name) } {
        Some(s) => s,
        None => return PRJ_E_INVALIDARG,
    };
    if length == 0 {
        return PRJ_S_OK;
    }

    let Some(req_comps) = normalize_projfs_rel_components(&raw_path) else {
        return PRJ_HRESULT_ERROR_ACCESS_DENIED;
    };
    if req_comps.is_empty() {
        return PRJ_HRESULT_ERROR_ACCESS_DENIED;
    }
    let rel_path: PathBuf = req_comps.iter().collect();

    let verified = match state
        .backend
        .read_verified_range(&rel_path, byte_offset, length as usize)
    {
        Ok(bytes) => bytes,
        Err(_) => return PRJ_HRESULT_ERROR_ACCESS_DENIED,
    };

    let write_len = verified.len().min(length as usize);
    if write_len == 0 {
        return PRJ_HRESULT_ERROR_ACCESS_DENIED;
    }
    let aligned_ptr =
        unsafe { (state.alloc_buf_fn)(cb.namespace_virtualization_context, write_len) };
    if aligned_ptr.is_null() {
        return PRJ_E_OUTOFMEMORY;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(verified.as_ptr(), aligned_ptr, write_len);
        let res = (state.write_data_fn)(
            cb.namespace_virtualization_context,
            &cb.data_stream_id,
            aligned_ptr,
            byte_offset,
            write_len as u32,
        );
        (state.free_buf_fn)(aligned_ptr);
        res
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
        let required_exports = [
            c"PrjMarkDirectoryAsPlaceholder",
            c"PrjStartVirtualizing",
            c"PrjStopVirtualizing",
            c"PrjFillDirEntryBuffer",
            c"PrjWritePlaceholderInfo",
            c"PrjAllocateAlignedBuffer",
            c"PrjFreeAlignedBuffer",
            c"PrjWriteFileData",
            c"PrjFileNameCompare",
            c"PrjFileNameMatch",
        ];
        let all_present = required_exports
            .iter()
            .all(|sym| unsafe { GetProcAddress(h_lib, sym.as_ptr().cast::<u8>()) != 0 });
        unsafe {
            let _ = FreeLibrary(h_lib);
        }
        all_present
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Marks `root_path` as a ProjFS virtualization root (`PrjMarkDirectoryAsPlaceholder`) and
/// starts a ProjFS virtualization instance (`PrjStartVirtualizing`) backed by `backend` (`Row 148`).
pub fn prj_start_virtualizing_root(
    root_path: &Path,
    backend: Box<dyn ProjFsVirtualizerBackend>,
) -> io::Result<ProjFsInstanceHandle> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryW(lp_lib_file_name: *const u16) -> isize;
            fn GetProcAddress(h_module: isize, lp_proc_name: *const u8) -> isize;
            fn FreeLibrary(h_lib_module: isize) -> i32;
        }

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

        let resolve_proc = |sym: &core::ffi::CStr| -> Result<isize, io::Error> {
            let addr = unsafe { GetProcAddress(h_lib, sym.as_ptr().cast::<u8>()) };
            if addr == 0 {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "ProjectedFSLib.dll missing {} entry point",
                        sym.to_string_lossy()
                    ),
                ))
            } else {
                Ok(addr)
            }
        };

        let mark_addr = match resolve_proc(c"PrjMarkDirectoryAsPlaceholder") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };
        let start_addr = match resolve_proc(c"PrjStartVirtualizing") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };
        let stop_addr = match resolve_proc(c"PrjStopVirtualizing") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };
        let fill_dir_addr = match resolve_proc(c"PrjFillDirEntryBuffer") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };
        let write_ph_addr = match resolve_proc(c"PrjWritePlaceholderInfo") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };
        let alloc_addr = match resolve_proc(c"PrjAllocateAlignedBuffer") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };
        let free_addr = match resolve_proc(c"PrjFreeAlignedBuffer") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };
        let write_data_addr = match resolve_proc(c"PrjWriteFileData") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };
        let cmp_addr = match resolve_proc(c"PrjFileNameCompare") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };
        let match_addr = match resolve_proc(c"PrjFileNameMatch") {
            Ok(a) => a,
            Err(e) => {
                unsafe {
                    let _ = FreeLibrary(h_lib);
                }
                return Err(e);
            }
        };

        let mark_fn: PrjMarkDirectoryAsPlaceholderFn = unsafe { core::mem::transmute(mark_addr) };
        let start_fn: PrjStartVirtualizingFn = unsafe { core::mem::transmute(start_addr) };
        let stop_fn: PrjStopVirtualizingFn = unsafe { core::mem::transmute(stop_addr) };
        let fill_dir_fn: PrjFillDirEntryBufferFn = unsafe { core::mem::transmute(fill_dir_addr) };
        let write_placeholder_fn: PrjWritePlaceholderInfoFn =
            unsafe { core::mem::transmute(write_ph_addr) };
        let alloc_buf_fn: PrjAllocateAlignedBufferFn = unsafe { core::mem::transmute(alloc_addr) };
        let free_buf_fn: PrjFreeAlignedBufferFn = unsafe { core::mem::transmute(free_addr) };
        let write_data_fn: PrjWriteFileDataFn = unsafe { core::mem::transmute(write_data_addr) };
        let compare_fn: PrjFileNameCompareFn = unsafe { core::mem::transmute(cmp_addr) };
        let match_fn: PrjFileNameMatchFn = unsafe { core::mem::transmute(match_addr) };

        let root_wide: Vec<u16> = root_path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut guid_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut guid_bytes);
        guid_bytes[6] = (guid_bytes[6] & 0x0F) | 0x40;
        guid_bytes[8] = (guid_bytes[8] & 0x3F) | 0x80;
        let mut d4 = [0u8; 8];
        d4.copy_from_slice(&guid_bytes[8..16]);
        let instance_guid = PrjGuid {
            data1: u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]),
            data2: u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]),
            data3: u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]),
            data4: d4,
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

        let state = Box::new(ProjFsInstanceState {
            callbacks: PrjCallbacks {
                start_directory_enumeration_cb: prj_start_dir_enum_cb,
                end_directory_enumeration_cb: prj_end_dir_enum_cb,
                get_directory_enumeration_cb: prj_get_dir_enum_cb,
                get_placeholder_info_cb: prj_get_placeholder_info_cb,
                get_file_data_cb: prj_get_file_data_cb,
                query_file_name_cb: 0,
                notification_cb: 0,
                cancel_command_cb: 0,
            },
            backend,
            dir_enums: std::sync::Mutex::new(std::collections::HashMap::new()),
            fill_dir_fn,
            write_placeholder_fn,
            alloc_buf_fn,
            free_buf_fn,
            write_data_fn,
            compare_fn,
            match_fn,
            stop_fn,
        });

        let state_ptr: *const ProjFsInstanceState = &*state;
        let callbacks_ptr: *const PrjCallbacks = &state.callbacks;
        let mut namespace_ctx: isize = 0;
        let hr_start = unsafe {
            start_fn(
                root_wide.as_ptr(),
                callbacks_ptr,
                state_ptr.cast::<core::ffi::c_void>(),
                core::ptr::null(),
                &mut namespace_ctx,
            )
        };
        if hr_start < 0 || namespace_ctx == 0 {
            drop(state);
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
            state: Some(state),
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (root_path, backend);
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

#[cfg(all(test, windows))]
mod projfs_callback_tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    struct RecordedDirEntry {
        name: String,
        is_directory: u8,
        file_size: i64,
        file_attributes: u32,
    }

    #[derive(Debug, Clone)]
    struct RecordedPlaceholder {
        dest_rel_path: String,
        is_directory: u8,
        file_size: i64,
        file_attributes: u32,
        provider_id: [u8; 128],
        content_id: [u8; 128],
    }

    #[derive(Debug, Clone)]
    struct RecordedFileData {
        stream_id: PrjGuid,
        byte_offset: u64,
        bytes: Vec<u8>,
    }

    #[derive(Default)]
    struct MockProjFsRecorder {
        fill_capacity: usize,
        filled_entries: Vec<RecordedDirEntry>,
        placeholders: Vec<RecordedPlaceholder>,
        allocations: HashMap<usize, Vec<u8>>,
        alloc_count: usize,
        freed_count: usize,
        written_data: Vec<RecordedFileData>,
        stop_calls: usize,
    }

    thread_local! {
        static MOCK_RECORDER: RefCell<MockProjFsRecorder> = RefCell::new(MockProjFsRecorder::default());
    }

    fn reset_mock_recorder(fill_capacity: usize) {
        MOCK_RECORDER.with(|cell| {
            let mut rec = cell.borrow_mut();
            *rec = MockProjFsRecorder {
                fill_capacity,
                ..MockProjFsRecorder::default()
            };
        });
    }

    unsafe extern "system" fn mock_compare_fn(a: *const u16, b: *const u16) -> i32 {
        let sa = unsafe { wide_ptr_to_string(a) }
            .unwrap_or_default()
            .to_lowercase();
        let sb = unsafe { wide_ptr_to_string(b) }
            .unwrap_or_default()
            .to_lowercase();
        match sa.cmp(&sb) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    fn wildcard_match(pattern: &[char], text: &[char]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }
        if pattern[0] == '*' {
            return wildcard_match(&pattern[1..], text)
                || (!text.is_empty() && wildcard_match(pattern, &text[1..]));
        }
        if !text.is_empty() && (pattern[0] == '?' || pattern[0] == text[0]) {
            return wildcard_match(&pattern[1..], &text[1..]);
        }
        false
    }

    unsafe extern "system" fn mock_match_fn(name: *const u16, expr: *const u16) -> u8 {
        let n_chars: Vec<char> = unsafe { wide_ptr_to_string(name) }
            .unwrap_or_default()
            .to_lowercase()
            .chars()
            .collect();
        let e_chars: Vec<char> = unsafe { wide_ptr_to_string(expr) }
            .unwrap_or_default()
            .to_lowercase()
            .chars()
            .collect();
        if wildcard_match(&e_chars, &n_chars) {
            1
        } else {
            0
        }
    }

    unsafe extern "system" fn mock_fill_dir_fn(
        file_name: *const u16,
        basic_info: *const PrjFileBasicInfo,
        _dir_entry_buffer_handle: isize,
    ) -> i32 {
        let Some(name) = (unsafe { wide_ptr_to_string(file_name) }) else {
            return PRJ_E_INVALIDARG;
        };
        if basic_info.is_null() {
            return PRJ_E_INVALIDARG;
        }
        let info = unsafe { *basic_info };
        MOCK_RECORDER.with(|cell| {
            let mut rec = cell.borrow_mut();
            if rec.fill_capacity == 0 {
                return PRJ_HRESULT_ERROR_INSUFFICIENT_BUFFER;
            }
            rec.fill_capacity -= 1;
            rec.filled_entries.push(RecordedDirEntry {
                name,
                is_directory: info.is_directory,
                file_size: info.file_size,
                file_attributes: info.file_attributes,
            });
            PRJ_S_OK
        })
    }

    unsafe extern "system" fn mock_write_placeholder_fn(
        _ns_ctx: isize,
        dest_file_name: *const u16,
        placeholder_info: *const PrjPlaceholderInfo,
        size: u32,
    ) -> i32 {
        if dest_file_name.is_null()
            || placeholder_info.is_null()
            || (size as usize) < core::mem::size_of::<PrjPlaceholderInfo>()
        {
            return PRJ_E_INVALIDARG;
        }
        let dest_rel_path = unsafe { wide_ptr_to_string(dest_file_name) }.unwrap_or_default();
        let info = unsafe { *placeholder_info };
        MOCK_RECORDER.with(|cell| {
            cell.borrow_mut().placeholders.push(RecordedPlaceholder {
                dest_rel_path,
                is_directory: info.file_basic_info.is_directory,
                file_size: info.file_basic_info.file_size,
                file_attributes: info.file_basic_info.file_attributes,
                provider_id: info.provider_id,
                content_id: info.content_id,
            });
        });
        PRJ_S_OK
    }

    unsafe extern "system" fn mock_alloc_buf_fn(_ns_ctx: isize, size: usize) -> *mut u8 {
        let mut buf = vec![0u8; size.max(1)];
        let ptr = buf.as_mut_ptr();
        MOCK_RECORDER.with(|cell| {
            let mut rec = cell.borrow_mut();
            rec.alloc_count += 1;
            rec.allocations.insert(ptr as usize, buf);
        });
        ptr
    }

    unsafe extern "system" fn mock_free_buf_fn(ptr: *mut u8) {
        MOCK_RECORDER.with(|cell| {
            let mut rec = cell.borrow_mut();
            if rec.allocations.remove(&(ptr as usize)).is_some() {
                rec.freed_count += 1;
            }
        });
    }

    unsafe extern "system" fn mock_write_data_fn(
        _ns_ctx: isize,
        stream_id: *const PrjGuid,
        buf: *const u8,
        byte_offset: u64,
        length: u32,
    ) -> i32 {
        if stream_id.is_null() || buf.is_null() {
            return PRJ_E_INVALIDARG;
        }
        let bytes = unsafe { core::slice::from_raw_parts(buf, length as usize) }.to_vec();
        let sid = unsafe { *stream_id };
        MOCK_RECORDER.with(|cell| {
            cell.borrow_mut().written_data.push(RecordedFileData {
                stream_id: sid,
                byte_offset,
                bytes,
            });
        });
        PRJ_S_OK
    }

    unsafe extern "system" fn mock_stop_fn(_ns_ctx: isize) {
        MOCK_RECORDER.with(|cell| {
            cell.borrow_mut().stop_calls += 1;
        });
    }

    struct MockProjFsBackend {
        entries: Vec<ProjFsProjectedEntry>,
        payloads: HashMap<String, Vec<u8>>,
    }

    impl ProjFsVirtualizerBackend for MockProjFsBackend {
        fn list_entries(&self) -> Vec<ProjFsProjectedEntry> {
            self.entries.clone()
        }

        fn read_verified_range(
            &self,
            relative_path: &Path,
            byte_offset: u64,
            length: usize,
        ) -> Result<Vec<u8>, String> {
            let key = relative_path
                .to_string_lossy()
                .replace('\\', "/")
                .to_lowercase();
            let payload = self
                .payloads
                .get(&key)
                .ok_or_else(|| format!("missing or tampered entry: {key}"))?;
            let start =
                usize::try_from(byte_offset).map_err(|_| "byte_offset overflow".to_string())?;
            if start > payload.len() {
                return Err("byte_offset out of range".to_string());
            }
            let end = start.saturating_add(length).min(payload.len());
            Ok(payload[start..end].to_vec())
        }
    }

    fn make_test_state() -> Box<ProjFsInstanceState> {
        let mut payloads = HashMap::new();
        let alpha_bytes = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
        let zebra_bytes = b"ZEBRA_VERIFIED_CONTENT".to_vec();
        let root_bytes = b"ROOT_BIN_BYTES".to_vec();
        payloads.insert("docs/alpha.txt".to_string(), alpha_bytes.clone());
        payloads.insert("docs/zebra.txt".to_string(), zebra_bytes.clone());
        payloads.insert("root.bin".to_string(), root_bytes.clone());
        // Note: "docs/tampered.txt" is listed in entries but omitted from payloads to simulate AEAD/SHA256 verification failure.

        let entries = vec![
            ProjFsProjectedEntry {
                relative_path: PathBuf::from("root.bin"),
                is_directory: false,
                file_size: root_bytes.len() as u64,
                content_sha256: [0x11u8; 32],
            },
            ProjFsProjectedEntry {
                relative_path: PathBuf::from("docs"),
                is_directory: true,
                file_size: 0,
                content_sha256: [0u8; 32],
            },
            ProjFsProjectedEntry {
                relative_path: PathBuf::from("docs/zebra.txt"),
                is_directory: false,
                file_size: zebra_bytes.len() as u64,
                content_sha256: [0x22u8; 32],
            },
            ProjFsProjectedEntry {
                relative_path: PathBuf::from("docs/sub"),
                is_directory: true,
                file_size: 0,
                content_sha256: [0u8; 32],
            },
            ProjFsProjectedEntry {
                relative_path: PathBuf::from("docs/alpha.txt"),
                is_directory: false,
                file_size: alpha_bytes.len() as u64,
                content_sha256: [0x33u8; 32],
            },
            ProjFsProjectedEntry {
                relative_path: PathBuf::from("docs/tampered.txt"),
                is_directory: false,
                file_size: 64,
                content_sha256: [0x44u8; 32],
            },
        ];

        Box::new(ProjFsInstanceState {
            callbacks: PrjCallbacks {
                start_directory_enumeration_cb: prj_start_dir_enum_cb,
                end_directory_enumeration_cb: prj_end_dir_enum_cb,
                get_directory_enumeration_cb: prj_get_dir_enum_cb,
                get_placeholder_info_cb: prj_get_placeholder_info_cb,
                get_file_data_cb: prj_get_file_data_cb,
                query_file_name_cb: 0,
                notification_cb: 0,
                cancel_command_cb: 0,
            },
            backend: Box::new(MockProjFsBackend { entries, payloads }),
            dir_enums: std::sync::Mutex::new(HashMap::new()),
            fill_dir_fn: mock_fill_dir_fn,
            write_placeholder_fn: mock_write_placeholder_fn,
            alloc_buf_fn: mock_alloc_buf_fn,
            free_buf_fn: mock_free_buf_fn,
            write_data_fn: mock_write_data_fn,
            compare_fn: mock_compare_fn,
            match_fn: mock_match_fn,
            stop_fn: mock_stop_fn,
        })
    }

    fn make_cb_data(
        state: &ProjFsInstanceState,
        flags: u32,
        rel_path_wide: &[u16],
        stream_id: PrjGuid,
    ) -> PrjCallbackData {
        PrjCallbackData {
            size: core::mem::size_of::<PrjCallbackData>() as u32,
            flags,
            namespace_virtualization_context: 0x1234,
            command_id: 7,
            file_id: PrjGuid {
                data1: 1,
                data2: 2,
                data3: 3,
                data4: [4; 8],
            },
            data_stream_id: stream_id,
            file_path_name: rel_path_wide.as_ptr(),
            version_info: core::ptr::null(),
            triggering_process_id: 42,
            triggering_process_image_file_name: core::ptr::null(),
            instance_context: (state as *const ProjFsInstanceState as *mut ProjFsInstanceState)
                .cast::<core::ffi::c_void>(),
        }
    }

    #[test]
    fn projfs_abi_sizes_and_full_callback_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(core::mem::size_of::<PrjGuid>(), 16);
        assert_eq!(core::mem::size_of::<PrjFileBasicInfo>(), 56);
        assert_eq!(core::mem::size_of::<PrjPlaceholderInfo>(), 344);

        let state = make_test_state();
        let dummy_stream = PrjGuid {
            data1: 0xAABB_CCDD,
            data2: 0x1122,
            data3: 0x3344,
            data4: [0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC],
        };
        let enum_id = PrjGuid {
            data1: 0x0000_0001,
            data2: 0x0002,
            data3: 0x0003,
            data4: [0x0A; 8],
        };

        // 1. Root enumeration (`""`) returns sorted immediate children (`docs`, `root.bin`)
        reset_mock_recorder(16);
        let root_wide: Vec<u16> = "".encode_utf16().chain(Some(0)).collect();
        let cb_root = make_cb_data(&state, 0, &root_wide, dummy_stream);
        assert_eq!(
            unsafe { prj_start_dir_enum_cb(&cb_root, &enum_id) },
            PRJ_S_OK
        );
        assert_eq!(
            unsafe { prj_get_dir_enum_cb(&cb_root, &enum_id, core::ptr::null(), 1) },
            PRJ_S_OK
        );
        MOCK_RECORDER.with(|cell| -> Result<(), Box<dyn std::error::Error>> {
            let rec = cell.borrow();
            assert_eq!(rec.filled_entries.len(), 2);
            assert_eq!(rec.filled_entries[0].name, "docs");
            assert_eq!(rec.filled_entries[0].is_directory, 1);
            assert_eq!(rec.filled_entries[0].file_attributes, 0x10);
            assert_eq!(rec.filled_entries[1].name, "root.bin");
            assert_eq!(rec.filled_entries[1].is_directory, 0);
            assert_eq!(rec.filled_entries[1].file_attributes, 0x01);
            assert_eq!(rec.filled_entries[1].file_size, 14);
            Ok(())
        })?;
        assert_eq!(unsafe { prj_end_dir_enum_cb(&cb_root, &enum_id) }, PRJ_S_OK);

        // 2. Subdir enumeration (`"DOCS"` case-insensitive) with wildcard `"*.txt"`,
        //    0-slot `ERROR_INSUFFICIENT_BUFFER`, 1-slot resume, and `RESTART_SCAN`.
        let docs_wide: Vec<u16> = "DOCS".encode_utf16().chain(Some(0)).collect();
        let expr_txt: Vec<u16> = "*.txt".encode_utf16().chain(Some(0)).collect();
        let cb_docs = make_cb_data(&state, 0, &docs_wide, dummy_stream);
        assert_eq!(
            unsafe { prj_start_dir_enum_cb(&cb_docs, &enum_id) },
            PRJ_S_OK
        );

        // 0-capacity buffer on first entry -> ERROR_INSUFFICIENT_BUFFER without advancing cursor
        reset_mock_recorder(0);
        assert_eq!(
            unsafe { prj_get_dir_enum_cb(&cb_docs, &enum_id, expr_txt.as_ptr(), 1) },
            PRJ_HRESULT_ERROR_INSUFFICIENT_BUFFER
        );

        // 1-capacity buffer -> adds first entry (`alpha.txt`) and hits insufficient buffer -> returns S_OK
        reset_mock_recorder(1);
        assert_eq!(
            unsafe { prj_get_dir_enum_cb(&cb_docs, &enum_id, core::ptr::null(), 1) },
            PRJ_S_OK
        );
        MOCK_RECORDER.with(|cell| {
            let rec = cell.borrow();
            assert_eq!(rec.filled_entries.len(), 1);
            assert_eq!(rec.filled_entries[0].name, "alpha.txt");
        });

        // Resume with larger buffer -> gets remaining `tampered.txt` and `zebra.txt` in sorted order
        reset_mock_recorder(10);
        assert_eq!(
            unsafe { prj_get_dir_enum_cb(&cb_docs, &enum_id, core::ptr::null(), 1) },
            PRJ_S_OK
        );
        MOCK_RECORDER.with(|cell| {
            let rec = cell.borrow();
            assert_eq!(rec.filled_entries.len(), 2);
            assert_eq!(rec.filled_entries[0].name, "tampered.txt");
            assert_eq!(rec.filled_entries[1].name, "zebra.txt");
        });

        // RESTART_SCAN with `*` resets cursor to 0 and includes `sub` directory too
        reset_mock_recorder(10);
        let star_wide: Vec<u16> = "*".encode_utf16().chain(Some(0)).collect();
        let cb_docs_restart = make_cb_data(
            &state,
            PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN,
            &docs_wide,
            dummy_stream,
        );
        assert_eq!(
            unsafe { prj_get_dir_enum_cb(&cb_docs_restart, &enum_id, star_wide.as_ptr(), 1) },
            PRJ_S_OK
        );
        MOCK_RECORDER.with(|cell| {
            let names: Vec<String> = cell
                .borrow()
                .filled_entries
                .iter()
                .map(|e| e.name.clone())
                .collect();
            assert_eq!(names, vec!["alpha.txt", "sub", "tampered.txt", "zebra.txt"]);
        });
        assert_eq!(unsafe { prj_end_dir_enum_cb(&cb_docs, &enum_id) }, PRJ_S_OK);
        // Ended enumeration ID must fail closed
        assert_eq!(
            unsafe { prj_get_dir_enum_cb(&cb_docs, &enum_id, core::ptr::null(), 1) },
            PRJ_E_INVALIDARG
        );

        // 3. `prj_get_placeholder_info_cb`: existing file + missing file
        reset_mock_recorder(10);
        let alpha_req_wide: Vec<u16> = "DOCS/alpha.txt".encode_utf16().chain(Some(0)).collect();
        let cb_alpha = make_cb_data(&state, 0, &alpha_req_wide, dummy_stream);
        assert_eq!(unsafe { prj_get_placeholder_info_cb(&cb_alpha) }, PRJ_S_OK);
        MOCK_RECORDER.with(|cell| -> Result<(), Box<dyn std::error::Error>> {
            let rec = cell.borrow();
            assert_eq!(rec.placeholders.len(), 1);
            let ph = &rec.placeholders[0];
            assert_eq!(ph.dest_rel_path, r"docs\alpha.txt");
            assert_eq!(ph.is_directory, 0);
            assert_eq!(ph.file_size, 36);
            assert_eq!(ph.file_attributes, 0x01);
            assert_eq!(&ph.provider_id[..16], b"OMNISENTINEL_V2\0");
            assert_eq!(ph.content_id[..32], [0x33u8; 32]);
            Ok(())
        })?;

        let missing_wide: Vec<u16> = r"docs\missing.exe".encode_utf16().chain(Some(0)).collect();
        let cb_missing = make_cb_data(&state, 0, &missing_wide, dummy_stream);
        assert_eq!(
            unsafe { prj_get_placeholder_info_cb(&cb_missing) },
            PRJ_HRESULT_ERROR_FILE_NOT_FOUND
        );

        // 4. `prj_get_file_data_cb`: exact non-zero slice at non-zero byte_offset with cb.data_stream_id,
        //    length=0 fast path, and ERROR_ACCESS_DENIED on missing/tampered file
        reset_mock_recorder(10);
        let cb_alpha_data = make_cb_data(&state, 0, &alpha_req_wide, dummy_stream);
        assert_eq!(
            unsafe { prj_get_file_data_cb(&cb_alpha_data, 10, 8) },
            PRJ_S_OK
        );
        assert_eq!(
            unsafe { prj_get_file_data_cb(&cb_alpha_data, 0, 0) },
            PRJ_S_OK
        );
        MOCK_RECORDER.with(|cell| -> Result<(), Box<dyn std::error::Error>> {
            let rec = cell.borrow();
            assert_eq!(rec.written_data.len(), 1);
            assert_eq!(rec.written_data[0].stream_id, dummy_stream);
            assert_eq!(rec.written_data[0].byte_offset, 10);
            assert_eq!(rec.written_data[0].bytes, b"ABCDEFGH");
            assert_eq!(rec.alloc_count, 1);
            assert_eq!(rec.freed_count, 1);
            assert!(rec.allocations.is_empty());
            Ok(())
        })?;

        let tampered_wide: Vec<u16> = r"docs\tampered.txt".encode_utf16().chain(Some(0)).collect();
        let cb_tampered = make_cb_data(&state, 0, &tampered_wide, dummy_stream);
        assert_eq!(
            unsafe { prj_get_file_data_cb(&cb_tampered, 0, 16) },
            PRJ_HRESULT_ERROR_ACCESS_DENIED
        );
        assert_eq!(
            unsafe { prj_get_file_data_cb(&cb_missing, 0, 16) },
            PRJ_HRESULT_ERROR_ACCESS_DENIED
        );

        // Request at exact EOF offset (36) with non-zero length (8) must fail closed without invoking PrjWriteFileData(length=0)
        reset_mock_recorder(10);
        assert_eq!(
            unsafe { prj_get_file_data_cb(&cb_alpha_data, 36, 8) },
            PRJ_HRESULT_ERROR_ACCESS_DENIED
        );
        MOCK_RECORDER.with(|cell| {
            let rec = cell.borrow();
            assert_eq!(rec.alloc_count, 0);
            assert!(rec.written_data.is_empty());
        });

        // Verify Win32FindDataW ABI size and is_projfs_reparse_point false-positive rejection on standard paths
        assert_eq!(core::mem::size_of::<Win32FindDataW>(), 592);
        let tmp_dir = std::env::temp_dir().join(format!("projfs_tag_probe_{}", std::process::id()));
        fs::create_dir_all(&tmp_dir)?;
        let regular_file = tmp_dir.join("regular.txt");
        fs::write(&regular_file, b"ok")?;
        assert!(!is_projfs_reparse_point(&tmp_dir));
        assert!(!is_projfs_reparse_point(&regular_file));
        assert!(!is_projfs_reparse_point(
            &tmp_dir.join("does_not_exist.txt")
        ));
        let _ = fs::remove_dir_all(&tmp_dir);

        Ok(())
    }

    #[test]
    fn staging_dacl_vs_restricted_dacl_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "sentinel_sys_dacl_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&root)?;

        let restricted_dir = root.join("restricted_dir");
        create_restricted_dir_atomic(&restricted_dir)?;
        let restricted_file = restricted_dir.join("secret.enc");
        create_restricted_file_atomic(&restricted_file, b"cipher")?;

        let staging_new_dir = root.join("staging_new_dir");
        create_readonly_staging_dir_atomic(&staging_new_dir)?;
        let staging_file = staging_new_dir.join("clean.txt");
        create_readonly_staging_file_atomic(&staging_file, b"clean")?;

        let r_dir = query_path_dacl_sddl(&restricted_dir)?;
        let r_file = query_path_dacl_sddl(&restricted_file)?;
        let s_new = query_path_dacl_sddl(&staging_new_dir)?;
        let s_file = query_path_dacl_sddl(&staging_file)?;

        #[cfg(windows)]
        {
            assert!(
                r_dir.starts_with("D:P"),
                "restricted dir DACL must be protected: {r_dir}"
            );
            assert!(!r_dir.contains(";;;AU)") && !r_dir.contains(";;;WD)"));
            assert!(
                r_file.starts_with("D:P"),
                "restricted file DACL must be protected: {r_file}"
            );
            assert!(!r_file.contains(";;;AU)") && !r_file.contains(";;;WD)"));
            assert!(
                s_new.starts_with("D:P") && s_new.contains(";;;AU)") && !s_new.contains(";;;WD)")
            );
            assert!(
                s_file.starts_with("D:P")
                    && s_file.contains("(A;;FR;;;AU)")
                    && !s_file.contains(";;;WD)")
            );
        }
        #[cfg(not(windows))]
        {
            assert_eq!(r_dir, "unix_mode:0o0700");
            assert_eq!(r_file, "unix_mode:0o0600");
            assert_eq!(s_new, "unix_mode:0o0755");
            assert_eq!(s_file, "unix_mode:0o0644");
        }

        let _ = fs::remove_dir_all(&root);
        Ok(())
    }
}
