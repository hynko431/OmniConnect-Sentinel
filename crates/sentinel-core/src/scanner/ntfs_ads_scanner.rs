use std::path::Path;
use super::universal_scanner::{UniversalThreat, CarrierCategory, ThreatSeverity};

#[cfg(windows)]
#[repr(C)]
struct Win32FindStreamData {
    stream_size: i64,
    c_stream_name: [u16; 296], // MAX_PATH + 36
}

#[cfg(windows)]
extern "system" {
    fn FindFirstStreamW(
        lpFileName: *const u16,
        InfoLevelId: i32,
        lpFindStreamData: *mut std::ffi::c_void,
        dwFlags: u32,
    ) -> isize;
    fn FindNextStreamW(hFindStream: isize, lpFindStreamData: *mut std::ffi::c_void) -> i32;
    fn FindClose(hFindFile: isize) -> i32;
}

pub struct NtfsAdsScanner;

impl NtfsAdsScanner {
    /// Enumerate all Alternate Data Streams (ADS) on the specified path
    pub fn scan_streams(path: &Path) -> Vec<UniversalThreat> {
        let mut threats = Vec::new();

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;

            // Prepend \\?\ for extended path support up to 32,767 chars
            let path_str = path.to_string_lossy();
            let canonical_str = if path_str.starts_with(r"\\?\") {
                path_str.to_string()
            } else {
                format!(r"\\?\{}", path.display())
            };

            let wide_path: Vec<u16> = std::ffi::OsStr::new(&canonical_str)
                .encode_wide()
                .chain(Some(0))
                .collect();

            let mut stream_data = Win32FindStreamData {
                stream_size: 0,
                c_stream_name: [0u16; 296],
            };

            // StreamInfoStandard = 0
            let handle = unsafe {
                FindFirstStreamW(
                    wide_path.as_ptr(),
                    0,
                    &mut stream_data as *mut _ as *mut std::ffi::c_void,
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
                    let stream_size = stream_data.stream_size;

                    // Exclude primary unnamed default stream "::$DATA"
                    if !stream_name.is_empty() && stream_name != "::$DATA" {
                        let stream_lower = stream_name.to_lowercase();
                        let is_executable_stream = stream_lower.ends_with(".exe:$data")
                            || stream_lower.ends_with(".dll:$data")
                            || stream_lower.ends_with(".ps1:$data")
                            || stream_lower.ends_with(".bat:$data")
                            || stream_lower.ends_with(".vbs:$data")
                            || stream_size > 4096;

                        let (severity, risk_score) = if is_executable_stream {
                            (ThreatSeverity::Critical, 96)
                        } else {
                            (ThreatSeverity::Medium, 65)
                        };

                        threats.push(UniversalThreat {
                            file_path: path.to_path_buf(),
                            carrier_category: CarrierCategory::FilesystemHidden,
                            threat_name: format!("NTFS Alternate Data Stream: {}", stream_name),
                            severity,
                            risk_score,
                            mitre_technique: "T1564.004 (Hide Artifacts: NTFS File Attributes)".to_string(),
                            technical_details: format!(
                                "Host file conceals alternate data stream '{}' (Payload size: {} bytes).",
                                stream_name, stream_size
                            ),
                            overlay_offset: None,
                            stream_name: Some(stream_name),
                            can_disarm_via_cdr: true,
                        });
                    }

                    if unsafe { FindNextStreamW(handle, &mut stream_data as *mut _ as *mut std::ffi::c_void) } == 0 {
                        break;
                    }
                }

                unsafe {
                    FindClose(handle);
                }
            }
        }

        threats
    }
}
