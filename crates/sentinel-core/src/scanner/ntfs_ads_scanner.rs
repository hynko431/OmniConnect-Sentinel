use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::Path;
use tracing::warn;

use sentinel_sys::enumerate_ntfs_ads;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdsThreatFinding {
    pub host_file_path: String,
    pub stream_name: String,
    pub stream_size_bytes: u64,
    pub is_executable_payload: bool,
    pub threat_summary: String,
}

/// NTFS Alternate Data Stream (ADS) Inspector
///
/// Uses safe OS wrappers in `sentinel_sys` (`FindFirstStreamW`/`FindNextStreamW`)
/// to enumerate non-default `$DATA` streams and inspect their magic bytes for
/// concealed executable or archive payloads.
pub struct NtfsAdsScanner;

impl NtfsAdsScanner {
    pub fn scan_file_streams(path: &Path) -> Vec<AdsThreatFinding> {
        let mut findings = Vec::new();

        let streams = enumerate_ntfs_ads(path);

        for (stream_name_raw, stream_size_bytes) in streams {
            let clean_name = stream_name_raw
                .trim_start_matches(':')
                .trim_end_matches(":$DATA")
                .to_string();

            if clean_name.is_empty() {
                continue;
            }

            // Inspect the first 256 bytes of the alternate stream
            let full_stream_path = format!("{}:{}", path.display(), clean_name);
            let mut header_buf = [0u8; 256];
            let mut bytes_read = 0usize;

            if let Ok(mut f) = fs::File::open(&full_stream_path) {
                bytes_read = f.read(&mut header_buf).unwrap_or(0);
            }

            let header_slice = &header_buf[..bytes_read];
            let (is_exec, summary) =
                Self::classify_stream_content(&clean_name, header_slice, stream_size_bytes);

            // Benign Zone.Identifier streams (< 1 KB without executable headers) are normal Mark-of-the-Web
            if clean_name.eq_ignore_ascii_case("Zone.Identifier")
                && !is_exec
                && stream_size_bytes < 4096
            {
                continue;
            }

            warn!(
                "NTFS Alternate Data Stream detected: {}:{} ({} bytes) - {}",
                path.display(),
                clean_name,
                stream_size_bytes,
                summary
            );

            findings.push(AdsThreatFinding {
                host_file_path: path.to_string_lossy().to_string(),
                stream_name: format!(":{}", clean_name),
                stream_size_bytes,
                is_executable_payload: is_exec,
                threat_summary: summary,
            });
        }

        findings
    }

    fn classify_stream_content(
        stream_name: &str,
        header: &[u8],
        size_bytes: u64,
    ) -> (bool, String) {
        if header.starts_with(b"MZ") {
            return (
                true,
                format!(
                    "Concealed Windows PE executable (MZ) in NTFS stream ':{}' ({} bytes)",
                    stream_name, size_bytes
                ),
            );
        }
        if header.starts_with(b"\x7FELF") {
            return (
                true,
                format!(
                    "Concealed Linux ELF binary in NTFS stream ':{}' ({} bytes)",
                    stream_name, size_bytes
                ),
            );
        }
        if header.starts_with(b"PK\x03\x04") {
            return (
                true,
                format!(
                    "Concealed ZIP/OOXML container in NTFS stream ':{}' ({} bytes)",
                    stream_name, size_bytes
                ),
            );
        }

        let lower_name = stream_name.to_ascii_lowercase();
        let has_exec_ext = lower_name.ends_with(".exe")
            || lower_name.ends_with(".dll")
            || lower_name.ends_with(".ps1")
            || lower_name.ends_with(".vbs")
            || lower_name.ends_with(".bat")
            || lower_name.ends_with(".cmd")
            || lower_name.ends_with(".hta")
            || lower_name.ends_with(".scr");

        if has_exec_ext {
            return (
                true,
                format!(
                    "Executable or script extension in NTFS stream ':{}' ({} bytes)",
                    stream_name, size_bytes
                ),
            );
        }

        (
            false,
            format!(
                "Unrecognized NTFS Alternate Data Stream ':{}' ({} bytes)",
                stream_name, size_bytes
            ),
        )
    }
}
