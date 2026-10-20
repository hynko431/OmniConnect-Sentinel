use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use super::content_scanner::ContentScanner;
use super::ntfs_ads_scanner::NtfsAdsScanner;
use super::polyglot_scanner::PolyglotScanner;
use super::unicode_trojan_detector::UnicodeTrojanDetector;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CarrierCategory {
    Document,         // PDF, Office OpenXML, RTF, HTML/HTA
    Image,            // JPEG, PNG, WebP, GIF, SVG, BMP
    VideoAudio,       // MP4, MKV, AVI, MOV, MP3
    SoftwareBinary,   // PE, ELF, Mach-O, APK, DLL
    ScriptCode,       // PowerShell, Batch, VBS, Python, Bash
    FilesystemHidden, // NTFS ADS, Hidden/System Attr, CLSID Cloak, BiDi
    Ransomware,       // Known ransomware extensions, high entropy + ransom notes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalThreat {
    pub file_path: PathBuf,
    pub carrier_category: CarrierCategory,
    pub threat_name: String,
    pub severity: ThreatSeverity,
    pub risk_score: u8, // 0 - 100
    pub mitre_technique: String,
    pub technical_details: String,
    pub overlay_offset: Option<u64>,
    pub stream_name: Option<String>,
    pub can_disarm_via_cdr: bool,
}

pub struct UniversalScanner;

impl UniversalScanner {
    /// Comprehensive universal inspection across path syntax, filesystem streams, and file content
    pub fn scan_file(path: &Path) -> Result<Vec<UniversalThreat>, std::io::Error> {
        let mut threats = Vec::new();

        // 1. Path-level inspection (BiDi overrides, zero-width spaces, reserved DOS names, CLSIDs)
        if let Some(path_threat) = UnicodeTrojanDetector::inspect_path(path) {
            threats.push(path_threat);
        }

        // 2. Filesystem-level inspection (NTFS Alternate Data Streams)
        let ads_threats = NtfsAdsScanner::scan_streams(path);
        threats.extend(ads_threats);

        // 3. Read content bytes (bounded preview up to 4 MB for efficiency)
        if path.is_file() {
            let metadata = fs::metadata(path)?;
            let file_len = metadata.len();

            let mut file = match File::open(path) {
                Ok(f) => f,
                Err(_e) => {
                    // Could be a locked or inaccessible file
                    return Ok(threats);
                }
            };

            let read_limit = (file_len as usize).min(4 * 1024 * 1024); // Up to 4 MB buffer
            let mut buffer = vec![0u8; read_limit];
            let bytes_read = file.read(&mut buffer)?;
            buffer.truncate(bytes_read);

            // 4. Polyglot and Trailer Overlay Inspection
            if let Some(poly_threat) = PolyglotScanner::inspect(path, &buffer, file_len) {
                threats.push(poly_threat);
            }

            // 5. Deep Content Scanner (PDF AST, OpenXML, Ransomware, Scripts, PE)
            if let Some(content_threat) = ContentScanner::inspect_content(path, &buffer, file_len) {
                threats.push(content_threat);
            }

            // 6. Script Trojan Source inspection
            if let Some(trojan_threat) = UnicodeTrojanDetector::inspect_content(path, &buffer) {
                threats.push(trojan_threat);
            }
        }

        Ok(threats)
    }

    /// Recursively scans an entire directory or drive root
    pub fn scan_directory(root: &Path, max_files: usize) -> Vec<UniversalThreat> {
        let mut all_threats = Vec::new();
        let walker = walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok());

        let mut count = 0;
        for entry in walker {
            let p = entry.path();
            if let Ok(threats) = Self::scan_file(p) {
                all_threats.extend(threats);
            }
            count += 1;
            if count >= max_files {
                break;
            }
        }

        all_threats
    }
}
