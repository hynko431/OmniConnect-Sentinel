use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use sentinel_sys::is_reparse_point_or_symlink;

use crate::scanner::content_scanner::ContentScanner;
use crate::scanner::ntfs_ads_scanner::NtfsAdsScanner;
use crate::scanner::polyglot_scanner::PolyglotScanner;
use crate::scanner::tier0_yara::Tier0YaraScanner;
use crate::scanner::unicode_trojan_detector::UnicodeTrojanDetector;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CarrierCategory {
    Image,
    VideoAudio,
    Document,
    Archive,
    ScriptCode,
    FilesystemHidden,
    Ransomware,
    Executable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub risk_score: u8,
    pub mitre_technique: String,
    pub technical_details: String,
    pub overlay_offset: Option<u64>,
    pub stream_name: Option<String>,
    pub can_disarm_via_cdr: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalkError {
    pub path: PathBuf,
    pub kind: String,
    pub reason: String,
}

/// Fail-Closed Directory Scan Report (`BUG-CORE-14`, Phase 1.3)
///
/// Tracks `files_scanned`, `errors` (locked/inaccessible files or walk failures),
/// `limit_reached`, and `complete` (`errors.is_empty() && !limit_reached`) so an
/// incomplete or obstructed scan is never mistaken for a clean volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub threats: Vec<UniversalThreat>,
    pub files_scanned: usize,
    pub errors: Vec<WalkError>,
    pub skipped_symlinks: Vec<PathBuf>,
    pub limit_reached: bool,
    pub complete: bool,
}

pub struct UniversalScanner;

impl UniversalScanner {
    /// Scans a single file using seekable stream handles in bounded O(64 KiB) memory (`BUG-CORE-03`, `Rows 69, 78`)
    /// and returns an explicit `Err(std::io::Error)` if the file cannot be opened or read (`BUG-CORE-14`, `Row 79`).
    pub fn scan_file(path: &Path) -> Result<Vec<UniversalThreat>, std::io::Error> {
        let mut threats = Vec::new();

        // 0. Check path for Unicode BiDi / Zero-Width / Reserved DOS names / CLSID cloaking
        if let Some(path_threat) = UnicodeTrojanDetector::inspect_path(path) {
            threats.push(path_threat);
        }

        // 1. Check NTFS Alternate Data Streams
        for ads in NtfsAdsScanner::scan_file_streams(path) {
            threats.push(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::FilesystemHidden,
                threat_name: format!("NTFS Alternate Data Stream ({})", ads.stream_name),
                severity: if ads.is_executable_payload {
                    ThreatSeverity::Critical
                } else {
                    ThreatSeverity::High
                },
                risk_score: if ads.is_executable_payload { 98 } else { 85 },
                mitre_technique: "T1564.004 (NTFS File Attributes: ADS)".to_string(),
                technical_details: ads.threat_summary,
                overlay_offset: None,
                stream_name: Some(ads.stream_name),
                can_disarm_via_cdr: true,
            });
        }

        if let Ok(sym_meta) = fs::symlink_metadata(path) {
            if is_reparse_point_or_symlink(&sym_meta) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Refusing to follow symlink or reparse point during file scan: {}",
                        path.display()
                    ),
                ));
            }
        }

        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                if e.raw_os_error() == Some(225) {
                    threats.push(UniversalThreat {
                        file_path: path.to_path_buf(),
                        carrier_category: CarrierCategory::Executable,
                        threat_name: "OS Antimalware Filter Block (ERROR_VIRUS_INFECTED)"
                            .to_string(),
                        severity: ThreatSeverity::Critical,
                        risk_score: 100,
                        mitre_technique: "T1204.002 (Malicious File Blocked by OS)".to_string(),
                        technical_details: e.to_string(),
                        overlay_offset: None,
                        stream_name: None,
                        can_disarm_via_cdr: false,
                    });
                    return Ok(threats);
                }
                return Err(e);
            }
        };
        let metadata = file.metadata()?;
        let file_size = metadata.len();
        if file_size == 0 {
            return Ok(threats);
        }

        // Read at most 64 KiB (`IN_MEM_CAP`) for initial header magic inspection while streaming
        // all scanners (`UnicodeTrojanDetector`, `PolyglotScanner`, `ContentScanner`, `Tier0YaraScanner`)
        // over the seekable `File` handle in O(64 KiB) memory (`Rows 69, 78`).
        const IN_MEM_CAP: u64 = 64 * 1024;
        let read_len = file_size.min(IN_MEM_CAP) as usize;
        let mut head_bytes = Vec::with_capacity(read_len);
        if let Err(e) = (&mut file).take(IN_MEM_CAP).read_to_end(&mut head_bytes) {
            if e.raw_os_error() == Some(225) {
                threats.push(UniversalThreat {
                    file_path: path.to_path_buf(),
                    carrier_category: CarrierCategory::Executable,
                    threat_name: "OS Antimalware Filter Block (ERROR_VIRUS_INFECTED)".to_string(),
                    severity: ThreatSeverity::Critical,
                    risk_score: 100,
                    mitre_technique: "T1204.002 (Malicious File Blocked by OS)".to_string(),
                    technical_details: e.to_string(),
                    overlay_offset: None,
                    stream_name: None,
                    can_disarm_via_cdr: false,
                });
                return Ok(threats);
            }
            return Err(e);
        }

        let in_mem_slice = if file_size <= IN_MEM_CAP {
            Some(head_bytes.as_slice())
        } else {
            None
        };

        // 2. Check source/script content for Trojan Source BiDi overrides across 64 KiB windows (`Rows 69, 78`)
        if let Some(bidi_content_threat) =
            UnicodeTrojanDetector::inspect_content_reader(path, &mut file)
        {
            threats.push(bidi_content_threat);
        }

        // 3. Structural Polyglot Inspection across full seekable file (`BUG-CORE-03`, `BUG-CORE-04`, `Rows 69, 71-73, 78`)
        if let Some(poly_threat) =
            PolyglotScanner::inspect_reader(path, &mut file, file_size, in_mem_slice)
        {
            threats.push(poly_threat);
        }

        // 4. Content & Heuristic Inspection using seekable file (`BUG-CORE-03`, `BUG-CORE-05`, `Rows 69, 74-78, 135`)
        for content_threat in ContentScanner::inspect_with_reader(path, &head_bytes, &mut file) {
            threats.push(content_threat);
        }

        // 5. Tier-0 YARA / Structural Executable Signature Inspection over 64 KiB streaming windows (`BUG-CORE-11`, `Rows 69, 78, 154, 156, 228, 229`)
        let yara = Tier0YaraScanner::new();
        let yara_res = yara.scan_reader(&mut file, &path.to_string_lossy());
        if yara_res.matched {
            threats.push(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::Executable,
                threat_name: yara_res
                    .rule_name
                    .unwrap_or_else(|| "TIER0_YARA_SIGNATURE".to_string()),
                severity: ThreatSeverity::Critical,
                risk_score: 99,
                mitre_technique: "T1027 / T1204 (Malicious Binary Signature)".to_string(),
                technical_details: yara_res
                    .threat_details
                    .unwrap_or_else(|| "Matched Tier-0 signature rule".to_string()),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        Ok(threats)
    }

    /// Scans an already-read byte buffer (`raw_bytes`) for `path` without re-opening the
    /// primary file stream on the USB device (`Invariant I2`, `Row 7, 70` TOCTOU defense).
    pub fn scan_bytes_single_read(path: &Path, raw_bytes: &[u8]) -> Vec<UniversalThreat> {
        let mut threats = Vec::new();

        // 0. Check path for Unicode BiDi / Zero-Width / Reserved DOS names / CLSID cloaking
        if let Some(path_threat) = UnicodeTrojanDetector::inspect_path(path) {
            threats.push(path_threat);
        }

        // 1. Check NTFS Alternate Data Streams
        for ads in NtfsAdsScanner::scan_file_streams(path) {
            threats.push(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::FilesystemHidden,
                threat_name: format!("NTFS Alternate Data Stream ({})", ads.stream_name),
                severity: if ads.is_executable_payload {
                    ThreatSeverity::Critical
                } else {
                    ThreatSeverity::High
                },
                risk_score: if ads.is_executable_payload { 98 } else { 85 },
                mitre_technique: "T1564.004 (NTFS File Attributes: ADS)".to_string(),
                technical_details: ads.threat_summary,
                overlay_offset: None,
                stream_name: Some(ads.stream_name),
                can_disarm_via_cdr: true,
            });
        }

        if raw_bytes.is_empty() {
            return threats;
        }

        let head_slice = &raw_bytes[..raw_bytes.len().min(64 * 1024)];

        // 2. Check source/script content for Trojan Source BiDi overrides over Cursor (`Read + Seek`)
        let mut bidi_cursor = std::io::Cursor::new(raw_bytes);
        if let Some(bidi_content_threat) =
            UnicodeTrojanDetector::inspect_content_reader(path, &mut bidi_cursor)
        {
            threats.push(bidi_content_threat);
        }

        // 3. Structural Polyglot Inspection over in-memory Cursor (`Read + Seek`)
        let mut cursor = std::io::Cursor::new(raw_bytes);
        let file_size = raw_bytes.len() as u64;
        if let Some(poly_threat) =
            PolyglotScanner::inspect_reader(path, &mut cursor, file_size, Some(head_slice))
        {
            threats.push(poly_threat);
        }

        // 4. Content & Heuristic Inspection over in-memory Cursor (`Read + Seek`)
        let mut content_cursor = std::io::Cursor::new(raw_bytes);
        for content_threat in
            ContentScanner::inspect_with_reader(path, head_slice, &mut content_cursor)
        {
            threats.push(content_threat);
        }

        // 5. Tier-0 YARA / Structural Executable Signature Inspection over Cursor (`Read + Seek`)
        let yara = Tier0YaraScanner::new();
        let mut yara_cursor = std::io::Cursor::new(raw_bytes);
        let yara_res = yara.scan_reader(&mut yara_cursor, &path.to_string_lossy());
        if yara_res.matched {
            threats.push(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::Executable,
                threat_name: yara_res
                    .rule_name
                    .unwrap_or_else(|| "TIER0_YARA_SIGNATURE".to_string()),
                severity: ThreatSeverity::Critical,
                risk_score: 99,
                mitre_technique: "T1027 / T1204 (Malicious Binary Signature)".to_string(),
                technical_details: yara_res
                    .threat_details
                    .unwrap_or_else(|| "Matched Tier-0 signature rule".to_string()),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        threats
    }

    /// String-error convenience wrapper around `scan_file`.
    pub fn scan_file_checked(path: &Path) -> Result<Vec<UniversalThreat>, String> {
        Self::scan_file(path).map_err(|e| format!("Failed to inspect '{}': {}", path.display(), e))
    }

    /// Walks a directory tree without following symlinks or NTFS reparse points,
    /// staying on the same filesystem (`same_file_system(true)`), counting only regular
    /// files toward `max_files`, and surfacing all metadata/walk/open errors (`BUG-CORE-14`, `Rows 79-84`).
    pub fn scan_directory_detailed(root: &Path, max_files: usize) -> ScanReport {
        let mut threats = Vec::new();
        let mut files_scanned = 0usize;
        let mut errors = Vec::new();
        let mut skipped_symlinks = Vec::new();
        let mut limit_reached = false;

        for entry_res in WalkDir::new(root)
            .follow_links(false)
            .same_file_system(true)
        {
            let entry = match entry_res {
                Ok(e) => e,
                Err(walk_err) => {
                    let err_path = walk_err
                        .path()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| root.to_path_buf());
                    let kind = walk_err
                        .io_error()
                        .map(|ioe| format!("{:?}", ioe.kind()))
                        .unwrap_or_else(|| "WalkError".to_string());
                    errors.push(WalkError {
                        path: err_path,
                        kind,
                        reason: walk_err.to_string(),
                    });
                    continue;
                }
            };

            let path = entry.path();

            // Inspect metadata without following links; record any metadata error as a WalkError (`Rows 80, 81`)
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(meta_err) => {
                    let kind = meta_err
                        .io_error()
                        .map(|ioe| format!("{:?}", ioe.kind()))
                        .unwrap_or_else(|| "MetadataError".to_string());
                    errors.push(WalkError {
                        path: path.to_path_buf(),
                        kind,
                        reason: meta_err.to_string(),
                    });
                    continue;
                }
            };

            // Skip symlinks and NTFS reparse points / junctions (`BUG-CORE-14` #4, `Row 81`, `T17`)
            if entry.path_is_symlink() || is_reparse_point_or_symlink(&meta) {
                skipped_symlinks.push(path.to_path_buf());
                continue;
            }

            // Count only regular files toward `max_files` (`BUG-CORE-14` #3, `Row 83`)
            if !entry.file_type().is_file() {
                continue;
            }

            if files_scanned >= max_files {
                limit_reached = true;
                break;
            }

            files_scanned += 1;

            match Self::scan_file(path) {
                Ok(mut file_threats) => threats.append(&mut file_threats),
                Err(io_err) => {
                    // Still preserve any path-level or ADS threats while recording the file open/read error (`Row 79`)
                    if let Some(path_threat) = UnicodeTrojanDetector::inspect_path(path) {
                        threats.push(path_threat);
                    }
                    errors.push(WalkError {
                        path: path.to_path_buf(),
                        kind: format!("{:?}", io_err.kind()),
                        reason: format!("Failed to inspect '{}': {}", path.display(), io_err),
                    });
                }
            }
        }

        let complete = errors.is_empty() && !limit_reached;

        ScanReport {
            threats,
            files_scanned,
            errors,
            skipped_symlinks,
            limit_reached,
            complete,
        }
    }

    pub fn scan_directory(root: &Path, max_files: usize) -> Vec<UniversalThreat> {
        Self::scan_directory_detailed(root, max_files).threats
    }
}
