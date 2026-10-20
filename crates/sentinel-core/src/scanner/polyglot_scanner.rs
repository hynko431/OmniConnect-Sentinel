use std::path::Path;
use super::universal_scanner::{UniversalThreat, CarrierCategory, ThreatSeverity};

pub struct PolyglotScanner;

impl PolyglotScanner {
    /// Inspects image or video file bytes for appended polyglots or trailer payloads
    pub fn inspect(path: &Path, bytes: &[u8], file_len: u64) -> Option<UniversalThreat> {
        // 1. JPEG Format
        if bytes.len() >= 4 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
            return Self::check_jpeg_overlay(path, bytes, file_len);
        }

        // 2. PNG Format
        if bytes.len() >= 8 && &bytes[0..4] == b"\x89PNG" {
            return Self::check_png_overlay(path, bytes, file_len);
        }

        // 3. WebP Format
        if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
            return Self::check_webp_overlay(path, bytes, file_len);
        }

        // 4. MP4 / MOV Video Container
        if bytes.len() >= 8 && (&bytes[4..8] == b"ftyp" || &bytes[4..8] == b"moov") {
            return Self::check_isobmff_video(path, bytes, file_len);
        }

        None
    }

    fn check_jpeg_overlay(path: &Path, bytes: &[u8], file_len: u64) -> Option<UniversalThreat> {
        if let Some(pos) = bytes.windows(2).rposition(|w| w == [0xFF, 0xD9]) {
            let eoi_offset = (pos + 2) as u64;
            let trailing_bytes = file_len.saturating_sub(eoi_offset);

            // Allow up to 32 bytes of harmless metadata/null padding
            if trailing_bytes > 32 {
                let overlay_slice = if bytes.len() > pos + 2 {
                    &bytes[pos + 2..]
                } else {
                    &[]
                };

                let is_pe = overlay_slice.windows(2).any(|w| w == b"MZ");
                let is_zip = overlay_slice.windows(4).any(|w| w == b"PK\x03\x04");

                let (threat_name, severity, risk_score) = if is_pe {
                    ("Polyglot Dropper: Executable (MZ) Appended Past JPEG EOI", ThreatSeverity::Critical, 98)
                } else if is_zip {
                    ("Polyglot Archive: ZIP/JAR Appended Past JPEG EOI", ThreatSeverity::High, 85)
                } else {
                    ("Suspicious Trailing Overlay Past JPEG EOI", ThreatSeverity::Medium, 72)
                };

                return Some(UniversalThreat {
                    file_path: path.to_path_buf(),
                    carrier_category: CarrierCategory::Image,
                    threat_name: threat_name.to_string(),
                    severity,
                    risk_score,
                    mitre_technique: "T1027.001 (Obfuscated Files: Binary Overlays)".to_string(),
                    technical_details: format!(
                        "JPEG ends at offset {}. Found {} trailing bytes with active payload signatures.",
                        eoi_offset, trailing_bytes
                    ),
                    overlay_offset: Some(eoi_offset),
                    stream_name: None,
                    can_disarm_via_cdr: true,
                });
            }
        }
        None
    }

    fn check_png_overlay(path: &Path, bytes: &[u8], file_len: u64) -> Option<UniversalThreat> {
        // PNG ends with IEND chunk: 4 bytes length (00 00 00 00) + 'IEND' + 4 bytes CRC
        if let Some(pos) = bytes.windows(4).rposition(|w| w == b"IEND") {
            let iend_chunk_end = (pos + 4 + 4) as u64; // past IEND + CRC
            let trailing_bytes = file_len.saturating_sub(iend_chunk_end);

            if trailing_bytes > 32 {
                let overlay_slice = if bytes.len() > (pos + 8) {
                    &bytes[pos + 8..]
                } else {
                    &[]
                };

                let is_pe = overlay_slice.windows(2).any(|w| w == b"MZ");
                let is_zip = overlay_slice.windows(4).any(|w| w == b"PK\x03\x04");

                let (threat_name, severity, risk_score) = if is_pe {
                    ("Polyglot Dropper: Executable Appended Past PNG IEND", ThreatSeverity::Critical, 98)
                } else if is_zip {
                    ("Polyglot Archive: ZIP Appended Past PNG IEND", ThreatSeverity::High, 85)
                } else {
                    ("Suspicious Trailing Overlay Past PNG IEND", ThreatSeverity::Medium, 70)
                };

                return Some(UniversalThreat {
                    file_path: path.to_path_buf(),
                    carrier_category: CarrierCategory::Image,
                    threat_name: threat_name.to_string(),
                    severity,
                    risk_score,
                    mitre_technique: "T1027.001 (Obfuscated Files: Binary Overlays)".to_string(),
                    technical_details: format!(
                        "PNG IEND terminates at offset {}. Found {} trailing bytes past valid chunk.",
                        iend_chunk_end, trailing_bytes
                    ),
                    overlay_offset: Some(iend_chunk_end),
                    stream_name: None,
                    can_disarm_via_cdr: true,
                });
            }
        }
        None
    }

    fn check_webp_overlay(path: &Path, bytes: &[u8], file_len: u64) -> Option<UniversalThreat> {
        if bytes.len() >= 8 {
            let declared_riff_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64;
            let expected_total_size = declared_riff_size.saturating_add(8);

            if file_len > expected_total_size.saturating_add(64) {
                let trailing = file_len - expected_total_size;
                return Some(UniversalThreat {
                    file_path: path.to_path_buf(),
                    carrier_category: CarrierCategory::Image,
                    threat_name: "WebP Polyglot: Overlay Beyond Declared RIFF Boundary".to_string(),
                    severity: ThreatSeverity::High,
                    risk_score: 82,
                    mitre_technique: "T1027.001 (Binary Overlays)".to_string(),
                    technical_details: format!(
                        "WebP declared RIFF size is {} bytes, but physical file is {} bytes ({} trailing bytes).",
                        expected_total_size, file_len, trailing
                    ),
                    overlay_offset: Some(expected_total_size),
                    stream_name: None,
                    can_disarm_via_cdr: true,
                });
            }
        }
        None
    }

    fn check_isobmff_video(path: &Path, bytes: &[u8], file_len: u64) -> Option<UniversalThreat> {
        let mut cursor = 0usize;
        let mut total_declared_box_len = 0u64;

        while cursor + 8 <= bytes.len() {
            let box_size = u32::from_be_bytes([bytes[cursor], bytes[cursor + 1], bytes[cursor + 2], bytes[cursor + 3]]) as u64;
            let box_type = &bytes[cursor + 4..cursor + 8];

            if box_size == 0 {
                // Box extends to EOF
                total_declared_box_len = file_len;
                break;
            } else if box_size == 1 {
                // 64-bit large size
                if cursor + 16 <= bytes.len() {
                    let large_size = u64::from_be_bytes([
                        bytes[cursor + 8], bytes[cursor + 9], bytes[cursor + 10], bytes[cursor + 11],
                        bytes[cursor + 12], bytes[cursor + 13], bytes[cursor + 14], bytes[cursor + 15],
                    ]);
                    total_declared_box_len = total_declared_box_len.saturating_add(large_size);
                    if large_size < 16 {
                        break;
                    }
                    cursor = cursor.saturating_add(large_size as usize);
                } else {
                    break;
                }
            } else {
                total_declared_box_len = total_declared_box_len.saturating_add(box_size);
                if box_size < 8 {
                    break;
                }
                cursor = cursor.saturating_add(box_size as usize);
            }

            // Check if user-extension 'uuid' box contains MZ payload
            if box_type == b"uuid" && cursor <= bytes.len() {
                let uuid_slice = &bytes[cursor.saturating_sub(box_size as usize)..cursor];
                if uuid_slice.windows(2).any(|w| w == b"MZ") {
                    return Some(UniversalThreat {
                        file_path: path.to_path_buf(),
                        carrier_category: CarrierCategory::VideoAudio,
                        threat_name: "Weaponized Video Container: Embedded PE inside UUID Box".to_string(),
                        severity: ThreatSeverity::Critical,
                        risk_score: 97,
                        mitre_technique: "T1027.001 (Binary Overlays)".to_string(),
                        technical_details: "MP4 container holds custom UUID box harboring executable PE headers.".to_string(),
                        overlay_offset: None,
                        stream_name: None,
                        can_disarm_via_cdr: true,
                    });
                }
            }
        }

        // If file_len exceeds parsed boxes significantly and we reached end of boxes
        if total_declared_box_len > 0 && file_len > total_declared_box_len.saturating_add(1024) && cursor >= bytes.len() {
            let trailing = file_len - total_declared_box_len;
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::VideoAudio,
                threat_name: "Video Carrier Discrepancy: Trailing Bytes Past Final Atom".to_string(),
                severity: ThreatSeverity::High,
                risk_score: 80,
                mitre_technique: "T1027.001 (Binary Overlays)".to_string(),
                technical_details: format!(
                    "MP4 box hierarchy terminates at {} bytes, leaving {} unreferenced trailing bytes at EOF.",
                    total_declared_box_len, trailing
                ),
                overlay_offset: Some(total_declared_box_len),
                stream_name: None,
                can_disarm_via_cdr: true,
            });
        }

        None
    }
}
