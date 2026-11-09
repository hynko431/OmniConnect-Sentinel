use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use crate::scanner::universal_scanner::{CarrierCategory, ThreatSeverity, UniversalThreat};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolyglotFinding {
    pub declared_format: String,
    pub hidden_payload_type: String,
    pub eof_marker_offset: usize,
    pub appended_bytes_size: usize,
    pub threat_summary: String,
}

/// Structural Polyglot & Appended-Overlay Scanner (`BUG-CORE-03`, `BUG-CORE-04`, Phase 1.3)
///
/// Uses forward container grammar walking (JPEG marker segments skipping `APP1` EXIF
/// thumbnails, PNG length-prefixed chunks to `IEND`, WebP RIFF bounds, and seekable
/// 32/64-bit ISOBMFF MP4 box headers across the full file) rather than naive byte searches.
pub struct PolyglotScanner;

impl PolyglotScanner {
    pub fn scan(path: &Path, bytes: &[u8]) -> Option<PolyglotFinding> {
        let mut cursor = Cursor::new(bytes);
        Self::scan_reader(path, &mut cursor, bytes.len() as u64, Some(bytes))
    }

    /// Backwards-compatible entry point returning `UniversalThreat`.
    pub fn inspect(path: &Path, bytes: &[u8], file_size: u64) -> Option<UniversalThreat> {
        let mut cursor = Cursor::new(bytes);
        Self::inspect_reader(path, &mut cursor, file_size, Some(bytes))
    }

    pub fn inspect_reader<R: Read + Seek>(
        path: &Path,
        reader: &mut R,
        file_size: u64,
        in_memory_slice: Option<&[u8]>,
    ) -> Option<UniversalThreat> {
        let finding = Self::scan_reader(path, reader, file_size, in_memory_slice)?;
        let is_video =
            finding.declared_format.contains("MP4") || finding.declared_format.contains("Video");
        let is_pe_or_elf = finding.hidden_payload_type.contains("PE Executable")
            || finding.hidden_payload_type.contains("ELF");

        let (severity, risk_score) = if is_pe_or_elf {
            (ThreatSeverity::Critical, 98)
        } else {
            (ThreatSeverity::High, 92)
        };

        let is_corrupt_container = finding.hidden_payload_type.contains("Malformed/Truncated");
        let can_cdr = !is_corrupt_container
            && matches!(
                finding.declared_format.as_str(),
                "JPEG Image" | "PNG Image" | "WebP Image"
            );

        Some(UniversalThreat {
            file_path: path.to_path_buf(),
            carrier_category: if is_video {
                CarrierCategory::VideoAudio
            } else {
                CarrierCategory::Image
            },
            threat_name: format!(
                "{} Polyglot Dropper ({})",
                finding.declared_format, finding.hidden_payload_type
            ),
            severity,
            risk_score,
            mitre_technique: "T1027.003 (Steganography / Polyglot File)".to_string(),
            technical_details: finding.threat_summary,
            overlay_offset: Some(finding.eof_marker_offset as u64),
            stream_name: None,
            can_disarm_via_cdr: can_cdr,
        })
    }

    pub fn scan_reader<R: Read + Seek>(
        path: &Path,
        reader: &mut R,
        file_size: u64,
        in_memory_slice: Option<&[u8]>,
    ) -> Option<PolyglotFinding> {
        if file_size < 16 {
            return None;
        }

        let mut head = [0u8; 32];
        let _ = reader.seek(SeekFrom::Start(0));
        let head_read = reader.read(&mut head).ok()?;
        if head_read < 8 {
            return None;
        }
        let header = &head[..head_read];

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // 1. JPEG: FF D8 FF (Forward seekable segment walk in O(64 KiB) RAM - skips EXIF APP1 thumbnails! Fixes BUG-CORE-03 & BUG-CORE-04 #1)
        if header.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Self::scan_jpeg_seekable(reader, file_size);
        }

        // 2. PNG: 89 50 4E 47 0D 0A 1A 0A (Forward seekable chunk walk to IEND in O(1) RAM! Fixes BUG-CORE-03 & BUG-CORE-04 #2)
        if header.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
            return Self::scan_png_seekable(reader, file_size);
        }

        // 3. WebP: RIFF....WEBP (Seekable RIFF bound check in O(1) RAM)
        if header.len() >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"WEBP" {
            return Self::scan_webp_seekable(reader, file_size);
        }

        // 4. GIF: GIF87a / GIF89a (Streaming 64 KiB window scan)
        if header.starts_with(b"GIF87a") || header.starts_with(b"GIF89a") {
            return Self::scan_gif_seekable(reader, file_size);
        }

        // 5. MP4 / MOV / ISOBMFF (`ftyp` at offset 4, or `.mp4`/`.mov`/`.m4a` extension)
        // Uses Seek::seek across all boxes regardless of >4 MB file size (`BUG-CORE-03`, `BUG-CORE-04` #3)
        if ((header.len() >= 8 && &header[4..8] == b"ftyp")
            || matches!(ext.as_str(), "mp4" | "mov" | "m4v" | "m4a"))
            && header.len() >= 8
            && &header[4..8] == b"ftyp"
        {
            return Self::scan_mp4_seekable(reader, file_size);
        }

        let _ = in_memory_slice;
        None
    }

    /// Streams through a JPEG container using `Read + Seek` and a fixed 64 KiB stack/heap window (`Rows 69, 71, 74`, `BUG-CORE-03`).
    ///
    /// Skips variable-length `APPn`/`COM` segments via `Seek::seek` (ignoring nested EXIF thumbnail EOIs)
    /// and scans entropy-coded data after `SOS` (`0xFF 0xDA`) in 64 KiB chunks until the true main-image `EOI` (`0xFF 0xD9`).
    pub fn find_true_jpeg_eoi_end_reader<R: Read + Seek>(
        reader: &mut R,
        file_size: u64,
    ) -> Option<u64> {
        if file_size < 4 {
            return None;
        }
        reader.seek(SeekFrom::Start(0)).ok()?;
        let mut soi = [0u8; 2];
        reader.read_exact(&mut soi).ok()?;
        if soi != [0xFF, 0xD8] {
            return None;
        }

        let mut pos = 2u64;
        let mut scan_buf = vec![0u8; 64 * 1024];

        while pos < file_size {
            reader.seek(SeekFrom::Start(pos)).ok()?;
            let mut b = [0u8; 1];
            if reader.read_exact(&mut b).is_err() {
                break;
            }
            pos += 1;
            if b[0] != 0xFF {
                continue;
            }

            // Skip any fill 0xFF bytes
            let mut marker = 0xFFu8;
            while pos < file_size && marker == 0xFF {
                if reader.read_exact(&mut b).is_err() {
                    return None;
                }
                pos += 1;
                marker = b[0];
            }
            if marker == 0xFF {
                break;
            }

            match marker {
                // Standalone markers or stuffed byte
                0x00 | 0x01 | 0xD0..=0xD8 => continue,
                // True main-image EOI
                0xD9 => return Some(pos),
                // SOS (Start of Scan): skip SOS header, then stream entropy-coded data in 64 KiB windows
                0xDA => {
                    if pos + 2 > file_size {
                        return None;
                    }
                    let mut len_bytes = [0u8; 2];
                    reader.read_exact(&mut len_bytes).ok()?;
                    let seg_len = u16::from_be_bytes(len_bytes) as u64;
                    if seg_len < 2 || pos + seg_len > file_size {
                        return None;
                    }
                    pos += seg_len;
                    reader.seek(SeekFrom::Start(pos)).ok()?;

                    let mut prev_ff = false;
                    let mut ff_offset = 0u64;
                    'entropy: while pos < file_size {
                        let to_read = ((file_size - pos) as usize).min(scan_buf.len());
                        let n = reader.read(&mut scan_buf[..to_read]).ok()?;
                        if n == 0 {
                            break;
                        }
                        for (i, &byte) in scan_buf[..n].iter().enumerate() {
                            let abs_idx = pos + (i as u64);
                            if !prev_ff {
                                if byte == 0xFF {
                                    prev_ff = true;
                                    ff_offset = abs_idx;
                                }
                            } else if byte == 0xFF {
                                // Repeated 0xFF fill byte before marker code
                                ff_offset = abs_idx;
                            } else if byte == 0x00 || (0xD0..=0xD7).contains(&byte) {
                                // Stuffed 0xFF 0x00 byte or RSTn restart marker inside entropy data
                                prev_ff = false;
                            } else if byte == 0xD9 {
                                // Found true EOI immediately after entropy stream!
                                return Some(abs_idx + 1);
                            } else {
                                // Found next real marker (e.g. DQT/DHT/SOS in progressive JPEG): rewind outer loop to `ff_offset`
                                pos = ff_offset;
                                break 'entropy;
                            }
                        }
                        pos += n as u64;
                    }
                }
                // Variable-length segment (`APP0`..`APP15`, `COM`, `DQT`, `DHT`, `SOFn`): seek past payload in O(1)
                _ => {
                    if pos + 2 > file_size {
                        return None;
                    }
                    let mut len_bytes = [0u8; 2];
                    reader.read_exact(&mut len_bytes).ok()?;
                    let seg_len = u16::from_be_bytes(len_bytes) as u64;
                    if seg_len < 2 || pos + seg_len > file_size {
                        return None;
                    }
                    pos += seg_len;
                }
            }
        }

        None
    }

    fn scan_jpeg_seekable<R: Read + Seek>(
        reader: &mut R,
        file_size: u64,
    ) -> Option<PolyglotFinding> {
        let valid_end_offset = match Self::find_true_jpeg_eoi_end_reader(reader, file_size) {
            Some(off) => off,
            None => {
                return Some(PolyglotFinding {
                    declared_format: "JPEG Image".to_string(),
                    hidden_payload_type: "Malformed/Truncated JPEG Container (Missing EOI)"
                        .to_string(),
                    eof_marker_offset: 0,
                    appended_bytes_size: file_size as usize,
                    threat_summary:
                        "Malformed or truncated JPEG container missing valid EOI marker (fail-closed)"
                            .to_string(),
                });
            }
        };
        if valid_end_offset >= file_size {
            return None;
        }
        let trailing_overlay_bytes = (file_size - valid_end_offset) as usize;
        let sample_len = trailing_overlay_bytes.min(4096);
        let mut overlay_sample = vec![0u8; sample_len];
        reader.seek(SeekFrom::Start(valid_end_offset)).ok()?;
        let n = reader.read(&mut overlay_sample).ok()?;

        if let Some(payload_type) =
            Self::classify_overlay_with_total(&overlay_sample[..n], trailing_overlay_bytes)
        {
            return Some(PolyglotFinding {
                declared_format: "JPEG Image".to_string(),
                hidden_payload_type: payload_type.clone(),
                eof_marker_offset: valid_end_offset as usize,
                appended_bytes_size: trailing_overlay_bytes,
                threat_summary: format!(
                    "Polyglot JPEG detected: {payload_type} ({trailing_overlay_bytes} bytes) appended after true EOI (0xFFD9) at offset {valid_end_offset}"
                ),
            });
        }
        None
    }

    /// Walks PNG chunks using `Read + Seek` in O(1) memory (`Rows 69, 71, 72, 74`, `BUG-CORE-03`).
    /// Reads only 8-byte `[length: u32 BE][type: 4B]` headers and seeks over chunk bodies + CRCs until `IEND`.
    pub fn find_true_png_iend_end_reader<R: Read + Seek>(
        reader: &mut R,
        file_size: u64,
    ) -> Option<u64> {
        const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        if file_size < 20 {
            return None;
        }
        reader.seek(SeekFrom::Start(0)).ok()?;
        let mut sig = [0u8; 8];
        reader.read_exact(&mut sig).ok()?;
        if sig != PNG_SIG {
            return None;
        }

        let mut offset = 8u64;
        while offset + 12 <= file_size {
            reader.seek(SeekFrom::Start(offset)).ok()?;
            let mut hdr = [0u8; 8];
            reader.read_exact(&mut hdr).ok()?;
            let length = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
            let chunk_type = &hdr[4..8];
            let chunk_total = 12u64.checked_add(length)?;
            if offset.checked_add(chunk_total)? > file_size {
                return None;
            }
            offset += chunk_total;
            if chunk_type == b"IEND" {
                return Some(offset);
            }
        }
        None
    }

    /// Optional IEEE 802.3 CRC-32 verifier for PNG chunks streamed in 64 KiB windows (`Row 72`).
    pub fn verify_png_crc_reader<R: Read + Seek>(reader: &mut R, file_size: u64) -> bool {
        const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        if file_size < 20 || reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut sig = [0u8; 8];
        if reader.read_exact(&mut sig).is_err() || sig != PNG_SIG {
            return false;
        }
        let mut offset = 8u64;
        let mut buf = vec![0u8; 64 * 1024];
        while offset + 12 <= file_size {
            if reader.seek(SeekFrom::Start(offset)).is_err() {
                return false;
            }
            let mut hdr = [0u8; 8];
            if reader.read_exact(&mut hdr).is_err() {
                return false;
            }
            let length = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
            let chunk_type = [hdr[4], hdr[5], hdr[6], hdr[7]];
            let chunk_total = match 12u64.checked_add(length) {
                Some(t)
                    if offset
                        .checked_add(t)
                        .map(|e| e <= file_size)
                        .unwrap_or(false) =>
                {
                    t
                }
                _ => return false,
            };
            let mut crc = 0xFFFF_FFFFu32;
            for &b in &chunk_type {
                crc = Self::crc32_step(crc, b);
            }
            let mut rem = length;
            while rem > 0 {
                let to_read = (rem as usize).min(buf.len());
                if reader.read_exact(&mut buf[..to_read]).is_err() {
                    return false;
                }
                for &b in &buf[..to_read] {
                    crc = Self::crc32_step(crc, b);
                }
                rem -= to_read as u64;
            }
            crc ^= 0xFFFF_FFFF;
            let mut expected_bytes = [0u8; 4];
            if reader.read_exact(&mut expected_bytes).is_err() {
                return false;
            }
            let expected = u32::from_be_bytes(expected_bytes);
            if crc != expected {
                return false;
            }
            offset += chunk_total;
            if &chunk_type == b"IEND" {
                return true;
            }
        }
        false
    }

    fn crc32_step(mut crc: u32, byte: u8) -> u32 {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
        crc
    }

    fn scan_png_seekable<R: Read + Seek>(
        reader: &mut R,
        file_size: u64,
    ) -> Option<PolyglotFinding> {
        let valid_end_offset = match Self::find_true_png_iend_end_reader(reader, file_size) {
            Some(off) => off,
            None => {
                return Some(PolyglotFinding {
                    declared_format: "PNG Image".to_string(),
                    hidden_payload_type: "Malformed/Truncated PNG Container (Missing IEND)"
                        .to_string(),
                    eof_marker_offset: 0,
                    appended_bytes_size: file_size as usize,
                    threat_summary:
                        "Malformed or truncated PNG container missing valid IEND chunk (fail-closed)"
                            .to_string(),
                });
            }
        };
        if valid_end_offset >= file_size {
            return None;
        }
        let trailing_overlay_bytes = (file_size - valid_end_offset) as usize;
        let sample_len = trailing_overlay_bytes.min(4096);
        let mut overlay_sample = vec![0u8; sample_len];
        reader.seek(SeekFrom::Start(valid_end_offset)).ok()?;
        let n = reader.read(&mut overlay_sample).ok()?;

        if let Some(payload_type) =
            Self::classify_overlay_with_total(&overlay_sample[..n], trailing_overlay_bytes)
        {
            return Some(PolyglotFinding {
                declared_format: "PNG Image".to_string(),
                hidden_payload_type: payload_type.clone(),
                eof_marker_offset: valid_end_offset as usize,
                appended_bytes_size: trailing_overlay_bytes,
                threat_summary: format!(
                    "Polyglot PNG detected: {payload_type} ({trailing_overlay_bytes} bytes) appended after IEND chunk at offset {valid_end_offset}"
                ),
            });
        }
        None
    }

    fn scan_webp_seekable<R: Read + Seek>(
        reader: &mut R,
        file_size: u64,
    ) -> Option<PolyglotFinding> {
        if file_size < 12 {
            return None;
        }
        reader.seek(SeekFrom::Start(0)).ok()?;
        let mut hdr = [0u8; 12];
        reader.read_exact(&mut hdr).ok()?;
        if &hdr[0..4] != b"RIFF" || &hdr[8..12] != b"WEBP" {
            return None;
        }
        let declared_riff_size = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as u64;
        let riff_total = declared_riff_size.saturating_add(8);
        if riff_total > file_size {
            return Some(PolyglotFinding {
                declared_format: "WebP Image".to_string(),
                hidden_payload_type: "Malformed/Truncated WebP RIFF Container".to_string(),
                eof_marker_offset: 0,
                appended_bytes_size: file_size as usize,
                threat_summary: format!(
                    "Malformed or truncated WebP container: RIFF bound {riff_total} exceeds file size {file_size} (fail-closed)"
                ),
            });
        }
        let valid_end_offset = riff_total;
        if valid_end_offset >= file_size {
            return None;
        }
        let trailing_overlay_bytes = (file_size - valid_end_offset) as usize;
        let sample_len = trailing_overlay_bytes.min(4096);
        let mut overlay_sample = vec![0u8; sample_len];
        reader.seek(SeekFrom::Start(valid_end_offset)).ok()?;
        let n = reader.read(&mut overlay_sample).ok()?;

        if let Some(payload_type) =
            Self::classify_overlay_with_total(&overlay_sample[..n], trailing_overlay_bytes)
        {
            return Some(PolyglotFinding {
                declared_format: "WebP Image".to_string(),
                hidden_payload_type: payload_type.clone(),
                eof_marker_offset: valid_end_offset as usize,
                appended_bytes_size: trailing_overlay_bytes,
                threat_summary: format!(
                    "Polyglot WebP detected: {payload_type} ({trailing_overlay_bytes} bytes) appended after RIFF bound at offset {valid_end_offset}"
                ),
            });
        }
        None
    }

    fn scan_gif_seekable<R: Read + Seek>(
        reader: &mut R,
        file_size: u64,
    ) -> Option<PolyglotFinding> {
        if file_size < 18 {
            return None;
        }
        reader.seek(SeekFrom::Start(14)).ok()?;
        let mut pos = 14u64;
        let mut buf = vec![0u8; 64 * 1024];
        while pos < file_size {
            let to_read = ((file_size - pos) as usize).min(buf.len());
            let n = reader.read(&mut buf[..to_read]).ok()?;
            if n == 0 {
                break;
            }
            for (i, &byte) in buf[..n].iter().enumerate() {
                if byte == 0x3B {
                    let eof_offset = pos + (i as u64) + 1;
                    if eof_offset + 4 <= file_size {
                        let rem = (file_size - eof_offset) as usize;
                        let mut sample = vec![0u8; rem.min(512)];
                        reader.seek(SeekFrom::Start(eof_offset)).ok()?;
                        let sn = reader.read(&mut sample).unwrap_or(0);
                        if let Some(sig) = Self::detect_explicit_signature(&sample[..sn]) {
                            return Some(PolyglotFinding {
                                declared_format: "GIF Image".to_string(),
                                hidden_payload_type: sig.clone(),
                                eof_marker_offset: eof_offset as usize,
                                appended_bytes_size: rem,
                                threat_summary: format!(
                                    "Polyglot GIF detected: {sig} ({rem} bytes) appended after GIF trailer (0x3B) at offset {eof_offset}"
                                ),
                            });
                        }
                        reader.seek(SeekFrom::Start(pos + (n as u64))).ok()?;
                    }
                }
            }
            pos += n as u64;
        }
        None
    }

    /// Walks ISO-BMFF (`MP4`/`MOV`) top-level boxes via `Seek::seek` across the entire file
    /// (`BUG-CORE-03`, `BUG-CORE-04` #3). Supports 32-bit `size`, 64-bit `largesize` (`size == 1`),
    /// `size == 0` (to EOF), and valid files where `moov` appears after `mdat`.
    fn scan_mp4_seekable<R: Read + Seek>(
        reader: &mut R,
        file_size: u64,
    ) -> Option<PolyglotFinding> {
        let mut offset = 0u64;
        let mut saw_ftyp = false;

        while offset + 8 <= file_size {
            reader.seek(SeekFrom::Start(offset)).ok()?;
            let mut hdr = [0u8; 16];
            reader.read_exact(&mut hdr[..8]).ok()?;

            let size32 = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
            let fourcc = [hdr[4], hdr[5], hdr[6], hdr[7]];

            if &fourcc == b"ftyp" {
                saw_ftyp = true;
            }

            if !Self::is_valid_isobmff_box(&fourcc) {
                if saw_ftyp {
                    let appended_size = (file_size - offset) as usize;
                    let mut sample = vec![0u8; appended_size.min(512)];
                    let _ = reader.seek(SeekFrom::Start(offset));
                    let n = reader.read(&mut sample).unwrap_or(0);
                    if let Some(payload_type) = Self::classify_overlay(&sample[..n]) {
                        return Some(PolyglotFinding {
                            declared_format: "MP4/ISOBMFF Video".to_string(),
                            hidden_payload_type: payload_type.clone(),
                            eof_marker_offset: offset as usize,
                            appended_bytes_size: appended_size,
                            threat_summary: format!(
                                "Polyglot MP4 detected: {payload_type} ({appended_size} bytes) appended after ISOBMFF boxes at offset {offset}"
                            ),
                        });
                    }
                }
                break;
            }

            let box_size = if size32 == 1 {
                if offset + 16 > file_size {
                    break;
                }
                reader.read_exact(&mut hdr[8..16]).ok()?;
                u64::from_be_bytes([
                    hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
                ])
            } else if size32 == 0 {
                file_size - offset
            } else {
                size32
            };

            if box_size < 8 || offset.saturating_add(box_size) > file_size {
                break;
            }

            offset += box_size;
        }

        if saw_ftyp && offset < file_size {
            let appended_size = (file_size - offset) as usize;
            let mut sample = vec![0u8; appended_size.min(512)];
            let _ = reader.seek(SeekFrom::Start(offset));
            let n = reader.read(&mut sample).unwrap_or(0);
            if let Some(payload_type) = Self::classify_overlay(&sample[..n]) {
                return Some(PolyglotFinding {
                    declared_format: "MP4/ISOBMFF Video".to_string(),
                    hidden_payload_type: payload_type.clone(),
                    eof_marker_offset: offset as usize,
                    appended_bytes_size: appended_size,
                    threat_summary: format!(
                        "Polyglot MP4 detected: {payload_type} ({appended_size} bytes) appended after final ISOBMFF box at offset {offset}"
                    ),
                });
            }
        }

        None
    }

    fn is_valid_isobmff_box(fourcc: &[u8; 4]) -> bool {
        matches!(
            fourcc,
            b"ftyp"
                | b"styp"
                | b"moov"
                | b"mdat"
                | b"free"
                | b"skip"
                | b"wide"
                | b"udta"
                | b"meta"
                | b"uuid"
                | b"moof"
                | b"mfra"
                | b"pdin"
                | b"meco"
                | b"sidx"
                | b"ssix"
                | b"prft"
                | b"emsg"
                | b"jp2 "
                | b"pnot"
        )
    }

    fn detect_explicit_signature(overlay: &[u8]) -> Option<String> {
        if overlay.starts_with(b"MZ") {
            return Some("Windows PE Executable (MZ)".to_string());
        }
        if overlay.starts_with(b"\x7FELF") {
            return Some("Linux ELF Binary".to_string());
        }
        if overlay.starts_with(b"PK\x03\x04") {
            return Some("ZIP / OOXML Archive (PK)".to_string());
        }
        if overlay.starts_with(b"Rar!") {
            return Some("RAR Archive".to_string());
        }
        if overlay.starts_with(b"%PDF-") {
            return Some("Embedded PDF Document".to_string());
        }
        let head_str = String::from_utf8_lossy(&overlay[..overlay.len().min(256)]).to_lowercase();
        if head_str.contains("powershell")
            || head_str.contains("invoke-expression")
            || head_str.contains("#!/bin/")
            || head_str.contains("<script")
        {
            return Some("Appended Script Payload".to_string());
        }
        None
    }

    fn classify_overlay(overlay: &[u8]) -> Option<String> {
        Self::classify_overlay_with_total(overlay, overlay.len())
    }

    fn classify_overlay_with_total(
        overlay_sample: &[u8],
        total_overlay_len: usize,
    ) -> Option<String> {
        if let Some(sig) = Self::detect_explicit_signature(overlay_sample) {
            return Some(sig);
        }
        if total_overlay_len > 64
            && overlay_sample
                .iter()
                .any(|&b| b != 0 && !b.is_ascii_whitespace())
        {
            return Some("Unrecognized Appended Binary Overlay".to_string());
        }
        None
    }
}
