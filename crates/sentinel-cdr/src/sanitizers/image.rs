use crate::error::{CdrError, Result};
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::DisarmReportItem;
use image::{ImageFormat, ImageReader, Limits};
use std::io::Cursor;
use tracing::{debug, info};

pub struct ImageSanitizer;

/// Result of forward structural parsing on an image container.
#[derive(Debug, Clone)]
pub struct ImageStructuralScan {
    /// True end offset of the primary image bitstream (excluding any appended overlay).
    pub valid_end_offset: usize,
    /// Number of trailing overlay bytes after `valid_end_offset`.
    pub trailing_overlay_bytes: usize,
    /// True if EXIF, XMP, IPTC, or text metadata segments/chunks were present in the input.
    pub has_metadata: bool,
}

impl ImageSanitizer {
    fn build_limits(policy: &SanitizationPolicy) -> Limits {
        let mut limits = Limits::default();
        limits.max_image_width = Some(16_384);
        limits.max_image_height = Some(16_384);
        limits.max_alloc = Some(policy.max_decompressed_bytes);
        limits
    }

    /// Forward JPEG segment parser (`BUG-CDR-05`, `BUG-CORE-03`, `BUG-CORE-04`).
    ///
    /// Walks markers sequentially from SOI (`FF D8`), skipping length-delimited `APPn`/`COM`
    /// headers (which automatically skips any nested EXIF thumbnail EOI inside `APP1`) and
    /// scanning entropy-coded scan data after `SOS` (`FF DA`) until the first true main-image
    /// `EOI` (`FF D9`).
    pub fn scan_jpeg_structure(bytes: &[u8]) -> Result<ImageStructuralScan> {
        if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
            return Err(CdrError::ParserCorruption(
                "Missing JPEG SOI (FF D8) header".to_string(),
            ));
        }

        let mut cursor = 2usize;
        let mut has_metadata = false;
        let mut found_eoi_end = None;

        while cursor < bytes.len() {
            // Find next 0xFF marker prefix
            if bytes[cursor] != 0xFF {
                cursor += 1;
                continue;
            }
            while cursor < bytes.len() && bytes[cursor] == 0xFF {
                cursor += 1;
            }
            if cursor >= bytes.len() {
                break;
            }

            let marker = bytes[cursor];
            cursor += 1;

            match marker {
                // Byte-stuffed 0x00 or standalone markers (TEM 0x01, RST0..RST7 0xD0..0xD7, SOI 0xD8)
                0x00 | 0x01 | 0xD0..=0xD8 => continue,
                // EOI (End of Image)
                0xD9 => {
                    found_eoi_end = Some(cursor);
                    break;
                }
                // SOS (Start of Scan): length-prefixed header followed by entropy-coded data
                0xDA => {
                    if cursor + 2 > bytes.len() {
                        return Err(CdrError::ParserCorruption(
                            "Truncated JPEG SOS segment header".to_string(),
                        ));
                    }
                    let seg_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                    if seg_len < 2 || cursor + seg_len > bytes.len() {
                        return Err(CdrError::ParserCorruption(
                            "Invalid JPEG SOS segment length".to_string(),
                        ));
                    }
                    cursor += seg_len;

                    // Scan entropy-coded scan data until an unstuffed marker
                    while cursor < bytes.len() {
                        if bytes[cursor] != 0xFF {
                            cursor += 1;
                            continue;
                        }
                        let ff_pos = cursor;
                        while cursor < bytes.len() && bytes[cursor] == 0xFF {
                            cursor += 1;
                        }
                        if cursor >= bytes.len() {
                            break;
                        }
                        let esc = bytes[cursor];
                        if esc == 0x00 || (0xD0..=0xD7).contains(&esc) {
                            // Stuffed 0xFF 0x00 byte or restart marker inside entropy stream
                            cursor += 1;
                            continue;
                        } else {
                            // Rewind to the 0xFF of the next real marker so the outer loop handles it
                            cursor = ff_pos;
                            break;
                        }
                    }
                }
                // Variable-length segments
                _ => {
                    if cursor + 2 > bytes.len() {
                        return Err(CdrError::ParserCorruption(
                            "Truncated JPEG segment length".to_string(),
                        ));
                    }
                    let seg_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                    if seg_len < 2 || cursor + seg_len > bytes.len() {
                        return Err(CdrError::ParserCorruption(
                            "JPEG segment length exceeds file bounds".to_string(),
                        ));
                    }
                    // APP1..APP15 (0xE1..=0xEF) or COM (0xFE) carry EXIF/XMP/IPTC/Comment metadata
                    if (0xE1..=0xEF).contains(&marker) || marker == 0xFE {
                        has_metadata = true;
                    }
                    cursor += seg_len;
                }
            }
        }

        let valid_end_offset = found_eoi_end.unwrap_or(bytes.len());
        let trailing_overlay_bytes = bytes.len().saturating_sub(valid_end_offset);

        Ok(ImageStructuralScan {
            valid_end_offset,
            trailing_overlay_bytes,
            has_metadata,
        })
    }

    /// Forward PNG chunk parser (`BUG-CDR-05`, `BUG-CORE-03`, `BUG-CORE-04`).
    ///
    /// Walks `[length: u32 BE][type: 4B][data: length][crc: 4B]` from byte 8 until the first
    /// `IEND` chunk.
    pub fn scan_png_structure(bytes: &[u8]) -> Result<ImageStructuralScan> {
        const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        if bytes.len() < 8 || bytes[..8] != PNG_SIG {
            return Err(CdrError::ParserCorruption(
                "Invalid PNG 8-byte signature".to_string(),
            ));
        }

        let mut cursor = 8usize;
        let mut has_metadata = false;
        let mut found_iend_end = None;

        while cursor + 12 <= bytes.len() {
            let length = u32::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            let chunk_type = &bytes[cursor + 4..cursor + 8];
            let chunk_total = 12usize.checked_add(length).ok_or_else(|| {
                CdrError::ParserCorruption("PNG chunk length overflow".to_string())
            })?;

            if cursor + chunk_total > bytes.len() {
                return Err(CdrError::ParserCorruption(
                    "PNG chunk extends past EOF".to_string(),
                ));
            }

            if matches!(chunk_type, b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt" | b"tIME") {
                has_metadata = true;
            }

            cursor += chunk_total;

            if chunk_type == b"IEND" {
                found_iend_end = Some(cursor);
                break;
            }
        }

        let valid_end_offset = found_iend_end.ok_or_else(|| {
            CdrError::ParserCorruption("PNG missing IEND terminator chunk".to_string())
        })?;
        let trailing_overlay_bytes = bytes.len().saturating_sub(valid_end_offset);

        Ok(ImageStructuralScan {
            valid_end_offset,
            trailing_overlay_bytes,
            has_metadata,
        })
    }

    /// Forward WebP RIFF container parser (`BUG-CDR-05`).
    pub fn scan_webp_structure(bytes: &[u8]) -> Result<ImageStructuralScan> {
        if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
            return Err(CdrError::ParserCorruption(
                "Invalid RIFF/WEBP container header".to_string(),
            ));
        }
        let declared_riff_size =
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let expected_total = declared_riff_size.saturating_add(8);
        if expected_total < 12 {
            return Err(CdrError::ParserCorruption(
                "Malformed WebP RIFF size".to_string(),
            ));
        }
        let valid_end_offset = expected_total.min(bytes.len());
        let trailing_overlay_bytes = bytes.len().saturating_sub(valid_end_offset);

        // Inspect RIFF subchunks for EXIF or XMP metadata
        let mut has_metadata = false;
        let mut cursor = 12usize;
        while cursor + 8 <= valid_end_offset {
            let fourcc = &bytes[cursor..cursor + 4];
            let chunk_size = u32::from_le_bytes([
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]) as usize;
            if matches!(fourcc, b"EXIF" | b"XMP ") {
                has_metadata = true;
            }
            let padded = chunk_size.saturating_add(chunk_size & 1);
            cursor = cursor.saturating_add(8).saturating_add(padded);
        }

        Ok(ImageStructuralScan {
            valid_end_offset,
            trailing_overlay_bytes,
            has_metadata,
        })
    }

    /// Structural JPEG metadata stripper used when `policy.reencode_images == false`.
    fn strip_jpeg_segments_lossless(bytes: &[u8], strip_meta: bool) -> Vec<u8> {
        if !strip_meta || bytes.len() < 4 {
            return bytes.to_vec();
        }
        let mut out = Vec::with_capacity(bytes.len());
        out.extend_from_slice(&bytes[0..2]); // FF D8
        let mut cursor = 2usize;
        while cursor < bytes.len() {
            if bytes[cursor] != 0xFF {
                out.extend_from_slice(&bytes[cursor..]);
                break;
            }
            let seg_start = cursor;
            while cursor < bytes.len() && bytes[cursor] == 0xFF {
                cursor += 1;
            }
            if cursor >= bytes.len() {
                break;
            }
            let marker = bytes[cursor];
            cursor += 1;
            if matches!(marker, 0x00 | 0x01 | 0xD0..=0xD9) {
                out.extend_from_slice(&bytes[seg_start..cursor]);
                if marker == 0xD9 {
                    break;
                }
                continue;
            }
            if marker == 0xDA {
                // Copy SOS and remainder of image up to valid_end_offset
                out.extend_from_slice(&bytes[seg_start..]);
                break;
            }
            if cursor + 2 > bytes.len() {
                break;
            }
            let seg_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            if seg_len < 2 || cursor + seg_len > bytes.len() {
                break;
            }
            let seg_end = cursor + seg_len;
            if !((0xE1..=0xEF).contains(&marker) || marker == 0xFE) {
                out.extend_from_slice(&bytes[seg_start..seg_end]);
            }
            cursor = seg_end;
        }
        out
    }

    /// Structural PNG metadata chunk stripper used when `policy.reencode_images == false`.
    fn strip_png_chunks_lossless(bytes: &[u8], strip_meta: bool) -> Vec<u8> {
        if !strip_meta || bytes.len() < 8 {
            return bytes.to_vec();
        }
        let mut out = Vec::with_capacity(bytes.len());
        out.extend_from_slice(&bytes[0..8]);
        let mut cursor = 8usize;
        while cursor + 12 <= bytes.len() {
            let length = u32::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            let chunk_type = &bytes[cursor + 4..cursor + 8];
            let chunk_total = 12 + length;
            if cursor + chunk_total > bytes.len() {
                break;
            }
            if !matches!(chunk_type, b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt" | b"tIME") {
                out.extend_from_slice(&bytes[cursor..cursor + chunk_total]);
            }
            cursor += chunk_total;
            if chunk_type == b"IEND" {
                break;
            }
        }
        out
    }

    /// Structural WebP RIFF metadata subchunk stripper used when `policy.reencode_images == false` (`Rows 128, 131`, `BUG-CDR-05`).
    ///
    /// Removes `EXIF` and `XMP ` RIFF subchunks, clears `EXIF` (`0x08`) and `XMP` (`0x04`) feature flags
    /// in any `VP8X` extended header chunk, and updates the 4-byte RIFF container size at bytes `4..8`.
    pub fn strip_webp_chunks_lossless(bytes: &[u8], strip_meta: bool) -> Vec<u8> {
        if !strip_meta || bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
            return bytes.to_vec();
        }
        let mut out = Vec::with_capacity(bytes.len());
        out.extend_from_slice(&bytes[0..12]); // RIFF + size placeholder + WEBP
        let mut cursor = 12usize;
        while cursor + 8 <= bytes.len() {
            let fourcc = &bytes[cursor..cursor + 4];
            let chunk_size = u32::from_le_bytes([
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]) as usize;
            let padded = chunk_size.saturating_add(chunk_size & 1);
            let chunk_end = cursor.saturating_add(8).saturating_add(padded);
            if chunk_end > bytes.len() {
                break;
            }
            if !matches!(fourcc, b"EXIF" | b"XMP ") {
                let start_in_out = out.len();
                out.extend_from_slice(&bytes[cursor..chunk_end]);
                // Clear EXIF (bit 3 = 0x08) and XMP (bit 2 = 0x04) flags in VP8X header if present
                if fourcc == b"VP8X" && chunk_size >= 4 && out.len() > start_in_out + 8 {
                    out[start_in_out + 8] &= !(0x08 | 0x04);
                }
            }
            cursor = chunk_end;
        }
        let riff_payload_len = (out.len().saturating_sub(8)) as u32;
        out[4..8].copy_from_slice(&riff_payload_len.to_le_bytes());
        out
    }

    pub fn sanitize_jpeg(
        input: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        let mut budget = ResourceBudget::from_policy(policy);
        Self::sanitize_jpeg_with_budget(input, policy, &mut budget)
    }

    pub fn sanitize_jpeg_with_budget(
        input: &[u8],
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        debug!("Beginning JPEG sanitization (input: {} bytes)", input.len());
        budget.check_deadline()?;
        budget.charge_object()?;
        budget.charge_bytes(input.len() as u64)?;

        let mut reports = Vec::new();
        let scan = Self::scan_jpeg_structure(input)?;

        let clean_input = if policy.truncate_image_overlays && scan.trailing_overlay_bytes > 0 {
            reports.push(DisarmReportItem::new(
                "OVERLAY_PAYLOAD",
                format!("EOF_Offset_{}", scan.valid_end_offset),
                format!("TRUNCATED_{}_BYTES", scan.trailing_overlay_bytes),
            ));
            &input[..scan.valid_end_offset]
        } else {
            input
        };

        let output = if policy.reencode_images {
            let mut reader = ImageReader::with_format(Cursor::new(clean_input), ImageFormat::Jpeg);
            reader.limits(Self::build_limits(policy));
            let dynamic_image = reader.decode().map_err(|e| {
                CdrError::ParserCorruption(format!("Corrupt JPEG bitstream: {}", e))
            })?;

            let mut out = Vec::with_capacity(clean_input.len());
            dynamic_image
                .write_to(&mut Cursor::new(&mut out), ImageFormat::Jpeg)
                .map_err(|e| {
                    CdrError::ReconstructionFailure(format!("Failed to re-encode JPEG: {}", e))
                })?;
            out
        } else {
            Self::strip_jpeg_segments_lossless(clean_input, policy.strip_image_metadata)
        };

        if policy.strip_image_metadata && scan.has_metadata {
            reports.push(DisarmReportItem::new(
                "IMAGE_EXIF_METADATA",
                "JPEG_APPn_COM_MARKERS",
                "STRIPPED",
            ));
        }

        info!("JPEG CDR completed. Output size: {} bytes", output.len());
        Ok((output, reports))
    }

    pub fn sanitize_png(
        input: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        let mut budget = ResourceBudget::from_policy(policy);
        Self::sanitize_png_with_budget(input, policy, &mut budget)
    }

    pub fn sanitize_png_with_budget(
        input: &[u8],
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        debug!("Beginning PNG sanitization (input: {} bytes)", input.len());
        budget.check_deadline()?;
        budget.charge_object()?;
        budget.charge_bytes(input.len() as u64)?;

        let mut reports = Vec::new();
        let scan = Self::scan_png_structure(input)?;

        let clean_input = if policy.truncate_image_overlays && scan.trailing_overlay_bytes > 0 {
            reports.push(DisarmReportItem::new(
                "OVERLAY_PAYLOAD",
                format!("IEND_Offset_{}", scan.valid_end_offset),
                format!("TRUNCATED_{}_BYTES", scan.trailing_overlay_bytes),
            ));
            &input[..scan.valid_end_offset]
        } else {
            input
        };

        let output = if policy.reencode_images {
            let mut reader = ImageReader::with_format(Cursor::new(clean_input), ImageFormat::Png);
            reader.limits(Self::build_limits(policy));
            let dynamic_image = reader
                .decode()
                .map_err(|e| CdrError::ParserCorruption(format!("Corrupt PNG bitstream: {}", e)))?;

            let mut out = Vec::with_capacity(clean_input.len());
            dynamic_image
                .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
                .map_err(|e| {
                    CdrError::ReconstructionFailure(format!("Failed to re-encode PNG: {}", e))
                })?;
            out
        } else {
            Self::strip_png_chunks_lossless(clean_input, policy.strip_image_metadata)
        };

        if policy.strip_image_metadata && scan.has_metadata {
            reports.push(DisarmReportItem::new(
                "PNG_METADATA_CHUNKS",
                "eXIf_tEXt_zTXt_iTXt",
                "STRIPPED",
            ));
        }

        info!("PNG CDR completed. Output size: {} bytes", output.len());
        Ok((output, reports))
    }

    pub fn sanitize_webp(
        input: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        let mut budget = ResourceBudget::from_policy(policy);
        Self::sanitize_webp_with_budget(input, policy, &mut budget)
    }

    pub fn sanitize_webp_with_budget(
        input: &[u8],
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        debug!("Beginning WebP sanitization (input: {} bytes)", input.len());
        budget.check_deadline()?;
        budget.charge_object()?;
        budget.charge_bytes(input.len() as u64)?;

        let mut reports = Vec::new();
        let scan = Self::scan_webp_structure(input)?;

        let clean_input = if policy.truncate_image_overlays && scan.trailing_overlay_bytes > 0 {
            reports.push(DisarmReportItem::new(
                "OVERLAY_PAYLOAD",
                format!("RIFF_Offset_{}", scan.valid_end_offset),
                format!("TRUNCATED_{}_BYTES", scan.trailing_overlay_bytes),
            ));
            &input[..scan.valid_end_offset]
        } else {
            input
        };

        let output = if policy.reencode_images {
            let mut reader = ImageReader::with_format(Cursor::new(clean_input), ImageFormat::WebP);
            reader.limits(Self::build_limits(policy));
            let dynamic_image = reader.decode().map_err(|e| {
                CdrError::ParserCorruption(format!("Corrupt WebP bitstream: {}", e))
            })?;

            let mut out = Vec::with_capacity(clean_input.len());
            dynamic_image
                .write_to(&mut Cursor::new(&mut out), ImageFormat::WebP)
                .map_err(|e| {
                    CdrError::ReconstructionFailure(format!("Failed to re-encode WebP: {}", e))
                })?;
            out
        } else {
            Self::strip_webp_chunks_lossless(clean_input, policy.strip_image_metadata)
        };

        if policy.strip_image_metadata && scan.has_metadata {
            reports.push(DisarmReportItem::new(
                "WEBP_METADATA_CHUNKS",
                "EXIF_XMP_CHUNKS",
                "STRIPPED",
            ));
        }

        info!("WebP CDR completed. Output size: {} bytes", output.len());
        Ok((output, reports))
    }
}
