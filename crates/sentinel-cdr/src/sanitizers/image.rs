use crate::error::{CdrError, Result};
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::DisarmReportItem;
use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, ImageFormat, ImageReader, Limits};
use std::io::Cursor;
use tracing::{debug, info};

/// Maximum IFD0 entries inspected while extracting EXIF Orientation (`0x0112`) (`CSE-21`).
const MAX_EXIF_IFD_ENTRIES: usize = 1024;
/// Maximum reassembled ICC profile size accepted for validation (`CSE-21`).
const MAX_ICC_PROFILE_BYTES: usize = 65_536;
/// Maximum JPEG `APP2` `ICC_PROFILE\0` sequence chunks accepted (`CSE-21`).
const MAX_ICC_CHUNKS: usize = 16;

pub struct ImageSanitizer;

/// Result of forward structural parsing on an image container.
#[derive(Debug, Clone)]
pub struct ImageStructuralScan {
    /// True end offset of the primary image bitstream (excluding any appended overlay).
    pub valid_end_offset: usize,
    /// Number of trailing overlay bytes after `valid_end_offset`.
    pub trailing_overlay_bytes: usize,
    /// True if EXIF, XMP, IPTC, ICC, or text metadata segments/chunks were present in the input.
    pub has_metadata: bool,
}

/// Pre-sanitization JPEG color-space, ICC, and EXIF orientation inspection result (`CSE-21`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JpegColorAndMetadataInfo {
    /// Parsed EXIF Orientation tag (`0x0112`), strictly within `1..=8`.
    pub exif_orientation: Option<u16>,
    /// True when an Adobe `APP14` (`0xFFEE` `"Adobe"`) segment is present.
    pub has_adobe_app14: bool,
    /// Adobe `APP14` color transform byte (`0` = Unknown/RGB/CMYK, `1` = YCbCr, `2` = YCCK).
    pub adobe_color_transform: Option<u8>,
    /// Number of color components declared in the JPEG `SOFn` frame header (`1`, `3`, or `4`).
    pub sof_components: Option<u8>,
    /// True when one or more `APP2` `"ICC_PROFILE\0"` segments were present.
    pub has_icc_profile: bool,
    /// True only when the reassembled ICC profile passed strict sRGB structural validation.
    pub icc_profile_valid_srgb: bool,
}

impl JpegColorAndMetadataInfo {
    /// True when the JPEG encodes 4-component CMYK or Adobe YCCK pixels.
    pub fn is_cmyk_or_ycck(&self) -> bool {
        self.sof_components == Some(4)
            || (self.has_adobe_app14 && self.adobe_color_transform == Some(2))
    }

    /// True when stripping `APP14` without canonical RGB re-encoding would invert or corrupt colors.
    pub fn requires_color_space_reencode(&self) -> bool {
        self.is_cmyk_or_ycck()
            || (self.has_adobe_app14
                && self.sof_components == Some(3)
                && self.adobe_color_transform == Some(0))
    }
}

fn read_u16_endian(bytes: &[u8], offset: usize, big_endian: bool) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    let arr = [slice[0], slice[1]];
    Some(if big_endian {
        u16::from_be_bytes(arr)
    } else {
        u16::from_le_bytes(arr)
    })
}

fn read_u32_endian(bytes: &[u8], offset: usize, big_endian: bool) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    let arr = [slice[0], slice[1], slice[2], slice[3]];
    Some(if big_endian {
        u32::from_be_bytes(arr)
    } else {
        u32::from_le_bytes(arr)
    })
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

            if matches!(
                chunk_type,
                b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt" | b"tIME" | b"iCCP"
            ) {
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
            if matches!(fourcc, b"EXIF" | b"XMP " | b"ICCP") {
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
            if !matches!(
                chunk_type,
                b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt" | b"tIME" | b"iCCP"
            ) {
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
            if !matches!(fourcc, b"EXIF" | b"XMP " | b"ICCP") {
                let start_in_out = out.len();
                out.extend_from_slice(&bytes[cursor..chunk_end]);
                // Clear ICCP (bit 5 = 0x20), EXIF (bit 3 = 0x08), and XMP (bit 2 = 0x04) flags in VP8X header if present
                if fourcc == b"VP8X" && chunk_size >= 4 && out.len() > start_in_out + 8 {
                    out[start_in_out + 8] &= !(0x20 | 0x08 | 0x04);
                }
            }
            cursor = chunk_end;
        }
        let riff_payload_len = (out.len().saturating_sub(8)) as u32;
        out[4..8].copy_from_slice(&riff_payload_len.to_le_bytes());
        out
    }

    /// Pure-Rust bounds-checked TIFF IFD0 parser for the EXIF Orientation tag (`0x0112`, values `1..=8`) (`CSE-21`).
    ///
    /// Supports both little-endian (`II`) and big-endian (`MM`) TIFF headers, enforcing strict
    /// checked arithmetic and `MAX_EXIF_IFD_ENTRIES` so malformed/truncated EXIF never panics.
    pub fn parse_tiff_exif_orientation(tiff: &[u8]) -> Option<u16> {
        if tiff.len() < 8 {
            return None;
        }
        let big_endian = match &tiff[0..2] {
            b"II" => false,
            b"MM" => true,
            _ => return None,
        };
        if read_u16_endian(tiff, 2, big_endian)? != 42 {
            return None;
        }
        let ifd0_offset = read_u32_endian(tiff, 4, big_endian)? as usize;
        if ifd0_offset < 8 || ifd0_offset.checked_add(2)? > tiff.len() {
            return None;
        }
        let entry_count =
            (read_u16_endian(tiff, ifd0_offset, big_endian)? as usize).min(MAX_EXIF_IFD_ENTRIES);
        let entries_start = ifd0_offset.checked_add(2)?;

        for idx in 0..entry_count {
            let entry_off = entries_start.checked_add(idx.checked_mul(12)?)?;
            if entry_off.checked_add(12)? > tiff.len() {
                break;
            }
            let tag = read_u16_endian(tiff, entry_off, big_endian)?;
            if tag != 0x0112 {
                continue;
            }
            let field_type = read_u16_endian(tiff, entry_off + 2, big_endian)?;
            let count = read_u32_endian(tiff, entry_off + 4, big_endian)?;
            if count != 1 {
                return None;
            }
            // Per TIFF 6.0 §2, values shorter than 4 bytes (SHORT = type 3) are left-justified
            // in the first 2 bytes of the 4-byte value/offset field regardless of endianness.
            let val = match field_type {
                3 => read_u16_endian(tiff, entry_off + 8, big_endian)?,
                4 => u16::try_from(read_u32_endian(tiff, entry_off + 8, big_endian)?).ok()?,
                _ => return None,
            };
            return (1..=8).contains(&val).then_some(val);
        }
        None
    }

    /// Parses an EXIF payload that either begins with `"Exif\0\0"` (JPEG `APP1`) or directly
    /// with a raw TIFF header (`II`/`MM`, PNG `eXIf`, WebP `EXIF`) (`CSE-21`).
    pub fn parse_exif_payload_orientation(payload: &[u8]) -> Option<u16> {
        let tiff = payload.strip_prefix(b"Exif\0\0").unwrap_or(payload);
        Self::parse_tiff_exif_orientation(tiff)
    }

    /// Applies the exact lossless pixel rotation/flip corresponding to EXIF Orientation `1..=8` (`CSE-21`).
    pub fn apply_exif_orientation(img: DynamicImage, orientation: u16) -> DynamicImage {
        match orientation {
            2 => img.fliph(),
            3 => img.rotate180(),
            4 => img.flipv(),
            5 => img.rotate90().fliph(),
            6 => img.rotate90(),
            7 => img.rotate270().fliph(),
            8 => img.rotate270(),
            _ => img,
        }
    }

    /// Verifies that an ICC `XYZType` tag (`rXYZ`, `gXYZ`, `bXYZ`) is a well-formed 20-byte
    /// `b"XYZ "` tag whose D50-adapted `s15Fixed16Number` primaries match standard sRGB within `±0.015`.
    fn matches_srgb_xyz_tag(tag_bytes: &[u8], expected: (f64, f64, f64)) -> bool {
        if tag_bytes.len() < 20 || &tag_bytes[0..4] != b"XYZ " || tag_bytes[4..8] != [0, 0, 0, 0] {
            return false;
        }
        let decode_s15_16 = |off: usize| -> f64 {
            i32::from_be_bytes([
                tag_bytes[off],
                tag_bytes[off + 1],
                tag_bytes[off + 2],
                tag_bytes[off + 3],
            ]) as f64
                / 65_536.0
        };
        let x = decode_s15_16(8);
        let y = decode_s15_16(12);
        let z = decode_s15_16(16);
        (x - expected.0).abs() <= 0.015
            && (y - expected.1).abs() <= 0.015
            && (z - expected.2).abs() <= 0.015
    }

    /// Strictly validates an ICC v2/v4 profile as a well-formed, bounded sRGB RGB/XYZ display profile (`CSE-21`).
    ///
    /// Rejects oversized profiles (`> 65_536` bytes), declared-length mismatches, non-`acsp` headers,
    /// non-`RGB `/`XYZ ` color spaces, non-display classes, malformed tag tables, non-sRGB wide-gamut
    /// descriptions/primaries (e.g., Display P3, Adobe RGB 1998, ProPhoto RGB), and requires verified
    /// 20-byte D50 sRGB `rXYZ`, `gXYZ`, and `bXYZ` chromaticity tags.
    pub fn is_valid_srgb_icc_profile(icc: &[u8]) -> bool {
        if icc.len() < 132 || icc.len() > MAX_ICC_PROFILE_BYTES {
            return false;
        }
        let declared_len = u32::from_be_bytes([icc[0], icc[1], icc[2], icc[3]]) as usize;
        if declared_len != icc.len() {
            return false;
        }
        let major_version = icc[8];
        if !matches!(major_version, 2 | 4) {
            return false;
        }
        if !matches!(&icc[12..16], b"mntr" | b"spac") {
            return false;
        }
        if &icc[16..20] != b"RGB " || &icc[20..24] != b"XYZ " {
            return false;
        }
        if &icc[36..40] != b"acsp" {
            return false;
        }

        let tag_count = u32::from_be_bytes([icc[128], icc[129], icc[130], icc[131]]) as usize;
        if tag_count == 0 || tag_count > 64 {
            return false;
        }
        let table_end = match 132usize.checked_add(tag_count.saturating_mul(12)) {
            Some(end) if end <= icc.len() => end,
            _ => return false,
        };

        // Standard ICC D50-adapted sRGB primaries (IEC 61966-2-1 / ICC sRGB v2 & v4)
        const SRGB_D50_R: (f64, f64, f64) = (0.4361, 0.2225, 0.0139);
        const SRGB_D50_G: (f64, f64, f64) = (0.3851, 0.7169, 0.0971);
        const SRGB_D50_B: (f64, f64, f64) = (0.1431, 0.0606, 0.7141);

        let mut valid_rxyz = false;
        let mut valid_gxyz = false;
        let mut valid_bxyz = false;
        let mut desc_mentions_non_srgb = false;

        for idx in 0..tag_count {
            let off = 132 + idx * 12;
            let sig = &icc[off..off + 4];
            let tag_offset =
                u32::from_be_bytes([icc[off + 4], icc[off + 5], icc[off + 6], icc[off + 7]])
                    as usize;
            let tag_size =
                u32::from_be_bytes([icc[off + 8], icc[off + 9], icc[off + 10], icc[off + 11]])
                    as usize;
            let tag_end = match tag_offset.checked_add(tag_size) {
                Some(end) if tag_offset >= table_end && end <= icc.len() && tag_size >= 4 => end,
                _ => return false,
            };
            let tag_bytes = &icc[tag_offset..tag_end];
            match sig {
                b"rXYZ" => {
                    if !Self::matches_srgb_xyz_tag(tag_bytes, SRGB_D50_R) {
                        return false;
                    }
                    valid_rxyz = true;
                }
                b"gXYZ" => {
                    if !Self::matches_srgb_xyz_tag(tag_bytes, SRGB_D50_G) {
                        return false;
                    }
                    valid_gxyz = true;
                }
                b"bXYZ" => {
                    if !Self::matches_srgb_xyz_tag(tag_bytes, SRGB_D50_B) {
                        return false;
                    }
                    valid_bxyz = true;
                }
                b"desc" => {
                    let ascii_lower: String = tag_bytes
                        .iter()
                        .filter(|b| {
                            b.is_ascii_alphanumeric() || **b == b' ' || **b == b'-' || **b == b'.'
                        })
                        .map(|b| (*b as char).to_ascii_lowercase())
                        .collect();
                    if ascii_lower.contains("display p3")
                        || ascii_lower.contains("dci-p3")
                        || ascii_lower.contains("adobe rgb")
                        || ascii_lower.contains("prophoto")
                        || ascii_lower.contains("rec2020")
                        || ascii_lower.contains("rec.2020")
                        || ascii_lower.contains("cmyk")
                    {
                        desc_mentions_non_srgb = true;
                    }
                }
                _ => {}
            }
        }

        valid_rxyz && valid_gxyz && valid_bxyz && !desc_mentions_non_srgb
    }

    /// Inspects JPEG header segments before `SOS` to extract EXIF Orientation (`APP1`),
    /// Adobe color transform (`APP14`), frame component count (`SOFn`), and `APP2` ICC profile metadata (`CSE-21`).
    pub fn extract_jpeg_color_and_exif(bytes: &[u8]) -> JpegColorAndMetadataInfo {
        let mut info = JpegColorAndMetadataInfo::default();
        if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
            return info;
        }

        let mut icc_chunks: Vec<(u8, &[u8])> = Vec::new();
        let mut icc_total_expected: Option<u8> = None;
        let mut icc_total_bytes = 0usize;
        let mut icc_malformed = false;

        let mut cursor = 2usize;
        while cursor < bytes.len() {
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
                0x00 | 0x01 | 0xD0..=0xD8 => continue,
                // Stop at Start of Scan (`SOS`) or End of Image (`EOI`)
                0xDA | 0xD9 => break,
                _ => {
                    if cursor + 2 > bytes.len() {
                        break;
                    }
                    let seg_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                    if seg_len < 2 || cursor + seg_len > bytes.len() {
                        break;
                    }
                    let payload = &bytes[cursor + 2..cursor + seg_len];
                    match marker {
                        // APP1: EXIF
                        0xE1 => {
                            if info.exif_orientation.is_none() && payload.starts_with(b"Exif\0\0") {
                                info.exif_orientation =
                                    Self::parse_tiff_exif_orientation(&payload[6..]);
                            }
                        }
                        // APP2: ICC_PROFILE\0 sequence
                        0xE2 => {
                            if let Some(rest) = payload.strip_prefix(b"ICC_PROFILE\0") {
                                info.has_icc_profile = true;
                                if rest.len() < 2 {
                                    icc_malformed = true;
                                } else {
                                    let seq = rest[0];
                                    let total = rest[1];
                                    let chunk = &rest[2..];
                                    if seq == 0
                                        || total == 0
                                        || seq > total
                                        || (total as usize) > MAX_ICC_CHUNKS
                                        || icc_total_expected.is_some_and(|exp| exp != total)
                                        || icc_chunks.iter().any(|(s, _)| *s == seq)
                                        || icc_total_bytes.saturating_add(chunk.len())
                                            > MAX_ICC_PROFILE_BYTES
                                    {
                                        icc_malformed = true;
                                    } else {
                                        icc_total_expected = Some(total);
                                        icc_total_bytes += chunk.len();
                                        icc_chunks.push((seq, chunk));
                                    }
                                }
                            }
                        }
                        // APP14: Adobe color space transform
                        0xEE => {
                            if payload.len() >= 12 && &payload[0..5] == b"Adobe" {
                                info.has_adobe_app14 = true;
                                info.adobe_color_transform = Some(payload[11]);
                            }
                        }
                        // SOFn frame headers declare number of image components at payload offset 5
                        0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF
                            if info.sof_components.is_none() && payload.len() >= 6 =>
                        {
                            info.sof_components = Some(payload[5]);
                        }
                        _ => {}
                    }
                    cursor += seg_len;
                }
            }
        }

        if info.has_icc_profile && !icc_malformed {
            if let Some(expected) = icc_total_expected {
                if icc_chunks.len() == expected as usize {
                    icc_chunks.sort_by_key(|(seq, _)| *seq);
                    let mut assembled = Vec::with_capacity(icc_total_bytes);
                    for (_, chunk) in icc_chunks {
                        assembled.extend_from_slice(chunk);
                    }
                    info.icc_profile_valid_srgb = Self::is_valid_srgb_icc_profile(&assembled);
                }
            }
        }

        info
    }

    /// Extracts EXIF orientation (`eXIf`) and ICC presence (`iCCP`) from a PNG chunk stream (`CSE-21`).
    fn extract_png_exif_and_icc(bytes: &[u8]) -> (Option<u16>, bool) {
        const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        if bytes.len() < 8 || bytes[..8] != PNG_SIG {
            return (None, false);
        }
        let mut orientation = None;
        let mut has_iccp = false;
        let mut cursor = 8usize;
        while cursor + 12 <= bytes.len() {
            let length = u32::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            let chunk_type = &bytes[cursor + 4..cursor + 8];
            let Some(chunk_total) = 12usize.checked_add(length) else {
                break;
            };
            let Some(chunk_end) = cursor.checked_add(chunk_total) else {
                break;
            };
            if chunk_end > bytes.len() {
                break;
            }
            let data = &bytes[cursor + 8..cursor + 8 + length];
            if chunk_type == b"eXIf" && orientation.is_none() {
                orientation = Self::parse_exif_payload_orientation(data);
            } else if chunk_type == b"iCCP" {
                has_iccp = true;
            }
            cursor = chunk_end;
            if chunk_type == b"IEND" {
                break;
            }
        }
        (orientation, has_iccp)
    }

    /// Extracts EXIF orientation (`EXIF`) and ICC profile validation (`ICCP`) from a WebP RIFF stream (`CSE-21`).
    fn extract_webp_exif_and_icc(bytes: &[u8]) -> (Option<u16>, bool, bool) {
        if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
            return (None, false, false);
        }
        let mut orientation = None;
        let mut has_iccp = false;
        let mut iccp_valid_srgb = false;
        let mut cursor = 12usize;
        while cursor + 8 <= bytes.len() {
            let fourcc = &bytes[cursor..cursor + 4];
            let chunk_size = u32::from_le_bytes([
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]) as usize;
            let data_end = cursor.saturating_add(8).saturating_add(chunk_size);
            if data_end > bytes.len() {
                break;
            }
            let data = &bytes[cursor + 8..data_end];
            if fourcc == b"EXIF" && orientation.is_none() {
                orientation = Self::parse_exif_payload_orientation(data);
            } else if fourcc == b"ICCP" {
                has_iccp = true;
                iccp_valid_srgb = Self::is_valid_srgb_icc_profile(data);
            }
            let padded = chunk_size.saturating_add(chunk_size & 1);
            cursor = cursor.saturating_add(8).saturating_add(padded);
        }
        (orientation, has_iccp, iccp_valid_srgb)
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

        let color_info = Self::extract_jpeg_color_and_exif(clean_input);
        let needs_orientation_bake = color_info
            .exif_orientation
            .is_some_and(|orientation| (2..=8).contains(&orientation));
        let must_reencode = policy.reencode_images
            || color_info.requires_color_space_reencode()
            || (policy.strip_image_metadata && needs_orientation_bake);

        let output = if must_reencode {
            let mut reader = ImageReader::with_format(Cursor::new(clean_input), ImageFormat::Jpeg);
            reader.limits(Self::build_limits(policy));
            let dynamic_image = reader
                .decode()
                .map_err(|e| CdrError::ParserCorruption(format!("Corrupt JPEG bitstream: {e}")))?;

            // Canonicalize to Rgb8 (or preserve Luma8 grayscale) so CMYK/YCCK/Adobe RGB inputs
            // always encode cleanly into standard non-inverted JFIF RGB without relying on APP14.
            let canonical_image = match dynamic_image {
                DynamicImage::ImageLuma8(gray) => DynamicImage::ImageLuma8(gray),
                other => DynamicImage::ImageRgb8(other.to_rgb8()),
            };

            // Bake EXIF Orientation (0x0112) into pixel coordinates prior to stripping EXIF metadata.
            let oriented_image = if let Some(orientation) = color_info.exif_orientation {
                if (2..=8).contains(&orientation) {
                    reports.push(DisarmReportItem::new(
                        "IMAGE_EXIF_ORIENTATION_BAKED",
                        format!("EXIF_ORIENTATION_{orientation}"),
                        "ROTATED_AND_BAKED_TO_NORMAL",
                    ));
                    Self::apply_exif_orientation(canonical_image, orientation)
                } else {
                    canonical_image
                }
            } else {
                canonical_image
            };

            let quality = policy.jpeg_reencode_quality.clamp(1, 100);
            let mut out = Vec::with_capacity(clean_input.len());
            let mut encoder = JpegEncoder::new_with_quality(&mut out, quality);
            encoder.encode_image(&oriented_image).map_err(|e| {
                CdrError::ReconstructionFailure(format!("Failed to re-encode JPEG: {e}"))
            })?;

            if color_info.is_cmyk_or_ycck() {
                reports.push(DisarmReportItem::new(
                    "JPEG_CMYK_TO_RGB_CONVERTED",
                    "APP14_ADOBE_CMYK",
                    "CONVERTED_TO_CANONICAL_RGB",
                ));
            } else if color_info.requires_color_space_reencode() {
                reports.push(DisarmReportItem::new(
                    "JPEG_ADOBE_RGB_NORMALIZED",
                    "APP14_ADOBE_RGB",
                    "CONVERTED_TO_CANONICAL_RGB",
                ));
            }

            out
        } else {
            Self::strip_jpeg_segments_lossless(clean_input, policy.strip_image_metadata)
        };

        if color_info.has_icc_profile && (must_reencode || policy.strip_image_metadata) {
            let action = if color_info.icc_profile_valid_srgb {
                "VALIDATED_SRGB_ICC_STRIPPED_TO_CANONICAL_SRGB"
            } else {
                "NON_SRGB_OR_MALFORMED_ICC_STRIPPED"
            };
            reports.push(DisarmReportItem::new(
                "IMAGE_ICC_PROFILE_STRIPPED",
                "JPEG_APP2_ICC_PROFILE",
                action,
            ));
        }

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

        let (exif_orientation, has_iccp) = Self::extract_png_exif_and_icc(clean_input);
        let needs_orientation_bake =
            exif_orientation.is_some_and(|orientation| (2..=8).contains(&orientation));
        let must_reencode =
            policy.reencode_images || (policy.strip_image_metadata && needs_orientation_bake);

        let output = if must_reencode {
            let mut reader = ImageReader::with_format(Cursor::new(clean_input), ImageFormat::Png);
            reader.limits(Self::build_limits(policy));
            let dynamic_image = reader
                .decode()
                .map_err(|e| CdrError::ParserCorruption(format!("Corrupt PNG bitstream: {e}")))?;

            let oriented_image = if let Some(orientation) = exif_orientation {
                if (2..=8).contains(&orientation) {
                    reports.push(DisarmReportItem::new(
                        "IMAGE_EXIF_ORIENTATION_BAKED",
                        format!("EXIF_ORIENTATION_{orientation}"),
                        "ROTATED_AND_BAKED_TO_NORMAL",
                    ));
                    Self::apply_exif_orientation(dynamic_image, orientation)
                } else {
                    dynamic_image
                }
            } else {
                dynamic_image
            };

            let mut out = Vec::with_capacity(clean_input.len());
            oriented_image
                .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
                .map_err(|e| {
                    CdrError::ReconstructionFailure(format!("Failed to re-encode PNG: {e}"))
                })?;
            out
        } else {
            Self::strip_png_chunks_lossless(clean_input, policy.strip_image_metadata)
        };

        if has_iccp && (must_reencode || policy.strip_image_metadata) {
            reports.push(DisarmReportItem::new(
                "IMAGE_ICC_PROFILE_STRIPPED",
                "PNG_ICCP_CHUNK",
                "PNG_ICCP_STRIPPED_TO_CANONICAL_SRGB",
            ));
        }

        if policy.strip_image_metadata && scan.has_metadata {
            reports.push(DisarmReportItem::new(
                "PNG_METADATA_CHUNKS",
                "eXIf_tEXt_zTXt_iTXt_iCCP",
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

        let (exif_orientation, has_iccp, iccp_valid_srgb) =
            Self::extract_webp_exif_and_icc(clean_input);
        let needs_orientation_bake =
            exif_orientation.is_some_and(|orientation| (2..=8).contains(&orientation));
        let must_reencode =
            policy.reencode_images || (policy.strip_image_metadata && needs_orientation_bake);

        let output = if must_reencode {
            let mut reader = ImageReader::with_format(Cursor::new(clean_input), ImageFormat::WebP);
            reader.limits(Self::build_limits(policy));
            let dynamic_image = reader
                .decode()
                .map_err(|e| CdrError::ParserCorruption(format!("Corrupt WebP bitstream: {e}")))?;

            let oriented_image = if let Some(orientation) = exif_orientation {
                if (2..=8).contains(&orientation) {
                    reports.push(DisarmReportItem::new(
                        "IMAGE_EXIF_ORIENTATION_BAKED",
                        format!("EXIF_ORIENTATION_{orientation}"),
                        "ROTATED_AND_BAKED_TO_NORMAL",
                    ));
                    Self::apply_exif_orientation(dynamic_image, orientation)
                } else {
                    dynamic_image
                }
            } else {
                dynamic_image
            };

            let mut out = Vec::with_capacity(clean_input.len());
            oriented_image
                .write_to(&mut Cursor::new(&mut out), ImageFormat::WebP)
                .map_err(|e| {
                    CdrError::ReconstructionFailure(format!("Failed to re-encode WebP: {e}"))
                })?;
            out
        } else {
            Self::strip_webp_chunks_lossless(clean_input, policy.strip_image_metadata)
        };

        if has_iccp && (must_reencode || policy.strip_image_metadata) {
            let action = if iccp_valid_srgb {
                "VALIDATED_SRGB_ICC_STRIPPED_TO_CANONICAL_SRGB"
            } else {
                "NON_SRGB_OR_MALFORMED_ICC_STRIPPED"
            };
            reports.push(DisarmReportItem::new(
                "IMAGE_ICC_PROFILE_STRIPPED",
                "WEBP_ICCP_CHUNK",
                action,
            ));
        }

        if policy.strip_image_metadata && scan.has_metadata {
            reports.push(DisarmReportItem::new(
                "WEBP_METADATA_CHUNKS",
                "EXIF_XMP_ICCP_CHUNKS",
                "STRIPPED",
            ));
        }

        info!("WebP CDR completed. Output size: {} bytes", output.len());
        Ok((output, reports))
    }
}
