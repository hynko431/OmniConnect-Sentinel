use crate::error::{CdrError, Result};
use crate::policy::SanitizationPolicy;
use crate::sanitizers::DisarmReportItem;
use image::{ImageFormat, ImageReader};
use std::io::Cursor;
use tracing::{debug, info};

pub struct ImageSanitizer;

impl ImageSanitizer {
    pub fn sanitize_jpeg(input: &[u8], policy: &SanitizationPolicy) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        debug!("Beginning JPEG sanitization (input: {} bytes)", input.len());
        let mut reports = Vec::new();

        // 1. Truncate trailing overlay bytes (bytes past FF D9 EOI marker)
        let clean_input = if policy.truncate_image_overlays {
            Self::truncate_jpeg_overlay(input, &mut reports)?
        } else {
            input
        };

        // 2. Decode pixels and re-encode to canonical standard (strips EXIF & embedded markers)
        let reader = ImageReader::with_format(Cursor::new(clean_input), ImageFormat::Jpeg);
        let dynamic_image = reader.decode()
            .map_err(|e| CdrError::ParserCorruption(format!("Corrupt JPEG bitstream: {}", e)))?;

        let mut output = Vec::with_capacity(clean_input.len());
        dynamic_image.write_to(&mut Cursor::new(&mut output), image::ImageFormat::Jpeg)
            .map_err(|e| CdrError::ReconstructionFailure(format!("Failed to re-encode JPEG: {}", e)))?;

        if policy.strip_image_metadata {
            reports.push(DisarmReportItem::new("IMAGE_EXIF_METADATA", "JPEG_APP1_MARKER", "STRIPPED"));
        }

        info!("JPEG CDR completed. Output size: {} bytes", output.len());
        Ok((output, reports))
    }

    pub fn sanitize_png(input: &[u8], policy: &SanitizationPolicy) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        debug!("Beginning PNG sanitization (input: {} bytes)", input.len());
        let mut reports = Vec::new();

        // 1. Truncate trailing overlay bytes past IEND chunk
        let clean_input = if policy.truncate_image_overlays {
            Self::truncate_png_overlay(input, &mut reports)?
        } else {
            input
        };

        // 2. Decode and re-encode
        let reader = ImageReader::with_format(Cursor::new(clean_input), ImageFormat::Png);
        let dynamic_image = reader.decode()
            .map_err(|e| CdrError::ParserCorruption(format!("Corrupt PNG bitstream: {}", e)))?;

        let mut output = Vec::with_capacity(clean_input.len());
        dynamic_image.write_to(&mut Cursor::new(&mut output), image::ImageFormat::Png)
            .map_err(|e| CdrError::ReconstructionFailure(format!("Failed to re-encode PNG: {}", e)))?;

        if policy.strip_image_metadata {
            reports.push(DisarmReportItem::new("PNG_METADATA_CHUNKS", "tEXt_zTXt_iTXt", "STRIPPED"));
        }

        info!("PNG CDR completed. Output size: {} bytes", output.len());
        Ok((output, reports))
    }

    pub fn sanitize_webp(input: &[u8], policy: &SanitizationPolicy) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        debug!("Beginning WebP sanitization (input: {} bytes)", input.len());
        let mut reports = Vec::new();

        let reader = ImageReader::with_format(Cursor::new(input), ImageFormat::WebP);
        let dynamic_image = reader.decode()
            .map_err(|e| CdrError::ParserCorruption(format!("Corrupt WebP bitstream: {}", e)))?;

        let mut output = Vec::with_capacity(input.len());
        dynamic_image.write_to(&mut Cursor::new(&mut output), image::ImageFormat::WebP)
            .map_err(|e| CdrError::ReconstructionFailure(format!("Failed to re-encode WebP: {}", e)))?;

        if policy.strip_image_metadata {
            reports.push(DisarmReportItem::new("WEBP_METADATA_CHUNKS", "EXIF_XMP_CHUNKS", "STRIPPED"));
        }

        info!("WebP CDR completed. Output size: {} bytes", output.len());
        Ok((output, reports))
    }

    fn truncate_jpeg_overlay<'a>(bytes: &'a [u8], reports: &mut Vec<DisarmReportItem>) -> Result<&'a [u8]> {
        if let Some(eoi_pos) = bytes.windows(2).rposition(|w| w == [0xFF, 0xD9]) {
            let valid_len = eoi_pos + 2;
            if valid_len < bytes.len() {
                let overlay_len = bytes.len() - valid_len;
                reports.push(DisarmReportItem::new(
                    "OVERLAY_PAYLOAD",
                    format!("EOF_Offset_{}", valid_len),
                    format!("TRUNCATED_{}_BYTES", overlay_len),
                ));
                return Ok(&bytes[..valid_len]);
            }
        }
        Ok(bytes)
    }

    fn truncate_png_overlay<'a>(bytes: &'a [u8], reports: &mut Vec<DisarmReportItem>) -> Result<&'a [u8]> {
        // Look for IEND chunk marker: 49 45 4E 44 followed by 4 bytes CRC
        if let Some(iend_pos) = bytes.windows(4).rposition(|w| w == b"IEND") {
            let valid_len = iend_pos + 4 + 4; // IEND marker + 4 CRC bytes
            if valid_len < bytes.len() {
                let overlay_len = bytes.len() - valid_len;
                reports.push(DisarmReportItem::new(
                    "OVERLAY_PAYLOAD",
                    format!("IEND_Offset_{}", valid_len),
                    format!("TRUNCATED_{}_BYTES", overlay_len),
                ));
                return Ok(&bytes[..valid_len]);
            }
        }
        Ok(bytes)
    }
}
