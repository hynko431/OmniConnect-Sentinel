use crate::error::{CdrError, Result};
use crate::policy::SanitizationPolicy;
use crate::sanitizers::image::ImageSanitizer;
use crate::sanitizers::openxml::OpenXmlSanitizer;
use crate::sanitizers::pdf::PdfSanitizer;
use crate::sanitizers::DisarmReportItem;
use sha2::{Digest, Sha256};
use std::time::Instant;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    Pdf,
    Docx,
    Xlsx,
    Pptx,
    Jpeg,
    Png,
    WebP,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SanitizationReport {
    pub original_sha256: [u8; 32],
    pub sanitized_sha256: [u8; 32],
    pub original_size_bytes: u64,
    pub sanitized_size_bytes: u64,
    pub format: DetectedFormat,
    pub stripped_elements: Vec<DisarmReportItem>,
    pub was_modified: bool,
    pub duration_micros: u64,
}

pub struct CdrEngine {
    policy: SanitizationPolicy,
}

impl CdrEngine {
    pub fn new(policy: SanitizationPolicy) -> Self {
        Self { policy }
    }

    pub fn detect_format(bytes: &[u8]) -> DetectedFormat {
        if bytes.starts_with(b"%PDF-") {
            return DetectedFormat::Pdf;
        }
        if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return DetectedFormat::Jpeg;
        }
        if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
            return DetectedFormat::Png;
        }
        if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
            return DetectedFormat::WebP;
        }
        if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            // Zip container - could be DOCX/XLSX/PPTX
            return DetectedFormat::Docx;
        }
        DetectedFormat::Unknown
    }

    pub fn sanitize(&self, input: &[u8]) -> Result<(Vec<u8>, SanitizationReport)> {
        let start = Instant::now();
        let format = Self::detect_format(input);

        let mut hasher = Sha256::new();
        hasher.update(input);
        let original_sha256: [u8; 32] = hasher.finalize().into();

        debug!("Dispatching CDR for format {:?}, input size: {} bytes", format, input.len());

        let (sanitized_bytes, stripped_items) = match format {
            DetectedFormat::Pdf => PdfSanitizer::sanitize(input, &self.policy)?,
            DetectedFormat::Docx | DetectedFormat::Xlsx | DetectedFormat::Pptx => {
                OpenXmlSanitizer::sanitize(input, &self.policy)?
            }
            DetectedFormat::Jpeg => ImageSanitizer::sanitize_jpeg(input, &self.policy)?,
            DetectedFormat::Png => ImageSanitizer::sanitize_png(input, &self.policy)?,
            DetectedFormat::WebP => ImageSanitizer::sanitize_webp(input, &self.policy)?,
            DetectedFormat::Unknown => {
                return Err(CdrError::UnsupportedFormat(
                    "File format not recognized by CDR parser".to_string(),
                ))
            }
        };

        let mut out_hasher = Sha256::new();
        out_hasher.update(&sanitized_bytes);
        let sanitized_sha256: [u8; 32] = out_hasher.finalize().into();

        let was_modified = original_sha256 != sanitized_sha256;
        let duration = start.elapsed();

        let report = SanitizationReport {
            original_sha256,
            sanitized_sha256,
            original_size_bytes: input.len() as u64,
            sanitized_size_bytes: sanitized_bytes.len() as u64,
            format,
            stripped_elements: stripped_items,
            was_modified,
            duration_micros: duration.as_micros() as u64,
        };

        info!(
            "Sanitization complete: {:?}, modified: {}, duration: {}µs",
            format, was_modified, report.duration_micros
        );

        Ok((sanitized_bytes, report))
    }
}
