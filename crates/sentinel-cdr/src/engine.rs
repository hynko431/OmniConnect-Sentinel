use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::time::Instant;
use tracing::{debug, info};
use zip::ZipArchive;

use crate::error::{CdrError, Result};
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::image::ImageSanitizer;
use crate::sanitizers::ole2::Ole2Sanitizer;
use crate::sanitizers::openxml::OpenXmlSanitizer;
use crate::sanitizers::pdf::PdfSanitizer;
use crate::sanitizers::svg::SvgSanitizer;
use crate::sanitizers::text::TextCsvSanitizer;
use crate::sanitizers::DisarmReportItem;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectedFormat {
    Pdf,
    Docx,
    Xlsx,
    Pptx,
    Jpeg,
    Png,
    WebP,
    Svg,
    Ole2,
    PlainText,
    Csv,
    ArchiveZip,
    Unknown,
}

impl DetectedFormat {
    pub fn as_mime_str(&self) -> &'static str {
        match self {
            Self::Pdf => "application/pdf",
            Self::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            Self::Xlsx => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            Self::Pptx => {
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            }
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::WebP => "image/webp",
            Self::Svg => "image/svg+xml",
            Self::Ole2 => "application/x-ole-storage",
            Self::PlainText => "text/plain",
            Self::Csv => "text/csv",
            Self::ArchiveZip => "application/zip",
            Self::Unknown => "application/octet-stream",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationOutcome {
    pub clean_bytes: Vec<u8>,
    pub original_sha256: String,
    pub sanitized_sha256: String,
    pub detected_format: DetectedFormat,
    pub disarm_report: Vec<DisarmReportItem>,
    pub processing_time_ms: u64,
}

/// Real forensic assessment returned by `CdrEngine::inspect_bytes` (`BUG-CDR-09`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionAssessment {
    pub is_malicious_polyglot: bool,
    pub detected_format: DetectedFormat,
    pub true_mime_type: String,
    pub entropy_score: f32,
    pub risk_tags: Vec<String>,
}

pub struct CdrEngine {
    policy: SanitizationPolicy,
}

impl CdrEngine {
    pub fn new(policy: SanitizationPolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &SanitizationPolicy {
        &self.policy
    }

    /// Detects the true structural format using magic bytes and container structure
    /// rather than trusting file extensions (`BUG-CDR-08`, Phase 2.6).
    pub fn detect_format(bytes: &[u8]) -> DetectedFormat {
        Self::detect_format_with_hint(bytes, "")
    }

    pub fn detect_format_with_hint(bytes: &[u8], file_name: &str) -> DetectedFormat {
        let lower_hint = file_name.to_ascii_lowercase();
        if bytes.len() < 4 {
            if std::str::from_utf8(bytes).is_ok() && !bytes.is_empty() {
                if lower_hint.ends_with(".csv") {
                    return DetectedFormat::Csv;
                }
                if lower_hint.ends_with(".txt") {
                    return DetectedFormat::PlainText;
                }
            }
            return DetectedFormat::Unknown;
        }

        // PDF: %PDF-
        if bytes.starts_with(b"%PDF-") {
            return DetectedFormat::Pdf;
        }

        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
            return DetectedFormat::Png;
        }

        // JPEG: FF D8 FF
        if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return DetectedFormat::Jpeg;
        }

        // WebP: RIFF....WEBP
        if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
            return DetectedFormat::WebP;
        }

        // OLE2 Compound File Binary: D0 CF 11 E0 A1 B1 1A E1
        if bytes.len() >= 8 && &bytes[0..8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
            return DetectedFormat::Ole2;
        }

        // ZIP / OpenXML Container: PK\x03\x04 (`BUG-CDR-08` Subtype Disambiguation)
        if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            if let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) {
                let mut has_word = false;
                let mut has_xl = false;
                let mut has_ppt = false;
                let mut has_content_types = false;

                for i in 0..archive.len().min(256) {
                    if let Ok(entry) = archive.by_index_raw(i) {
                        let name = entry.name().replace('\\', "/").to_ascii_lowercase();
                        if name == "[content_types].xml" {
                            has_content_types = true;
                        } else if name.starts_with("word/") {
                            has_word = true;
                        } else if name.starts_with("xl/") {
                            has_xl = true;
                        } else if name.starts_with("ppt/") {
                            has_ppt = true;
                        }
                    }
                }

                if has_word {
                    return DetectedFormat::Docx;
                }
                if has_xl {
                    return DetectedFormat::Xlsx;
                }
                if has_ppt {
                    return DetectedFormat::Pptx;
                }
                if has_content_types {
                    return DetectedFormat::Docx;
                }
                return DetectedFormat::ArchiveZip;
            }
            return DetectedFormat::Unknown;
        }

        // Check for SVG XML or strict `.txt` / `.csv` UTF-8 text (Plan v2 §2.6 9-format allowlist)
        let head_len = bytes.len().min(4096);
        if let Ok(head_str) = std::str::from_utf8(&bytes[..head_len]) {
            let trimmed = head_str.trim_start_matches('\u{feff}').trim_start();
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("<svg")
                || (lower.starts_with("<?xml") && lower.contains("<svg"))
                || (lower.starts_with("<!doctype svg") && lower.contains("<svg"))
            {
                return DetectedFormat::Svg;
            }

            if lower_hint.ends_with(".csv") {
                return DetectedFormat::Csv;
            }
            if lower_hint.ends_with(".txt") {
                return DetectedFormat::PlainText;
            }
        }

        DetectedFormat::Unknown
    }

    /// Primary CDR pipeline entry point returning `(Vec<u8>, SanitizationReport)`.
    pub fn sanitize(&self, input: &[u8]) -> Result<(Vec<u8>, SanitizationReport)> {
        self.sanitize_with_policy_report(input, &self.policy, "")
    }

    pub fn sanitize_with_policy_report(
        &self,
        input: &[u8],
        policy: &SanitizationPolicy,
        file_name: &str,
    ) -> Result<(Vec<u8>, SanitizationReport)> {
        let start = Instant::now();
        let outcome = self.sanitize_with_hint(input, file_name, policy)?;

        let mut orig_arr = [0u8; 32];
        if let Ok(decoded) = hex::decode(&outcome.original_sha256) {
            if decoded.len() == 32 {
                orig_arr.copy_from_slice(&decoded);
            }
        }

        let mut san_arr = [0u8; 32];
        if let Ok(decoded) = hex::decode(&outcome.sanitized_sha256) {
            if decoded.len() == 32 {
                san_arr.copy_from_slice(&decoded);
            }
        }

        let was_modified = orig_arr != san_arr || !outcome.disarm_report.is_empty();
        let report = SanitizationReport {
            original_sha256: orig_arr,
            sanitized_sha256: san_arr,
            original_size_bytes: input.len() as u64,
            sanitized_size_bytes: outcome.clean_bytes.len() as u64,
            format: outcome.detected_format,
            stripped_elements: outcome.disarm_report,
            was_modified,
            duration_micros: start.elapsed().as_micros() as u64,
        };

        Ok((outcome.clean_bytes, report))
    }

    /// Primary CDR pipeline entry point honoring a caller-provided per-request policy (`BUG-CDR-03`).
    pub fn sanitize_with_policy(
        &self,
        input_bytes: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<SanitizationOutcome> {
        self.sanitize_with_hint(input_bytes, "", policy)
    }

    pub fn sanitize_with_hint(
        &self,
        input_bytes: &[u8],
        file_name: &str,
        policy: &SanitizationPolicy,
    ) -> Result<SanitizationOutcome> {
        let start_time = Instant::now();

        if input_bytes.len() as u64 > policy.max_decompressed_bytes {
            return Err(CdrError::ResourceLimitExceeded(format!(
                "Input size ({} bytes) exceeds policy limit ({} bytes)",
                input_bytes.len(),
                policy.max_decompressed_bytes
            )));
        }

        let original_sha256 = Self::compute_sha256(input_bytes);
        let format = Self::detect_format_with_hint(input_bytes, file_name);

        Self::check_format_allowlist(format, policy)?;

        debug!(
            "CDR processing format {:?} (SHA256: {}, Size: {} bytes)",
            format,
            original_sha256,
            input_bytes.len()
        );

        let mut budget = ResourceBudget::from_policy(policy);
        let (clean_bytes, disarm_report) = match format {
            DetectedFormat::Pdf => {
                PdfSanitizer::sanitize_with_budget(input_bytes, policy, &mut budget)?
            }
            DetectedFormat::Docx | DetectedFormat::Xlsx | DetectedFormat::Pptx => {
                OpenXmlSanitizer::sanitize_with_budget(input_bytes, policy, &mut budget, false)?
            }
            DetectedFormat::ArchiveZip => {
                OpenXmlSanitizer::sanitize_with_budget(input_bytes, policy, &mut budget, true)?
            }
            DetectedFormat::Jpeg => {
                ImageSanitizer::sanitize_jpeg_with_budget(input_bytes, policy, &mut budget)?
            }
            DetectedFormat::Png => {
                ImageSanitizer::sanitize_png_with_budget(input_bytes, policy, &mut budget)?
            }
            DetectedFormat::WebP => {
                ImageSanitizer::sanitize_webp_with_budget(input_bytes, policy, &mut budget)?
            }
            DetectedFormat::Svg => {
                SvgSanitizer::sanitize_with_budget(input_bytes, policy, &mut budget)?
            }
            DetectedFormat::Ole2 => {
                Ole2Sanitizer::sanitize_with_budget(input_bytes, policy, &mut budget)?
            }
            DetectedFormat::PlainText => {
                TextCsvSanitizer::sanitize_with_budget(input_bytes, policy, &mut budget, false)?
            }
            DetectedFormat::Csv => {
                TextCsvSanitizer::sanitize_with_budget(input_bytes, policy, &mut budget, true)?
            }
            DetectedFormat::Unknown => {
                return Err(CdrError::UnsupportedFormat(
                    "File format not recognized by CDR parser".to_string(),
                ))
            }
        };

        // Phase 2.2: Post-CDR output verification (re-verify sanitized output across all formats)
        Self::verify_sanitized_output(&clean_bytes, format, policy)?;

        let sanitized_sha256 = Self::compute_sha256(&clean_bytes);
        let processing_time_ms = start_time.elapsed().as_millis() as u64;

        info!(
            "CDR complete for {:?}. Original: {} -> Clean: {} ({} ms, {} actions)",
            format,
            original_sha256,
            sanitized_sha256,
            processing_time_ms,
            disarm_report.len()
        );

        Ok(SanitizationOutcome {
            clean_bytes,
            original_sha256,
            sanitized_sha256,
            detected_format: format,
            disarm_report,
            processing_time_ms,
        })
    }

    /// Enforces the Plan v2 §2.6 default-deny allowlist (`High #11`, `Rows 132-136`):
    /// Only the 9 rebuildable formats (`PDF`, `DOCX`, `XLSX`, `PPTX`, `JPEG`, `PNG`, `WebP`, `TXT`, `CSV`)
    /// are permitted by default; `Svg`, `Ole2`, and `ArchiveZip` require explicit opt-in flags.
    fn check_format_allowlist(format: DetectedFormat, policy: &SanitizationPolicy) -> Result<()> {
        match format {
            DetectedFormat::Unknown => Err(CdrError::UnsupportedFormat(
                "File format not recognized by CDR parser".to_string(),
            )),
            DetectedFormat::Svg if !policy.allow_svg => Err(CdrError::UnsupportedFormat(
                "SVG format is blocked by default-deny CDR allowlist (allow_svg = false)"
                    .to_string(),
            )),
            DetectedFormat::Ole2 if !policy.allow_legacy_ole2 => Err(CdrError::UnsupportedFormat(
                "Legacy OLE2 format is blocked by default-deny CDR allowlist (allow_legacy_ole2 = false)".to_string(),
            )),
            DetectedFormat::ArchiveZip if !policy.allow_generic_zip => {
                Err(CdrError::UnsupportedFormat(
                    "Generic ZIP container is blocked by default-deny CDR allowlist (allow_generic_zip = false)".to_string(),
                ))
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn sanitize_nested_with_budget(
        input_bytes: &[u8],
        file_name: &str,
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        let format = Self::detect_format_with_hint(input_bytes, file_name);
        Self::check_format_allowlist(format, policy)?;
        let (clean_bytes, reports) = match format {
            DetectedFormat::Pdf => PdfSanitizer::sanitize_with_budget(input_bytes, policy, budget)?,
            DetectedFormat::Docx | DetectedFormat::Xlsx | DetectedFormat::Pptx => {
                OpenXmlSanitizer::sanitize_with_budget(input_bytes, policy, budget, false)?
            }
            DetectedFormat::ArchiveZip => {
                OpenXmlSanitizer::sanitize_with_budget(input_bytes, policy, budget, true)?
            }
            DetectedFormat::Jpeg => {
                ImageSanitizer::sanitize_jpeg_with_budget(input_bytes, policy, budget)?
            }
            DetectedFormat::Png => {
                ImageSanitizer::sanitize_png_with_budget(input_bytes, policy, budget)?
            }
            DetectedFormat::WebP => {
                ImageSanitizer::sanitize_webp_with_budget(input_bytes, policy, budget)?
            }
            DetectedFormat::Svg => SvgSanitizer::sanitize_with_budget(input_bytes, policy, budget)?,
            DetectedFormat::Ole2 => {
                Ole2Sanitizer::sanitize_with_budget(input_bytes, policy, budget)?
            }
            DetectedFormat::PlainText => {
                TextCsvSanitizer::sanitize_with_budget(input_bytes, policy, budget, false)?
            }
            DetectedFormat::Csv => {
                TextCsvSanitizer::sanitize_with_budget(input_bytes, policy, budget, true)?
            }
            DetectedFormat::Unknown => {
                return Err(CdrError::UnsupportedFormat(
                    "Unrecognized nested format".to_string(),
                ))
            }
        };
        Self::verify_sanitized_output(&clean_bytes, format, policy)?;
        Ok((clean_bytes, reports))
    }

    /// Re-scans the sanitized output to guarantee no active content survived (`Phase 2.2`, `Row 110`).
    /// Any residual finding returns `CdrError::OutputRejected` (`CDR_OUTPUT_REJECTED`).
    pub fn verify_sanitized_output(
        clean_bytes: &[u8],
        format: DetectedFormat,
        policy: &SanitizationPolicy,
    ) -> Result<()> {
        match format {
            DetectedFormat::Pdf => {
                let doc = lopdf::Document::load_mem(clean_bytes).map_err(|e| {
                    CdrError::OutputRejected(format!(
                        "CDR_OUTPUT_REJECTED: Sanitized PDF failed AST re-parse: {}",
                        e
                    ))
                })?;
                for (_, obj) in &doc.objects {
                    Self::verify_pdf_object_clean(obj, policy)?;
                }
            }
            DetectedFormat::Docx
            | DetectedFormat::Xlsx
            | DetectedFormat::Pptx
            | DetectedFormat::ArchiveZip => {
                let is_generic_zip = format == DetectedFormat::ArchiveZip;
                let mut archive = ZipArchive::new(Cursor::new(clean_bytes)).map_err(|e| {
                    CdrError::OutputRejected(format!(
                        "CDR_OUTPUT_REJECTED: Sanitized OOXML/ZIP is not a valid ZIP: {}",
                        e
                    ))
                })?;
                for i in 0..archive.len() {
                    let mut entry = archive.by_index(i).map_err(|e| {
                        CdrError::OutputRejected(format!(
                            "CDR_OUTPUT_REJECTED: Invalid ZIP entry {}: {}",
                            i, e
                        ))
                    })?;
                    let lower = entry.name().replace('\\', "/").to_ascii_lowercase();
                    if !is_generic_zip && policy.strip_office_macros {
                        if lower.ends_with("vbaproject.bin")
                            || lower.ends_with("vbaprojectsignature.bin")
                            || lower.ends_with("xlmacrosheet.xml")
                            || lower.contains("/macrosheets/")
                        {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual macro artifact '{}' in sanitized OOXML",
                                lower
                            )));
                        }
                    }
                    if !is_generic_zip && policy.strip_office_ole_objects {
                        if lower.contains("/embeddings/")
                            || lower.starts_with("embeddings/")
                            || lower.contains("/activex/")
                            || lower.starts_with("activex/")
                        {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual OLE/ActiveX object '{}' in sanitized OOXML",
                                lower
                            )));
                        }
                    }
                    if !is_generic_zip
                        && policy.sanitize_office_external_relationships
                        && lower.ends_with(".rels")
                    {
                        let mut rels_bytes = Vec::new();
                        std::io::Read::read_to_end(&mut entry, &mut rels_bytes).map_err(|e| {
                            CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Failed reading .rels entry {}: {}",
                                lower, e
                            ))
                        })?;
                        Self::verify_rels_clean(&rels_bytes, policy)?;
                    } else if !is_generic_zip && policy.strip_office_dde && lower.ends_with(".xml")
                    {
                        let mut xml_bytes = Vec::new();
                        std::io::Read::read_to_end(&mut entry, &mut xml_bytes).map_err(|e| {
                            CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Failed reading .xml entry {}: {}",
                                lower, e
                            ))
                        })?;
                        let xml_str = std::str::from_utf8(&xml_bytes).map_err(|e| {
                            CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Invalid UTF-8 in .xml entry {}: {}",
                                lower, e
                            ))
                        })?;
                        let xml_lower = xml_str.to_ascii_lowercase();
                        if xml_lower.contains("<ddelink")
                            || xml_lower.contains("<ddeitem")
                            || xml_lower.contains("ddeauto")
                            || xml_lower.contains("<!entity")
                        {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual DDE/ENTITY marker in OOXML entry {}",
                                lower
                            )));
                        }
                    }
                }
            }
            DetectedFormat::Svg => {
                let s = std::str::from_utf8(clean_bytes).map_err(|e| {
                    CdrError::OutputRejected(format!(
                        "CDR_OUTPUT_REJECTED: Invalid UTF-8 in sanitized SVG: {}",
                        e
                    ))
                })?;
                let lower = s.to_ascii_lowercase();
                if lower.contains("<!doctype")
                    || lower.contains("<!entity")
                    || lower.contains("<script")
                    || lower.contains("<foreignobject")
                {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual DOCTYPE/ENTITY/<script>/<foreignObject> in sanitized SVG"
                            .to_string(),
                    ));
                }
                let mut reader = quick_xml::Reader::from_str(s);
                let mut buf = Vec::new();
                let mut element_depth: usize = 0;
                loop {
                    match reader.read_event_into(&mut buf) {
                        Ok(quick_xml::events::Event::Eof) => break,
                        Ok(quick_xml::events::Event::DocType(_)) => {
                            return Err(CdrError::OutputRejected(
                                "CDR_OUTPUT_REJECTED: Residual DOCTYPE in sanitized SVG"
                                    .to_string(),
                            ));
                        }
                        Ok(quick_xml::events::Event::GeneralRef(ref entity)) => {
                            if !crate::sanitizers::is_allowed_xml_general_ref(
                                entity.as_ref().as_bytes(),
                            ) {
                                return Err(CdrError::OutputRejected(format!(
                                    "CDR_OUTPUT_REJECTED: Residual non-predefined XML entity '&{};' in sanitized SVG",
                                    entity.as_ref()
                                )));
                            }
                        }
                        Ok(quick_xml::events::Event::Start(ref e)) => {
                            element_depth = element_depth.saturating_add(1);
                            if element_depth > crate::sanitizers::MAX_XML_ELEMENT_DEPTH {
                                return Err(CdrError::OutputRejected(format!(
                                    "CDR_OUTPUT_REJECTED: Sanitized SVG exceeds MAX_XML_ELEMENT_DEPTH ({})",
                                    crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                                )));
                            }
                            let tag_lower = e.local_name().as_ref().to_ascii_lowercase();
                            if SvgSanitizer::is_forbidden_tag(&tag_lower) {
                                return Err(CdrError::OutputRejected(format!(
                                    "CDR_OUTPUT_REJECTED: Residual <{}> in sanitized SVG",
                                    tag_lower
                                )));
                            }
                            let validated_attrs =
                                crate::sanitizers::collect_validated_xml_attributes(e).map_err(
                                    |err| {
                                        CdrError::OutputRejected(format!(
                                            "CDR_OUTPUT_REJECTED: Malformed SVG attribute: {}",
                                            err
                                        ))
                                    },
                                )?;
                            for attr in validated_attrs {
                                let k = attr.key.as_ref().to_ascii_lowercase();
                                let v = attr.value.trim().to_ascii_lowercase();
                                if k.starts_with("on") {
                                    return Err(CdrError::OutputRejected(format!(
                                        "CDR_OUTPUT_REJECTED: Residual event handler '{}' in sanitized SVG",
                                        k
                                    )));
                                }
                                if (k == "href" || k.ends_with(":href")) && !v.starts_with('#') {
                                    return Err(CdrError::OutputRejected(format!(
                                        "CDR_OUTPUT_REJECTED: Residual non-anchor href '{}' in sanitized SVG",
                                        v
                                    )));
                                }
                                if k == "style" && SvgSanitizer::has_dangerous_css(&v) {
                                    return Err(CdrError::OutputRejected(
                                        "CDR_OUTPUT_REJECTED: Residual dangerous style attribute in sanitized SVG"
                                            .to_string(),
                                    ));
                                }
                            }
                        }
                        Ok(quick_xml::events::Event::Empty(ref e)) => {
                            if element_depth.saturating_add(1)
                                > crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                            {
                                return Err(CdrError::OutputRejected(format!(
                                    "CDR_OUTPUT_REJECTED: Sanitized SVG exceeds MAX_XML_ELEMENT_DEPTH ({})",
                                    crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                                )));
                            }
                            let tag_lower = e.local_name().as_ref().to_ascii_lowercase();
                            if SvgSanitizer::is_forbidden_tag(&tag_lower) {
                                return Err(CdrError::OutputRejected(format!(
                                    "CDR_OUTPUT_REJECTED: Residual <{}> in sanitized SVG",
                                    tag_lower
                                )));
                            }
                            let validated_attrs =
                                crate::sanitizers::collect_validated_xml_attributes(e).map_err(
                                    |err| {
                                        CdrError::OutputRejected(format!(
                                            "CDR_OUTPUT_REJECTED: Malformed SVG attribute: {}",
                                            err
                                        ))
                                    },
                                )?;
                            for attr in validated_attrs {
                                let k = attr.key.as_ref().to_ascii_lowercase();
                                let v = attr.value.trim().to_ascii_lowercase();
                                if k.starts_with("on") {
                                    return Err(CdrError::OutputRejected(format!(
                                        "CDR_OUTPUT_REJECTED: Residual event handler '{}' in sanitized SVG",
                                        k
                                    )));
                                }
                                if (k == "href" || k.ends_with(":href")) && !v.starts_with('#') {
                                    return Err(CdrError::OutputRejected(format!(
                                        "CDR_OUTPUT_REJECTED: Residual non-anchor href '{}' in sanitized SVG",
                                        v
                                    )));
                                }
                                if k == "style" && SvgSanitizer::has_dangerous_css(&v) {
                                    return Err(CdrError::OutputRejected(
                                        "CDR_OUTPUT_REJECTED: Residual dangerous style attribute in sanitized SVG"
                                            .to_string(),
                                    ));
                                }
                            }
                        }
                        Ok(quick_xml::events::Event::End(_)) => {
                            element_depth = element_depth.saturating_sub(1);
                        }
                        Ok(_) => {}
                        Err(e) => {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Malformed sanitized SVG XML: {}",
                                e
                            )));
                        }
                    }
                    buf.clear();
                }
            }
            DetectedFormat::Jpeg => {
                let scan = ImageSanitizer::scan_jpeg_structure(clean_bytes).map_err(|e| {
                    CdrError::OutputRejected(format!(
                        "CDR_OUTPUT_REJECTED: Invalid sanitized JPEG structure: {}",
                        e
                    ))
                })?;
                if policy.truncate_image_overlays && scan.trailing_overlay_bytes > 0 {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual trailing overlay in sanitized JPEG"
                            .to_string(),
                    ));
                }
                if policy.strip_image_metadata && scan.has_metadata {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual EXIF/XMP metadata in sanitized JPEG"
                            .to_string(),
                    ));
                }
            }
            DetectedFormat::Png => {
                let scan = ImageSanitizer::scan_png_structure(clean_bytes).map_err(|e| {
                    CdrError::OutputRejected(format!(
                        "CDR_OUTPUT_REJECTED: Invalid sanitized PNG structure: {}",
                        e
                    ))
                })?;
                if policy.truncate_image_overlays && scan.trailing_overlay_bytes > 0 {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual trailing overlay in sanitized PNG"
                            .to_string(),
                    ));
                }
                if policy.strip_image_metadata && scan.has_metadata {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual metadata chunks in sanitized PNG"
                            .to_string(),
                    ));
                }
            }
            DetectedFormat::WebP => {
                let scan = ImageSanitizer::scan_webp_structure(clean_bytes).map_err(|e| {
                    CdrError::OutputRejected(format!(
                        "CDR_OUTPUT_REJECTED: Invalid sanitized WebP structure: {}",
                        e
                    ))
                })?;
                if policy.truncate_image_overlays && scan.trailing_overlay_bytes > 0 {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual trailing overlay in sanitized WebP"
                            .to_string(),
                    ));
                }
                if policy.strip_image_metadata && scan.has_metadata {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual EXIF/XMP metadata in sanitized WebP"
                            .to_string(),
                    ));
                }
            }
            DetectedFormat::Ole2 => {
                if Ole2Sanitizer::has_residual_active_streams(clean_bytes, policy) {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual VBA macro or OLE package directory entry in sanitized CFB"
                            .to_string(),
                    ));
                }
            }
            DetectedFormat::PlainText | DetectedFormat::Csv => {
                let text = std::str::from_utf8(clean_bytes).map_err(|e| {
                    CdrError::OutputRejected(format!(
                        "CDR_OUTPUT_REJECTED: Sanitized Text/CSV is not valid UTF-8: {}",
                        e
                    ))
                })?;
                if text.chars().any(TextCsvSanitizer::is_bidi_override_char) {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual BiDi override character in sanitized Text/CSV"
                            .to_string(),
                    ));
                }
                if format == DetectedFormat::Csv && policy.strip_office_dde {
                    for line in text.lines() {
                        for cell in line.split(',') {
                            if TextCsvSanitizer::is_dangerous_csv_cell(cell) {
                                return Err(CdrError::OutputRejected(
                                    "CDR_OUTPUT_REJECTED: Residual unneutralized formula cell in sanitized CSV"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            DetectedFormat::Unknown => {
                return Err(CdrError::OutputRejected(
                    "CDR_OUTPUT_REJECTED: Unknown format".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn verify_pdf_object_clean(obj: &lopdf::Object, policy: &SanitizationPolicy) -> Result<()> {
        match obj {
            lopdf::Object::Dictionary(dict) => {
                Self::verify_pdf_dict_clean(dict, policy)?;
            }
            lopdf::Object::Stream(stream) => {
                Self::verify_pdf_dict_clean(&stream.dict, policy)?;
            }
            lopdf::Object::Array(arr) => {
                for item in arr {
                    Self::verify_pdf_object_clean(item, policy)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn verify_pdf_dict_clean(dict: &lopdf::Dictionary, policy: &SanitizationPolicy) -> Result<()> {
        if policy.strip_pdf_scripts && (dict.has(b"JS") || dict.has(b"JavaScript")) {
            return Err(CdrError::OutputRejected(
                "CDR_OUTPUT_REJECTED: Residual /JS or /JavaScript in sanitized PDF".to_string(),
            ));
        }
        if policy.strip_pdf_actions
            && (dict.has(b"OpenAction")
                || dict.has(b"AA")
                || dict.has(b"Launch")
                || dict.has(b"RichMedia"))
        {
            return Err(CdrError::OutputRejected(
                "CDR_OUTPUT_REJECTED: Residual /OpenAction, /AA, /Launch, or /RichMedia in sanitized PDF"
                    .to_string(),
            ));
        }
        if policy.strip_pdf_attachments && dict.has(b"EmbeddedFiles") {
            return Err(CdrError::OutputRejected(
                "CDR_OUTPUT_REJECTED: Residual /EmbeddedFiles in sanitized PDF".to_string(),
            ));
        }
        if let Ok(s_name) = dict.get(b"S").and_then(|o| o.as_name()) {
            if policy.strip_pdf_scripts && (s_name == b"JavaScript" || s_name == b"JS") {
                return Err(CdrError::OutputRejected(
                    "CDR_OUTPUT_REJECTED: Residual /S /JavaScript action in sanitized PDF"
                        .to_string(),
                ));
            }
            if policy.strip_pdf_actions && PdfSanitizer::is_dangerous_action_subtype(s_name) {
                return Err(CdrError::OutputRejected(format!(
                    "CDR_OUTPUT_REJECTED: Residual dangerous /S /{} action in sanitized PDF",
                    String::from_utf8_lossy(s_name)
                )));
            }
        }
        for (_, child) in dict.iter() {
            Self::verify_pdf_object_clean(child, policy)?;
        }
        Ok(())
    }

    fn verify_rels_clean(rels_bytes: &[u8], policy: &SanitizationPolicy) -> Result<()> {
        let mut reader = quick_xml::Reader::from_reader(rels_bytes);
        let mut buf = Vec::new();
        let mut element_depth: usize = 0;
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(quick_xml::events::Event::DocType(_)) => {
                    return Err(CdrError::OutputRejected(
                        "CDR_OUTPUT_REJECTED: Residual DOCTYPE in sanitized .rels XML".to_string(),
                    ));
                }
                Ok(quick_xml::events::Event::GeneralRef(ref entity)) => {
                    if !crate::sanitizers::is_allowed_xml_general_ref(entity.as_ref().as_bytes()) {
                        return Err(CdrError::OutputRejected(format!(
                            "CDR_OUTPUT_REJECTED: Residual non-predefined XML entity '&{};' in sanitized .rels XML",
                            entity.as_ref()
                        )));
                    }
                }
                Ok(quick_xml::events::Event::Start(ref e)) => {
                    element_depth = element_depth.saturating_add(1);
                    if element_depth > crate::sanitizers::MAX_XML_ELEMENT_DEPTH {
                        return Err(CdrError::OutputRejected(format!(
                            "CDR_OUTPUT_REJECTED: Sanitized .rels XML exceeds MAX_XML_ELEMENT_DEPTH ({})",
                            crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                        )));
                    }
                    let validated_attrs = crate::sanitizers::collect_validated_xml_attributes(e)
                        .map_err(|err| {
                            CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Malformed .rels XML attribute: {}",
                                err
                            ))
                        })?;
                    let local = e.name().local_name().into_inner().to_ascii_lowercase();
                    if local == "relationship" {
                        let mut target = String::new();
                        let mut target_mode = String::new();
                        let mut rel_type = String::new();
                        for attr in validated_attrs {
                            let k = attr.key.local_name().into_inner().to_ascii_lowercase();
                            let v = attr.value.into_owned();
                            if k == "target" {
                                target = v;
                            } else if k == "targetmode" {
                                target_mode = v;
                            } else if k == "type" {
                                rel_type = v;
                            }
                        }
                        let is_external = target_mode.trim().eq_ignore_ascii_case("external");
                        let target_lower = target.trim().to_ascii_lowercase();
                        let has_dangerous_scheme = target_lower.starts_with("ms-msdt:")
                            || target_lower.starts_with("javascript:")
                            || target_lower.starts_with("vbscript:")
                            || target_lower.starts_with("mhtml:")
                            || target_lower.starts_with("file:")
                            || target_lower.starts_with("data:")
                            || target_lower.starts_with("\\\\");
                        let is_benign_hyperlink =
                            rel_type.to_ascii_lowercase().ends_with("/hyperlink")
                                && !has_dangerous_scheme
                                && !policy.strip_external_hyperlinks;
                        if has_dangerous_scheme || (is_external && !is_benign_hyperlink) {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual external/unsafe relationship targeting '{}'",
                                target
                            )));
                        }
                    }
                }
                Ok(quick_xml::events::Event::Empty(ref e)) => {
                    if element_depth.saturating_add(1) > crate::sanitizers::MAX_XML_ELEMENT_DEPTH {
                        return Err(CdrError::OutputRejected(format!(
                            "CDR_OUTPUT_REJECTED: Sanitized .rels XML exceeds MAX_XML_ELEMENT_DEPTH ({})",
                            crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                        )));
                    }
                    let validated_attrs = crate::sanitizers::collect_validated_xml_attributes(e)
                        .map_err(|err| {
                            CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Malformed .rels XML attribute: {}",
                                err
                            ))
                        })?;
                    let local = e.name().local_name().into_inner().to_ascii_lowercase();
                    if local == "relationship" {
                        let mut target = String::new();
                        let mut target_mode = String::new();
                        let mut rel_type = String::new();
                        for attr in validated_attrs {
                            let k = attr.key.local_name().into_inner().to_ascii_lowercase();
                            let v = attr.value.into_owned();
                            if k == "target" {
                                target = v;
                            } else if k == "targetmode" {
                                target_mode = v;
                            } else if k == "type" {
                                rel_type = v;
                            }
                        }
                        let is_external = target_mode.trim().eq_ignore_ascii_case("external");
                        let target_lower = target.trim().to_ascii_lowercase();
                        let has_dangerous_scheme = target_lower.starts_with("ms-msdt:")
                            || target_lower.starts_with("javascript:")
                            || target_lower.starts_with("vbscript:")
                            || target_lower.starts_with("mhtml:")
                            || target_lower.starts_with("file:")
                            || target_lower.starts_with("data:")
                            || target_lower.starts_with("\\\\");
                        let is_benign_hyperlink =
                            rel_type.to_ascii_lowercase().ends_with("/hyperlink")
                                && !has_dangerous_scheme
                                && !policy.strip_external_hyperlinks;
                        if has_dangerous_scheme || (is_external && !is_benign_hyperlink) {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual external/unsafe relationship targeting '{}'",
                                target
                            )));
                        }
                    }
                }
                Ok(quick_xml::events::Event::End(_)) => {
                    element_depth = element_depth.saturating_sub(1);
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(CdrError::OutputRejected(format!(
                        "CDR_OUTPUT_REJECTED: Malformed .rels XML in output: {}",
                        e
                    )));
                }
            }
            buf.clear();
        }
        Ok(())
    }

    fn inspect_pdf_object_risks(obj: &lopdf::Object, risk_tags: &mut Vec<String>) {
        match obj {
            lopdf::Object::Dictionary(dict) => {
                if dict.has(b"JS") || dict.has(b"JavaScript") {
                    risk_tags.push("PDF_EMBEDDED_JAVASCRIPT".to_string());
                }
                if dict.has(b"OpenAction") || dict.has(b"AA") {
                    risk_tags.push("PDF_AUTO_TRIGGER_ACTION".to_string());
                }
                if dict.has(b"Launch") {
                    risk_tags.push("PDF_LAUNCH_ACTION".to_string());
                }
                if let Ok(s_name) = dict.get(b"S").and_then(|o| o.as_name()) {
                    if s_name.eq_ignore_ascii_case(b"Launch") {
                        risk_tags.push("PDF_LAUNCH_ACTION".to_string());
                    } else if s_name.eq_ignore_ascii_case(b"JavaScript")
                        || s_name.eq_ignore_ascii_case(b"JS")
                    {
                        risk_tags.push("PDF_EMBEDDED_JAVASCRIPT".to_string());
                    } else if PdfSanitizer::is_dangerous_action_subtype(s_name) {
                        risk_tags.push(format!(
                            "PDF_ACTION_{}",
                            String::from_utf8_lossy(s_name).to_ascii_uppercase()
                        ));
                    }
                }
                for (_, child) in dict.iter() {
                    Self::inspect_pdf_object_risks(child, risk_tags);
                }
            }
            lopdf::Object::Stream(stream) => {
                for (_, child) in stream.dict.iter() {
                    Self::inspect_pdf_object_risks(child, risk_tags);
                }
            }
            lopdf::Object::Array(arr) => {
                for item in arr {
                    Self::inspect_pdf_object_risks(item, risk_tags);
                }
            }
            _ => {}
        }
    }

    /// Performs deep structural inspection on raw bytes (`BUG-CDR-09`).
    pub fn inspect_bytes(bytes: &[u8], file_name: &str) -> InspectionAssessment {
        let detected_format = Self::detect_format_with_hint(bytes, file_name);
        let true_mime_type = detected_format.as_mime_str().to_string();
        let entropy_score = Self::shannon_entropy(bytes);
        let mut risk_tags = Vec::new();
        let mut is_malicious_polyglot = false;

        let lower_name = file_name.to_ascii_lowercase();
        if !lower_name.is_empty() {
            if (lower_name.ends_with(".pdf") && detected_format != DetectedFormat::Pdf)
                || ((lower_name.ends_with(".jpg") || lower_name.ends_with(".jpeg"))
                    && detected_format != DetectedFormat::Jpeg)
                || (lower_name.ends_with(".png") && detected_format != DetectedFormat::Png)
            {
                risk_tags.push(format!(
                    "EXTENSION_MISMATCH: File '{}' has true format {:?}",
                    file_name, detected_format
                ));
            }
        }

        // Check for polyglot / dual-signature markers (using structural bounds for images)
        match detected_format {
            DetectedFormat::Jpeg => {
                if let Ok(scan) = ImageSanitizer::scan_jpeg_structure(bytes) {
                    if scan.trailing_overlay_bytes > 0 {
                        is_malicious_polyglot = true;
                        risk_tags.push(format!(
                            "JPEG_TRAILING_OVERLAY_{}_BYTES",
                            scan.trailing_overlay_bytes
                        ));
                    }
                }
            }
            DetectedFormat::Png => {
                if let Ok(scan) = ImageSanitizer::scan_png_structure(bytes) {
                    if scan.trailing_overlay_bytes > 0 {
                        is_malicious_polyglot = true;
                        risk_tags.push(format!(
                            "PNG_TRAILING_OVERLAY_{}_BYTES",
                            scan.trailing_overlay_bytes
                        ));
                    }
                }
            }
            DetectedFormat::WebP => {
                if let Ok(scan) = ImageSanitizer::scan_webp_structure(bytes) {
                    if scan.trailing_overlay_bytes > 0 {
                        is_malicious_polyglot = true;
                        risk_tags.push(format!(
                            "WEBP_TRAILING_OVERLAY_{}_BYTES",
                            scan.trailing_overlay_bytes
                        ));
                    }
                }
            }
            DetectedFormat::Pdf => {
                if bytes.windows(4).skip(4).any(|w| w == b"PK\x03\x04") {
                    is_malicious_polyglot = true;
                    risk_tags.push("POLYGLOT_ZIP_ARCHIVE_APPENDED".to_string());
                }
                if let Ok(doc) = lopdf::Document::load_mem(bytes) {
                    for (_, obj) in &doc.objects {
                        Self::inspect_pdf_object_risks(obj, &mut risk_tags);
                    }
                }
            }
            DetectedFormat::Docx | DetectedFormat::Xlsx | DetectedFormat::Pptx => {
                if let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) {
                    for i in 0..archive.len() {
                        if let Ok(file) = archive.by_index_raw(i) {
                            let lower = file.name().to_ascii_lowercase();
                            if lower.ends_with("vbaproject.bin") {
                                risk_tags.push("OOXML_VBA_MACRO_PROJECT".to_string());
                            } else if lower.contains("embeddings/") || lower.contains("activex/") {
                                risk_tags.push("OOXML_EMBEDDED_OLE_OBJECT".to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        risk_tags.dedup();

        InspectionAssessment {
            is_malicious_polyglot,
            detected_format,
            true_mime_type,
            entropy_score,
            risk_tags,
        }
    }

    pub fn shannon_entropy(bytes: &[u8]) -> f32 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let len = bytes.len() as f64;
        let mut entropy = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = (c as f64) / len;
                entropy -= p * p.log2();
            }
        }
        entropy as f32
    }

    fn compute_sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }
}
