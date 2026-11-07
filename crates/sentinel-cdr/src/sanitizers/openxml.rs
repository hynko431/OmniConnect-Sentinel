use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::{Reader, Writer};
use std::collections::HashSet;
use std::io::{Cursor, Read, Write};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::error::CdrError;
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::DisarmReportItem;

pub const MAX_ZIP_ENTRIES: usize = 4_096;

/// OOXML & ZIP Container Sanitizer (`BUG-CDR-04`, `BUG-CDR-08`, `EV-04`, Phase 2.3)
///
/// Rebuilds `.docx`, `.xlsx`, `.pptx`, and general `.zip` archives from verified
/// entries while enforcing actual decompressed byte budgets and structural XML
/// rewriting via `quick-xml`.
pub struct OpenXmlSanitizer;

impl OpenXmlSanitizer {
    pub const MAX_OOXML_ENTRIES: usize = MAX_ZIP_ENTRIES;
    /// Validates a ZIP central-directory entry against path traversal (`RUSTSEC-2026-0367`),
    /// symbolic link attacks (`RUSTSEC-2026-0368`), and SUID/SGID/sticky mode bits (`RUSTSEC-2026-0369`).
    /// Returns `(normalized_entry_name, had_suid_sgid_sticky_bits)` on success.
    pub fn validate_zip_entry_security(
        raw_name: &str,
        is_symlink: bool,
        unix_mode: Option<u32>,
    ) -> Result<(String, bool), CdrError> {
        if raw_name.is_empty()
            || raw_name.len() > 1024
            || raw_name.contains('\0')
            || raw_name.contains(':')
        {
            return Err(CdrError::InvalidFormat(
                "ZIP path traversal or invalid entry name rejected (RUSTSEC-2026-0367)".to_string(),
            ));
        }

        let normalized = raw_name.replace('\\', "/");
        if normalized.starts_with('/') || normalized.split('/').any(|seg| seg == ".." || seg == ".")
        {
            return Err(CdrError::InvalidFormat(
                "ZIP path traversal or relative segment rejected (RUSTSEC-2026-0367)".to_string(),
            ));
        }

        if is_symlink || unix_mode.is_some_and(|m| (m & 0o170000) == 0o120000) {
            return Err(CdrError::InvalidFormat(
                "ZIP symlink entries are forbidden in OpenXML containers (RUSTSEC-2026-0368)"
                    .to_string(),
            ));
        }

        let had_suid_sgid = unix_mode.is_some_and(|m| (m & 0o7000) != 0);
        Ok((normalized, had_suid_sgid))
    }

    /// Scans raw ZIP central-directory (`PK\x01\x02`) headers to detect entries whose raw
    /// `external_file_attributes >> 16` carry SUID/SGID/sticky (`0o7000`) bits, even when
    /// `zip 9.x`'s `unix_mode()` accessor clears those bits in memory (`RUSTSEC-2026-0369`).
    pub fn collect_raw_cd_suid_sgid_entries(zip_bytes: &[u8]) -> HashSet<String> {
        let mut flagged = HashSet::new();
        let mut idx = 0usize;
        while idx + 46 <= zip_bytes.len() {
            if zip_bytes[idx..idx + 4] == [0x50, 0x4B, 0x01, 0x02] {
                let name_len =
                    u16::from_le_bytes([zip_bytes[idx + 28], zip_bytes[idx + 29]]) as usize;
                let extra_len =
                    u16::from_le_bytes([zip_bytes[idx + 30], zip_bytes[idx + 31]]) as usize;
                let comment_len =
                    u16::from_le_bytes([zip_bytes[idx + 32], zip_bytes[idx + 33]]) as usize;
                let ext_attrs = u32::from_le_bytes([
                    zip_bytes[idx + 38],
                    zip_bytes[idx + 39],
                    zip_bytes[idx + 40],
                    zip_bytes[idx + 41],
                ]);
                let raw_unix_mode = ext_attrs >> 16;
                if idx + 46 + name_len <= zip_bytes.len() && (raw_unix_mode & 0o7000) != 0 {
                    let name = String::from_utf8_lossy(&zip_bytes[idx + 46..idx + 46 + name_len])
                        .replace('\\', "/");
                    flagged.insert(name);
                }
                let step = 46usize
                    .saturating_add(name_len)
                    .saturating_add(extra_len)
                    .saturating_add(comment_len);
                idx = idx.saturating_add(step.max(1));
            } else {
                idx += 1;
            }
        }
        flagged
    }

    pub fn sanitize(
        input_bytes: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>), CdrError> {
        let mut budget = ResourceBudget::from_policy(policy);
        Self::sanitize_with_budget(input_bytes, policy, &mut budget, false)
    }

    pub fn sanitize_with_budget(
        input_bytes: &[u8],
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
        is_generic_zip: bool,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>), CdrError> {
        let reader = Cursor::new(input_bytes);
        let mut archive = ZipArchive::new(reader).map_err(|e| {
            CdrError::ParserCorruption(format!("ZIP central directory parse failure: {e}"))
        })?;

        if archive.len() > MAX_ZIP_ENTRIES {
            return Err(CdrError::ResourceLimitExceeded(format!(
                "Archive entry count ({}) exceeds safety limit ({})",
                archive.len(),
                MAX_ZIP_ENTRIES
            )));
        }

        let mut report = Vec::new();
        let mut stripped_parts: HashSet<String> = HashSet::new();
        let mut raw_entries: Vec<(String, CompressionMethod, Vec<u8>)> =
            Vec::with_capacity(archive.len());
        let raw_suid_entries = Self::collect_raw_cd_suid_sgid_entries(input_bytes);

        // Pass 1: Read entries with bounded Take reader (fixes BUG-CDR-04 / RUSTSEC-2026-0429 header spoofing)
        // and identify macro / OLE / ActiveX parts to strip before rewriting .rels and [Content_Types].xml.
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| {
                CdrError::ParserCorruption(format!("ZIP entry index {i} error: {e}"))
            })?;

            let raw_entry_name = file
                .name()
                .map_err(|e| {
                    CdrError::InvalidFormat(format!(
                        "Invalid UTF-8 ZIP entry name rejected (RUSTSEC-2026-0367): {e}"
                    ))
                })?
                .into_owned();
            let (name, had_suid_sgid) = Self::validate_zip_entry_security(
                &raw_entry_name,
                file.is_symlink(),
                file.unix_mode(),
            )?;

            if had_suid_sgid || raw_suid_entries.contains(&name) {
                report.push(DisarmReportItem::new(
                    "ZIP_SUID_SGID_MODE_BITS",
                    name.clone(),
                    "Stripped SUID/SGID/sticky unix permission bits (0o7000) from ZIP entry (RUSTSEC-2026-0369)",
                ));
            }

            if file.is_dir() {
                raw_entries.push((name, CompressionMethod::Stored, Vec::new()));
                continue;
            }

            // Decide if this part must be stripped based on policy
            if !is_generic_zip {
                if let Some((element_type, action_taken)) =
                    Self::classify_stripped_part(&name, policy)
                {
                    stripped_parts.insert(Self::normalize_part_key(&name));
                    report.push(DisarmReportItem::new(element_type, name, action_taken));
                    continue;
                }
            }

            // Read actual decompressed stream capped by remaining budget + 1 byte,
            // pre-allocating at most 64 KiB rather than trusting central-directory file.size() (RUSTSEC-2026-0429)
            let prealloc_cap = (file.size().min(64 * 1024)) as usize;
            let read_cap = budget.bytes_remaining.saturating_add(1);
            let mut bounded_reader = (&mut file).take(read_cap);
            let mut entry_bytes = Vec::with_capacity(prealloc_cap);
            bounded_reader.read_to_end(&mut entry_bytes).map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("larger than its declared uncompressed size") {
                    CdrError::ResourceLimitExceeded(format!(
                        "ZIP entry {name} exceeded declared uncompressed size header (RUSTSEC-2026-0429 / BUG-CDR-04): {err_str}"
                    ))
                } else {
                    CdrError::ParserCorruption(format!(
                        "Decompression stream error in {name}: {err_str}"
                    ))
                }
            })?;

            budget.charge_bytes(entry_bytes.len() as u64)?;

            let method = match file.compression() {
                CompressionMethod::Stored => CompressionMethod::Stored,
                _ => CompressionMethod::Deflated,
            };

            raw_entries.push((name, method, entry_bytes));
        }

        // Pass 2a: Rewrite all *.rels parts first so we collect every removed Relationship `Id`
        // (e.g., `rId5`) before rewriting content XML parts (`Row 115`, `SP4.1-06`).
        let mut removed_rel_ids: HashSet<String> = HashSet::new();
        if !is_generic_zip {
            for (name, _method, entry_bytes) in &mut raw_entries {
                if name.ends_with('/') {
                    continue;
                }
                if name.to_ascii_lowercase().ends_with(".rels") {
                    *entry_bytes = Self::rewrite_rels_xml(
                        entry_bytes,
                        name,
                        &stripped_parts,
                        policy,
                        &mut removed_rel_ids,
                        &mut report,
                    )?;
                }
            }
        }

        // Pass 2b: Rewrite XML parts ([Content_Types].xml, document/sheet/slide XML)
        // and recursively sanitize nested files when present.
        let mut out_buf = Cursor::new(Vec::with_capacity(input_bytes.len()));
        {
            let mut zip_writer = ZipWriter::new(&mut out_buf);

            for (name, method, mut entry_bytes) in raw_entries {
                if name.ends_with('/') {
                    let options = SimpleFileOptions::default()
                        .compression_method(CompressionMethod::Stored)
                        .unix_permissions(0o755);
                    zip_writer.add_directory(&name, options).map_err(|e| {
                        CdrError::ReconstructionFailure(format!(
                            "Failed adding ZIP directory {name}: {e}"
                        ))
                    })?;
                    continue;
                }

                let lower_name = name.to_ascii_lowercase();

                if !is_generic_zip && lower_name == "[content_types].xml" {
                    entry_bytes = Self::rewrite_content_types_xml(
                        &entry_bytes,
                        &stripped_parts,
                        policy,
                        &mut report,
                        &name,
                    )?;
                } else if !is_generic_zip && lower_name.ends_with(".rels") {
                    // Already rewritten in Pass 2a while collecting `removed_rel_ids`
                } else if !is_generic_zip && lower_name.ends_with(".xml") {
                    if policy.strip_office_dde
                        || policy.sanitize_office_external_relationships
                        || !removed_rel_ids.is_empty()
                    {
                        entry_bytes = Self::sanitize_office_xml_dde_and_dangling_rels(
                            &entry_bytes,
                            &name,
                            policy,
                            &removed_rel_ids,
                            &mut report,
                        )?;
                    }
                } else if Self::is_nested_sanitizable(&lower_name, &entry_bytes) {
                    // Fail closed when recursion depth is exhausted or nested sanitization fails (`Row 108`, `BUG-CDR-04`)
                    let mut child_budget = budget.descend()?;
                    let (clean_nested, nested_reports) =
                        crate::engine::CdrEngine::sanitize_nested_with_budget(
                            &entry_bytes,
                            &name,
                            policy,
                            &mut child_budget,
                        )?;
                    entry_bytes = clean_nested;
                    for mut r in nested_reports {
                        r.location_path = format!("{} -> {}", name, r.location_path);
                        report.push(r);
                    }
                    budget.bytes_remaining = child_budget.bytes_remaining;
                    budget.objects_remaining = child_budget.objects_remaining;
                }

                let options = SimpleFileOptions::default()
                    .compression_method(method)
                    .unix_permissions(0o644);
                zip_writer.start_file(&name, options).map_err(|e| {
                    CdrError::ReconstructionFailure(format!(
                        "Failed starting ZIP entry {name}: {e}"
                    ))
                })?;
                zip_writer.write_all(&entry_bytes).map_err(|e| {
                    CdrError::ReconstructionFailure(format!("Failed writing ZIP entry {name}: {e}"))
                })?;
            }

            zip_writer.finish().map_err(|e| {
                CdrError::ReconstructionFailure(format!("Failed finalizing ZIP archive: {e}"))
            })?;
        }

        Ok((out_buf.into_inner(), report))
    }

    fn classify_stripped_part(
        name: &str,
        policy: &SanitizationPolicy,
    ) -> Option<(&'static str, &'static str)> {
        let lower = name.to_ascii_lowercase();
        let file_name = lower.rsplit('/').next().unwrap_or(&lower);

        // Notice: We intentionally do NOT strip arbitrary `.bin` files like
        // `word/printerSettings/printerSettings1.bin` (`BUG-CDR-04`).
        if policy.strip_office_macros
            && (file_name == "vbaproject.bin"
                || file_name == "vbaprojectsignature.bin"
                || file_name == "vbadata.xml"
                || file_name == "xlmacrosheet.xml"
                || lower.contains("/macrosheets/")
                || lower.starts_with("macrosheets/")
                || lower.contains("/dialogsheets/"))
        {
            return Some((
                "VBA_MACRO_PROJECT",
                "Removed executable VBA macro stream from OOXML container",
            ));
        }

        if policy.strip_office_ole_objects
            && (lower.contains("/embeddings/")
                || lower.starts_with("embeddings/")
                || lower.contains("/activex/")
                || lower.starts_with("activex/")
                || file_name.starts_with("oleobject"))
        {
            return Some((
                "EMBEDDED_OLE_OBJECT",
                "Removed embedded OLE/ActiveX binary object from OOXML container",
            ));
        }

        None
    }

    fn normalize_part_key(path: &str) -> String {
        path.trim_start_matches('/').to_ascii_lowercase()
    }

    fn resolve_rel_target(rels_path: &str, target: &str) -> String {
        let target_clean = target.trim_start_matches('/');
        if target.starts_with('/') {
            return target_clean.to_ascii_lowercase();
        }
        let base_dir = if let Some(idx) = rels_path.rfind("/_rels/") {
            &rels_path[..idx]
        } else {
            ""
        };
        let combined = if base_dir.is_empty() {
            target_clean.to_string()
        } else {
            format!("{}/{}", base_dir.trim_start_matches('/'), target_clean)
        };
        let mut stack: Vec<&str> = Vec::new();
        for seg in combined.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            } else if seg == ".." {
                stack.pop();
            } else {
                stack.push(seg);
            }
        }
        stack.join("/").to_ascii_lowercase()
    }

    /// Rewrites `[Content_Types].xml` using `quick-xml` (`BUG-CDR-04`):
    /// - Drops `<Override>` elements referencing stripped parts (`vbaProject.bin`, `embeddings/*`, etc.)
    /// - Rewrites macro-enabled main document ContentTypes to standard OOXML ContentTypes so
    ///   Word/Excel/PowerPoint open the disarmed file without corruption dialogs.
    fn rewrite_content_types_xml(
        xml_bytes: &[u8],
        stripped_parts: &HashSet<String>,
        policy: &SanitizationPolicy,
        report: &mut Vec<DisarmReportItem>,
        location: &str,
    ) -> Result<Vec<u8>, CdrError> {
        let mut reader = Reader::from_reader(xml_bytes);
        let mut writer = Writer::new(Vec::with_capacity(xml_bytes.len()));
        let mut buf = Vec::new();
        let mut skip_depth = 0usize;
        let mut xml_depth = 0usize;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::DocType(_)) => {
                    return Err(CdrError::ParserCorruption(
                        "DOCTYPE declaration forbidden in [Content_Types].xml".to_string(),
                    ));
                }
                Ok(event) => {
                    match event {
                        Event::Start(_) => {
                            xml_depth += 1;
                            if xml_depth > crate::sanitizers::MAX_XML_ELEMENT_DEPTH {
                                return Err(CdrError::ResourceLimitExceeded(format!(
                                    "[Content_Types].xml element nesting depth exceeds maximum allowed ({}) (RUSTSEC-2026-0195 mitigation)",
                                    crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                                )));
                            }
                        }
                        Event::Empty(_) => {
                            if xml_depth + 1 > crate::sanitizers::MAX_XML_ELEMENT_DEPTH {
                                return Err(CdrError::ResourceLimitExceeded(format!(
                                    "[Content_Types].xml element nesting depth exceeds maximum allowed ({}) (RUSTSEC-2026-0195 mitigation)",
                                    crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                                )));
                            }
                        }
                        Event::End(_) => {
                            xml_depth = xml_depth.saturating_sub(1);
                        }
                        _ => {}
                    }

                    if skip_depth > 0 {
                        match event {
                            Event::Start(_) => skip_depth += 1,
                            Event::End(_) => skip_depth -= 1,
                            _ => {}
                        }
                        buf.clear();
                        continue;
                    }

                    match event {
                        Event::Start(ref e) | Event::Empty(ref e) => {
                            let is_empty = matches!(event, Event::Empty(_));
                            let validated_attrs =
                                crate::sanitizers::collect_validated_xml_attributes(e)?;
                            let local = e.name().local_name().into_inner().to_ascii_lowercase();

                            if local == "override" {
                                let mut part_name = String::new();
                                let mut content_type = String::new();
                                for attr in &validated_attrs {
                                    let k = attr.key.local_name().into_inner().to_ascii_lowercase();
                                    let v = attr.value.as_ref().to_string();
                                    if k == "partname" {
                                        part_name = v;
                                    } else if k == "contenttype" {
                                        content_type = v;
                                    }
                                }

                                let norm_part = Self::normalize_part_key(&part_name);
                                let is_vba_ct = policy.strip_office_macros
                                    && content_type
                                        .to_ascii_lowercase()
                                        .contains("vnd.ms-office.vbaproject");

                                if stripped_parts.contains(&norm_part) || is_vba_ct {
                                    if !is_empty {
                                        skip_depth = 1;
                                    }
                                    buf.clear();
                                    continue;
                                }

                                let new_ct = if policy.strip_office_macros {
                                    Self::upgrade_macro_content_type(&content_type)
                                } else {
                                    None
                                };

                                if let Some(replaced_ct) = new_ct {
                                    let tag_name = e.name().as_ref().to_string();
                                    let mut clean_elem = BytesStart::new(tag_name);
                                    for attr in &validated_attrs {
                                        let key_str = attr.key.as_ref().to_string();
                                        let local_k =
                                            attr.key.local_name().into_inner().to_ascii_lowercase();
                                        if local_k == "contenttype" {
                                            clean_elem
                                                .push_attribute((key_str.as_str(), replaced_ct));
                                        } else {
                                            let val_str = attr.value.as_ref();
                                            clean_elem.push_attribute((key_str.as_str(), val_str));
                                        }
                                    }
                                    report.push(DisarmReportItem::new(
                                        "MACRO_ENABLED_CONTENT_TYPE",
                                        location.to_string(),
                                        format!(
                                            "Converted {content_type} to standard document ContentType"
                                        ),
                                    ));
                                    let write_ev = if is_empty {
                                        Event::Empty(clean_elem)
                                    } else {
                                        Event::Start(clean_elem)
                                    };
                                    writer
                                        .write_event(write_ev)
                                        .map_err(|err| CdrError::XmlError(err.to_string()))?;
                                    buf.clear();
                                    continue;
                                }
                            }

                            writer
                                .write_event(event.into_owned())
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                        Event::GeneralRef(ref e) => {
                            if !crate::sanitizers::is_allowed_xml_general_ref(e.as_ref().as_bytes())
                            {
                                return Err(CdrError::ParserCorruption(
                                    "Custom XML entity reference forbidden in [Content_Types].xml"
                                        .to_string(),
                                ));
                            }
                            writer
                                .write_event(event.into_owned())
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                        other => {
                            writer
                                .write_event(other.into_owned())
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                    }
                }
                Err(e) => {
                    return Err(CdrError::ParserCorruption(format!(
                        "[Content_Types].xml parse error: {e}"
                    )));
                }
            }
            buf.clear();
        }

        Ok(writer.into_inner())
    }

    fn upgrade_macro_content_type(ct: &str) -> Option<&'static str> {
        match ct {
            "application/vnd.ms-word.document.macroEnabled.main+xml" => Some(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            ),
            "application/vnd.ms-word.template.macroEnabledTemplate.main+xml" => Some(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
            ),
            "application/vnd.ms-excel.sheet.macroEnabled.main+xml" => {
                Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")
            }
            "application/vnd.ms-excel.template.macroEnabled.main+xml" => Some(
                "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
            ),
            "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml" => Some(
                "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
            ),
            _ => None,
        }
    }

    /// Rewrites `.rels` files using `quick-xml` (`BUG-CDR-04`, `EV-04`):
    /// - Drops `<Relationship>` elements pointing to stripped parts (`vbaProject.bin`, `embeddings/*`).
    /// - Drops `<Relationship>` elements with `TargetMode="External"` (matched case-insensitively,
    ///   independent of single/double quotes or whitespace around `=`) or unsafe URI schemes
    ///   when `policy.sanitize_office_external_relationships` is enabled.
    fn rewrite_rels_xml(
        xml_bytes: &[u8],
        rels_path: &str,
        stripped_parts: &HashSet<String>,
        policy: &SanitizationPolicy,
        removed_rel_ids: &mut HashSet<String>,
        report: &mut Vec<DisarmReportItem>,
    ) -> Result<Vec<u8>, CdrError> {
        let mut reader = Reader::from_reader(xml_bytes);
        let mut writer = Writer::new(Vec::with_capacity(xml_bytes.len()));
        let mut buf = Vec::new();
        let mut skip_depth = 0usize;
        let mut xml_depth = 0usize;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::DocType(_)) => {
                    return Err(CdrError::ParserCorruption(format!(
                        "DOCTYPE declaration forbidden in {rels_path}"
                    )));
                }
                Ok(event) => {
                    match event {
                        Event::Start(_) => {
                            xml_depth += 1;
                            if xml_depth > crate::sanitizers::MAX_XML_ELEMENT_DEPTH {
                                return Err(CdrError::ResourceLimitExceeded(format!(
                                    "Relationship XML nesting depth exceeds maximum allowed ({}) in {rels_path} (RUSTSEC-2026-0195 mitigation)",
                                    crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                                )));
                            }
                        }
                        Event::Empty(_) => {
                            if xml_depth + 1 > crate::sanitizers::MAX_XML_ELEMENT_DEPTH {
                                return Err(CdrError::ResourceLimitExceeded(format!(
                                    "Relationship XML nesting depth exceeds maximum allowed ({}) in {rels_path} (RUSTSEC-2026-0195 mitigation)",
                                    crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                                )));
                            }
                        }
                        Event::End(_) => {
                            xml_depth = xml_depth.saturating_sub(1);
                        }
                        _ => {}
                    }

                    if skip_depth > 0 {
                        match event {
                            Event::Start(_) => skip_depth += 1,
                            Event::End(_) => skip_depth -= 1,
                            _ => {}
                        }
                        buf.clear();
                        continue;
                    }

                    match event {
                        Event::Start(ref e) | Event::Empty(ref e) => {
                            let is_empty = matches!(event, Event::Empty(_));
                            let validated_attrs =
                                crate::sanitizers::collect_validated_xml_attributes(e)?;
                            let local = e.name().local_name().into_inner().to_ascii_lowercase();

                            if local == "relationship" {
                                let mut rel_id = String::new();
                                let mut target = String::new();
                                let mut target_mode = String::new();
                                let mut rel_type = String::new();

                                for attr in &validated_attrs {
                                    let k = attr.key.local_name().into_inner().to_ascii_lowercase();
                                    let v = attr.value.as_ref().to_string();
                                    if k == "id" {
                                        rel_id = v;
                                    } else if k == "target" {
                                        target = v;
                                    } else if k == "targetmode" {
                                        target_mode = v;
                                    } else if k == "type" {
                                        rel_type = v;
                                    }
                                }

                                let resolved_target = Self::resolve_rel_target(rels_path, &target);
                                let rel_type_lower = rel_type.to_ascii_lowercase();
                                let target_lower = target.trim().to_ascii_lowercase();

                                // 1. Drop relationships pointing to stripped macro/OLE parts
                                let is_stripped_target = stripped_parts.contains(&resolved_target)
                                    || (policy.strip_office_macros
                                        && (rel_type_lower.contains("vbaproject")
                                            || rel_type_lower.contains("macrosheet")
                                            || target_lower.ends_with("vbaproject.bin")))
                                    || (policy.strip_office_ole_objects
                                        && (rel_type_lower.contains("/oleobject")
                                            || rel_type_lower.contains("/control")
                                            || rel_type_lower.contains("/activex")));

                                if is_stripped_target {
                                    if !rel_id.is_empty() {
                                        removed_rel_ids.insert(rel_id);
                                    }
                                    report.push(DisarmReportItem::new(
                                        "DANGLING_MACRO_OR_OLE_REL",
                                        rels_path.to_string(),
                                        format!(
                                            "Removed <Relationship> referencing stripped target '{target}'"
                                        ),
                                    ));
                                    if !is_empty {
                                        skip_depth = 1;
                                    }
                                    buf.clear();
                                    continue;
                                }

                                // 2. Drop external relationships (`TargetMode="External"` case-insensitive) on
                                //    templates, framesets, OLE, packages, subdocuments, slideMasters, externalWorkbooks,
                                //    or dangerous URI schemes, while preserving benign external hyperlinks (`Row 115`, `EV-04`, `BUG-CDR-04`).
                                let is_external_mode =
                                    target_mode.trim().eq_ignore_ascii_case("external");
                                let has_dangerous_scheme = target_lower.starts_with("ms-msdt:")
                                    || target_lower.starts_with("javascript:")
                                    || target_lower.starts_with("vbscript:")
                                    || target_lower.starts_with("mhtml:")
                                    || target_lower.starts_with("file:")
                                    || target_lower.starts_with("data:")
                                    || target_lower.starts_with("\\\\");
                                let is_benign_hyperlink = rel_type_lower.ends_with("/hyperlink")
                                    && !has_dangerous_scheme
                                    && !policy.strip_external_hyperlinks;

                                if policy.sanitize_office_external_relationships
                                    && (has_dangerous_scheme
                                        || (is_external_mode && !is_benign_hyperlink))
                                {
                                    if !rel_id.is_empty() {
                                        removed_rel_ids.insert(rel_id);
                                    }
                                    report.push(DisarmReportItem::new(
                                        "EXTERNAL_RELATIONSHIP_INJECTION",
                                        rels_path.to_string(),
                                        format!(
                                            "Removed external <Relationship> targeting '{target}'"
                                        ),
                                    ));
                                    if !is_empty {
                                        skip_depth = 1;
                                    }
                                    buf.clear();
                                    continue;
                                }
                            }

                            writer
                                .write_event(event.into_owned())
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                        Event::GeneralRef(ref e) => {
                            if !crate::sanitizers::is_allowed_xml_general_ref(e.as_ref().as_bytes())
                            {
                                return Err(CdrError::ParserCorruption(format!(
                                    "Custom XML entity reference forbidden in {rels_path}"
                                )));
                            }
                            writer
                                .write_event(event.into_owned())
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                        other => {
                            writer
                                .write_event(other.into_owned())
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                    }
                }
                Err(e) => {
                    return Err(CdrError::ParserCorruption(format!(
                        "Relationship XML parse error in {rels_path}: {e}"
                    )));
                }
            }
            buf.clear();
        }

        Ok(writer.into_inner())
    }

    pub fn neutralize_dde_in_xml(
        xml_bytes: &[u8],
        xml_path: &str,
        report: &mut Vec<DisarmReportItem>,
    ) -> Result<Vec<u8>, CdrError> {
        Self::sanitize_office_xml_dde(xml_bytes, xml_path, report)
    }

    /// Strips `<ddeLink>`, `ddeService`, `ddeTopic`, `DDEAUTO`/`DDE` fields, and `=cmd|` formulas
    /// from OOXML content XML files when `policy.strip_office_dde` is true (`Row 118`, `BUG-CDR-04`).
    /// Fails closed (`Err(CdrError::ParserCorruption)`) on invalid UTF-8 or malformed XML.
    fn sanitize_office_xml_dde(
        xml_bytes: &[u8],
        xml_path: &str,
        report: &mut Vec<DisarmReportItem>,
    ) -> Result<Vec<u8>, CdrError> {
        let default_policy = SanitizationPolicy::default();
        let empty_removed = HashSet::new();
        Self::sanitize_office_xml_dde_and_dangling_rels(
            xml_bytes,
            xml_path,
            &default_policy,
            &empty_removed,
            report,
        )
    }

    /// Rewrites OOXML content XML parts to:
    /// 1. Strip `<ddeLink>`, `ddeService`, `ddeTopic`, `DDEAUTO`/`DDE` fields, `=cmd|` formulas,
    ///    and `<!DOCTYPE>` declarations when `policy.strip_office_dde` is true (`Row 118`).
    /// 2. Strip dangling `r:id` / `r:embed` / `r:link` / `id` hyperlink and relationship attributes
    ///    that reference any `<Relationship>` removed during `.rels` sanitization (`Row 115`, `SP4.1-06`).
    /// 3. Fail closed (`Err(CdrError::ParserCorruption)`) on invalid UTF-8 or malformed XML.
    fn sanitize_office_xml_dde_and_dangling_rels(
        xml_bytes: &[u8],
        xml_path: &str,
        policy: &SanitizationPolicy,
        removed_rel_ids: &HashSet<String>,
        report: &mut Vec<DisarmReportItem>,
    ) -> Result<Vec<u8>, CdrError> {
        let _xml_str = std::str::from_utf8(xml_bytes).map_err(|e| {
            CdrError::ParserCorruption(format!("Invalid UTF-8 in OOXML part {xml_path}: {e}"))
        })?;

        let mut reader = Reader::from_reader(xml_bytes);
        let mut writer = Writer::new(Vec::with_capacity(xml_bytes.len()));
        let mut buf = Vec::new();
        let mut skip_depth = 0usize;
        let mut xml_depth = 0usize;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::DocType(_)) => {
                    report.push(DisarmReportItem::new(
                        "OOXML_DOCTYPE_DECLARATION",
                        xml_path.to_string(),
                        "Removed DOCTYPE/ENTITY declaration from OOXML part",
                    ));
                    buf.clear();
                    continue;
                }
                Ok(event) => {
                    match event {
                        Event::Start(_) => {
                            xml_depth += 1;
                            if xml_depth > crate::sanitizers::MAX_XML_ELEMENT_DEPTH {
                                return Err(CdrError::ResourceLimitExceeded(format!(
                                    "OOXML element nesting depth exceeds maximum allowed ({}) in {xml_path} (RUSTSEC-2026-0195 mitigation)",
                                    crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                                )));
                            }
                        }
                        Event::Empty(_) => {
                            if xml_depth + 1 > crate::sanitizers::MAX_XML_ELEMENT_DEPTH {
                                return Err(CdrError::ResourceLimitExceeded(format!(
                                    "OOXML element nesting depth exceeds maximum allowed ({}) in {xml_path} (RUSTSEC-2026-0195 mitigation)",
                                    crate::sanitizers::MAX_XML_ELEMENT_DEPTH
                                )));
                            }
                        }
                        Event::End(_) => {
                            xml_depth = xml_depth.saturating_sub(1);
                        }
                        _ => {}
                    }

                    if skip_depth > 0 {
                        match event {
                            Event::Start(_) => skip_depth += 1,
                            Event::End(_) => skip_depth -= 1,
                            _ => {}
                        }
                        buf.clear();
                        continue;
                    }

                    match event {
                        Event::Start(ref e) | Event::Empty(ref e) => {
                            let is_empty = matches!(event, Event::Empty(_));
                            let validated_attrs =
                                crate::sanitizers::collect_validated_xml_attributes(e)?;
                            let local = e.name().local_name().into_inner().to_ascii_lowercase();

                            if policy.strip_office_dde
                                && (local == "ddelink" || local == "ddeitem" || local == "olelink")
                            {
                                report.push(DisarmReportItem::new(
                                    "OOXML_DDE_LINK",
                                    xml_path.to_string(),
                                    "Removed Dynamic Data Exchange link element",
                                ));
                                if !is_empty {
                                    skip_depth = 1;
                                }
                                buf.clear();
                                continue;
                            }

                            let mut neutralized_attr = false;
                            let tag_name = e.name().as_ref().to_string();
                            let mut clean_elem = BytesStart::new(tag_name);

                            for attr in validated_attrs {
                                let key_str = attr.key.as_ref().to_string();
                                let key_lower = key_str.to_ascii_lowercase();
                                let local_key =
                                    attr.key.local_name().into_inner().to_ascii_lowercase();
                                let val_str = attr.value.into_owned();
                                let val_upper = val_str.to_ascii_uppercase();

                                // Strip dangling `r:id` / `r:embed` / `r:link` / `id` attributes whose
                                // target `<Relationship>` was removed from `.rels` (`Row 115`, `SP4.1-06`).
                                let is_rel_ref_attr = key_lower == "r:id"
                                    || key_lower == "r:embed"
                                    || key_lower == "r:link"
                                    || local_key == "id";
                                if is_rel_ref_attr && removed_rel_ids.contains(val_str.trim()) {
                                    report.push(DisarmReportItem::new(
                                        "DANGLING_RELATIONSHIP_ATTR",
                                        xml_path.to_string(),
                                        format!(
                                            "Stripped dangling relationship attribute {key_str}='{val_str}'"
                                        ),
                                    ));
                                    continue;
                                }

                                if policy.strip_office_dde
                                    && (key_lower.contains("ddeservice")
                                        || key_lower.contains("ddetopic")
                                        || val_upper.contains("DDEAUTO")
                                        || val_upper.starts_with("DDE ")
                                        || val_upper.contains("CMD|")
                                        || val_upper.contains("POWERSHELL"))
                                {
                                    neutralized_attr = true;
                                    clean_elem.push_attribute((key_str.as_str(), "REM_DISARMED"));
                                } else {
                                    clean_elem.push_attribute((key_str.as_str(), val_str.as_str()));
                                }
                            }

                            if neutralized_attr {
                                report.push(DisarmReportItem::new(
                                    "OOXML_DDE_ATTRIBUTE",
                                    xml_path.to_string(),
                                    "Neutralized DDE/DDEAUTO instruction attribute",
                                ));
                            }

                            let out_ev = if is_empty {
                                Event::Empty(clean_elem)
                            } else {
                                Event::Start(clean_elem)
                            };
                            writer
                                .write_event(out_ev)
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                        Event::Text(ref t) => {
                            let raw_text = t.as_ref();
                            let upper = raw_text.to_ascii_uppercase();
                            if policy.strip_office_dde
                                && (upper.contains("DDEAUTO")
                                    || upper.trim_start().starts_with("DDE ")
                                    || upper.contains("CMD|"))
                            {
                                report.push(DisarmReportItem::new(
                                    "DDE_FORMULA_INJECTION",
                                    xml_path.to_string(),
                                    "Neutralized inline DDE/command formula instruction",
                                ));
                                writer
                                    .write_event(Event::Text(quick_xml::events::BytesText::new(
                                        "REM_DISARMED",
                                    )))
                                    .map_err(|err| CdrError::XmlError(err.to_string()))?;
                            } else {
                                writer
                                    .write_event(Event::Text(t.clone().into_owned()))
                                    .map_err(|err| CdrError::XmlError(err.to_string()))?;
                            }
                        }
                        Event::GeneralRef(ref e) => {
                            if !crate::sanitizers::is_allowed_xml_general_ref(e.as_ref().as_bytes())
                            {
                                let entity_name = e.as_ref();
                                report.push(DisarmReportItem::new(
                                    "OOXML_CUSTOM_ENTITY_REF",
                                    xml_path.to_string(),
                                    format!("Removed custom XML entity reference &{entity_name};"),
                                ));
                                buf.clear();
                                continue;
                            }
                            writer
                                .write_event(event.into_owned())
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                        Event::End(ref e) => {
                            let tag_name = e.name().as_ref().to_string();
                            writer
                                .write_event(Event::End(BytesEnd::new(tag_name)))
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                        other => {
                            writer
                                .write_event(other.into_owned())
                                .map_err(|err| CdrError::XmlError(err.to_string()))?;
                        }
                    }
                }
                Err(e) => {
                    return Err(CdrError::ParserCorruption(format!(
                        "Malformed OOXML content in {xml_path}: {e}"
                    )));
                }
            }
            buf.clear();
        }

        Ok(writer.into_inner())
    }

    fn is_nested_sanitizable(lower_name: &str, bytes: &[u8]) -> bool {
        lower_name.ends_with(".pdf")
            || lower_name.ends_with(".docx")
            || lower_name.ends_with(".xlsx")
            || lower_name.ends_with(".pptx")
            || lower_name.ends_with(".svg")
            || lower_name.ends_with(".zip")
            || lower_name.ends_with(".png")
            || lower_name.ends_with(".jpg")
            || lower_name.ends_with(".jpeg")
            || lower_name.ends_with(".webp")
            || lower_name.ends_with(".doc")
            || lower_name.ends_with(".xls")
            || lower_name.ends_with(".ppt")
            || bytes.starts_with(b"%PDF-")
            || bytes.starts_with(b"PK\x03\x04")
            || bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
            || (bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
            || (bytes.len() >= 8 && bytes[..8] == crate::sanitizers::ole2::OLE2_MAGIC)
    }
}
