use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::{Reader, Writer};
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Write};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::engine::DetectedFormat;
use crate::error::CdrError;
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::{
    resolve_allowed_xml_general_ref, unescape_xml_attribute_value, DisarmReportItem,
};

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

            // CSE-19: Enforce allowlist-only binary parts inside OOXML containers and strip
            // prohibited binary/script/metafile parts (`.wmf`, `.emf`, `.bin`, `.exe`, `.ps1`,
            // `.ole`, `.activex`) even when generic ZIP nesting is enabled.
            if let Some((element_type, action_taken)) =
                Self::classify_disallowed_binary_part(&name, &entry_bytes, is_generic_zip, policy)
            {
                stripped_parts.insert(Self::normalize_part_key(&name));
                report.push(DisarmReportItem::new(element_type, name, action_taken));
                continue;
            }

            let method = match file.compression() {
                CompressionMethod::Stored => CompressionMethod::Stored,
                _ => CompressionMethod::Deflated,
            };

            raw_entries.push((name, method, entry_bytes));
        }

        // Pass 2a: Rewrite all *.rels parts first, collecting removed Relationship `Id`s strictly
        // scoped by their owning part path (`CSE-19`: e.g. `xl/worksheets/_rels/sheet1.xml.rels`
        // -> `xl/worksheets/sheet1.xml`) so stripping `rId1` in one part never breaks `rId1` elsewhere.
        let mut removed_rel_ids_by_part: HashMap<String, HashSet<String>> = HashMap::new();
        if !is_generic_zip {
            for (name, _method, entry_bytes) in &mut raw_entries {
                if name.ends_with('/') {
                    continue;
                }
                if name.to_ascii_lowercase().ends_with(".rels") {
                    let owner_key = Self::owner_part_for_rels(name).unwrap_or_default();
                    let scoped_removed = removed_rel_ids_by_part.entry(owner_key).or_default();
                    *entry_bytes = Self::rewrite_rels_xml(
                        entry_bytes,
                        name,
                        &stripped_parts,
                        policy,
                        scoped_removed,
                        &mut report,
                    )?;
                }
            }
        }

        // Pass 2b: Rewrite XML parts ([Content_Types].xml, document/sheet/slide XML)
        // and recursively sanitize nested files when present.
        let empty_removed_rels: HashSet<String> = HashSet::new();
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
                    // Already rewritten in Pass 2a while collecting per-part `removed_rel_ids_by_part`
                } else if !is_generic_zip && lower_name.ends_with(".xml") {
                    let part_key = Self::normalize_part_key(&name);
                    let part_removed_rels = removed_rel_ids_by_part
                        .get(&part_key)
                        .unwrap_or(&empty_removed_rels);
                    if policy.strip_office_dde
                        || policy.sanitize_office_external_relationships
                        || !part_removed_rels.is_empty()
                    {
                        entry_bytes = Self::sanitize_office_xml_dde_and_dangling_rels(
                            &entry_bytes,
                            &name,
                            policy,
                            part_removed_rels,
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

    /// Derives the normalized owning part path for an OOXML `.rels` file (`CSE-19`):
    /// - `_rels/.rels` -> `Some("")` (package root)
    /// - `word/_rels/document.xml.rels` -> `Some("word/document.xml")`
    /// - `xl/worksheets/_rels/sheet1.xml.rels` -> `Some("xl/worksheets/sheet1.xml")`
    /// - `_rels/foo.xml.rels` -> `Some("foo.xml")`
    pub fn owner_part_for_rels(rels_path: &str) -> Option<String> {
        let norm = Self::normalize_part_key(rels_path);
        if norm == "_rels/.rels" {
            return Some(String::new());
        }
        let stem = norm.strip_suffix(".rels")?;
        if let Some(idx) = stem.rfind("/_rels/") {
            let dir = &stem[..idx];
            let file = &stem[idx + "/_rels/".len()..];
            if file.is_empty() {
                return Some(String::new());
            }
            Some(format!("{dir}/{file}"))
        } else {
            stem.strip_prefix("_rels/").map(|file| file.to_string())
        }
    }

    /// Returns `true` strictly for benign Office `printerSettings<digits>.bin` parts under
    /// `word|xl|ppt/printersettings/` whose payload does NOT carry executable, OLE2, archive,
    /// script, or Windows metafile magic bytes (`BUG-CDR-04` + `CSE-19`).
    pub fn is_benign_printer_settings_bin(lower_path: &str, bytes: &[u8]) -> bool {
        let norm = lower_path.trim_start_matches('/');
        let rest = norm
            .strip_prefix("word/printersettings/")
            .or_else(|| norm.strip_prefix("xl/printersettings/"))
            .or_else(|| norm.strip_prefix("ppt/printersettings/"));
        let Some(file_name) = rest else {
            return false;
        };
        let Some(digits) = file_name
            .strip_prefix("printersettings")
            .and_then(|s| s.strip_suffix(".bin"))
        else {
            return false;
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        !Self::has_prohibited_binary_magic(bytes) && !bytes.starts_with(b"PK\x03\x04")
    }

    fn has_prohibited_binary_magic(bytes: &[u8]) -> bool {
        if bytes.starts_with(b"MZ")
            || bytes.starts_with(b"\x7fELF")
            || bytes.starts_with(b"#!")
            || bytes.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A]) // Aldus Placeable WMF
            || (bytes.len() >= 6
                && bytes[0..4] == [0x01, 0x00, 0x09, 0x00]
                && (bytes[4..6] == [0x00, 0x03] || bytes[4..6] == [0x00, 0x01])) // Standard WMF
            || (bytes.len() >= 44
                && bytes[0..4] == [0x01, 0x00, 0x00, 0x00]
                && &bytes[40..44] == b" EMF") // EMF
            || (bytes.len() >= 8 && bytes[..8] == crate::sanitizers::ole2::OLE2_MAGIC)
            || bytes.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])
        // LNK
        {
            return true;
        }
        false
    }

    pub fn has_prohibited_part_extension(lower_path: &str) -> bool {
        const PROHIBITED_EXTS: &[&str] = &[
            ".wmf", ".emf", ".wmz", ".emz", ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".vbs",
            ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".psd1", ".msi", ".msp",
            ".hta", ".lnk", ".jar", ".class", ".sh", ".elf", ".so", ".dylib", ".ole", ".activex",
            ".ocx", ".cab", ".swf", ".xap",
        ];
        PROHIBITED_EXTS.iter().any(|ext| lower_path.ends_with(ext))
    }

    fn is_allowlisted_ooxml_static_asset(lower_path: &str, bytes: &[u8]) -> bool {
        let in_media = lower_path.starts_with("word/media/")
            || lower_path.starts_with("xl/media/")
            || lower_path.starts_with("ppt/media/");
        let is_safe_raster = lower_path.ends_with(".bmp")
            || lower_path.ends_with(".gif")
            || lower_path.ends_with(".tif")
            || lower_path.ends_with(".tiff");
        let in_fonts = lower_path.starts_with("word/fonts/")
            || lower_path.starts_with("xl/fonts/")
            || lower_path.starts_with("ppt/fonts/");
        let is_safe_font = lower_path.ends_with(".ttf")
            || lower_path.ends_with(".otf")
            || lower_path.ends_with(".woff")
            || lower_path.ends_with(".woff2");
        ((in_media && is_safe_raster) || (in_fonts && is_safe_font))
            && !Self::has_prohibited_binary_magic(bytes)
    }

    /// Enforces allowlist-only binary parts inside OOXML packages and strips prohibited binary,
    /// script, and metafile parts (`.wmf`, `.emf`, `.bin`, `.exe`, `.ps1`, `.ole`, `.activex`)
    /// in both OOXML and generic ZIP containers (`CSE-19`).
    pub fn classify_disallowed_binary_part(
        name: &str,
        bytes: &[u8],
        is_generic_zip: bool,
        policy: &SanitizationPolicy,
    ) -> Option<(&'static str, &'static str)> {
        let lower = Self::normalize_part_key(name);

        if Self::has_prohibited_part_extension(&lower) {
            return Some((
                if is_generic_zip {
                    "DISALLOWED_ARCHIVE_BINARY_PART"
                } else {
                    "DISALLOWED_OOXML_BINARY_PART"
                },
                "Stripped prohibited binary, script, ActiveX/OLE, or metafile part",
            ));
        }

        if lower.ends_with(".bin") {
            if !is_generic_zip && Self::is_benign_printer_settings_bin(&lower, bytes) {
                return None;
            }
            return Some((
                if is_generic_zip {
                    "DISALLOWED_ARCHIVE_BINARY_PART"
                } else {
                    "DISALLOWED_OOXML_BINARY_PART"
                },
                "Stripped non-allowlisted .bin binary part from container",
            ));
        }

        let is_xml_or_rels =
            lower == "[content_types].xml" || lower.ends_with(".rels") || lower.ends_with(".xml");
        if is_xml_or_rels && !is_generic_zip {
            return None;
        }

        // Allow policy-opted OLE2 only when explicitly enabled in generic ZIPs
        let is_ole2_magic = bytes.len() >= 8 && bytes[..8] == crate::sanitizers::ole2::OLE2_MAGIC;
        if Self::has_prohibited_binary_magic(bytes)
            && !(is_generic_zip && is_ole2_magic && policy.allow_legacy_ole2)
        {
            return Some((
                if is_generic_zip {
                    "DISALLOWED_ARCHIVE_BINARY_PART"
                } else {
                    "DISALLOWED_OOXML_BINARY_PART"
                },
                "Stripped binary part carrying prohibited executable/OLE2/metafile magic bytes",
            ));
        }

        if !is_generic_zip {
            // Strict OOXML part allowlist: XML/rels (handled above), benign printerSettings.bin
            // (handled above), allowlisted static media/fonts, or nested sanitizable files.
            if !Self::is_nested_sanitizable(&lower, bytes)
                && !Self::is_allowlisted_ooxml_static_asset(&lower, bytes)
            {
                return Some((
                    "DISALLOWED_OOXML_BINARY_PART",
                    "Stripped non-allowlisted binary part from OOXML package",
                ));
            }
        }

        None
    }

    /// Strict URI allowlist validator for OOXML `<Relationship Target="...">` values (`CSE-19`).
    /// Must be called ONLY on XML-unescaped strings (after `unescape_xml_attribute_value`).
    /// Allows strictly `https://`, `http://`, `mailto:`, `#` fragments, and (when internal)
    /// safe relative intra-package paths. Blocks `file:`, `smb:`, `mhtml:`, `search-ms:`,
    /// `ms-appinstaller:`, `ms-msdt:`, `javascript:`, `vbscript:`, `data:`, UNC paths, and
    /// obfuscated whitespace/control prefixes.
    pub fn is_allowed_ooxml_relationship_target(
        decoded_target: &str,
        is_external_mode: bool,
    ) -> bool {
        if decoded_target.is_empty() {
            return false;
        }
        // Reject any ASCII control character (including NUL, tab, CR, LF) used for scheme obfuscation
        if decoded_target.bytes().any(|b| b <= 0x1F || b == 0x7F) {
            return false;
        }
        let trimmed = decoded_target.trim();
        if trimmed.is_empty() {
            return false;
        }
        if trimmed.contains('\\') || trimmed.starts_with("//") {
            return false;
        }
        if trimmed.starts_with('#') {
            return true;
        }

        // Check for a URI scheme (`:` occurring before the first `/`, `?`, or `#`).
        // Per ECMA-376 Part 2 §9.3.2, explicit URI schemes are ONLY valid when
        // `TargetMode="External"`; omitting `TargetMode` on an external URL (e.g.
        // `<Relationship Type=".../attachedTemplate" Target="https://evil.example/a.dotm"/>`)
        // MUST be rejected.
        let scheme_end = trimmed.find(':');
        let first_delim = trimmed.find(['/', '?', '#']).unwrap_or(trimmed.len());
        if let Some(colon_idx) = scheme_end {
            if colon_idx < first_delim {
                if !is_external_mode {
                    return false;
                }
                let scheme = trimmed[..colon_idx].to_ascii_lowercase();
                return match scheme.as_str() {
                    "https" => {
                        trimmed[colon_idx + 1..].starts_with("//") && trimmed.len() > colon_idx + 3
                    }
                    "http" => {
                        trimmed[colon_idx + 1..].starts_with("//") && trimmed.len() > colon_idx + 3
                    }
                    "mailto" => !trimmed[colon_idx + 1..].trim().is_empty(),
                    _ => false,
                };
            }
        }

        // No explicit URI scheme: only permitted for internal intra-package relative paths
        !is_external_mode
    }

    /// Derives the safe macro-free file extension (`"xlsx" | "docx" | "pptx"`) whenever macros
    /// or macro-enabled ContentTypes were stripped from an Office container (`CSE-19`).
    pub fn derive_recommended_extension(
        format: DetectedFormat,
        file_name: &str,
        disarm_report: &[DisarmReportItem],
    ) -> Option<String> {
        let stripped_macro = disarm_report.iter().any(|item| {
            item.element_type == "MACRO_ENABLED_CONTENT_TYPE"
                || item.element_type == "VBA_MACRO_PROJECT"
        });
        if !stripped_macro {
            return None;
        }
        let lower_name = file_name.to_ascii_lowercase();
        match format {
            DetectedFormat::Xlsx => Some("xlsx".to_string()),
            DetectedFormat::Docx => Some("docx".to_string()),
            DetectedFormat::Pptx => Some("pptx".to_string()),
            _ if lower_name.ends_with(".xlsm") || lower_name.ends_with(".xltm") => {
                Some("xlsx".to_string())
            }
            _ if lower_name.ends_with(".docm") || lower_name.ends_with(".dotm") => {
                Some("docx".to_string())
            }
            _ if lower_name.ends_with(".pptm") || lower_name.ends_with(".potm") => {
                Some("pptx".to_string())
            }
            _ => None,
        }
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
                                    let v = unescape_xml_attribute_value(attr)?;
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
                                            let val_str = unescape_xml_attribute_value(attr)?;
                                            clean_elem.push_attribute((
                                                key_str.as_str(),
                                                val_str.as_str(),
                                            ));
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
                                    let v = unescape_xml_attribute_value(attr)?;
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

                                // 1. Drop relationships pointing to stripped macro/OLE/disallowed binary parts
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

                                // 2. Enforce strict URI scheme allowlist after XML entity decoding (`CSE-19`):
                                //    Only `https://`, `http://`, `mailto:`, `#`, and (for internal rels)
                                //    relative intra-package paths are permitted. External relationships are
                                //    retained ONLY for allowlisted benign hyperlinks when policy allows.
                                let is_external_mode =
                                    target_mode.trim().eq_ignore_ascii_case("external");
                                let target_allowed = Self::is_allowed_ooxml_relationship_target(
                                    &target,
                                    is_external_mode,
                                );
                                let is_benign_hyperlink = rel_type_lower.ends_with("/hyperlink")
                                    && target_allowed
                                    && !policy.strip_external_hyperlinks;

                                if policy.sanitize_office_external_relationships
                                    && (!target_allowed
                                        || (is_external_mode && !is_benign_hyperlink))
                                {
                                    if !rel_id.is_empty() {
                                        removed_rel_ids.insert(rel_id);
                                    }
                                    report.push(DisarmReportItem::new(
                                        "EXTERNAL_RELATIONSHIP_INJECTION",
                                        rels_path.to_string(),
                                        format!(
                                            "Removed disallowed or external <Relationship> targeting '{target}'"
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

    fn contains_dangerous_field_instruction(text: &str) -> bool {
        let upper = text.to_ascii_uppercase();
        if upper.contains("DDEAUTO")
            || upper.contains("INCLUDETEXT")
            || upper.contains("INCLUDEPICTURE")
            || upper.contains("CMD|")
            || upper.contains("POWERSHELL")
        {
            return true;
        }
        Self::contains_word_bounded_dde(&upper)
    }

    fn contains_word_bounded_dde(upper: &str) -> bool {
        let bytes = upper.as_bytes();
        let mut idx = 0usize;
        while idx + 3 <= bytes.len() {
            if &bytes[idx..idx + 3] == b"DDE" {
                let prev_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
                let next_ok = idx + 3 == bytes.len()
                    || matches!(
                        bytes[idx + 3],
                        b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b'\\'
                    );
                if prev_ok && next_ok {
                    return true;
                }
            }
            idx += 1;
        }
        false
    }

    /// Scans OOXML content XML once to concatenate adjacent `<w:instrText>` and `<w:t>`/`<a:t>`/`<t>`/`<f>`
    /// runs (including resolved XML character entities such as `&#68;DEAUTO`) across XML element
    /// boundaries, returning the set of event ordinals belonging to neutralized split-run DDE or
    /// field-code payloads (`DDEAUTO`, `DDE`, `INCLUDETEXT`, `INCLUDEPICTURE`, `CMD|`) (`CSE-19`).
    fn detect_split_run_dde_event_ordinals(xml_bytes: &[u8]) -> Result<HashSet<usize>, CdrError> {
        let mut reader = Reader::from_reader(xml_bytes);
        let mut buf = Vec::new();
        let mut flagged: HashSet<usize> = HashSet::new();
        let mut event_ordinal: usize = 0;

        let mut instr_depth: usize = 0;
        let mut text_depth: usize = 0;
        let mut instr_runs: Vec<(usize, String)> = Vec::new();
        let mut text_runs: Vec<(usize, String)> = Vec::new();

        let flush_runs = |runs: &mut Vec<(usize, String)>, flagged: &mut HashSet<usize>| {
            if runs.is_empty() {
                return;
            }
            let mut combined = String::new();
            for (_, seg) in runs.iter() {
                combined.push_str(seg);
            }
            if Self::contains_dangerous_field_instruction(&combined) {
                for (ord, _) in runs.iter() {
                    flagged.insert(*ord);
                }
            }
            runs.clear();
        };

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(event) => {
                    let ord = event_ordinal;
                    event_ordinal += 1;

                    match event {
                        Event::Start(ref e) => {
                            let local = e.name().local_name().into_inner().to_ascii_lowercase();
                            if local == "instrtext" {
                                instr_depth += 1;
                            } else if matches!(local.as_str(), "t" | "f") {
                                text_depth += 1;
                            } else if matches!(local.as_str(), "p" | "si" | "c") {
                                flush_runs(&mut instr_runs, &mut flagged);
                                flush_runs(&mut text_runs, &mut flagged);
                            }
                        }
                        Event::Empty(ref e) => {
                            let local = e.name().local_name().into_inner().to_ascii_lowercase();
                            if local == "fldchar" {
                                // Field boundary (`begin` / `separate` / `end`) flushes accumulated instrText runs
                                flush_runs(&mut instr_runs, &mut flagged);
                            }
                        }
                        Event::End(ref e) => {
                            let local = e.name().local_name().into_inner().to_ascii_lowercase();
                            if local == "instrtext" {
                                instr_depth = instr_depth.saturating_sub(1);
                            } else if matches!(local.as_str(), "t" | "f") {
                                text_depth = text_depth.saturating_sub(1);
                            } else if matches!(local.as_str(), "p" | "si" | "c" | "fldchar") {
                                flush_runs(&mut instr_runs, &mut flagged);
                                flush_runs(&mut text_runs, &mut flagged);
                            }
                        }
                        Event::Text(ref t) => {
                            let seg = t.as_ref().to_string();
                            if instr_depth > 0 {
                                instr_runs.push((ord, seg));
                            } else if text_depth > 0 {
                                text_runs.push((ord, seg));
                            }
                        }
                        Event::CData(ref c) => {
                            let seg = c.as_ref().to_string();
                            if instr_depth > 0 {
                                instr_runs.push((ord, seg));
                            } else if text_depth > 0 {
                                text_runs.push((ord, seg));
                            }
                        }
                        Event::GeneralRef(ref g) => {
                            if let Some(resolved) =
                                resolve_allowed_xml_general_ref(g.as_ref().as_bytes())
                            {
                                if instr_depth > 0 {
                                    instr_runs.push((ord, resolved));
                                } else if text_depth > 0 {
                                    text_runs.push((ord, resolved));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    return Err(CdrError::ParserCorruption(format!(
                        "Malformed OOXML content during split-run DDE scan: {e}"
                    )));
                }
            }
            buf.clear();
        }

        flush_runs(&mut instr_runs, &mut flagged);
        flush_runs(&mut text_runs, &mut flagged);

        Ok(flagged)
    }

    /// Post-CDR verification helper detecting residual split-run or attribute DDE/field codes (`CSE-19`).
    pub fn has_residual_dde_or_field_code(xml_bytes: &[u8]) -> Result<bool, CdrError> {
        if !Self::detect_split_run_dde_event_ordinals(xml_bytes)?.is_empty() {
            return Ok(true);
        }
        let mut reader = Reader::from_reader(xml_bytes);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                    let local = e.name().local_name().into_inner().to_ascii_lowercase();
                    if local == "ddelink" || local == "ddeitem" || local == "olelink" {
                        return Ok(true);
                    }
                    let attrs = crate::sanitizers::collect_validated_xml_attributes(e)?;
                    for attr in attrs {
                        let key_lower = attr.key.as_ref().to_ascii_lowercase();
                        let val_str = unescape_xml_attribute_value(&attr)?;
                        if key_lower.contains("ddeservice")
                            || key_lower.contains("ddetopic")
                            || Self::contains_dangerous_field_instruction(&val_str)
                        {
                            return Ok(true);
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(CdrError::ParserCorruption(format!(
                        "Malformed OOXML content during DDE verification: {e}"
                    )));
                }
            }
            buf.clear();
        }
        Ok(false)
    }

    /// Rewrites OOXML content XML parts to:
    /// 1. Strip `<ddeLink>`, `ddeService`, `ddeTopic`, split-run & inline `DDEAUTO`/`DDE`/
    ///    `INCLUDETEXT`/`INCLUDEPICTURE` fields, `=cmd|` formulas, and `<!DOCTYPE>` declarations
    ///    when `policy.strip_office_dde` is true (`Row 118`, `CSE-19`).
    /// 2. Strip dangling `r:id` / `r:embed` / `r:link` / `id` hyperlink and relationship attributes
    ///    that reference any `<Relationship>` removed from THIS part's `.rels` (`Row 115`, `CSE-19`).
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

        let flagged_split_ordinals = if policy.strip_office_dde {
            Self::detect_split_run_dde_event_ordinals(xml_bytes)?
        } else {
            HashSet::new()
        };

        let mut reader = Reader::from_reader(xml_bytes);
        let mut writer = Writer::new(Vec::with_capacity(xml_bytes.len()));
        let mut buf = Vec::new();
        let mut skip_depth = 0usize;
        let mut xml_depth = 0usize;
        let mut event_ordinal: usize = 0;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(event) => {
                    let ord = event_ordinal;
                    event_ordinal += 1;

                    if matches!(event, Event::DocType(_)) {
                        report.push(DisarmReportItem::new(
                            "OOXML_DOCTYPE_DECLARATION",
                            xml_path.to_string(),
                            "Removed DOCTYPE/ENTITY declaration from OOXML part",
                        ));
                        buf.clear();
                        continue;
                    }

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
                                let val_str = unescape_xml_attribute_value(&attr)?;

                                // Strip dangling `r:id` / `r:embed` / `r:link` / `id` attributes whose
                                // target `<Relationship>` was removed from THIS part's `.rels` (`CSE-19`).
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
                                        || Self::contains_dangerous_field_instruction(&val_str))
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
                                    "Neutralized DDE/DDEAUTO/field-code instruction attribute",
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
                            let is_flagged_split = flagged_split_ordinals.contains(&ord);
                            if policy.strip_office_dde
                                && (is_flagged_split
                                    || Self::contains_dangerous_field_instruction(raw_text))
                            {
                                report.push(DisarmReportItem::new(
                                    "DDE_FORMULA_INJECTION",
                                    xml_path.to_string(),
                                    if is_flagged_split {
                                        "Neutralized split-run DDE/field-code instruction across XML runs"
                                    } else {
                                        "Neutralized inline DDE/field-code instruction"
                                    },
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
                        Event::CData(ref c) => {
                            let raw_text = c.as_ref();
                            let is_flagged_split = flagged_split_ordinals.contains(&ord);
                            if policy.strip_office_dde
                                && (is_flagged_split
                                    || Self::contains_dangerous_field_instruction(raw_text))
                            {
                                report.push(DisarmReportItem::new(
                                    "DDE_FORMULA_INJECTION",
                                    xml_path.to_string(),
                                    if is_flagged_split {
                                        "Neutralized split-run CDATA DDE/field-code instruction across XML runs"
                                    } else {
                                        "Neutralized CDATA DDE/field-code instruction"
                                    },
                                ));
                                writer
                                    .write_event(Event::Text(quick_xml::events::BytesText::new(
                                        "REM_DISARMED",
                                    )))
                                    .map_err(|err| CdrError::XmlError(err.to_string()))?;
                            } else {
                                writer
                                    .write_event(Event::CData(c.clone().into_owned()))
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
                            if policy.strip_office_dde && flagged_split_ordinals.contains(&ord) {
                                report.push(DisarmReportItem::new(
                                    "DDE_FORMULA_INJECTION",
                                    xml_path.to_string(),
                                    "Neutralized entity-encoded split-run DDE/field-code instruction",
                                ));
                                writer
                                    .write_event(Event::Text(quick_xml::events::BytesText::new(
                                        "REM_DISARMED",
                                    )))
                                    .map_err(|err| CdrError::XmlError(err.to_string()))?;
                            } else {
                                writer
                                    .write_event(event.into_owned())
                                    .map_err(|err| CdrError::XmlError(err.to_string()))?;
                            }
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
            || lower_name.ends_with(".txt")
            || lower_name.ends_with(".csv")
            || bytes.starts_with(b"%PDF-")
            || bytes.starts_with(b"PK\x03\x04")
            || bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
            || (bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
            || (bytes.len() >= 8 && bytes[..8] == crate::sanitizers::ole2::OLE2_MAGIC)
    }
}
