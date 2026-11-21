use lopdf::{Dictionary, Document, Object, ObjectId};
use std::collections::HashSet;
use std::io::Cursor;
use tracing::info;

use crate::error::CdrError;
use crate::policy::{ResourceBudget, SanitizationPolicy, SignedPdfPolicy};
use crate::sanitizers::DisarmReportItem;

const MAX_PDF_WALK_DEPTH: u32 = 64;

/// Maximum permitted lexical array (`[...]`) and dictionary (`<<...>>`) nesting depth before `lopdf::Document::load_mem` (`RUSTSEC-2026-0187` `[Standard]`).
pub const MAX_PDF_NESTING_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PdfSpecialStructures {
    pub has_digital_signature: bool,
    pub has_facturx_af: bool,
    pub has_xfa: bool,
    pub has_active_content: bool,
}

#[derive(Debug, Default)]
struct PdfStructureScanState {
    saw_byterange: bool,
    saw_sig_marker: bool,
    direct_sig_dict: bool,
    has_facturx_af: bool,
    has_xfa: bool,
    has_active_content: bool,
}

/// Structural PDF Sanitizer (`BUG-CDR-06`, Phase 2.4, `CSE-20`)
///
/// Parses the PDF Object AST via `lopdf`, selectively cleans `/Root -> /Names`
/// (preserving `/Dests` and internal navigation), recursively walks both
/// dictionaries and arrays (catching inline `/Annots` and `/Next` chains),
/// strips `/EF` & `/EmbeddedFiles` unconditionally regardless of `/Type /Filespec`,
/// enforces `SignedPdfPolicy` before mutating signed PDFs, and inspects `/S` action
/// subtype values rather than blindly deleting `/S`.
pub struct PdfSanitizer;

impl PdfSanitizer {
    pub const MAX_PDF_NESTING_DEPTH: usize = MAX_PDF_NESTING_DEPTH;

    fn is_pdf_whitespace(b: u8) -> bool {
        matches!(b, 0x00 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
    }

    fn is_pdf_delimiter(b: u8) -> bool {
        matches!(
            b,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
    }

    fn is_pdf_token_boundary(raw: &[u8], idx: usize) -> bool {
        idx == 0
            || idx >= raw.len()
            || Self::is_pdf_whitespace(raw[idx])
            || Self::is_pdf_delimiter(raw[idx])
    }

    /// Attempts to parse a direct integer value following `/Length` at `after_keyword`
    /// (ignoring indirect references like `/Length 9 0 R`).
    fn parse_direct_length_hint(raw: &[u8], mut idx: usize) -> Option<usize> {
        let len = raw.len();
        while idx < len && Self::is_pdf_whitespace(raw[idx]) {
            idx += 1;
        }
        let num_start = idx;
        while idx < len && raw[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == num_start {
            return None;
        }
        let val = std::str::from_utf8(&raw[num_start..idx])
            .ok()?
            .parse::<usize>()
            .ok()?;

        // Reject indirect object reference `<obj> <gen> R`
        let mut look = idx;
        while look < len && Self::is_pdf_whitespace(raw[look]) {
            look += 1;
        }
        let gen_start = look;
        while look < len && raw[look].is_ascii_digit() {
            look += 1;
        }
        if look > gen_start {
            while look < len && Self::is_pdf_whitespace(raw[look]) {
                look += 1;
            }
            if look < len && raw[look] == b'R' && Self::is_pdf_token_boundary(raw, look + 1) {
                return None;
            }
        }
        Some(val)
    }

    /// Skips a PDF binary stream body (`stream\r?\n...endstream`), honoring a verified direct
    /// `/Length` hint first (`O(1)` jump) and falling back to scanning for a token-bounded
    /// `endstream` marker so arbitrary binary bytes (`(`, `[`, `<<`, `%`) inside compressed
    /// image/content streams can never blind the lexical depth guard (`CSE-20`, `RUSTSEC-2026-0187`).
    fn skip_pdf_stream_body(raw: &[u8], data_start: usize, length_hint: Option<usize>) -> usize {
        let len = raw.len();
        const ENDSTREAM: &[u8] = b"endstream";

        // 1. Honor verified `/Length` hint if `endstream` appears right after the declared payload
        if let Some(hint) = length_hint {
            if let Some(mut pos) = data_start.checked_add(hint) {
                if pos <= len {
                    // Optional single EOL (`\r\n`, `\n`, or `\r`) and trailing spaces before `endstream`
                    while pos < len && matches!(raw[pos], b'\r' | b'\n' | b' ' | b'\t') {
                        pos += 1;
                    }
                    if pos + ENDSTREAM.len() <= len
                        && &raw[pos..pos + ENDSTREAM.len()] == ENDSTREAM
                        && Self::is_pdf_token_boundary(raw, pos + ENDSTREAM.len())
                    {
                        return pos + ENDSTREAM.len();
                    }
                }
            }
        }

        // 2. Fallback: scan forward from `data_start` for token-bounded `endstream`
        let mut scan = data_start;
        while scan + ENDSTREAM.len() <= len {
            if &raw[scan..scan + ENDSTREAM.len()] == ENDSTREAM {
                let prev_ok = scan == data_start
                    || Self::is_pdf_whitespace(raw[scan - 1])
                    || Self::is_pdf_delimiter(raw[scan - 1]);
                let next_ok = Self::is_pdf_token_boundary(raw, scan + ENDSTREAM.len());
                if prev_ok && next_ok {
                    return scan + ENDSTREAM.len();
                }
            }
            scan += 1;
        }
        len
    }

    /// Single-pass `O(N)` stream-aware PDF lexical tokenizer that validates array (`[`/`]`) and
    /// dictionary (`<<`/`>>`) nesting depth prior to invoking `lopdf::Document::load_mem`
    /// (`RUSTSEC-2026-0187` mitigation, `CSE-20`).
    ///
    /// Tracks:
    /// - Binary `stream\r?\n...endstream` bodies (honoring `/Length` hints and `endstream` boundaries)
    /// - Comments (`%` outside strings/streams until `\r` or `\n`)
    /// - Literal strings (`(` ... `)` with balanced parens and `\` escapes: `\(`, `\)`, `\\`)
    /// - Hex strings (`<...>` distinct from `<<...>>` dictionaries, terminating safely on non-hex)
    pub fn validate_pdf_token_nesting_depth(raw: &[u8], max_depth: usize) -> Result<(), CdrError> {
        let mut depth: usize = 0;
        let mut in_comment = false;
        let mut string_paren_depth: usize = 0;
        let mut escaped = false;
        let mut pending_stream_length: Option<usize> = None;
        let mut just_closed_top_level_dict = false;
        let mut idx = 0usize;
        let len = raw.len();

        while idx < len {
            let b = raw[idx];

            if in_comment {
                if b == b'\r' || b == b'\n' {
                    in_comment = false;
                }
                idx += 1;
                continue;
            }

            if string_paren_depth > 0 {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'(' {
                    string_paren_depth = string_paren_depth.saturating_add(1);
                } else if b == b')' {
                    string_paren_depth = string_paren_depth.saturating_sub(1);
                }
                idx += 1;
                continue;
            }

            if Self::is_pdf_whitespace(b) {
                idx += 1;
                continue;
            }

            match b {
                b'%' => {
                    // Comments between `>>` and `stream` preserve `just_closed_top_level_dict`.
                    in_comment = true;
                    idx += 1;
                }
                b'(' => {
                    just_closed_top_level_dict = false;
                    string_paren_depth = 1;
                    escaped = false;
                    idx += 1;
                }
                b'[' => {
                    just_closed_top_level_dict = false;
                    depth = depth.saturating_add(1);
                    if depth > max_depth {
                        return Err(CdrError::ResourceLimitExceeded(format!(
                            "PDF structural nesting depth exceeds maximum allowed ({max_depth}) (RUSTSEC-2026-0187 mitigation)"
                        )));
                    }
                    idx += 1;
                }
                b']' => {
                    just_closed_top_level_dict = false;
                    depth = depth.saturating_sub(1);
                    idx += 1;
                }
                b'<' if idx + 1 < len && raw[idx + 1] == b'<' => {
                    just_closed_top_level_dict = false;
                    depth = depth.saturating_add(1);
                    if depth > max_depth {
                        return Err(CdrError::ResourceLimitExceeded(format!(
                            "PDF structural nesting depth exceeds maximum allowed ({max_depth}) (RUSTSEC-2026-0187 mitigation)"
                        )));
                    }
                    idx += 2;
                }
                b'<' => {
                    just_closed_top_level_dict = false;
                    // Hex string `<...>`: advance strictly over hex digits & PDF whitespace until `>`.
                    // Stop without consuming non-hex delimiters so an unclosed `<` cannot blind the guard.
                    idx += 1;
                    while idx < len {
                        let hb = raw[idx];
                        if hb == b'>' {
                            idx += 1;
                            break;
                        }
                        if hb.is_ascii_hexdigit() || Self::is_pdf_whitespace(hb) {
                            idx += 1;
                        } else {
                            break;
                        }
                    }
                }
                b'>' if idx + 1 < len && raw[idx + 1] == b'>' => {
                    let closing_top_level = depth == 1;
                    depth = depth.saturating_sub(1);
                    just_closed_top_level_dict = closing_top_level;
                    idx += 2;
                }
                b'/' => {
                    just_closed_top_level_dict = false;
                    // Consume the entire PDF Name token (ISO 32000-1 §7.3.5) so names like
                    // `/stream` or `/endobj` can NEVER be misclassified as keywords.
                    let name_start = idx;
                    idx += 1;
                    while idx < len && !Self::is_pdf_token_boundary(raw, idx) {
                        idx += 1;
                    }
                    if &raw[name_start..idx] == b"/Length" {
                        if let Some(hint) = Self::parse_direct_length_hint(raw, idx) {
                            pending_stream_length = Some(hint);
                        }
                    }
                }
                b's' => {
                    const STREAM_KW: &[u8] = b"stream";
                    let prev_ok = idx == 0 || Self::is_pdf_token_boundary(raw, idx - 1);
                    // ISO 32000-1 §7.3.8.1: `stream` is ONLY valid at depth 0 immediately
                    // following a closed top-level stream dictionary (`>>`), never inside
                    // arrays/dicts or after a `/` Name prefix.
                    if depth == 0
                        && just_closed_top_level_dict
                        && prev_ok
                        && idx + STREAM_KW.len() < len
                        && &raw[idx..idx + STREAM_KW.len()] == STREAM_KW
                    {
                        let after_kw = idx + STREAM_KW.len();
                        let data_start = if after_kw + 1 < len
                            && raw[after_kw] == b'\r'
                            && raw[after_kw + 1] == b'\n'
                        {
                            Some(after_kw + 2)
                        } else if raw[after_kw] == b'\n' {
                            Some(after_kw + 1)
                        } else {
                            None
                        };
                        if let Some(start) = data_start {
                            just_closed_top_level_dict = false;
                            let hint = pending_stream_length.take();
                            idx = Self::skip_pdf_stream_body(raw, start, hint);
                            continue;
                        }
                    }
                    just_closed_top_level_dict = false;
                    idx += 1;
                }
                b'e' => {
                    just_closed_top_level_dict = false;
                    const ENDOBJ_KW: &[u8] = b"endobj";
                    let prev_ok = idx == 0 || Self::is_pdf_token_boundary(raw, idx - 1);
                    if prev_ok
                        && idx + ENDOBJ_KW.len() <= len
                        && &raw[idx..idx + ENDOBJ_KW.len()] == ENDOBJ_KW
                        && Self::is_pdf_token_boundary(raw, idx + ENDOBJ_KW.len())
                    {
                        pending_stream_length = None;
                        idx += ENDOBJ_KW.len();
                    } else {
                        idx += 1;
                    }
                }
                _ => {
                    just_closed_top_level_dict = false;
                    idx += 1;
                }
            }
        }

        Ok(())
    }

    /// Pre-checks raw PDF byte budget and lexical array/dictionary nesting depth before `lopdf::Document::load_mem` (`RUSTSEC-2026-0187`).
    pub fn precheck_stream_nesting_and_counts(
        raw: &[u8],
        budget: &mut ResourceBudget,
    ) -> Result<(), CdrError> {
        budget.charge_bytes(raw.len() as u64)?;
        Self::validate_pdf_token_nesting_depth(raw, Self::MAX_PDF_NESTING_DEPTH)
    }

    /// Inspects a loaded PDF AST prior to mutation to detect cryptographic signatures
    /// (`/ByteRange` + `/Sig`), Factur-X `/AF` associated files, `/XFA`, and active threats (`CSE-20`).
    pub fn inspect_special_pdf_structures(
        doc: &Document,
        policy: &SanitizationPolicy,
    ) -> PdfSpecialStructures {
        let mut state = PdfStructureScanState::default();

        for obj in doc.objects.values() {
            Self::inspect_pdf_object_structures(obj, policy, 0, &mut state);
        }

        // Check for circular indirect `/Next` chains without mutating `doc`
        if !state.has_active_content && Self::has_indirect_next_cycle(doc) {
            state.has_active_content = true;
        }

        PdfSpecialStructures {
            has_digital_signature: state.direct_sig_dict
                || (state.saw_byterange && state.saw_sig_marker),
            has_facturx_af: state.has_facturx_af,
            has_xfa: state.has_xfa,
            has_active_content: state.has_active_content,
        }
    }

    fn has_indirect_next_cycle(doc: &Document) -> bool {
        let mut globally_visited: HashSet<ObjectId> = HashSet::new();
        for &start_id in doc.objects.keys() {
            if globally_visited.contains(&start_id) {
                continue;
            }
            let mut chain_visited: HashSet<ObjectId> = HashSet::new();
            let mut cursor = Some(start_id);
            while let Some(curr_id) = cursor {
                if !chain_visited.insert(curr_id) {
                    return true;
                }
                globally_visited.insert(curr_id);
                cursor = doc
                    .objects
                    .get(&curr_id)
                    .and_then(|o| o.as_dict().ok())
                    .and_then(|d| d.get(b"Next").ok())
                    .and_then(|n| n.as_reference().ok());
            }
        }
        false
    }

    fn inspect_pdf_object_structures(
        obj: &Object,
        policy: &SanitizationPolicy,
        depth: u32,
        state: &mut PdfStructureScanState,
    ) {
        if depth > MAX_PDF_WALK_DEPTH {
            state.has_active_content = true;
            return;
        }
        match obj {
            Object::Dictionary(dict) => {
                Self::inspect_pdf_dict_structures(dict, policy, depth, state);
            }
            Object::Stream(stream) => {
                Self::inspect_pdf_dict_structures(&stream.dict, policy, depth, state);
            }
            Object::Array(arr) => {
                for item in arr {
                    Self::inspect_pdf_object_structures(item, policy, depth + 1, state);
                }
            }
            _ => {}
        }
    }

    fn inspect_pdf_dict_structures(
        dict: &Dictionary,
        policy: &SanitizationPolicy,
        depth: u32,
        state: &mut PdfStructureScanState,
    ) {
        let has_br = dict.has(b"ByteRange");
        let is_sig_type = dict
            .get(b"Type")
            .ok()
            .and_then(|o| o.as_name().ok())
            .is_some_and(|n| n.eq_ignore_ascii_case(b"Sig"));
        let is_sig_ft = dict
            .get(b"FT")
            .ok()
            .and_then(|o| o.as_name().ok())
            .is_some_and(|n| n.eq_ignore_ascii_case(b"Sig"));
        let has_subfilter = dict.has(b"SubFilter");

        if has_br {
            state.saw_byterange = true;
            if is_sig_type || is_sig_ft || has_subfilter {
                state.direct_sig_dict = true;
            }
        }
        if is_sig_type || is_sig_ft {
            state.saw_sig_marker = true;
        }
        if dict.has(b"AF") {
            state.has_facturx_af = true;
            if policy.strip_pdf_attachments {
                state.has_active_content = true;
            }
        }
        if dict.has(b"XFA") {
            state.has_xfa = true;
            if policy.strip_pdf_scripts {
                state.has_active_content = true;
            }
        }
        if policy.strip_pdf_scripts && (dict.has(b"JS") || dict.has(b"JavaScript")) {
            state.has_active_content = true;
        }
        if policy.strip_pdf_actions
            && (dict.has(b"OpenAction")
                || dict.has(b"AA")
                || dict.has(b"Launch")
                || dict.has(b"RichMedia")
                || dict.has(b"SubmitForm")
                || dict.has(b"ImportData")
                || dict.has(b"GoToR")
                || dict.has(b"GoToE")
                || dict.has(b"URI"))
        {
            state.has_active_content = true;
        }
        if policy.strip_pdf_attachments && (dict.has(b"EF") || dict.has(b"EmbeddedFiles")) {
            state.has_active_content = true;
        }
        if let Ok(s_name) = dict.get(b"S").and_then(|o| o.as_name()) {
            if (policy.strip_pdf_scripts && (s_name == b"JavaScript" || s_name == b"JS"))
                || (policy.strip_pdf_actions && Self::is_dangerous_action_subtype(s_name))
            {
                state.has_active_content = true;
            }
        }

        for (_, child) in dict.iter() {
            Self::inspect_pdf_object_structures(child, policy, depth + 1, state);
        }
    }

    pub fn sanitize(
        input_bytes: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>), CdrError> {
        let mut budget = ResourceBudget::from_policy(policy);
        Self::sanitize_with_budget(input_bytes, policy, &mut budget)
    }

    pub fn sanitize_with_budget(
        input_bytes: &[u8],
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>), CdrError> {
        Self::precheck_stream_nesting_and_counts(input_bytes, budget)?;
        let mut doc = Document::load_mem(input_bytes)
            .map_err(|e| CdrError::ParserCorruption(format!("PDF AST parse error: {e}")))?;

        let mut disarm_report = Vec::new();

        // 0. CSE-20: Detect cryptographic signatures (`/ByteRange` + `/Sig`), `/AF` (Factur-X),
        //    and `/XFA` BEFORE mutating via `lopdf::Document::save_to`, enforcing `SignedPdfPolicy`.
        let special = Self::inspect_special_pdf_structures(&doc, policy);
        if special.has_digital_signature {
            match policy.signed_pdf_policy {
                SignedPdfPolicy::QuarantineWithReason => {
                    return Err(CdrError::OutputRejected(format!(
                        "SIGNED_PDF_QUARANTINE_REQUIRED: Digital signature (/ByteRange + /Sig) detected (active_content={}, facturx_af={}, xfa={}); refusing silent signature invalidation under SignedPdfPolicy::QuarantineWithReason",
                        special.has_active_content, special.has_facturx_af, special.has_xfa
                    )));
                }
                SignedPdfPolicy::AllowReadOnlyVerifiedClean => {
                    if special.has_active_content || special.has_xfa {
                        return Err(CdrError::OutputRejected(format!(
                            "SIGNED_PDF_ACTIVE_CONTENT_QUARANTINE_REQUIRED: Signed PDF contains active/disarmable content (active_content={}, facturx_af={}, xfa={}); refusing clean passthrough",
                            special.has_active_content, special.has_facturx_af, special.has_xfa
                        )));
                    }
                    disarm_report.push(DisarmReportItem::new(
                        "PDF_SIGNED_VERIFIED_CLEAN_PASSTHROUGH",
                        "Document",
                        "Verified zero active threats; preserved signed PDF bytes verbatim under SignedPdfPolicy::AllowReadOnlyVerifiedClean",
                    ));
                    return Ok((input_bytes.to_vec(), disarm_report));
                }
                SignedPdfPolicy::FlattenAndWarnSignatureBroken => {
                    disarm_report.push(DisarmReportItem::new(
                        "PDF_SIGNATURE_INVALIDATED_WARNING",
                        "Document",
                        format!(
                            "Digital signature (/ByteRange + /Sig) invalidated by CDR reconstruction under SignedPdfPolicy::FlattenAndWarnSignatureBroken (facturx_af={}, xfa={})",
                            special.has_facturx_af, special.has_xfa
                        ),
                    ));
                }
            }
        }

        // 1. Selectively clean `/Root -> /Names`, `/Root -> /AF`, and `/Root -> /AcroForm -> /XFA`
        Self::sanitize_catalog_structures(&mut doc, policy, &mut disarm_report);

        // 1b. Traverse indirect `/Next` chains with an explicit `visited: HashSet<ObjectId>`
        // cycle guard so circular `/Next` chains (`10 0 R -> 11 0 R -> 10 0 R`) terminate cleanly
        // and charge the cross-format object budget (Master Plan v2 §2.2, §2.4, §5).
        Self::break_indirect_next_cycles(&mut doc, budget, &mut disarm_report)?;

        // 2. Recursively walk all objects (both top-level dictionaries and arrays)
        let object_ids: Vec<ObjectId> = doc.objects.keys().copied().collect();
        for object_id in object_ids {
            budget.charge_object()?;

            let location = format!("Obj({},{})", object_id.0, object_id.1);
            if let Some(obj) = doc.objects.get_mut(&object_id) {
                Self::sanitize_pdf_object(obj, &location, policy, budget, 0, &mut disarm_report)?;
            }
        }

        // 3. Re-serialize clean AST into memory buffer
        let mut output_buffer = Cursor::new(Vec::with_capacity(input_bytes.len()));
        doc.save_to(&mut output_buffer).map_err(|e| {
            CdrError::ReconstructionFailure(format!("Failed saving disarmed PDF AST: {e}"))
        })?;

        Ok((output_buffer.into_inner(), disarm_report))
    }

    fn break_indirect_next_cycles(
        doc: &mut Document,
        budget: &mut ResourceBudget,
        reports: &mut Vec<DisarmReportItem>,
    ) -> Result<(), CdrError> {
        let object_ids: Vec<ObjectId> = doc.objects.keys().copied().collect();
        let mut globally_visited: HashSet<ObjectId> = HashSet::new();

        for start_id in object_ids {
            if globally_visited.contains(&start_id) {
                continue;
            }
            let mut chain_visited: HashSet<ObjectId> = HashSet::new();
            let mut cursor = Some(start_id);

            while let Some(curr_id) = cursor {
                budget.charge_object()?;
                if !chain_visited.insert(curr_id) {
                    // Cycle detected! Break `/Next` on `curr_id`
                    if let Some(Object::Dictionary(d)) = doc.objects.get_mut(&curr_id) {
                        d.remove(b"Next");
                    }
                    reports.push(DisarmReportItem::new(
                        "PDF_ACTION_NEXT_CYCLE",
                        format!("Obj({},{})[/Next]", curr_id.0, curr_id.1),
                        "Broke circular /Next reference chain in PDF action dictionary",
                    ));
                    break;
                }
                globally_visited.insert(curr_id);

                cursor = doc
                    .objects
                    .get(&curr_id)
                    .and_then(|o| o.as_dict().ok())
                    .and_then(|d| d.get(b"Next").ok())
                    .and_then(|n| n.as_reference().ok());
            }
        }
        Ok(())
    }

    fn sanitize_catalog_structures(
        doc: &mut Document,
        policy: &SanitizationPolicy,
        reports: &mut Vec<DisarmReportItem>,
    ) {
        let root_id = match doc
            .trailer
            .get(b"Root")
            .ok()
            .and_then(|o| o.as_reference().ok())
        {
            Some(id) => id,
            None => return,
        };

        let mut names_ref_to_clean: Option<ObjectId> = None;
        let mut acroform_ref_to_clean: Option<ObjectId> = None;

        if let Some(Object::Dictionary(root_dict)) = doc.objects.get_mut(&root_id) {
            let root_loc = format!("Obj({},{})[/Root]", root_id.0, root_id.1);

            if policy.strip_pdf_attachments && root_dict.has(b"AF") {
                root_dict.remove(b"AF");
                reports.push(DisarmReportItem::new(
                    "PDF_CATALOG_AF",
                    root_loc.clone(),
                    "Removed Associated Files array from Catalog",
                ));
            }

            match root_dict.get_mut(b"Names") {
                Ok(Object::Dictionary(names_dict)) => {
                    Self::clean_names_dictionary(names_dict, &root_loc, policy, reports);
                }
                Ok(Object::Reference(ref_id)) => {
                    names_ref_to_clean = Some(*ref_id);
                }
                _ => {}
            }

            if policy.strip_pdf_scripts {
                match root_dict.get_mut(b"AcroForm") {
                    Ok(Object::Dictionary(acro_dict)) => {
                        if acro_dict.has(b"XFA") {
                            acro_dict.remove(b"XFA");
                            reports.push(DisarmReportItem::new(
                                "PDF_ACROFORM_XFA",
                                root_loc,
                                "Removed XFA form scripting payload from AcroForm",
                            ));
                        }
                    }
                    Ok(Object::Reference(ref_id)) => {
                        acroform_ref_to_clean = Some(*ref_id);
                    }
                    _ => {}
                }
            }
        }

        if let Some(names_id) = names_ref_to_clean {
            let loc = format!("Obj({},{})[/Names]", names_id.0, names_id.1);
            if let Some(Object::Dictionary(names_dict)) = doc.objects.get_mut(&names_id) {
                Self::clean_names_dictionary(names_dict, &loc, policy, reports);
            }
        }

        if let Some(acro_id) = acroform_ref_to_clean {
            let loc = format!("Obj({},{})[/AcroForm]", acro_id.0, acro_id.1);
            if let Some(Object::Dictionary(acro_dict)) = doc.objects.get_mut(&acro_id) {
                if acro_dict.has(b"XFA") {
                    acro_dict.remove(b"XFA");
                    reports.push(DisarmReportItem::new(
                        "PDF_ACROFORM_XFA",
                        loc,
                        "Removed XFA form scripting payload from indirect AcroForm",
                    ));
                }
            }
        }
    }

    fn clean_names_dictionary(
        names_dict: &mut Dictionary,
        location: &str,
        policy: &SanitizationPolicy,
        reports: &mut Vec<DisarmReportItem>,
    ) {
        if policy.strip_pdf_scripts && names_dict.has(b"JavaScript") {
            names_dict.remove(b"JavaScript");
            reports.push(DisarmReportItem::new(
                "PDF_NAMES_JAVASCRIPT",
                location.to_string(),
                "Removed /JavaScript name tree while preserving /Dests navigation",
            ));
        }

        if policy.strip_pdf_attachments && names_dict.has(b"EmbeddedFiles") {
            names_dict.remove(b"EmbeddedFiles");
            reports.push(DisarmReportItem::new(
                "PDF_NAMES_EMBEDDED_FILES",
                location.to_string(),
                "Removed /EmbeddedFiles name tree while preserving /Dests navigation",
            ));
        }
    }

    fn sanitize_pdf_object(
        obj: &mut Object,
        location: &str,
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
        depth: u32,
        reports: &mut Vec<DisarmReportItem>,
    ) -> Result<(), CdrError> {
        if depth > MAX_PDF_WALK_DEPTH {
            return Err(CdrError::ResourceLimitExceeded(format!(
                "PDF nested object depth exceeded {MAX_PDF_WALK_DEPTH} at {location}"
            )));
        }

        match obj {
            Object::Dictionary(dict) => {
                let replace_with_null =
                    Self::sanitize_dictionary(dict, location, policy, budget, depth, reports)?;
                if replace_with_null {
                    *obj = Object::Null;
                }
            }
            Object::Array(arr) => {
                for (idx, item) in arr.iter_mut().enumerate() {
                    budget.charge_object()?;
                    let item_loc = format!("{location}[{idx}]");
                    Self::sanitize_pdf_object(item, &item_loc, policy, budget, depth + 1, reports)?;
                }
            }
            Object::Stream(stream) => {
                let _ = Self::sanitize_dictionary(
                    &mut stream.dict,
                    location,
                    policy,
                    budget,
                    depth,
                    reports,
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    fn sanitize_dictionary(
        dict: &mut Dictionary,
        location: &str,
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
        depth: u32,
        reports: &mut Vec<DisarmReportItem>,
    ) -> Result<bool, CdrError> {
        let mut neutralized_action_dict = false;
        let is_structural_node = dict
            .get(b"Type")
            .ok()
            .and_then(|o| o.as_name().ok())
            .map(|t| {
                t.eq_ignore_ascii_case(b"Catalog")
                    || t.eq_ignore_ascii_case(b"Page")
                    || t.eq_ignore_ascii_case(b"Pages")
                    || t.eq_ignore_ascii_case(b"Annot")
            })
            .unwrap_or(false);

        let s_subtype: Option<Vec<u8>> = dict
            .get(b"S")
            .ok()
            .and_then(|o| o.as_name().ok())
            .map(|n| n.to_vec());

        if let Some(subtype) = s_subtype {
            if policy.strip_pdf_scripts
                && (subtype.as_slice() == b"JavaScript" || subtype.as_slice() == b"JS")
            {
                dict.remove(b"S");
                dict.remove(b"JS");
                dict.remove(b"JavaScript");
                dict.remove(b"Next");
                neutralized_action_dict = !is_structural_node;
                info!(
                    "Disarmed PDF /S /{} script action at {}",
                    String::from_utf8_lossy(&subtype),
                    location
                );
                reports.push(DisarmReportItem::new(
                    format!("PDF_ACTION_S_{}", String::from_utf8_lossy(&subtype)),
                    location.to_string(),
                    "Neutralized JavaScript action dictionary (replaced with null)",
                ));
            } else if policy.strip_pdf_actions && Self::is_dangerous_action_subtype(&subtype) {
                let subtype_name = String::from_utf8_lossy(&subtype).into_owned();
                dict.remove(b"S");
                dict.remove(b"F");
                dict.remove(b"Win");
                dict.remove(b"Mac");
                dict.remove(b"Unix");
                dict.remove(b"URI");
                dict.remove(b"Next");
                neutralized_action_dict = !is_structural_node;
                info!("Disarmed PDF /S /{} action at {}", subtype_name, location);
                reports.push(DisarmReportItem::new(
                    format!("PDF_ACTION_S_{subtype_name}"),
                    location.to_string(),
                    "Neutralized active PDF action dictionary (replaced with null)",
                ));
            }
        }

        if policy.strip_pdf_scripts {
            for &key in &[
                b"JS".as_slice(),
                b"JavaScript".as_slice(),
                b"XFA".as_slice(),
            ] {
                if dict.has(key) {
                    dict.remove(key);
                    let key_name = String::from_utf8_lossy(key).into_owned();
                    reports.push(DisarmReportItem::new(
                        format!("PDF_{}", key_name.to_ascii_uppercase()),
                        location.to_string(),
                        "Removed embedded PDF JavaScript/XFA key",
                    ));
                }
            }
        }

        if policy.strip_pdf_actions {
            for &key in &[
                b"OpenAction".as_slice(),
                b"AA".as_slice(),
                b"Launch".as_slice(),
                b"RichMedia".as_slice(),
                b"SubmitForm".as_slice(),
                b"ImportData".as_slice(),
                b"GoToR".as_slice(),
                b"GoToE".as_slice(),
                b"URI".as_slice(),
            ] {
                if dict.has(key) {
                    dict.remove(key);
                    let key_name = String::from_utf8_lossy(key).into_owned();
                    reports.push(DisarmReportItem::new(
                        format!("PDF_{}", key_name.to_ascii_uppercase()),
                        location.to_string(),
                        "Removed automatic/external PDF trigger key",
                    ));
                }
            }
        }

        if policy.strip_pdf_attachments {
            // CSE-20: Strip `/EF` (Embedded File streams) unconditionally on EVERY dictionary
            // regardless of whether `/Type /Filespec` is explicitly declared.
            if dict.has(b"EF") {
                dict.remove(b"EF");
                reports.push(DisarmReportItem::new(
                    "PDF_FILESPEC_EF",
                    location.to_string(),
                    "Removed embedded file stream dictionary (/EF) unconditionally",
                ));
            }

            if dict.has(b"EmbeddedFiles") {
                dict.remove(b"EmbeddedFiles");
                reports.push(DisarmReportItem::new(
                    "PDF_EMBEDDED_FILES",
                    location.to_string(),
                    "Removed embedded files dictionary entry (/EmbeddedFiles)",
                ));
            }

            if dict.has(b"AF") {
                dict.remove(b"AF");
                reports.push(DisarmReportItem::new(
                    "PDF_CATALOG_AF",
                    location.to_string(),
                    "Removed Associated Files (/AF) attachment array",
                ));
            }
        }

        let keys: Vec<Vec<u8>> = dict.iter().map(|(k, _)| k.clone()).collect();
        for key in keys {
            let mut remove_empty_action = false;
            if let Ok(child_obj) = dict.get_mut(&key) {
                budget.charge_object()?;
                let child_loc = format!("{}/{}", location, String::from_utf8_lossy(&key));
                Self::sanitize_pdf_object(
                    child_obj,
                    &child_loc,
                    policy,
                    budget,
                    depth + 1,
                    reports,
                )?;
                if key.as_slice() == b"A" {
                    match child_obj {
                        Object::Null => {
                            remove_empty_action = true;
                        }
                        Object::Dictionary(child_dict) if child_dict.is_empty() => {
                            remove_empty_action = true;
                        }
                        _ => {}
                    }
                }
            }
            if remove_empty_action {
                dict.remove(&key);
            }
        }

        Ok(neutralized_action_dict)
    }

    pub fn is_dangerous_action_subtype(subtype: &[u8]) -> bool {
        matches!(
            subtype,
            b"Launch"
                | b"URI"
                | b"SubmitForm"
                | b"ImportData"
                | b"GoToR"
                | b"GoToE"
                | b"Movie"
                | b"Sound"
                | b"Rendition"
                | b"RichMedia"
        )
    }
}
