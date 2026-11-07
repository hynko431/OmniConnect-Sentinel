pub mod image;
pub mod ole2;
pub mod openxml;
pub mod pdf;
pub mod svg;
pub mod text;

use crate::error::{CdrError, Result};
use quick_xml::events::attributes::Attribute;
use quick_xml::events::BytesStart;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Maximum attributes permitted on a single XML start/empty tag (`RUSTSEC-2026-0194` `[Standard]`).
pub const MAX_XML_ATTRIBUTES_PER_ELEMENT: usize = 256;

/// Maximum `xmlns` / `xmlns:*` declarations permitted on a single XML element (`RUSTSEC-2026-0195` `[Standard]`).
pub const MAX_XMLNS_DECLS_PER_ELEMENT: usize = 32;

/// Maximum byte length of a single `xmlns` namespace URI (`RUSTSEC-2026-0195` `[Standard]`).
pub const MAX_XMLNS_URI_BYTES: usize = 2_048;

/// Maximum XML element nesting depth permitted across SVG and OpenXML parts (`RUSTSEC-2026-0195` `[Standard]`).
pub const MAX_XML_ELEMENT_DEPTH: usize = 256;

/// Collects and validates all attributes on an XML element in `O(A)` amortized time (`RUSTSEC-2026-0194`, `RUSTSEC-2026-0195`):
/// 1. Disables `quick-xml`'s quadratic pairwise scan via `.with_checks(false)`.
/// 2. Never calls `.flatten()` — any malformed attribute (`Err(AttrError)`) fails closed.
/// 3. Enforces `MAX_XML_ATTRIBUTES_PER_ELEMENT` (`256`).
/// 4. Rejects case-insensitive duplicate attribute names in `O(1)` amortized time per attribute using a `HashSet`,
///    preventing XML attribute smuggling (`TargetMode="External"` + `TargetMode="Internal"`).
/// 5. Enforces `MAX_XMLNS_DECLS_PER_ELEMENT` (`32`), `MAX_XMLNS_URI_BYTES` (`2048`), and dangerous URI scheme bans on `xmlns` declarations.
pub fn collect_validated_xml_attributes<'a>(
    elem: &'a BytesStart<'a>,
) -> Result<Vec<Attribute<'a>>> {
    let mut attrs = Vec::new();
    let mut seen_keys: HashSet<Vec<u8>> = HashSet::with_capacity(16);
    let mut xmlns_count: usize = 0;

    for attr_res in elem.attributes().with_checks(false) {
        let attr = attr_res
            .map_err(|err| CdrError::ParserCorruption(format!("Malformed XML attribute: {err}")))?;

        if attrs.len() >= MAX_XML_ATTRIBUTES_PER_ELEMENT {
            return Err(CdrError::ResourceLimitExceeded(format!(
                "XML element exceeds maximum attribute count ({MAX_XML_ATTRIBUTES_PER_ELEMENT}) (RUSTSEC-2026-0194 mitigation)"
            )));
        }

        let key_lower = attr.key.as_ref().to_ascii_lowercase();
        if !seen_keys.insert(key_lower.clone().into_bytes()) {
            return Err(CdrError::ParserCorruption(
                "Duplicate XML attribute detected (RUSTSEC-2026-0194 / XML attribute smuggling mitigation)"
                    .to_string(),
            ));
        }

        if key_lower == "xmlns" || key_lower.starts_with("xmlns:") {
            xmlns_count += 1;
            if xmlns_count > MAX_XMLNS_DECLS_PER_ELEMENT {
                return Err(CdrError::ResourceLimitExceeded(format!(
                    "XML element exceeds maximum xmlns declarations ({MAX_XMLNS_DECLS_PER_ELEMENT}) (RUSTSEC-2026-0195 mitigation)"
                )));
            }
            if attr.value.len() > MAX_XMLNS_URI_BYTES {
                return Err(CdrError::ResourceLimitExceeded(format!(
                    "xmlns URI exceeds {MAX_XMLNS_URI_BYTES} bytes (RUSTSEC-2026-0195 mitigation)"
                )));
            }
            let uri_lower = attr.value.trim().to_ascii_lowercase();
            if uri_lower.starts_with("javascript:")
                || uri_lower.starts_with("vbscript:")
                || uri_lower.starts_with("data:")
                || uri_lower.starts_with("file:")
                || uri_lower.starts_with("ms-msdt:")
                || uri_lower.starts_with("mhtml:")
            {
                return Err(CdrError::ParserCorruption(
                    "Forbidden URI scheme in xmlns declaration (RUSTSEC-2026-0195 mitigation)"
                        .to_string(),
                ));
            }
        }

        attrs.push(attr);
    }

    Ok(attrs)
}

/// Validates whether a `quick-xml` `Event::GeneralRef` entity reference is a safe standard XML
/// predefined entity (`lt`, `gt`, `amp`, `apos`, `quot`) or a bounded numeric character reference (`#...`).
/// Custom/DTD general entities (such as `&lol;` or `&xxe;`) return `false`.
pub fn is_allowed_xml_general_ref(raw_ref: &[u8]) -> bool {
    if matches!(raw_ref, b"lt" | b"gt" | b"amp" | b"apos" | b"quot") {
        return true;
    }
    if let Some(rest) = raw_ref.strip_prefix(b"#") {
        if rest.is_empty() || rest.len() > 9 {
            return false;
        }
        let code =
            if let Some(hex_bytes) = rest.strip_prefix(b"x").or_else(|| rest.strip_prefix(b"X")) {
                std::str::from_utf8(hex_bytes)
                    .ok()
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
            } else {
                std::str::from_utf8(rest)
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
            };
        return code.is_some_and(|c| c > 0 && char::from_u32(c).is_some());
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisarmReportItem {
    pub element_type: String,
    pub location_path: String,
    pub action_taken: String,
    pub severity: String,
}

impl DisarmReportItem {
    pub fn new(
        element_type: impl Into<String>,
        location_path: impl Into<String>,
        action_taken: impl Into<String>,
    ) -> Self {
        Self {
            element_type: element_type.into(),
            location_path: location_path.into(),
            action_taken: action_taken.into(),
            severity: "HIGH".to_string(),
        }
    }
}
