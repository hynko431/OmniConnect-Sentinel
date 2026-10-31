use crate::error::{CdrError, Result};
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::DisarmReportItem;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};
use std::io::Cursor;

pub struct SvgSanitizer;

impl SvgSanitizer {
    /// Sanitizes an SVG XML document using `quick-xml` (`EV-04`, Phase 2.6, Row 133):
    /// - Removes `<!DOCTYPE>` and `<!ENTITY>` declarations (`Event::DocType`)
    /// - Removes `<script>`, `<foreignObject>`, `<iframe>`, `<embed>`, `<object>`, `<handler>`
    /// - Removes `on*` event attributes (`onload`, `onerror`, `onclick`, etc.)
    /// - Removes any `href` or `xlink:href` attribute that is not an internal `#anchor` reference
    /// - Removes `<style>` elements or `style` attributes containing `url(`, `@import`, `javascript:`, or `expression(`
    pub fn sanitize(
        input: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        let mut budget = ResourceBudget::from_policy(policy);
        Self::sanitize_with_budget(input, policy, &mut budget)
    }

    pub fn sanitize_with_budget(
        input: &[u8],
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        if input.len() as u64 > policy.max_decompressed_bytes {
            return Err(CdrError::ResourceLimitExceeded(
                "SVG input exceeds max_decompressed_bytes".to_string(),
            ));
        }
        budget.check_deadline()?;
        budget.charge_bytes(input.len() as u64)?;

        // Also check raw input for `<!ENTITY` inside any DOCTYPE preamble
        let raw_lower = String::from_utf8_lossy(input).to_ascii_lowercase();

        let mut reader = Reader::from_reader(Cursor::new(input));
        let mut writer = Writer::new(Cursor::new(Vec::with_capacity(input.len())));
        let mut buf = Vec::new();
        let mut reports = Vec::new();
        let mut skip_depth: usize = 0;
        let mut in_style_depth: usize = 0;

        if raw_lower.contains("<!entity") {
            reports.push(DisarmReportItem::new(
                "SVG_XML_ENTITY",
                "<!ENTITY>",
                "REMOVED",
            ));
        }

        loop {
            budget.check_deadline()?;
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::DocType(_)) => {
                    reports.push(DisarmReportItem::new(
                        "SVG_DOCTYPE_DECLARATION",
                        "<!DOCTYPE>",
                        "REMOVED",
                    ));
                    buf.clear();
                    continue;
                }
                Ok(Event::Start(e)) => {
                    budget.charge_object()?;
                    if skip_depth > 0 {
                        skip_depth += 1;
                        buf.clear();
                        continue;
                    }
                    let tag_lower =
                        String::from_utf8_lossy(e.local_name().as_ref()).to_ascii_lowercase();
                    if Self::is_forbidden_tag(&tag_lower) {
                        reports.push(DisarmReportItem::new(
                            "SVG_ACTIVE_ELEMENT",
                            format!("<{}>", tag_lower),
                            "REMOVED",
                        ));
                        skip_depth = 1;
                        buf.clear();
                        continue;
                    }
                    if tag_lower == "style" {
                        in_style_depth += 1;
                    }
                    let cleaned = Self::filter_attributes(&e, &tag_lower, &mut reports)?;
                    writer
                        .write_event(Event::Start(cleaned))
                        .map_err(|err| CdrError::XmlError(err.to_string()))?;
                }
                Ok(Event::Empty(e)) => {
                    budget.charge_object()?;
                    if skip_depth > 0 {
                        buf.clear();
                        continue;
                    }
                    let tag_lower =
                        String::from_utf8_lossy(e.local_name().as_ref()).to_ascii_lowercase();
                    if Self::is_forbidden_tag(&tag_lower) {
                        reports.push(DisarmReportItem::new(
                            "SVG_ACTIVE_ELEMENT",
                            format!("<{}/>", tag_lower),
                            "REMOVED",
                        ));
                        buf.clear();
                        continue;
                    }
                    let cleaned = Self::filter_attributes(&e, &tag_lower, &mut reports)?;
                    writer
                        .write_event(Event::Empty(cleaned))
                        .map_err(|err| CdrError::XmlError(err.to_string()))?;
                }
                Ok(Event::End(e)) => {
                    if skip_depth > 0 {
                        skip_depth -= 1;
                        buf.clear();
                        continue;
                    }
                    let tag_lower =
                        String::from_utf8_lossy(e.local_name().as_ref()).to_ascii_lowercase();
                    if tag_lower == "style" && in_style_depth > 0 {
                        in_style_depth -= 1;
                    }
                    writer
                        .write_event(Event::End(e))
                        .map_err(|err| CdrError::XmlError(err.to_string()))?;
                }
                Ok(Event::Text(t)) => {
                    if skip_depth > 0 {
                        buf.clear();
                        continue;
                    }
                    if in_style_depth > 0 {
                        let css_lower =
                            String::from_utf8_lossy(t.as_ref()).to_ascii_lowercase();
                        if Self::has_dangerous_css(&css_lower) {
                            reports.push(DisarmReportItem::new(
                                "SVG_STYLE_EXTERNAL_OR_SCRIPT",
                                "<style>",
                                "REMOVED",
                            ));
                            buf.clear();
                            continue;
                        }
                    }
                    writer
                        .write_event(Event::Text(t))
                        .map_err(|err| CdrError::XmlError(err.to_string()))?;
                }
                Ok(Event::CData(c)) => {
                    if skip_depth > 0 {
                        buf.clear();
                        continue;
                    }
                    if in_style_depth > 0 {
                        let css_lower =
                            String::from_utf8_lossy(c.as_ref()).to_ascii_lowercase();
                        if Self::has_dangerous_css(&css_lower) {
                            reports.push(DisarmReportItem::new(
                                "SVG_STYLE_EXTERNAL_OR_SCRIPT",
                                "<style>",
                                "REMOVED",
                            ));
                            buf.clear();
                            continue;
                        }
                    }
                    writer
                        .write_event(Event::CData(c))
                        .map_err(|err| CdrError::XmlError(err.to_string()))?;
                }
                Ok(ev) => {
                    if skip_depth == 0 {
                        writer
                            .write_event(ev)
                            .map_err(|err| CdrError::XmlError(err.to_string()))?;
                    }
                }
                Err(e) => {
                    return Err(CdrError::ParserCorruption(format!(
                        "Malformed SVG XML: {}",
                        e
                    )));
                }
            }
            buf.clear();
        }

        Ok((writer.into_inner().into_inner(), reports))
    }

    pub fn is_forbidden_tag(tag_lower: &str) -> bool {
        matches!(
            tag_lower,
            "script"
                | "foreignobject"
                | "iframe"
                | "embed"
                | "object"
                | "handler"
                | "set"
                | "animate"
        )
    }

    pub fn has_dangerous_css(css_lower: &str) -> bool {
        css_lower.contains("url(")
            || css_lower.contains("@import")
            || css_lower.contains("javascript:")
            || css_lower.contains("vbscript:")
            || css_lower.contains("expression(")
    }

    fn filter_attributes<'a>(
        elem: &BytesStart<'a>,
        tag_lower: &str,
        reports: &mut Vec<DisarmReportItem>,
    ) -> Result<BytesStart<'static>> {
        let name_str = String::from_utf8_lossy(elem.name().as_ref()).into_owned();
        let mut cleaned = BytesStart::new(name_str);

        for attr_res in elem.attributes() {
            let attr = attr_res.map_err(|e| CdrError::XmlError(e.to_string()))?;
            let key_raw = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
            let key_lower = key_raw.to_ascii_lowercase();
            let val_str = String::from_utf8_lossy(&attr.value).into_owned();
            let val_trimmed = val_str.trim().to_ascii_lowercase();

            if key_lower.starts_with("on") {
                reports.push(DisarmReportItem::new(
                    "SVG_EVENT_HANDLER",
                    format!("{}@{}", tag_lower, key_raw),
                    "STRIPPED",
                ));
                continue;
            }

            // Only internal `#anchor` fragment references are permitted on `href` / `xlink:href` (Row 133)
            if (key_lower == "href" || key_lower.ends_with(":href"))
                && !val_trimmed.starts_with('#')
            {
                reports.push(DisarmReportItem::new(
                    "SVG_EXTERNAL_OR_SCRIPT_HREF",
                    format!("{}@{}", tag_lower, key_raw),
                    "STRIPPED",
                ));
                continue;
            }

            if key_lower == "style" && Self::has_dangerous_css(&val_trimmed) {
                reports.push(DisarmReportItem::new(
                    "SVG_DANGEROUS_STYLE",
                    format!("{}@style", tag_lower),
                    "STRIPPED",
                ));
                continue;
            }

            cleaned.push_attribute((key_raw.as_str(), val_str.as_str()));
        }

        Ok(cleaned)
    }
}

