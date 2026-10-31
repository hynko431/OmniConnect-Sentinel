use crate::error::{CdrError, Result};
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::DisarmReportItem;

pub struct TextCsvSanitizer;

impl TextCsvSanitizer {
    /// Sanitizes plain-text and CSV files (Phase 2.6, Row 135):
    /// - Validates UTF-8
    /// - Strips Unicode Bidirectional Override characters (CVE-2021-42574 Trojan Source)
    /// - Neutralizes leading `=`, `+`, `-`, `@`, `\t`, `\r` formula cells in CSV (prefixes with `'`)
    pub fn sanitize(
        input: &[u8],
        policy: &SanitizationPolicy,
        is_csv: bool,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        let mut budget = ResourceBudget::from_policy(policy);
        Self::sanitize_with_budget(input, policy, &mut budget, is_csv)
    }

    pub fn sanitize_with_budget(
        input: &[u8],
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
        is_csv: bool,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        if input.len() as u64 > policy.max_decompressed_bytes {
            return Err(CdrError::ResourceLimitExceeded(
                "Text/CSV input exceeds max_decompressed_bytes".to_string(),
            ));
        }
        budget.check_deadline()?;
        budget.charge_object()?;
        budget.charge_bytes(input.len() as u64)?;

        let text = std::str::from_utf8(input)
            .map_err(|e| CdrError::ParserCorruption(format!("Invalid UTF-8 text: {}", e)))?;

        let mut reports = Vec::new();
        let mut bidi_count = 0usize;
        let mut cleaned_chars = String::with_capacity(text.len());

        for c in text.chars() {
            if Self::is_bidi_override_char(c) {
                bidi_count += 1;
            } else {
                cleaned_chars.push(c);
            }
        }

        if bidi_count > 0 {
            reports.push(DisarmReportItem::new(
                "UNICODE_BIDI_OVERRIDE",
                "TextStream",
                format!("STRIPPED_{}_CHARS", bidi_count),
            ));
        }

        if is_csv && policy.strip_office_dde {
            let mut out_lines = Vec::new();
            for (line_idx, line) in cleaned_chars.lines().enumerate() {
                budget.check_deadline()?;
                let mut cells = Vec::new();
                for cell in line.split(',') {
                    if Self::is_dangerous_csv_cell(cell) {
                        reports.push(DisarmReportItem::new(
                            "CSV_DDE_FORMULA",
                            format!("Row_{}", line_idx + 1),
                            "NEUTRALIZED",
                        ));
                        cells.push(format!("'{}", cell));
                    } else {
                        cells.push(cell.to_string());
                    }
                }
                out_lines.push(cells.join(","));
            }
            let rebuilt = out_lines.join("\n");
            return Ok((rebuilt.into_bytes(), reports));
        }

        Ok((cleaned_chars.into_bytes(), reports))
    }

    pub fn is_bidi_override_char(c: char) -> bool {
        matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
    }

    pub fn is_dangerous_csv_cell(cell: &str) -> bool {
        if cell.is_empty() || cell.starts_with('\'') {
            return false;
        }
        let trimmed = cell.trim_start_matches([' ', '\t', '\r']);
        trimmed.starts_with('=')
            || trimmed.starts_with('+')
            || trimmed.starts_with('-')
            || trimmed.starts_with('@')
            || cell.starts_with('\t')
            || cell.starts_with('\r')
    }
}

