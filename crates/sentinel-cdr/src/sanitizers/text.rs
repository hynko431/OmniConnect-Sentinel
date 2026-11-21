use crate::error::{CdrError, Result};
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::DisarmReportItem;

/// Hard upper bound on a single RFC 4180 CSV field in memory (`CSE-19`, `O(max_cell)` bounded).
pub const MAX_CSV_CELL_BYTES: usize = 4 * 1024 * 1024;

pub struct TextCsvSanitizer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CsvState {
    FieldStart,
    Unquoted,
    Quoted,
    QuoteAfterQuoted,
}

impl TextCsvSanitizer {
    /// Sanitizes plain-text and CSV files (`Phase 2.6, Row 135`, `CSE-19`):
    /// - Validates UTF-8
    /// - Strips Unicode Bidirectional Override characters (CVE-2021-42574 Trojan Source)
    /// - Parses CSV with a streaming RFC 4180 finite-state parser (`O(N)` time, `O(max_cell)` RAM)
    /// - Preserves valid signed numeric literals (`-45000.00`, `+3.14`, `-1.5e-3`) untouched
    /// - Disarms formula triggers (`=`, `@`, `\t`, `\r`, or non-numeric `+`/`-` expressions)
    ///   in both unquoted and quoted cells while preserving proper RFC 4180 quoting.
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
            .map_err(|e| CdrError::ParserCorruption(format!("Invalid UTF-8 text: {e}")))?;

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
                format!("STRIPPED_{bidi_count}_CHARS"),
            ));
        }

        if is_csv && policy.strip_office_dde {
            let max_cell = (policy.max_decompressed_bytes as usize).min(MAX_CSV_CELL_BYTES);
            let rebuilt =
                Self::sanitize_csv_rfc4180(&cleaned_chars, budget, max_cell, &mut reports)?;
            return Ok((rebuilt.into_bytes(), reports));
        }

        Ok((cleaned_chars.into_bytes(), reports))
    }

    pub fn is_bidi_override_char(c: char) -> bool {
        matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
    }

    /// Matches `^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$` in `O(L)` without backtracking.
    pub fn is_valid_signed_number(s: &str) -> bool {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return false;
        }
        let mut i = 0usize;
        if bytes[i] == b'+' || bytes[i] == b'-' {
            i += 1;
        }
        let mut int_digits = 0usize;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            int_digits += 1;
            i += 1;
        }
        let mut frac_digits = 0usize;
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                frac_digits += 1;
                i += 1;
            }
        }
        if int_digits == 0 && frac_digits == 0 {
            return false;
        }
        if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
            i += 1;
            if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                i += 1;
            }
            let mut exp_digits = 0usize;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                exp_digits += 1;
                i += 1;
            }
            if exp_digits == 0 {
                return false;
            }
        }
        i == bytes.len()
    }

    /// Evaluates an unescaped RFC 4180 CSV field value for spreadsheet formula / DDE triggers.
    /// Valid signed numbers (`-45000.00`, `+3.14`, `-1.5e-3`) return `false` (preserved untouched);
    /// formula triggers (`=`, `@`, `\t`, `\r`, or non-numeric `+`/`-` expressions, including
    /// payloads hidden behind leading UTF-8 BOM `\u{FEFF}`) return `true`.
    pub fn is_dangerous_csv_cell(cell: &str) -> bool {
        let stripped = cell.trim_start_matches('\u{FEFF}');
        if stripped.is_empty() || stripped.starts_with('\'') {
            return false;
        }
        if stripped.starts_with('\t') || stripped.starts_with('\r') {
            return true;
        }
        let after_spaces = stripped.trim_start_matches(' ');
        if after_spaces.starts_with('\t') || after_spaces.starts_with('\r') {
            return true;
        }
        let trimmed = stripped.trim_start_matches([' ', '\t', '\r']);
        if trimmed.starts_with('=') || trimmed.starts_with('@') {
            return true;
        }
        if trimmed.starts_with('+') || trimmed.starts_with('-') {
            return !Self::is_valid_signed_number(stripped.trim_matches(' '));
        }
        false
    }

    fn emit_rfc4180_field(out: &mut String, field: &str, was_quoted: bool) {
        let needs_quotes = was_quoted
            || field.contains(',')
            || field.contains('"')
            || field.contains('\n')
            || field.contains('\r');
        if !needs_quotes {
            out.push_str(field);
            return;
        }
        out.push('"');
        for ch in field.chars() {
            if ch == '"' {
                out.push_str("\"\"");
            } else {
                out.push(ch);
            }
        }
        out.push('"');
    }

    /// Streaming RFC 4180 finite-state CSV sanitizer (`CSE-19`, `O(N)` time, `O(max_cell)` memory).
    fn sanitize_csv_rfc4180(
        input: &str,
        budget: &mut ResourceBudget,
        max_cell_bytes: usize,
        reports: &mut Vec<DisarmReportItem>,
    ) -> Result<String> {
        let mut out = String::with_capacity(input.len().saturating_add(16));
        let mut cell = String::new();
        let mut was_quoted = false;
        let mut state = CsvState::FieldStart;
        let mut row_num: usize = 1;
        let mut col_num: usize = 1;
        let mut has_any_content_in_row = false;

        let mut chars = input.chars().peekable();
        while let Some(ch) = chars.next() {
            match state {
                CsvState::FieldStart => match ch {
                    '"' => {
                        was_quoted = true;
                        has_any_content_in_row = true;
                        state = CsvState::Quoted;
                    }
                    ',' => {
                        Self::finalize_csv_field(
                            &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                        );
                        out.push(',');
                        was_quoted = false;
                        col_num += 1;
                        has_any_content_in_row = true;
                    }
                    '\r' => {
                        let is_crlf = chars.peek() == Some(&'\n');
                        if is_crlf {
                            chars.next();
                        }
                        if has_any_content_in_row {
                            Self::finalize_csv_field(
                                &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                            );
                        }
                        out.push_str(if is_crlf { "\r\n" } else { "\n" });
                        was_quoted = false;
                        row_num += 1;
                        col_num = 1;
                        has_any_content_in_row = false;
                        budget.check_deadline()?;
                    }
                    '\n' => {
                        if has_any_content_in_row {
                            Self::finalize_csv_field(
                                &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                            );
                        }
                        out.push('\n');
                        was_quoted = false;
                        row_num += 1;
                        col_num = 1;
                        has_any_content_in_row = false;
                        budget.check_deadline()?;
                    }
                    other => {
                        Self::push_bounded_char(&mut cell, other, max_cell_bytes)?;
                        was_quoted = false;
                        has_any_content_in_row = true;
                        state = CsvState::Unquoted;
                    }
                },
                CsvState::Unquoted => match ch {
                    ',' => {
                        Self::finalize_csv_field(
                            &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                        );
                        out.push(',');
                        was_quoted = false;
                        col_num += 1;
                        state = CsvState::FieldStart;
                    }
                    '\r' => {
                        let is_crlf = chars.peek() == Some(&'\n');
                        if is_crlf {
                            chars.next();
                        }
                        Self::finalize_csv_field(
                            &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                        );
                        out.push_str(if is_crlf { "\r\n" } else { "\n" });
                        was_quoted = false;
                        row_num += 1;
                        col_num = 1;
                        has_any_content_in_row = false;
                        state = CsvState::FieldStart;
                        budget.check_deadline()?;
                    }
                    '\n' => {
                        Self::finalize_csv_field(
                            &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                        );
                        out.push('\n');
                        was_quoted = false;
                        row_num += 1;
                        col_num = 1;
                        has_any_content_in_row = false;
                        state = CsvState::FieldStart;
                        budget.check_deadline()?;
                    }
                    '"' => {
                        return Err(CdrError::ParserCorruption(format!(
                            "Malformed RFC 4180 CSV: unexpected quote inside unquoted field at Row_{row_num}:Col_{col_num}"
                        )));
                    }
                    other => {
                        Self::push_bounded_char(&mut cell, other, max_cell_bytes)?;
                    }
                },
                CsvState::Quoted => {
                    if ch == '"' {
                        state = CsvState::QuoteAfterQuoted;
                    } else {
                        Self::push_bounded_char(&mut cell, ch, max_cell_bytes)?;
                    }
                }
                CsvState::QuoteAfterQuoted => match ch {
                    '"' => {
                        Self::push_bounded_char(&mut cell, '"', max_cell_bytes)?;
                        state = CsvState::Quoted;
                    }
                    ',' => {
                        Self::finalize_csv_field(
                            &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                        );
                        out.push(',');
                        was_quoted = false;
                        col_num += 1;
                        state = CsvState::FieldStart;
                    }
                    '\r' => {
                        let is_crlf = chars.peek() == Some(&'\n');
                        if is_crlf {
                            chars.next();
                        }
                        Self::finalize_csv_field(
                            &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                        );
                        out.push_str(if is_crlf { "\r\n" } else { "\n" });
                        was_quoted = false;
                        row_num += 1;
                        col_num = 1;
                        has_any_content_in_row = false;
                        state = CsvState::FieldStart;
                        budget.check_deadline()?;
                    }
                    '\n' => {
                        Self::finalize_csv_field(
                            &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                        );
                        out.push('\n');
                        was_quoted = false;
                        row_num += 1;
                        col_num = 1;
                        has_any_content_in_row = false;
                        state = CsvState::FieldStart;
                        budget.check_deadline()?;
                    }
                    _ => {
                        return Err(CdrError::ParserCorruption(format!(
                            "Malformed RFC 4180 CSV: trailing character after closing quote at Row_{row_num}:Col_{col_num}"
                        )));
                    }
                },
            }
        }

        match state {
            CsvState::Quoted => {
                return Err(CdrError::ParserCorruption(format!(
                    "Malformed RFC 4180 CSV: unclosed quoted field at Row_{row_num}:Col_{col_num}"
                )));
            }
            CsvState::Unquoted | CsvState::QuoteAfterQuoted => {
                Self::finalize_csv_field(
                    &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                );
            }
            CsvState::FieldStart => {
                if has_any_content_in_row {
                    Self::finalize_csv_field(
                        &mut out, &mut cell, was_quoted, row_num, col_num, reports,
                    );
                }
            }
        }

        Ok(out)
    }

    fn push_bounded_char(cell: &mut String, ch: char, max_cell_bytes: usize) -> Result<()> {
        if cell.len().saturating_add(ch.len_utf8()) > max_cell_bytes {
            return Err(CdrError::ResourceLimitExceeded(format!(
                "CSV cell exceeds maximum bounded size ({max_cell_bytes} bytes)"
            )));
        }
        cell.push(ch);
        Ok(())
    }

    fn finalize_csv_field(
        out: &mut String,
        cell: &mut String,
        was_quoted: bool,
        row_num: usize,
        col_num: usize,
        reports: &mut Vec<DisarmReportItem>,
    ) {
        if Self::is_dangerous_csv_cell(cell) {
            reports.push(DisarmReportItem::new(
                "CSV_DDE_FORMULA",
                format!("Row_{row_num}:Col_{col_num}"),
                "NEUTRALIZED",
            ));
            let stripped = cell.trim_start_matches('\u{FEFF}');
            let mut disarmed = String::with_capacity(stripped.len() + 1);
            disarmed.push('\'');
            disarmed.push_str(stripped);
            Self::emit_rfc4180_field(out, &disarmed, was_quoted);
        } else {
            Self::emit_rfc4180_field(out, cell, was_quoted);
        }
        cell.clear();
    }

    /// Re-parses sanitized CSV output using the exact RFC 4180 state machine and fails closed
    /// if any malformed syntax or residual unneutralized formula field remains (`CSE-19`).
    pub fn verify_csv_fields_clean(text: &str) -> Result<()> {
        let mut cell = String::new();
        let mut state = CsvState::FieldStart;
        let mut row_num: usize = 1;
        let mut col_num: usize = 1;
        let mut chars = text.chars().peekable();

        while let Some(ch) = chars.next() {
            match state {
                CsvState::FieldStart => match ch {
                    '"' => state = CsvState::Quoted,
                    ',' => {
                        col_num += 1;
                    }
                    '\r' => {
                        if chars.peek() == Some(&'\n') {
                            chars.next();
                        }
                        row_num += 1;
                        col_num = 1;
                    }
                    '\n' => {
                        row_num += 1;
                        col_num = 1;
                    }
                    other => {
                        Self::push_bounded_char(&mut cell, other, MAX_CSV_CELL_BYTES)?;
                        state = CsvState::Unquoted;
                    }
                },
                CsvState::Unquoted => match ch {
                    ',' => {
                        if Self::is_dangerous_csv_cell(&cell) {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual unneutralized formula cell in sanitized CSV at Row_{row_num}:Col_{col_num}"
                            )));
                        }
                        cell.clear();
                        col_num += 1;
                        state = CsvState::FieldStart;
                    }
                    '\r' => {
                        if chars.peek() == Some(&'\n') {
                            chars.next();
                        }
                        if Self::is_dangerous_csv_cell(&cell) {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual unneutralized formula cell in sanitized CSV at Row_{row_num}:Col_{col_num}"
                            )));
                        }
                        cell.clear();
                        row_num += 1;
                        col_num = 1;
                        state = CsvState::FieldStart;
                    }
                    '\n' => {
                        if Self::is_dangerous_csv_cell(&cell) {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual unneutralized formula cell in sanitized CSV at Row_{row_num}:Col_{col_num}"
                            )));
                        }
                        cell.clear();
                        row_num += 1;
                        col_num = 1;
                        state = CsvState::FieldStart;
                    }
                    '"' => {
                        return Err(CdrError::OutputRejected(
                            "CDR_OUTPUT_REJECTED: Malformed quote in sanitized CSV".to_string(),
                        ));
                    }
                    other => {
                        Self::push_bounded_char(&mut cell, other, MAX_CSV_CELL_BYTES)?;
                    }
                },
                CsvState::Quoted => {
                    if ch == '"' {
                        state = CsvState::QuoteAfterQuoted;
                    } else {
                        Self::push_bounded_char(&mut cell, ch, MAX_CSV_CELL_BYTES)?;
                    }
                }
                CsvState::QuoteAfterQuoted => match ch {
                    '"' => {
                        Self::push_bounded_char(&mut cell, '"', MAX_CSV_CELL_BYTES)?;
                        state = CsvState::Quoted;
                    }
                    ',' => {
                        if Self::is_dangerous_csv_cell(&cell) {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual unneutralized quoted formula cell in sanitized CSV at Row_{row_num}:Col_{col_num}"
                            )));
                        }
                        cell.clear();
                        col_num += 1;
                        state = CsvState::FieldStart;
                    }
                    '\r' => {
                        if chars.peek() == Some(&'\n') {
                            chars.next();
                        }
                        if Self::is_dangerous_csv_cell(&cell) {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual unneutralized quoted formula cell in sanitized CSV at Row_{row_num}:Col_{col_num}"
                            )));
                        }
                        cell.clear();
                        row_num += 1;
                        col_num = 1;
                        state = CsvState::FieldStart;
                    }
                    '\n' => {
                        if Self::is_dangerous_csv_cell(&cell) {
                            return Err(CdrError::OutputRejected(format!(
                                "CDR_OUTPUT_REJECTED: Residual unneutralized quoted formula cell in sanitized CSV at Row_{row_num}:Col_{col_num}"
                            )));
                        }
                        cell.clear();
                        row_num += 1;
                        col_num = 1;
                        state = CsvState::FieldStart;
                    }
                    _ => {
                        return Err(CdrError::OutputRejected(
                            "CDR_OUTPUT_REJECTED: Malformed trailing character after closing quote in sanitized CSV"
                                .to_string(),
                        ));
                    }
                },
            }
        }

        if state == CsvState::Quoted {
            return Err(CdrError::OutputRejected(
                "CDR_OUTPUT_REJECTED: Unclosed quoted field in sanitized CSV".to_string(),
            ));
        }
        if !cell.is_empty() && Self::is_dangerous_csv_cell(&cell) {
            return Err(CdrError::OutputRejected(format!(
                "CDR_OUTPUT_REJECTED: Residual unneutralized formula cell in sanitized CSV at Row_{row_num}:Col_{col_num}"
            )));
        }
        Ok(())
    }
}
