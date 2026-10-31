#![forbid(unsafe_code)]

use arbitrary::{Arbitrary, Unstructured};
use sentinel_cdr::policy::SanitizationPolicy;
use sentinel_cdr::sanitizers::{
    image::ImageSanitizer, ole2::Ole2Sanitizer, openxml::OpenXmlSanitizer, pdf::PdfSanitizer,
    svg::SvgSanitizer, text::TextCsvSanitizer,
};
use sentinel_core::scanner::polyglot_scanner::PolyglotScanner;
use std::path::Path;

#[derive(Debug, Arbitrary)]
struct FuzzCorpusInput {
    selector: u8,
    payload: Vec<u8>,
}

/// Deterministic corpus & structured fuzzer harness for `cargo-fuzz` (`Row 201`)
/// Enforces a strict 128 MiB decompression ceiling and verifies zero panics across
/// all 6 CDR sanitizers and the seekable forward polyglot scanner.
pub fn run_fuzz_one(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let Ok(input) = FuzzCorpusInput::arbitrary(&mut u) else {
        return;
    };
    let mut policy = SanitizationPolicy::default();
    policy.max_decompressed_bytes = 128 * 1024 * 1024;
    policy.allow_svg = true;
    policy.allow_legacy_ole2 = true;

    match input.selector % 7 {
        0 => {
            let _ = PdfSanitizer::sanitize(&input.payload, &policy);
        }
        1 => {
            let _ = OpenXmlSanitizer::sanitize(&input.payload, &policy);
        }
        2 => {
            let _ = ImageSanitizer::sanitize_jpeg(&input.payload, &policy);
            let _ = ImageSanitizer::sanitize_png(&input.payload, &policy);
            let _ = ImageSanitizer::sanitize_webp(&input.payload, &policy);
        }
        3 => {
            let _ = SvgSanitizer::sanitize(&input.payload, &policy);
        }
        4 => {
            let _ = Ole2Sanitizer::sanitize(&input.payload, &policy);
        }
        5 => {
            let _ = TextCsvSanitizer::sanitize(&input.payload, &policy, true);
            let _ = TextCsvSanitizer::sanitize(&input.payload, &policy, false);
        }
        _ => {
            let _ = PolyglotScanner::inspect(
                Path::new("fuzz_sample.bin"),
                &input.payload,
                input.payload.len() as u64,
            );
        }
    }
}

fn main() {
    let mut buf = Vec::new();
    if std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf).is_ok() {
        run_fuzz_one(&buf);
    }
}

