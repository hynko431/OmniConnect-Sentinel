use image::{ImageBuffer, Rgb};
use sentinel_cdr::engine::CdrEngine;
use sentinel_cdr::policy::SanitizationPolicy;
use std::io::Cursor;

#[test]
fn test_fuzz_random_garbage_inputs_never_panic() {
    let policy = SanitizationPolicy::default();
    let engine = CdrEngine::new(policy);

    // Array of adversarial payloads: empty, single-byte, malformed magic headers, huge zeroes
    let adversarial_inputs: Vec<&[u8]> = vec![
        b"",
        b"\x00",
        b"%PDF-1.7\r\n\x00\x00\x00",
        b"PK\x03\x04\x14\x00\x00\x00",
        b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00",
        &[0xFF; 4096],
        &[0x00; 8192],
    ];

    for input in adversarial_inputs {
        // Must never panic! Must cleanly return Ok or handled Err (Fail-Closed)
        let result = engine.sanitize(input);
        match result {
            Ok((sanitized_bytes, report)) => {
                assert!(!sanitized_bytes.is_empty() || input.is_empty());
                println!("Sanitized input cleanly: format={:?}", report.format);
            }
            Err(e) => {
                // Expected fail-closed behavior on corrupted/garbage input
                assert!(!e.to_string().is_empty());
            }
        }
    }
}

#[test]
fn test_fuzz_image_polyglot_truncation() {
    let policy = SanitizationPolicy::default();
    let engine = CdrEngine::new(policy);

    // Generate a valid 4x4 PNG in-memory using pure-Rust codec
    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_pixel(4, 4, Rgb([255, 0, 0]));
    let mut valid_png_bytes = Vec::new();
    img.write_to(&mut Cursor::new(&mut valid_png_bytes), image::ImageFormat::Png)
        .expect("PNG encoding should succeed");

    // Append malicious overlay shellcode past PNG IEND chunk
    let overlay_shellcode = b"MALICIOUS_OVERLAY_SHELLCODE_VIRUS_PAYLOAD";
    valid_png_bytes.extend_from_slice(overlay_shellcode);

    let (clean_bytes, report) = engine.sanitize(&valid_png_bytes).expect("PNG sanitization should succeed");

    // Verify trailing overlay was stripped and file remains valid
    assert!(!clean_bytes.is_empty());
    assert!(
        !clean_bytes.windows(overlay_shellcode.len()).any(|w| w == overlay_shellcode),
        "Overlay shellcode must be purged"
    );
    assert!(report.was_modified);
}
