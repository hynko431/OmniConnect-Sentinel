//! Behavioral & Adversarial Verification Suite for Master Security Hardening Plan v3
//! Sub-Phase 1.2 (`CSE-20`, `F-04`, `F-06`): `T46` and `T47`.

use lopdf::{dictionary, Document, Object, Stream};
use sentinel_cdr::sanitizers::ole2::{Ole2Sanitizer, OLE2_MAGIC};
use sentinel_cdr::sanitizers::pdf::PdfSanitizer;
use sentinel_cdr::{CdrEngine, CdrError, SanitizationPolicy, SignedPdfPolicy};
use std::io::Cursor;

fn build_minimal_pdf_bytes<F>(mutate: F) -> Vec<u8>
where
    F: FnOnce(&mut Document),
{
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let content_id = doc.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf (Hello) Tj ET".to_vec(),
    ));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Contents" => content_id,
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        }),
    );
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog_id);
    mutate(&mut doc);

    let mut out = Cursor::new(Vec::new());
    doc.save_to(&mut out).expect("save synthetic PDF");
    out.into_inner()
}

/// Builds a minimal valid MS-CFB (OLE2, sector_shift=9 => 512-byte sectors) container containing
/// a Root Entry, one benign stream, and one target stream (`stream_name`) storing `payload` across
/// one FAT sector (`sector 2`).
fn build_synthetic_ole2_cfb(stream_name: &str, payload: &[u8]) -> Vec<u8> {
    const SECTOR_SIZE: usize = 512;
    // Layout: Header (512) + Sector 0 (FAT) + Sector 1 (Directory) + Sector 2 (Target stream data) + Sector 3 (Benign data)
    let mut buf = vec![0u8; SECTOR_SIZE * 5];

    // Header
    buf[0..8].copy_from_slice(&OLE2_MAGIC);
    buf[24..26].copy_from_slice(&0x003Eu16.to_le_bytes()); // Minor version
    buf[26..28].copy_from_slice(&0x0003u16.to_le_bytes()); // Major version 3
    buf[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes()); // Little-endian BOM
    buf[30..32].copy_from_slice(&9u16.to_le_bytes()); // Sector shift = 9 (512B)
    buf[32..34].copy_from_slice(&6u16.to_le_bytes()); // Mini sector shift = 6 (64B)
    buf[44..48].copy_from_slice(&1u32.to_le_bytes()); // Num FAT sectors = 1
    buf[48..52].copy_from_slice(&1u32.to_le_bytes()); // First dir sector = 1
    buf[56..60].copy_from_slice(&4096u32.to_le_bytes()); // MiniStream cutoff = 4096
    buf[60..64].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // First MiniFAT = ENDOFCHAIN
    buf[68..72].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // First DIFAT = ENDOFCHAIN
    buf[72..76].copy_from_slice(&0u32.to_le_bytes()); // Num DIFAT sectors = 0
                                                      // DIFAT[0] = Sector 0 (FAT), remaining 108 entries = FREESECT
    buf[76..80].copy_from_slice(&0u32.to_le_bytes());
    for i in 1..109 {
        let off = 76 + i * 4;
        buf[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }

    // Sector 0 (offset 512): FAT table
    let fat_off = SECTOR_SIZE;
    buf[fat_off..fat_off + 4].copy_from_slice(&0xFFFF_FFFDu32.to_le_bytes()); // Sec 0 = FATSECT
    buf[fat_off + 4..fat_off + 8].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // Sec 1 = ENDOFCHAIN (Dir)
    buf[fat_off + 8..fat_off + 12].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // Sec 2 = ENDOFCHAIN (Target)
    buf[fat_off + 12..fat_off + 16].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // Sec 3 = ENDOFCHAIN (Benign)
    for i in 4..128 {
        let off = fat_off + i * 4;
        buf[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }

    // Helper to write a 128-byte CFB Directory Entry
    let write_dir_entry =
        |buf: &mut [u8], slot: usize, name: &str, obj_type: u8, start_sec: u32, size: u32| {
            let base = SECTOR_SIZE * 2 + slot * 128;
            let utf16: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            for (i, unit) in utf16.iter().enumerate() {
                buf[base + i * 2..base + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
            }
            buf[base + 64..base + 66].copy_from_slice(&((utf16.len() * 2) as u16).to_le_bytes());
            buf[base + 66] = obj_type;
            buf[base + 68..base + 72].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            buf[base + 72..base + 76].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            buf[base + 76..base + 80].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            buf[base + 116..base + 120].copy_from_slice(&start_sec.to_le_bytes());
            buf[base + 120..base + 124].copy_from_slice(&size.to_le_bytes());
        };

    // Sector 1 (offset 1024): Directory entries
    write_dir_entry(&mut buf, 0, "Root Entry", 5, 0xFFFF_FFFE, 0);
    write_dir_entry(
        &mut buf,
        1,
        stream_name,
        2,
        2,
        payload.len().min(SECTOR_SIZE) as u32,
    );
    let benign = b"BENIGN_WORD_DOCUMENT_BODY";
    write_dir_entry(&mut buf, 2, "WordDocument", 2, 3, benign.len() as u32);

    // Sector 2 (offset 1536): Target stream payload
    let copy_len = payload.len().min(SECTOR_SIZE);
    buf[SECTOR_SIZE * 3..SECTOR_SIZE * 3 + copy_len].copy_from_slice(&payload[..copy_len]);

    // Sector 3 (offset 2048): Benign WordDocument payload
    buf[SECTOR_SIZE * 4..SECTOR_SIZE * 4 + benign.len()].copy_from_slice(benign);

    buf
}

#[test]
fn t46_pdf_stream_aware_depth_guard_ef_without_filespec_and_signature_policy() {
    // 1. Stream-aware PDF depth guard: unbalanced `(` and `[` inside a binary stream MUST NOT
    //    blind the recursion depth check on subsequent objects (`RUSTSEC-2026-0187`, `CSE-20`).
    let stream_payload = b"\x89PNG\r\n(unclosed_paren_in_image_bytes_(((([[[";
    let deep_arrays = format!(
        "{}{}",
        "[".repeat(PdfSanitizer::MAX_PDF_NESTING_DEPTH + 10),
        "]".repeat(PdfSanitizer::MAX_PDF_NESTING_DEPTH + 10)
    );
    let crafted_bypass_pdf = format!(
        "%PDF-1.7\n\
         1 0 obj\n<< /Length {} >>\nstream\n",
        stream_payload.len()
    );
    let mut raw_bypass = crafted_bypass_pdf.into_bytes();
    raw_bypass.extend_from_slice(stream_payload);
    raw_bypass.extend_from_slice(
        format!("\nendstream\nendobj\n2 0 obj\n{deep_arrays}\nendobj\n%%EOF\n").as_bytes(),
    );

    let depth_err = PdfSanitizer::validate_pdf_token_nesting_depth(
        &raw_bypass,
        PdfSanitizer::MAX_PDF_NESTING_DEPTH,
    )
    .expect_err("Binary stream containing '(' must NEVER blind deep array nesting guard");
    assert!(matches!(depth_err, CdrError::ResourceLimitExceeded(_)));

    // Also test indirect `/Length 9 0 R` fallback (no direct length hint) with `(` inside stream
    let mut raw_indirect_bypass =
        b"%PDF-1.7\n1 0 obj\n<< /Length 9 0 R >>\nstream\n(((binary_blob(((\nendstream\nendobj\n2 0 obj\n"
            .to_vec();
    raw_indirect_bypass.extend_from_slice(deep_arrays.as_bytes());
    raw_indirect_bypass.extend_from_slice(b"\nendobj\n%%EOF\n");
    assert!(matches!(
        PdfSanitizer::validate_pdf_token_nesting_depth(
            &raw_indirect_bypass,
            PdfSanitizer::MAX_PDF_NESTING_DEPTH
        ),
        Err(CdrError::ResourceLimitExceeded(_))
    ));

    // Binary stream containing 200 raw `[` bytes inside a valid image stream MUST NOT false-positive
    let stream_with_brackets = vec![b'['; 200];
    let mut benign_stream_pdf = format!(
        "%PDF-1.7\n1 0 obj\n<< /Length {} >>\nstream\n",
        stream_with_brackets.len()
    )
    .into_bytes();
    benign_stream_pdf.extend_from_slice(&stream_with_brackets);
    benign_stream_pdf.extend_from_slice(
        b"\nendstream\nendobj\n2 0 obj\n<< /Hex <48656C6C6F> /Str (a\\(b\\)c) >>\nendobj\n%%EOF\n",
    );
    PdfSanitizer::validate_pdf_token_nesting_depth(
        &benign_stream_pdf,
        PdfSanitizer::MAX_PDF_NESTING_DEPTH,
    )
    .expect(
        "Raw '[' bytes inside a valid PDF stream must NOT trigger false-positive nesting errors",
    );

    // 2. Unconditional `/EF` stripping even when `/Type /Filespec` is intentionally omitted (`CSE-20`)
    let ef_no_filespec_pdf = build_minimal_pdf_bytes(|doc| {
        let embedded_stream = doc.add_object(Stream::new(
            dictionary! { "Type" => "EmbeddedFile" },
            b"MZ\x90\x00SMUGGLED_PAYLOAD".to_vec(),
        ));
        // Deliberately omit `/Type /Filespec`!
        let stealth_attach = doc.add_object(dictionary! {
            "F" => Object::string_literal("invoice.exe"),
            "EF" => dictionary! { "F" => embedded_stream },
        });
        let root_id = doc
            .trailer
            .get(b"Root")
            .expect("Root")
            .as_reference()
            .expect("Root ref");
        if let Some(Object::Dictionary(root)) = doc.objects.get_mut(&root_id) {
            root.set("StealthAttach", stealth_attach);
        }
    });

    let engine = CdrEngine::new(SanitizationPolicy::default());
    let (clean_ef_pdf, ef_report) = engine
        .sanitize(&ef_no_filespec_pdf)
        .expect("PDF with /EF lacking /Type /Filespec must sanitize cleanly");
    assert!(
        ef_report
            .stripped_elements
            .iter()
            .any(|i| i.element_type == "PDF_FILESPEC_EF"),
        "Expected PDF_FILESPEC_EF disarm item"
    );
    let reparsed = Document::load_mem(&clean_ef_pdf).expect("reparse clean PDF");
    for obj in reparsed.objects.values() {
        if let Ok(d) = obj.as_dict() {
            assert!(
                !d.has(b"EF"),
                "Residual /EF dictionary survived sanitization without /Type /Filespec"
            );
        }
    }

    // 3. Signed PDF Preservation Policy (`SignedPdfPolicy`, `CSE-20`)
    // 3a. Clean DocuSign/PAdES-style signed PDF (`/ByteRange` + `/Type /Sig`, ZERO active threats)
    let clean_signed_pdf = build_minimal_pdf_bytes(|doc| {
        let sig_dict = doc.add_object(dictionary! {
            "Type" => "Sig",
            "Filter" => "Adobe.PPKLite",
            "SubFilter" => "adbe.pkcs7.detached",
            "ByteRange" => vec![0.into(), 100.into(), 200.into(), 300.into()],
            "Contents" => Object::String(vec![0x30, 0x82, 0x01, 0x00], lopdf::StringFormat::Hexadecimal),
        });
        let sig_field = doc.add_object(dictionary! {
            "FT" => "Sig",
            "T" => Object::string_literal("Signature1"),
            "V" => sig_dict,
        });
        let root_id = doc
            .trailer
            .get(b"Root")
            .expect("Root")
            .as_reference()
            .expect("Root ref");
        if let Some(Object::Dictionary(root)) = doc.objects.get_mut(&root_id) {
            root.set(
                "AcroForm",
                dictionary! { "Fields" => vec![sig_field.into()] },
            );
        }
    });

    // Default (`QuarantineWithReason`) MUST refuse silent signature invalidation
    let default_err = engine
        .sanitize(&clean_signed_pdf)
        .expect_err("Default SignedPdfPolicy::QuarantineWithReason must reject signed PDF");
    assert!(
        matches!(&default_err, CdrError::OutputRejected(msg) if msg.contains("SIGNED_PDF_QUARANTINE_REQUIRED")),
        "Expected SIGNED_PDF_QUARANTINE_REQUIRED, got: {default_err:?}"
    );

    // Explicit `AllowReadOnlyVerifiedClean` MUST preserve clean signed PDF byte-for-byte intact!
    let allow_clean_policy = SanitizationPolicy {
        signed_pdf_policy: SignedPdfPolicy::AllowReadOnlyVerifiedClean,
        ..Default::default()
    };
    let (preserved_bytes, preserved_report) = engine
        .sanitize_with_policy_report(&clean_signed_pdf, &allow_clean_policy, "contract.pdf")
        .expect("Clean signed PDF must pass verbatim under AllowReadOnlyVerifiedClean");
    assert_eq!(
        preserved_bytes, clean_signed_pdf,
        "Clean signed PDF bytes must remain byte-for-byte identical to keep signature valid"
    );
    assert!(preserved_report
        .stripped_elements
        .iter()
        .any(|i| i.element_type == "PDF_SIGNED_VERIFIED_CLEAN_PASSTHROUGH"));

    // 3b. Signed PDF carrying active content (`/JavaScript` + `/XFA` + `/AF`)
    let dirty_signed_pdf = build_minimal_pdf_bytes(|doc| {
        let sig_dict = doc.add_object(dictionary! {
            "Type" => "Sig",
            "SubFilter" => "adbe.pkcs7.detached",
            "ByteRange" => vec![0.into(), 50.into(), 100.into(), 150.into()],
        });
        let root_id = doc
            .trailer
            .get(b"Root")
            .expect("Root")
            .as_reference()
            .expect("Root ref");
        if let Some(Object::Dictionary(root)) = doc.objects.get_mut(&root_id) {
            root.set(
                "OpenAction",
                dictionary! { "S" => "JavaScript", "JS" => Object::string_literal("app.alert(1);") },
            );
            root.set("AF", vec![sig_dict.into()]);
            root.set(
                "AcroForm",
                dictionary! {
                    "Fields" => vec![sig_dict.into()],
                    "XFA" => Object::string_literal("<xdp:xdp/>"),
                },
            );
        }
    });

    // `AllowReadOnlyVerifiedClean` MUST STILL reject signed PDFs containing active JS/XFA/AF!
    let dirty_clean_err = engine
        .sanitize_with_policy_report(&dirty_signed_pdf, &allow_clean_policy, "evil_signed.pdf")
        .expect_err("Signed PDF with active JS/XFA MUST NOT pass AllowReadOnlyVerifiedClean");
    assert!(
        matches!(&dirty_clean_err, CdrError::OutputRejected(msg) if msg.contains("SIGNED_PDF_ACTIVE_CONTENT_QUARANTINE_REQUIRED")),
        "Expected SIGNED_PDF_ACTIVE_CONTENT_QUARANTINE_REQUIRED, got: {dirty_clean_err:?}"
    );

    // Explicit `FlattenAndWarnSignatureBroken` MUST sanitize active threats AND emit explicit warning
    let flatten_policy = SanitizationPolicy {
        signed_pdf_policy: SignedPdfPolicy::FlattenAndWarnSignatureBroken,
        ..Default::default()
    };
    let (flattened_bytes, flattened_report) = engine
        .sanitize_with_policy_report(&dirty_signed_pdf, &flatten_policy, "flatten_signed.pdf")
        .expect("FlattenAndWarnSignatureBroken must disarm threats and warn");
    assert!(flattened_report
        .stripped_elements
        .iter()
        .any(|i| i.element_type == "PDF_SIGNATURE_INVALIDATED_WARNING"));
    assert!(flattened_report
        .stripped_elements
        .iter()
        .any(|i| i.element_type == "PDF_ACROFORM_XFA"));
    let flat_doc = Document::load_mem(&flattened_bytes).expect("reparse flattened PDF");
    for obj in flat_doc.objects.values() {
        if let Ok(d) = obj.as_dict() {
            assert!(!d.has(b"JS") && !d.has(b"JavaScript") && !d.has(b"XFA") && !d.has(b"AF"));
        }
    }

    // 4. Adversarial PDF Name `/stream\n` & bare `stream\n` nesting guard regressions (Full Phase 1 Cold-Eye):
    //    `/stream\n` inside a dictionary or array MUST NOT skip to EOF and blind RUSTSEC-2026-0187.
    let mut name_stream_in_dict = b"%PDF-1.7\n1 0 obj\n<< /K /stream\n/Deep ".to_vec();
    name_stream_in_dict.extend(std::iter::repeat_n(b'[', 150));
    name_stream_in_dict.extend(std::iter::repeat_n(b']', 150));
    name_stream_in_dict.extend_from_slice(b" >>\nendobj\n%%EOF\n");
    assert!(
        matches!(
            PdfSanitizer::validate_pdf_token_nesting_depth(&name_stream_in_dict, 64),
            Err(CdrError::ResourceLimitExceeded(_))
        ),
        "PDF Name `/stream\\n` inside dictionary must NEVER bypass nesting depth guard"
    );

    let mut name_stream_in_array = b"%PDF-1.7\n1 0 obj\n[ /stream\n".to_vec();
    name_stream_in_array.extend(std::iter::repeat_n(b'[', 150));
    name_stream_in_array.extend(std::iter::repeat_n(b']', 150));
    name_stream_in_array.extend_from_slice(b" ]\nendobj\n%%EOF\n");
    assert!(
        matches!(
            PdfSanitizer::validate_pdf_token_nesting_depth(&name_stream_in_array, 64),
            Err(CdrError::ResourceLimitExceeded(_))
        ),
        "PDF Name `/stream\\n` inside array must NEVER bypass nesting depth guard"
    );

    let mut bare_stream_no_dict = b"%PDF-1.7\n1 0 obj\nstream\n".to_vec();
    bare_stream_no_dict.extend(std::iter::repeat_n(b'[', 150));
    bare_stream_no_dict.extend(std::iter::repeat_n(b']', 150));
    bare_stream_no_dict.extend_from_slice(b"\nendobj\n%%EOF\n");
    assert!(
        matches!(
            PdfSanitizer::validate_pdf_token_nesting_depth(&bare_stream_no_dict, 64),
            Err(CdrError::ResourceLimitExceeded(_))
        ),
        "Bare `stream\\n` without a preceding closed stream dictionary `>>` must NEVER skip nesting check"
    );

    // 5. `/XFA` key on a non-AcroForm dictionary MUST be stripped symmetrically with `verify_pdf_dict_clean`
    let rogue_xfa_pdf = build_minimal_pdf_bytes(|doc| {
        let rogue_obj = doc.add_object(dictionary! {
            "Type" => "Annot",
            "XFA" => Object::string_literal("<xdp:xdp/>"),
        });
        let root_id = doc
            .trailer
            .get(b"Root")
            .expect("Root")
            .as_reference()
            .expect("Root ref");
        if let Some(Object::Dictionary(root)) = doc.objects.get_mut(&root_id) {
            root.set("RogueRef", rogue_obj);
        }
    });
    let (clean_rogue_xfa, _) = engine
        .sanitize(&rogue_xfa_pdf)
        .expect("PDF with non-AcroForm /XFA must sanitize and pass post-CDR verification");
    let clean_rogue_doc = Document::load_mem(&clean_rogue_xfa).expect("reparse clean PDF");
    for obj in clean_rogue_doc.objects.values() {
        if let Ok(d) = obj.as_dict() {
            assert!(!d.has(b"XFA"), "Residual /XFA found in dictionary");
        }
    }

    // 6. Parent-to-worker pipe framing MUST preserve `signed_pdf_policy` and `jpeg_reencode_quality`
    let custom_policy = SanitizationPolicy {
        signed_pdf_policy: SignedPdfPolicy::AllowReadOnlyVerifiedClean,
        jpeg_reencode_quality: 77,
        ..Default::default()
    };
    let req = sentinel_cdr::WorkerRequest {
        file_name: "signed.pdf".to_string(),
        policy: custom_policy,
        raw_bytes: b"%PDF-1.7\n%%EOF\n".to_vec(),
    };
    let mut framed = Vec::new();
    req.write_framed(&mut framed)
        .expect("WorkerRequest::write_framed");
    let decoded = sentinel_cdr::WorkerRequest::read_framed(std::io::Cursor::new(&framed))
        .expect("WorkerRequest::read_framed");
    assert_eq!(
        decoded.policy.signed_pdf_policy,
        SignedPdfPolicy::AllowReadOnlyVerifiedClean
    );
    assert_eq!(decoded.policy.jpeg_reencode_quality, 77);
}

#[test]
fn t47_ole2_equation_native_stream_zeroed_and_verified() {
    let ole2_policy = SanitizationPolicy {
        allow_legacy_ole2: true,
        ..Default::default()
    };
    let engine = CdrEngine::new(ole2_policy.clone());

    // 1. CVE-2017-11882 `Equation Native` stream (mixed case + shellcode canary)
    let eq_canary = b"CVE_2017_11882_EQNEDT32_STACK_OVERFLOW_SHELLCODE_CANARY_9999";
    let eq_ole2 = build_synthetic_ole2_cfb("Equation Native", eq_canary);
    assert!(
        Ole2Sanitizer::has_residual_active_streams(&eq_ole2, &ole2_policy),
        "Pre-CDR detector must flag Equation Native stream"
    );

    let (clean_eq, eq_report) = engine
        .sanitize_with_policy_report(&eq_ole2, &ole2_policy, "legacy_eq.doc")
        .expect("OLE2 Equation Native sanitization must succeed");
    assert!(
        eq_report
            .stripped_elements
            .iter()
            .any(|i| i.element_type == "OLE2_EQUATION_NATIVE_EXPLOIT"),
        "Expected OLE2_EQUATION_NATIVE_EXPLOIT report item; got: {:?}",
        eq_report.stripped_elements
    );
    assert!(
        !Ole2Sanitizer::has_residual_active_streams(&clean_eq, &ole2_policy),
        "Post-CDR OLE2 must contain zero residual Equation Native directory entries"
    );
    assert!(
        !clean_eq.windows(eq_canary.len()).any(|w| w == eq_canary),
        "Equation Native stream data sector must be zeroized on disk"
    );
    assert!(
        clean_eq
            .windows(b"BENIGN_WORD_DOCUMENT_BODY".len())
            .any(|w| w == b"BENIGN_WORD_DOCUMENT_BODY"),
        "Benign WordDocument stream must remain intact"
    );

    // 2. `\x01Ole10Native` COM-prefixed embedded package stream (regression guard for `c < 0x20` skip bug!)
    let native_canary = b"OLE10NATIVE_EMBEDDED_DROPPER_CANARY_7777";
    let native_ole2 = build_synthetic_ole2_cfb("\u{0001}Ole10Native", native_canary);
    assert!(
        Ole2Sanitizer::has_residual_active_streams(&native_ole2, &ole2_policy),
        "Pre-CDR detector must flag \\x01Ole10Native COM-prefixed stream"
    );
    let (clean_native, native_report) = engine
        .sanitize_with_policy_report(&native_ole2, &ole2_policy, "legacy_ole.doc")
        .expect("OLE2 \\x01Ole10Native sanitization must succeed");
    assert!(native_report
        .stripped_elements
        .iter()
        .any(|i| i.element_type == "OLE2_EMBEDDED_PACKAGE"));
    assert!(!Ole2Sanitizer::has_residual_active_streams(
        &clean_native,
        &ole2_policy
    ));
    assert!(!clean_native
        .windows(native_canary.len())
        .any(|w| w == native_canary));

    // 3. `Package` stream eradication
    let pkg_canary = b"OLE2_PACKAGE_STREAM_CANARY_5555";
    let pkg_ole2 = build_synthetic_ole2_cfb("Package", pkg_canary);
    let (clean_pkg, _) = engine
        .sanitize_with_policy_report(&pkg_ole2, &ole2_policy, "legacy_pkg.doc")
        .expect("OLE2 Package sanitization must succeed");
    assert!(!Ole2Sanitizer::has_residual_active_streams(
        &clean_pkg,
        &ole2_policy
    ));
    assert!(!clean_pkg.windows(pkg_canary.len()).any(|w| w == pkg_canary));
}
