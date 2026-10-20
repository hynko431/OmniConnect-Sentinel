use sentinel_core::scanner::content_scanner::ContentScanner;
use sentinel_core::scanner::polyglot_scanner::PolyglotScanner;
use sentinel_core::scanner::secure_shredder::SecureShredder;
use sentinel_core::scanner::unicode_trojan_detector::UnicodeTrojanDetector;
use sentinel_core::scanner::universal_scanner::{CarrierCategory, ThreatSeverity, UniversalScanner};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_secure_shredder_readonly_bypass_and_zero_remanence() {
    let dir = tempdir().expect("Failed to create tempdir");
    let file_path = dir.path().join("malicious_dropper.bin");

    // Write a mock payload
    let test_bytes = b"MALWARE_SIGNATURE_PAYLOAD_C2_DROPPER_DATA_BLOCK";
    fs::write(&file_path, test_bytes).expect("Failed to write test file");

    #[cfg(windows)]
    {
        // Set READONLY attribute
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = file_path.as_os_str().encode_wide().chain(Some(0)).collect();
        unsafe {
            // FILE_ATTRIBUTE_READONLY = 0x01
            windows_sys_set_attr(wide.as_ptr(), 0x01);
        }
    }

    // Execute 3-pass NIST SP 800-88 cryptographic shred
    let receipt = SecureShredder::shred_file(&file_path, 3).expect("Shredder failed");

    assert_eq!(receipt.original_size_bytes, test_bytes.len() as u64);
    assert_eq!(receipt.passes_completed, 3);
    assert_eq!(receipt.mft_scramble_cycles, 3);
    assert!(receipt.hardware_flushed);

    // Verify file is completely unlinked and unrecoverable
    assert!(!file_path.exists(), "Target file must not exist after shredding");
}

#[cfg(windows)]
unsafe fn windows_sys_set_attr(path: *const u16, attr: u32) {
    extern "system" {
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
    }
    SetFileAttributesW(path, attr);
}

#[test]
fn test_polyglot_scanner_jpeg_with_pe_overlay() {
    let dir = tempdir().expect("Failed to create tempdir");
    let file_path = dir.path().join("vacation_photo.jpg");

    // Construct valid JPEG header (FF D8) + image data + EOI (FF D9)
    let mut file_data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00];
    file_data.extend_from_slice(&[0x00; 100]); // dummy pixel scan
    file_data.extend_from_slice(&[0xFF, 0xD9]); // EOI marker

    // Append 500 bytes of PE binary overlay (MZ...)
    file_data.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00");
    file_data.extend_from_slice(&[0x90; 200]);

    fs::write(&file_path, &file_data).expect("Failed to write mock polyglot JPEG");

    let threat = PolyglotScanner::inspect(&file_path, &file_data, file_data.len() as u64)
        .expect("PolyglotScanner must detect JPEG with PE overlay");

    assert_eq!(threat.carrier_category, CarrierCategory::Image);
    assert_eq!(threat.severity, ThreatSeverity::Critical);
    assert_eq!(threat.risk_score, 98);
    assert!(threat.threat_name.contains("Polyglot Dropper"));
    assert!(threat.can_disarm_via_cdr);
    assert!(threat.overlay_offset.is_some());
}

#[test]
fn test_polyglot_scanner_png_with_zip_overlay() {
    let dir = tempdir().expect("Failed to create tempdir");
    let file_path = dir.path().join("logo.png");

    // PNG signature: 89 50 4E 47 0D 0A 1A 0A
    let mut file_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    file_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D, b'I', b'H', b'D', b'R']); // IHDR
    file_data.extend_from_slice(&[0x00; 13]); // IHDR data
    file_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC

    // IEND chunk: 0 length + IEND + 4 bytes CRC
    file_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]);

    // Append ZIP container past IEND (PK\x03\x04...)
    file_data.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x08\x00");
    file_data.extend_from_slice(&[0x55; 100]);

    fs::write(&file_path, &file_data).expect("Failed to write mock polyglot PNG");

    let threat = PolyglotScanner::inspect(&file_path, &file_data, file_data.len() as u64)
        .expect("PolyglotScanner must detect PNG with ZIP overlay");

    assert_eq!(threat.carrier_category, CarrierCategory::Image);
    assert_eq!(threat.severity, ThreatSeverity::High);
    assert!(threat.threat_name.contains("ZIP"));
    assert!(threat.can_disarm_via_cdr);
}

#[test]
fn test_unicode_trojan_detector_bidi_override() {
    let dir = tempdir().expect("Failed to create tempdir");
    // Right-to-Left Override (U+202E) disguises .exe as .doc
    let deceptive_filename = format!("invoice_{}cod.exe", '\u{202E}');
    let file_path = dir.path().join(deceptive_filename);

    let threat = UnicodeTrojanDetector::inspect_path(&file_path)
        .expect("UnicodeTrojanDetector must detect Right-to-Left Override");

    assert_eq!(threat.carrier_category, CarrierCategory::FilesystemHidden);
    assert_eq!(threat.severity, ThreatSeverity::Critical);
    assert_eq!(threat.risk_score, 99);
    assert_eq!(threat.mitre_technique, "T1036.002 (Right-to-Left Override)");
}

#[test]
fn test_unicode_trojan_detector_zero_width_space() {
    let dir = tempdir().expect("Failed to create tempdir");
    let cloaked_filename = format!("{}stealth_payload.exe", '\u{200B}');
    let file_path = dir.path().join(cloaked_filename);

    let threat = UnicodeTrojanDetector::inspect_path(&file_path)
        .expect("UnicodeTrojanDetector must detect Zero-Width space");

    assert_eq!(threat.carrier_category, CarrierCategory::FilesystemHidden);
    assert_eq!(threat.severity, ThreatSeverity::High);
    assert!(threat.technical_details.contains("U+200B"));
}

#[test]
fn test_unicode_trojan_detector_reserved_dos_name() {
    let dir = tempdir().expect("Failed to create tempdir");
    let file_path = dir.path().join("CON.txt");

    let threat = UnicodeTrojanDetector::inspect_path(&file_path)
        .expect("UnicodeTrojanDetector must flag reserved DOS device names");

    assert_eq!(threat.carrier_category, CarrierCategory::FilesystemHidden);
    assert_eq!(threat.severity, ThreatSeverity::High);
    assert!(threat.threat_name.contains("DOS Reserved Device Name"));
}

#[test]
fn test_content_scanner_weaponized_pdf() {
    let dir = tempdir().expect("Failed to create tempdir");
    let file_path = dir.path().join("invoice.pdf");

    let pdf_bytes = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (cmd.exe) >> >>\nendobj\n";
    fs::write(&file_path, pdf_bytes).expect("Failed to write mock PDF");

    let threat = ContentScanner::inspect_content(&file_path, pdf_bytes, pdf_bytes.len() as u64)
        .expect("ContentScanner must detect /Launch in weaponized PDF");

    assert_eq!(threat.carrier_category, CarrierCategory::Document);
    assert_eq!(threat.severity, ThreatSeverity::Critical);
    assert_eq!(threat.risk_score, 98);
    assert!(threat.threat_name.contains("/Launch"));
    assert!(threat.can_disarm_via_cdr);
}

#[test]
fn test_content_scanner_ransomware_indicators() {
    let dir = tempdir().expect("Failed to create tempdir");
    let ransom_note = dir.path().join("HOW_TO_RESTORE_FILES.txt");
    let note_content = b"All your files have been encrypted with military-grade AES-256. Pay 2 BTC to restore.";
    fs::write(&ransom_note, note_content).expect("Failed to write ransom note");

    let threat = ContentScanner::inspect_content(&ransom_note, note_content, note_content.len() as u64)
        .expect("ContentScanner must detect ransom note");

    assert_eq!(threat.carrier_category, CarrierCategory::Ransomware);
    assert_eq!(threat.severity, ThreatSeverity::Critical);
    assert_eq!(threat.risk_score, 100);

    // Test ransomware extension
    let locked_file = dir.path().join("financials.xlsx.locked");
    let high_entropy_bytes = vec![0xAA, 0x55, 0x12, 0x99, 0xFE, 0x33, 0x44, 0x88, 0x77, 0x66];
    let threat2 = ContentScanner::inspect_content(&locked_file, &high_entropy_bytes, high_entropy_bytes.len() as u64)
        .expect("ContentScanner must flag .locked ransomware files");
    assert_eq!(threat2.carrier_category, CarrierCategory::Ransomware);
}

#[test]
fn test_content_scanner_amsi_bypass_script() {
    let dir = tempdir().expect("Failed to create tempdir");
    let script_path = dir.path().join("stage1.ps1");
    let script_content = b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";
    fs::write(&script_path, script_content).expect("Failed to write mock PS1");

    let threat = ContentScanner::inspect_content(&script_path, script_content, script_content.len() as u64)
        .expect("ContentScanner must detect AMSI bypass in PowerShell script");

    assert_eq!(threat.carrier_category, CarrierCategory::ScriptCode);
    assert_eq!(threat.severity, ThreatSeverity::Critical);
    assert!(threat.threat_name.contains("AMSI"));
}

#[test]
fn test_universal_scanner_end_to_end_directory_scan() {
    let dir = tempdir().expect("Failed to create tempdir");

    // 1. Clean text file
    let clean_file = dir.path().join("readme.txt");
    fs::write(&clean_file, b"This is a perfectly safe text file with normal text.").unwrap();

    // 2. Polyglot JPEG
    let polyglot_file = dir.path().join("photo.jpg");
    let mut poly_bytes = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00];
    poly_bytes.extend_from_slice(&[0x00; 50]);
    poly_bytes.extend_from_slice(&[0xFF, 0xD9]); // EOI
    poly_bytes.extend_from_slice(b"MZ_EXECUTABLE_PAYLOAD_HERE_OVERLAY_TEST");
    fs::write(&polyglot_file, &poly_bytes).unwrap();

    // 3. BiDi Trojan Source Script
    let bidi_file = dir.path().join(format!("calc_{}cod.exe", '\u{202E}'));
    fs::write(&bidi_file, b"fake content").unwrap();

    let all_threats = UniversalScanner::scan_directory(dir.path(), 100);

    // Assert that the clean file did not generate threats, while polyglot and BiDi file did
    assert!(all_threats.len() >= 2, "Expected at least 2 threats, found {}", all_threats.len());
    let threat_paths: Vec<_> = all_threats.iter().map(|t| &t.file_path).collect();
    assert!(!threat_paths.contains(&&clean_file));
    assert!(threat_paths.contains(&&polyglot_file));
    assert!(threat_paths.contains(&&bidi_file));
}
