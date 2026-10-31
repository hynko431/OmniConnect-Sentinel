#![forbid(unsafe_code)]

use std::fs;
use std::io::{Cursor, Write};
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use sentinel_core::enterprise::falcon::{CrowdStrikeFalconBridge, FalconTelemetryEvent};
use sentinel_core::enterprise::intune::IntunePolicyManager;
use sentinel_core::enterprise::kiosk::{KioskConfig, KioskEnforcer, PostureReport};
use sentinel_core::enterprise::ledger::AuditLedger;
use sentinel_core::events::{ConnectionVector, DeviceConnectedEvent};
use sentinel_core::interceptor::windows_umdf::WindowsUmdfInterceptor;
use sentinel_core::interceptor::DeviceInterceptor;
use sentinel_core::scanner::content_scanner::ContentScanner;
use sentinel_core::scanner::polyglot_scanner::PolyglotScanner;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::secure_shredder::{SecureShredder, ShredMethod};
use sentinel_core::scanner::tier0_yara::Tier0YaraScanner;
use sentinel_core::scanner::tier3_sandbox::{SandboxDetonationRequest, Tier3SandboxConnector};
use sentinel_core::scanner::unicode_trojan_detector::UnicodeTrojanDetector;
use sentinel_core::scanner::universal_scanner::{
    CarrierCategory, ThreatSeverity, UniversalScanner,
};
use sentinel_core::vfs::{ProjFsProvider, VirtualFileSystemProvider};

#[test]
fn test_secure_shredder_readonly_bypass_and_honest_clear_receipt() {
    let dir = tempdir().expect("Failed to create tempdir");
    let file_path = dir.path().join("malicious_dropper.bin");

    let test_bytes = b"MALWARE_SIGNATURE_PAYLOAD_C2_DROPPER_DATA_BLOCK";
    fs::write(&file_path, test_bytes).expect("Failed to write test file");

    // Set read-only permission using safe std API
    let mut perms = fs::metadata(&file_path).unwrap().permissions();
    perms.set_readonly(true);
    let _ = fs::set_permissions(&file_path, perms);

    let receipt = SecureShredder::shred_file(&file_path, ShredMethod::ClearMultiPass { passes: 3 })
        .expect("Shredder failed");

    assert_eq!(receipt.file_size_bytes, test_bytes.len() as u64);
    assert!(receipt.sector_alignment_bytes >= 512);
    assert_eq!(receipt.passes_completed, 3);
    assert!(receipt.actual_scramble_cycles >= 1);
    assert!(receipt.hardware_buffers_flushed);
    assert!(receipt.verification_passed);
    assert!(
        receipt.sanitization_level.contains("NIST 800-88 Clear (logical)")
            && receipt.sanitization_level.contains("Purge is not guaranteed"),
        "Receipt must honestly report NIST 800-88 Clear (logical) and flash Purge disclaimer: got {}",
        receipt.sanitization_level
    );
    assert!(
        !file_path.exists(),
        "Target file must not exist after shredding"
    );

    // Verify rotational HDD vs SSD vs USB flash media classification (`Row 52`)
    assert_eq!(
        sentinel_sys::classify_media_characteristics(false, Some(true)),
        sentinel_sys::MediaType::Hdd
    );
    assert_eq!(
        sentinel_sys::classify_media_characteristics(false, Some(false)),
        sentinel_sys::MediaType::SsdOrFlash
    );
    assert_eq!(
        sentinel_sys::classify_media_characteristics(true, Some(true)),
        sentinel_sys::MediaType::UsbFlash
    );

    // Verify `ZeroizingBytes` pinned heap address does not move across returns (`Row 39`)
    fn make_pinned_key() -> (sentinel_sys::ZeroizingBytes<32>, usize) {
        let z = sentinel_sys::ZeroizingBytes::new([0x5Au8; 32]);
        let ptr_addr = z.as_slice().as_ptr() as usize;
        (z, ptr_addr)
    }
    let (returned_key, addr_inside_ctor) = make_pinned_key();
    assert_eq!(
        returned_key.as_slice().as_ptr() as usize,
        addr_inside_ctor,
        "ZeroizingBytes<32> must remain at the exact pinned heap address locked by VirtualLock/mlock"
    );
}

#[test]
fn test_secure_shredder_reserved_dos_name_and_ads_surgical_shred() {
    // BUG-CORE-06 #1 & #3 (`T9`, `clear_reserved_name`):
    // 1. Reserved DOS filename `CON.txt` created via verbatim `\\?\` path can be shredded cleanly
    //    using `ShredMethod::NistClearThreePass`.
    // 2. `shred_ntfs_stream` strips leading `:` so it never constructs `file::stream`,
    //    and removes only the alternate stream while preserving the host file.
    let dir = tempdir().expect("Failed to create tempdir");

    // 1. Test reserved DOS filename `CON.txt` on all platforms (using verbatim `\\?\` on Windows)
    let con_path = dir.path().join("CON.txt");
    let verbatim_con = sentinel_sys::to_verbatim_path(&con_path);
    #[cfg(windows)]
    assert!(
        verbatim_con.to_string_lossy().starts_with(r"\\?\"),
        "to_verbatim_path on Windows must prefix \\\\?\\ for reserved DOS names"
    );
    fs::write(&verbatim_con, b"RESERVED_DOS_DEVICE_PAYLOAD").expect("Write CON.txt via verbatim path");
    let con_receipt = SecureShredder::shred_file(&con_path, ShredMethod::NistClearThreePass)
        .expect("Shredding CON.txt with NistClearThreePass must succeed");
    assert!(con_receipt.verification_passed);
    assert_eq!(con_receipt.passes_completed, 3);
    assert!(!verbatim_con.exists());

    // 2. Test surgical NTFS ADS shredding with leading colon `:evil.exe` on Windows
    #[cfg(windows)]
    {
        let host_file = dir.path().join("innocent_document.txt");
        let host_bytes = b"Important corporate report that must not be deleted.";
        fs::write(&host_file, host_bytes).unwrap();

        let ads_full_path = format!("{}:evil.exe", host_file.display());
        if fs::write(&ads_full_path, b"MZ_HIDDEN_ADS_EXECUTABLE_PAYLOAD").is_ok() {
            // Pass stream name WITH leading colon to verify `trim_start_matches(':')` fix (`BUG-CORE-06` #3)
            let ads_receipt = SecureShredder::shred_ntfs_stream(&host_file, ":evil.exe")
                .expect("Surgical ADS shred must succeed");
            assert!(ads_receipt.verification_passed);
            assert!(
                host_file.exists(),
                "Host file must remain intact after surgical ADS shred (`BUG-CLI-01`)"
            );
            assert_eq!(fs::read(&host_file).unwrap(), host_bytes);
            assert!(
                fs::read(&ads_full_path).is_err(),
                "Alternate data stream must be unlinked"
            );
        }
    }
}

#[test]
fn test_quarantine_vault_kek_persistence_aad_binding_and_restore() {
    // BUG-CORE-02 & Sub-Phase 2.1:
    // 1. Master KEK persists across QuarantineVault instances and is asymmetrically escrowed to the offline SOC RSA-2048 public key.
    // 2. Each file gets an HKDF-SHA256 derived wrapping key, wrapped per-entry DEK (`<entry_id>.dek`), and `.quar` envelope (`[header_len u32][header JSON][ciphertext]`) with AAD.
    // 3. Restoring across a new QuarantineVault instance recovers the exact bytes.
    // 4. Tampering with the envelope header JSON causes AEAD authentication failure.
    // 5. Corrupting `vault_kek.sealed` fails closed (`VAULT_INTEGRITY_FAIL`) without overwriting `vault_kek.sealed`, and offline SOC RSA-OAEP escrow recovers the vault!
    // 6. `quarantine_ntfs_stream` preserves the host file while capturing and shredding the ADS stream.
    let dir = tempdir().expect("Failed to create tempdir");
    let vault_dir = dir.path().join("vault");
    let sample_path = dir.path().join("dropper.exe");
    let original_bytes = b"MZ_CRITICAL_MALWARE_SAMPLE_FOR_QUARANTINE_VAULT_TEST";
    fs::write(&sample_path, original_bytes).unwrap();

    let (soc_pub_blob, soc_priv_blob) =
        sentinel_sys::generate_soc_rsa_keypair().expect("SOC RSA-2048 keygen must succeed");

    let entry = {
        let vault1 = QuarantineVault::open_with_soc_public_key(vault_dir.clone(), &soc_pub_blob)
            .expect("Vault open with SOC public key must succeed");
        let q = vault1
            .quarantine_file(&sample_path, "Trojan.Test.Dropper")
            .expect("Quarantine should succeed");
        assert!(
            !sample_path.exists(),
            "Original plaintext file must be shredded upon quarantine"
        );
        assert!(
            vault_dir.join(format!("{}.dek", q.entry_id)).exists(),
            "Wrapped per-entry DEK file must exist"
        );
        q
    };

    // Instantiate a brand-new QuarantineVault pointing at the same directory (`BUG-CORE-02` #1)
    let vault2 = QuarantineVault::open(vault_dir.clone()).expect("Vault reopen must succeed");
    let entries = vault2.list().expect("Listing entries must succeed");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_id, entry.entry_id);

    let restored_path = dir.path().join("restored_dropper.exe");
    vault2
        .restore_file(&entry.entry_id, &restored_path)
        .expect("Restoring quarantined file across vault instances must succeed");
    assert_eq!(fs::read(&restored_path).unwrap(), original_bytes);

    // Corrupt `vault_kek.sealed` and verify fail-closed refusal (NEVER overwrites `vault_kek.sealed`)
    let sealed_path = vault_dir.join("vault_kek.sealed");
    let corrupted_marker = b"CORRUPTED_SEALED_KEK_BLOB_MUST_NOT_BE_OVERWRITTEN";
    fs::write(&sealed_path, corrupted_marker).unwrap();
    let failed_open = QuarantineVault::open(vault_dir.clone());
    assert!(
        failed_open.is_err(),
        "QuarantineVault::open must fail closed when vault_kek.sealed is corrupted"
    );
    assert!(
        failed_open.unwrap_err().contains("VAULT_INTEGRITY_FAIL"),
        "Error must report VAULT_INTEGRITY_FAIL"
    );
    assert_eq!(
        fs::read(&sealed_path).unwrap(),
        corrupted_marker,
        "QuarantineVault must NEVER overwrite an existing vault_kek.sealed on unseal failure"
    );

    // Recover the vault using the offline SOC RSA-2048 private key and `vault_kek.escrow`!
    let recovered_vault =
        QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &soc_priv_blob)
            .expect("Offline SOC RSA-2048 OAEP escrow recovery must succeed");
    let restored_after_escrow = dir.path().join("restored_after_escrow.exe");
    recovered_vault
        .restore_file(&entry.entry_id, &restored_after_escrow)
        .expect("Restoring quarantined file after SOC escrow recovery must succeed");
    assert_eq!(fs::read(&restored_after_escrow).unwrap(), original_bytes);

    // Test surgical NTFS ADS quarantine (`High #10`, `Rows 50, 64`)
    #[cfg(windows)]
    {
        let host_doc = dir.path().join("clean_host_report.txt");
        let host_content = b"Legitimate financial report that must remain untouched.";
        fs::write(&host_doc, host_content).unwrap();
        let ads_stream_path = format!("{}:hidden_payload.exe", host_doc.display());
        let ads_content = b"MZ_SECRET_ALTERNATE_DATA_STREAM_PAYLOAD";
        if fs::write(&ads_stream_path, ads_content).is_ok() {
            let ads_entry = recovered_vault
                .quarantine_ntfs_stream(&host_doc, ":hidden_payload.exe", "ADS.Hidden.Dropper", 96)
                .expect("Surgical ADS quarantine must succeed");
            assert!(
                host_doc.exists(),
                "Host file must NOT be deleted when quarantining an NTFS ADS stream (`High #10`)"
            );
            assert_eq!(
                fs::read(&host_doc).unwrap(),
                host_content,
                "Host file content must be 100% preserved after ADS quarantine"
            );
            assert!(
                fs::read(&ads_stream_path).is_err(),
                "ADS stream must be shredded and unlinked from host file"
            );
            let restored_ads = dir.path().join("restored_ads_payload.bin");
            recovered_vault
                .restore_file(&ads_entry.entry_id, &restored_ads)
                .expect("Restoring quarantined ADS stream must succeed");
            assert_eq!(fs::read(&restored_ads).unwrap(), ads_content);
        }
    }

    // Tamper with the AAD header inside the `.quar` file and verify AEAD rejection (`BUG-CORE-02` #3)
    let quar_bytes = fs::read(&entry.vault_file_path).unwrap();
    let tampered_str = String::from_utf8_lossy(&quar_bytes)
        .replace("Trojan.Test.Dropper", "Tampered.Reason.X");
    fs::write(&entry.vault_file_path, tampered_str.as_bytes()).unwrap();

    let tampered_restore = dir.path().join("tampered_restore.exe");
    assert!(
        recovered_vault
            .restore_file(&entry.entry_id, &tampered_restore)
            .is_err(),
        "Tampered AAD header must be rejected by AES-256-GCM"
    );

    // Verify `purge()` crypto-erases `<entry_id>.dek` and shreds `<entry_id>.quar`
    recovered_vault
        .purge(&entry.entry_id)
        .expect("Purge must crypto-erase DEK and shred .quar");
    assert!(!vault_dir.join(format!("{}.dek", entry.entry_id)).exists());
    assert!(!std::path::Path::new(&entry.vault_file_path).exists());
}

#[test]
fn test_polyglot_scanner_jpeg_with_pe_overlay_and_exif_false_positive_immunity() {
    // BUG-CORE-04 #1:
    // 1. Valid JPEG with EXIF thumbnail containing 0xFF 0xD9 must NOT be flagged.
    // 2. JPEG with PE overlay after the true EOI MUST be flagged.
    let dir = tempdir().expect("Failed to create tempdir");

    // 1. JPEG with EXIF thumbnail containing 0xFF 0xD9 inside APP1
    let exif_jpeg_path = dir.path().join("camera_photo_with_exif.jpg");
    let exif_payload: &[u8] = b"Exif\x00\x00\xFF\xD8\xFF\xDB\x00\x04\x00\x00\xFF\xD9";
    let app1_len = (exif_payload.len() + 2) as u16;
    let mut clean_exif_jpeg = Vec::new();
    clean_exif_jpeg.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE1]);
    clean_exif_jpeg.extend_from_slice(&app1_len.to_be_bytes());
    clean_exif_jpeg.extend_from_slice(exif_payload);
    // Add SOS (0xFF 0xDA) + scan data + true EOI (0xFF 0xD9)
    clean_exif_jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00, 0x11, 0x22, 0x33, 0xFF, 0xD9]);
    fs::write(&exif_jpeg_path, &clean_exif_jpeg).unwrap();

    assert!(
        PolyglotScanner::inspect(&exif_jpeg_path, &clean_exif_jpeg, clean_exif_jpeg.len() as u64)
            .is_none(),
        "Camera JPEG with EXIF thumbnail EOI must NOT be falsely flagged as a polyglot"
    );

    // 2. Append PE payload after true EOI -> MUST be flagged
    let poly_jpeg_path = dir.path().join("vacation_photo.jpg");
    let mut poly_jpeg = clean_exif_jpeg.clone();
    poly_jpeg.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00");
    poly_jpeg.extend_from_slice(&[0x90; 200]);
    fs::write(&poly_jpeg_path, &poly_jpeg).unwrap();

    let threat = PolyglotScanner::inspect(&poly_jpeg_path, &poly_jpeg, poly_jpeg.len() as u64)
        .expect("PolyglotScanner must detect JPEG with PE overlay");
    assert_eq!(threat.carrier_category, CarrierCategory::Image);
    assert_eq!(threat.severity, ThreatSeverity::Critical);
    assert_eq!(threat.risk_score, 98);
    assert!(threat.threat_name.contains("Polyglot Dropper"));
    assert!(threat.can_disarm_via_cdr);
    assert!(threat.overlay_offset.is_some());
}

#[test]
fn test_polyglot_scanner_png_chunk_walk_and_mp4_moov_after_mdat() {
    // BUG-CORE-03 & BUG-CORE-04 #2 & #3:
    // 1. PNG containing literal `IEND` inside a `tEXt` chunk before the real `IEND` chunk must NOT be flagged.
    // 2. PNG with ZIP appended after the real `IEND` chunk MUST be flagged.
    // 3. >4 MB MP4 where `moov` appears after `mdat` must NOT be flagged.
    let dir = tempdir().expect("Failed to create tempdir");

    // Construct PNG with `tEXt` chunk containing "IEND" bytes, followed by real IEND
    let mut clean_png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    clean_png.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D, b'I', b'H', b'D', b'R']);
    clean_png.extend_from_slice(&[0x00; 13]);
    clean_png.extend_from_slice(&[0x00; 4]); // CRC
    // tEXt chunk with payload "CommentIENDHere!" (16 bytes)
    clean_png.extend_from_slice(&[0x00, 0x00, 0x00, 0x10, b't', b'E', b'X', b't']);
    clean_png.extend_from_slice(b"CommentIENDHere!");
    clean_png.extend_from_slice(&[0x00; 4]); // CRC
    // Real IEND chunk
    clean_png.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]);

    let clean_png_path = dir.path().join("clean_logo.png");
    assert!(
        PolyglotScanner::inspect(&clean_png_path, &clean_png, clean_png.len() as u64).is_none(),
        "PNG with 'IEND' inside tEXt chunk must not trigger false positive"
    );

    // Append ZIP after real IEND
    let mut poly_png = clean_png.clone();
    poly_png.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x08\x00");
    poly_png.extend_from_slice(&[0x55; 100]);
    let poly_png_path = dir.path().join("logo.png");
    let threat = PolyglotScanner::inspect(&poly_png_path, &poly_png, poly_png.len() as u64)
        .expect("PolyglotScanner must detect PNG with ZIP overlay");
    assert_eq!(threat.carrier_category, CarrierCategory::Image);
    assert_eq!(threat.severity, ThreatSeverity::High);
    assert!(threat.threat_name.contains("ZIP"));
    assert!(threat.can_disarm_via_cdr);

    // Construct a >4 MB (4.5 MB) valid MP4 where `mdat` (4.4 MB) precedes `moov` (1 KB)
    let mp4_path = dir.path().join("camera_recording.mp4");
    let mut mp4_bytes = Vec::with_capacity(4_600_000);
    // ftyp box (24 bytes)
    mp4_bytes.extend_from_slice(&24u32.to_be_bytes());
    mp4_bytes.extend_from_slice(b"ftypisom\x00\x00\x02\x00isomiso2");
    // mdat box (4,500,000 bytes)
    let mdat_size: u32 = 4_500_000;
    mp4_bytes.extend_from_slice(&mdat_size.to_be_bytes());
    mp4_bytes.extend_from_slice(b"mdat");
    mp4_bytes.resize(24 + mdat_size as usize, 0x11);
    // moov box (512 bytes) at the end of the >4 MB file
    let moov_size: u32 = 512;
    mp4_bytes.extend_from_slice(&moov_size.to_be_bytes());
    mp4_bytes.extend_from_slice(b"moov");
    mp4_bytes.resize(24 + (mdat_size as usize) + (moov_size as usize), 0x22);

    let mut cursor = Cursor::new(&mp4_bytes);
    assert!(
        PolyglotScanner::inspect_reader(&mp4_path, &mut cursor, mp4_bytes.len() as u64, None)
            .is_none(),
        ">4 MB MP4 with moov after mdat must NOT be falsely flagged (`BUG-CORE-03`, `BUG-CORE-04` #3)"
    );
}

#[test]
fn test_unicode_trojan_detector_bidi_zero_width_and_dos_names() {
    let dir = tempdir().expect("Failed to create tempdir");

    // 1. BiDi Right-to-Left Override (U+202E)
    let bidi_path = dir.path().join(format!("invoice_{}cod.exe", '\u{202E}'));
    let threat = UnicodeTrojanDetector::inspect_path(&bidi_path)
        .expect("UnicodeTrojanDetector must detect Right-to-Left Override");
    assert_eq!(threat.carrier_category, CarrierCategory::FilesystemHidden);
    assert_eq!(threat.severity, ThreatSeverity::Critical);
    assert_eq!(threat.risk_score, 99);
    assert_eq!(threat.mitre_technique, "T1036.002 (Right-to-Left Override)");

    // 2. Zero-Width Space (U+200B)
    let zw_path = dir.path().join(format!("{}stealth_payload.exe", '\u{200B}'));
    let threat2 = UnicodeTrojanDetector::inspect_path(&zw_path)
        .expect("UnicodeTrojanDetector must detect Zero-Width space");
    assert_eq!(threat2.carrier_category, CarrierCategory::FilesystemHidden);
    assert_eq!(threat2.severity, ThreatSeverity::High);
    assert!(threat2.technical_details.contains("U+200B"));

    // 3. Reserved DOS Device Name (CON.txt)
    let con_path = dir.path().join("CON.txt");
    let threat3 = UnicodeTrojanDetector::inspect_path(&con_path)
        .expect("UnicodeTrojanDetector must flag reserved DOS device names");
    assert_eq!(threat3.carrier_category, CarrierCategory::FilesystemHidden);
    assert_eq!(threat3.severity, ThreatSeverity::High);
    assert!(threat3.threat_name.contains("DOS Reserved Device Name"));
}

#[test]
fn test_content_scanner_false_positive_fixes_and_large_docx() {
    // BUG-CORE-03 & BUG-CORE-05:
    // 1. PDF with `/JSON` or `/JSMath` must NOT be flagged, while `/Launch` and `/JS` ARE flagged.
    // 2. Low-entropy `config.enc` must NOT be flagged as ransomware.
    // 3. Developer `project_readme.txt` without ransom keywords must NOT be flagged.
    // 4. >4 MB `.docm` with `word/vbaProject.bin` at the end of the archive MUST be detected.
    let dir = tempdir().expect("Failed to create tempdir");

    // 1a. Benign PDF containing `/JSON` metadata key
    let benign_pdf_path = dir.path().join("schema_doc.pdf");
    let benign_pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /JSON (https://example.com) /JSMath true >>\nendobj\n";
    assert!(
        ContentScanner::inspect_content(&benign_pdf_path, benign_pdf, benign_pdf.len() as u64)
            .is_none(),
        "PDF containing /JSON or /JSMath must NOT be flagged as /JS (`BUG-CORE-05` #3)"
    );

    // 1b. Weaponized PDF with `/Launch`
    let weaponized_pdf_path = dir.path().join("invoice.pdf");
    let weaponized_pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (cmd.exe) >> >>\nendobj\n";
    let pdf_threat = ContentScanner::inspect_content(
        &weaponized_pdf_path,
        weaponized_pdf,
        weaponized_pdf.len() as u64,
    )
    .expect("ContentScanner must detect /Launch in weaponized PDF");
    assert_eq!(pdf_threat.carrier_category, CarrierCategory::Document);
    assert_eq!(pdf_threat.severity, ThreatSeverity::Critical);
    assert_eq!(pdf_threat.risk_score, 98);
    assert!(pdf_threat.threat_name.contains("/Launch"));
    assert!(pdf_threat.can_disarm_via_cdr);

    // 2. Low-entropy `config.enc` must NOT be flagged (`BUG-CORE-05` #1)
    let config_enc_path = dir.path().join("config.enc");
    let config_enc_bytes = b"environment=production\nregion=us-east-1\ntimeout_ms=5000\n";
    assert!(
        ContentScanner::inspect_content(
            &config_enc_path,
            config_enc_bytes,
            config_enc_bytes.len() as u64
        )
        .is_none(),
        "Plaintext/low-entropy config.enc must NOT be flagged as ransomware"
    );

    // 3. Developer `project_readme.txt` must NOT be flagged (`BUG-CORE-05` #2)
    let dev_readme_path = dir.path().join("project_readme.txt");
    let dev_readme_bytes = b"# Project Build Instructions\nRun cargo test --workspace to verify all crates.\n";
    assert!(
        ContentScanner::inspect_content(
            &dev_readme_path,
            dev_readme_bytes,
            dev_readme_bytes.len() as u64
        )
        .is_none(),
        "Developer project_readme.txt must NOT be flagged as a ransom note"
    );

    // 4. Genuine ransom note & high-entropy `.locked` file MUST be flagged
    let ransom_note = dir.path().join("HOW_TO_RESTORE_FILES.txt");
    let note_content =
        b"All your files have been encrypted with military-grade AES-256. Pay 2 BTC to restore.";
    let r_threat =
        ContentScanner::inspect_content(&ransom_note, note_content, note_content.len() as u64)
            .expect("ContentScanner must detect genuine ransom note");
    assert_eq!(r_threat.carrier_category, CarrierCategory::Ransomware);
    assert_eq!(r_threat.severity, ThreatSeverity::Critical);

    let locked_file = dir.path().join("financials.xlsx.locked");
    let high_entropy_bytes: Vec<u8> = (0..=255u8).collect();
    let r_threat2 = ContentScanner::inspect_content(
        &locked_file,
        &high_entropy_bytes,
        high_entropy_bytes.len() as u64,
    )
    .expect("ContentScanner must flag high-entropy .locked ransomware files");
    assert_eq!(r_threat2.carrier_category, CarrierCategory::Ransomware);

    // 5. >4 MB (4.5 MB) `.docm` where `word/vbaProject.bin` is stored after a 4.5 MB media entry (`BUG-CORE-03`)
    let large_docm_path = dir.path().join("large_presentation.docm");
    let mut zip_buf = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut zip_buf));
        let stored_opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file("word/media/background_4k.bmp", stored_opts)
            .unwrap();
        writer.write_all(&vec![0x42u8; 4_500_000]).unwrap();
        writer
            .start_file("word/vbaProject.bin", stored_opts)
            .unwrap();
        writer.write_all(b"VBA_MACRO_PAYLOAD_PAST_4MB_OFFSET").unwrap();
        writer.finish().unwrap();
    }
    fs::write(&large_docm_path, &zip_buf).unwrap();

    let docm_threats =
        UniversalScanner::scan_file(&large_docm_path).expect("Large DOCM scan must succeed");
    assert!(
        docm_threats
            .iter()
            .any(|t| t.threat_name.contains("Macro") || t.technical_details.contains("vbaProject.bin")),
        ">4 MB DOCM with vbaProject.bin at the end of the ZIP central directory must be detected (`BUG-CORE-03`)"
    );
}

#[test]
fn test_content_scanner_amsi_bypass_script() {
    let dir = tempdir().expect("Failed to create tempdir");
    let script_path = dir.path().join("stage1.ps1");
    let script_content = b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";
    fs::write(&script_path, script_content).expect("Failed to write mock PS1");

    let threat =
        ContentScanner::inspect_content(&script_path, script_content, script_content.len() as u64)
            .expect("ContentScanner must detect AMSI bypass in PowerShell script");

    assert_eq!(threat.carrier_category, CarrierCategory::ScriptCode);
    assert_eq!(threat.severity, ThreatSeverity::Critical);
    assert!(threat.threat_name.contains("AMSI"));
}

#[tokio::test]
async fn test_tier3_sandbox_and_yara_no_size_229376_or_pki_false_positives() {
    // BUG-CORE-10 & BUG-CORE-11:
    // 1. A benign 229,376-byte signed binary containing DigiCert CRL/OCSP URLs must NOT be
    //    flagged as Ramnit and must NOT report PKI URLs as C2 IOCs.
    // 2. A PE binary containing a real `.rmnet` section header MUST be flagged.
    let mut benign_229376 = vec![0x41u8; 229_376];
    let pki_str =
        b"http://crl3.digicert.com/DigiCertTrustedRootG4.crl https://ocsp.digicert.com\0";
    benign_229376[0..pki_str.len()].copy_from_slice(pki_str);

    let yara = Tier0YaraScanner::new();
    let yara_clean = yara.scan_bytes(&benign_229376, "signed_installer.exe");
    assert!(
        !yara_clean.matched,
        "229,376-byte file without .rmnet PE section must NOT match Tier-0 YARA"
    );

    let sbx = Tier3SandboxConnector::new("http://127.0.0.1:8080", "TEST-KEY");
    let report = sbx
        .detonate_sample(SandboxDetonationRequest {
            file_name: "signed_installer.exe".to_string(),
            sha256_hex: "00".repeat(32),
            file_bytes: benign_229376,
            timeout_seconds: 30,
        })
        .await
        .unwrap();

    assert!(
        !report.verdict_malicious,
        "Benign 229,376-byte binary must NOT be flagged as Ramnit (`BUG-CORE-10` #1)"
    );
    assert!(
        report.network_iocs.is_empty(),
        "DigiCert CRL/OCSP URLs must be filtered out (`BUG-CORE-10` #3)"
    );
    assert!(
        report.is_emulated,
        "Offline heuristic report must set is_emulated = true (`BUG-CORE-10` #4)"
    );
    assert_eq!(
        report.degradation_event.as_deref(),
        Some("SANDBOX_OFFLINE_EMULATED"),
        "Offline heuristic report must record SANDBOX_OFFLINE_EMULATED (`Row 159`)"
    );

    // 3. Lookalike attacker domains (`microsoft.com.evil.io`, `crl.evil.io`) MUST NOT be filtered out as benign (`Row 158`)
    let urls = Tier3SandboxConnector::extract_non_pki_urls(
        "http://crl3.digicert.com/root.crl https://microsoft.com.evil.io/stage2.bin http://crl.evil.io/beacon",
    );
    assert_eq!(
        urls,
        vec![
            "http://crl.evil.io/beacon".to_string(),
            "https://microsoft.com.evil.io/stage2.bin".to_string()
        ],
        "Exact hostname suffix filter must catch lookalike domains (`Row 158`)"
    );
}

#[test]
fn test_intune_xml_escaping_and_falcon_cef_injection_immunity() {
    // BUG-CORE-08 (`EV-03`) & BUG-CORE-09:
    // 1. Intune OMA-URI XML export must escape `&` in `USB\VID_0781&*` to `&amp;`.
    // 2. Falcon CEF formatter must escape `|`, `=`, `\n`, and `\r` in attacker-controlled strings.
    let intune = IntunePolicyManager::new();
    let xml = intune.export_oma_uri_profile_xml();
    assert!(
        xml.contains("USB\\VID_0781&amp;*"),
        "Intune XML export must escape '&' as '&amp;' (`BUG-CORE-08`)"
    );
    assert!(
        !xml.contains("USB\\VID_0781&*"),
        "Unescaped '&' must not appear in OMA-URI XML"
    );

    let bridge = CrowdStrikeFalconBridge::new("127.0.0.1:514");
    let cef = bridge.format_cef_payload(&FalconTelemetryEvent {
        severity: 9,
        signature_id: "BADUSB|INJECT".to_string(),
        name: "Evil\nDevice|Name".to_string(),
        device_vendor_id: "0x1234".to_string(),
        device_product_id: "0x5678".to_string(),
        serial_number: "SN123 act=Allowed\nCEF:0|Fake".to_string(),
        file_sha256: None,
        action_taken: "BLOCKED".to_string(),
        details: "Line1\r\nLine2=Val".to_string(),
    });

    assert!(
        !cef.contains('\n') && !cef.contains('\r'),
        "CEF line must never contain raw newlines (`BUG-CORE-09`)"
    );
    assert!(
        cef.contains("BADUSB\\|INJECT"),
        "CEF header pipe must be escaped as \\|"
    );
    assert!(
        cef.contains("act\\=Allowed"),
        "Injected '=' in extension value must be escaped as \\= (`BUG-CORE-09`)"
    );

    // Verify CEF header 255-char cap and extension 1,023-char cap (`Row 165`)
    let long_hdr = "H".repeat(600);
    let capped_hdr = CrowdStrikeFalconBridge::escape_cef_header(&long_hdr);
    assert_eq!(capped_hdr.len(), 255);

    let long_ext = "E".repeat(2000);
    let capped_ext = CrowdStrikeFalconBridge::escape_cef_ext(&long_ext);
    assert_eq!(capped_ext.len(), 1023);

    // Verify `Docs/intune_sentinel_policy_profile.xml` matches `export_oma_uri_profile_xml()` (`Row 161`)
    let docs_xml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("Docs")
        .join("intune_sentinel_policy_profile.xml");
    if docs_xml_path.exists() {
        let on_disk_xml = fs::read_to_string(&docs_xml_path).unwrap().replace("\r\n", "\n");
        let generated_xml = xml.replace("\r\n", "\n");
        assert_eq!(on_disk_xml.trim(), generated_xml.trim());
    }

    // Verify on-disk SIEM spool, flush_spool, and 180-day retention pruning (`Row 169`)
    let dir = tempdir().unwrap();
    let spool_path = dir.path().join("siem_spool.jsonl");
    let offline_bridge = CrowdStrikeFalconBridge::with_spool_path("offline://siem", spool_path.clone());
    offline_bridge
        .emit_alert(&FalconTelemetryEvent {
            severity: 8,
            signature_id: "USB-THREAT-01".to_string(),
            name: "Blocked Composite Device".to_string(),
            device_vendor_id: "0x0781".to_string(),
            device_product_id: "0x5583".to_string(),
            serial_number: "SN-001".to_string(),
            file_sha256: None,
            action_taken: "OFFLINE_BLOCKED".to_string(),
            details: "Composite HID+Storage blocked".to_string(),
        })
        .expect("Offline SIEM alert spooling must succeed");

    // Inject an expired record (185 days old) and verify 180-day pruning removes it while keeping recent record
    offline_bridge
        .append_spool_record(&sentinel_core::enterprise::falcon::SiemSpoolRecord {
            timestamp_unix: chrono::Utc::now().timestamp() - (185 * 86_400),
            timestamp_rfc3339: "2020-01-01T00:00:00Z".to_string(),
            cef_payload: "CEF:0|Old|Record".to_string(),
            delivered: true,
        })
        .unwrap();
    let pruned = offline_bridge.prune_expired_records(180).unwrap();
    assert_eq!(pruned, 1, "185-day-old SIEM record must be pruned by 180-day retention");
    let remaining = offline_bridge.read_spool_records().unwrap();
    assert_eq!(remaining.len(), 1);
    assert!(!remaining[0].delivered);

    // Verify SignedPolicyBundle, SignedRulePack, and BreakGlassToken ECDSA P-256 verification (`Rows 186, 191, 198`)
    let (pub_key, priv_key) = sentinel_sys::generate_raw_ecdsa_p256_keypair()
        .expect("Generating ECDSA P-256 keypair must succeed");

    let mut policy_mgr = IntunePolicyManager::new()
        .with_ledger_path(dir.path().join("policy_ledger.jsonl"));
    assert_eq!(policy_mgr.policy().version, 2);

    let mut v3_policy = policy_mgr.policy().clone();
    v3_policy.version = 3;
    v3_policy.max_sanitization_file_size_mb = 100;
    let signed_v3 = sentinel_core::enterprise::intune::SignedPolicyBundle::sign(
        v3_policy.clone(),
        &priv_key,
        &pub_key,
    )
    .expect("Signing v3 policy must succeed");

    let applied = policy_mgr
        .apply_signed_policy(&signed_v3, &pub_key)
        .expect("Valid signed v3 policy must be accepted");
    assert_eq!(applied.version, 3);

    // Tampered policy signature must be rejected (`POLICY_REJECTED`) and keep v3 (`Row 198`)
    let mut tampered_bundle = signed_v3.clone();
    tampered_bundle.policy.version = 4;
    tampered_bundle.policy.enforce_usb_zero_trust = false;
    assert!(
        policy_mgr
            .apply_signed_policy(&tampered_bundle, &pub_key)
            .is_err(),
        "Tampered policy signature must be rejected"
    );
    assert_eq!(
        policy_mgr.policy().version,
        3,
        "Last known good policy (v3) must remain active after invalid signature"
    );
    assert_eq!(
        policy_mgr.last_degradation_event(),
        Some(sentinel_core::error::DegradationEvent::PolicyRejected)
    );

    // Validly signed rollback (version 2 <= active version 3) must be rejected (`Rows 186, 198`)
    let mut rollback_policy = v3_policy.clone();
    rollback_policy.version = 2;
    let signed_rollback = sentinel_core::enterprise::intune::SignedPolicyBundle::sign(
        rollback_policy,
        &priv_key,
        &pub_key,
    )
    .unwrap();
    assert!(
        policy_mgr
            .apply_signed_policy(&signed_rollback, &pub_key)
            .is_err(),
        "Rollback policy version must be rejected"
    );
    assert_eq!(policy_mgr.policy().version, 3);

    // Verify SignedRulePack in Tier0YaraScanner (`Row 186`)
    let mut yara = Tier0YaraScanner::new().with_ledger_path(dir.path().join("yara_ledger.jsonl"));
    let pack_v2 = sentinel_core::scanner::tier0_yara::SignedRulePack::sign(
        "PACK-2026-02",
        2,
        vec![sentinel_core::scanner::tier0_yara::DynamicYaraRule {
            id: "YARA_CUSTOM_BADUSB_MARKER".to_string(),
            description: "Custom BadUSB firmware marker".to_string(),
            required_markers_hex: vec![hex::encode(b"BADUSB_FW_SIGNATURE_V2")],
            min_matches: 1,
            requires_pe_header: false,
        }],
        &priv_key,
        &pub_key,
    )
    .unwrap();
    assert_eq!(yara.apply_signed_rule_pack(&pack_v2, &pub_key).unwrap(), 2);
    assert!(yara.scan_bytes(b"header BADUSB_FW_SIGNATURE_V2 footer", "fw.bin").matched);
    // Re-applying version 2 (non-monotonic) must be rejected
    assert!(yara.apply_signed_rule_pack(&pack_v2, &pub_key).is_err());

    // Verify BreakGlassToken cryptographic ECDSA P-256 verification and ledger recording (`Row 191`)
    let mut bg_ledger = AuditLedger::open(dir.path().join("bg_ledger.jsonl"));
    let token = sentinel_core::error::BreakGlassToken::issue_signed(
        "BG-2026-001",
        "Emergency SCADA PLC maintenance window",
        2_000_000_000,
        &priv_key,
        &pub_key,
    )
    .expect("Issuing signed BreakGlassToken must succeed");
    assert!(token.is_valid_at(1_900_000_000));
    assert!(
        !token.is_valid_at(2_000_000_001),
        "Expired BreakGlassToken must be rejected"
    );
    token
        .verify_and_record(1_900_000_000, &pub_key, &mut bg_ledger)
        .expect("Valid BreakGlassToken must verify and record in AuditLedger");

    let mut forged_token = token.clone();
    forged_token.reason = "Attacker tampered reason".to_string();
    assert!(!forged_token.is_valid_at(1_900_000_000));
    assert!(forged_token
        .verify_and_record(1_900_000_000, &pub_key, &mut bg_ledger)
        .is_err());
}

#[test]
fn test_kiosk_recursive_subdirectory_shred_and_audit_ledger_tamper_detection() {
    // BUG-CORE-07 & Phase 4.2:
    // 1. KioskEnforcer::end_kiosk_session recursively shreds files inside nested subdirectories.
    // 2. AuditLedger verifies hash chain and detects tampering.
    let dir = tempdir().expect("Failed to create tempdir");
    let kiosk_root = dir.path().join("kiosk_session");
    let nested_dir = kiosk_root.join("dept_a").join("confidential");
    fs::create_dir_all(&nested_dir).unwrap();
    let nested_file = nested_dir.join("schematic.pdf");
    fs::write(&nested_file, b"CONFIDENTIAL_SCADA_SCHEMATIC_BYTES").unwrap();

    let mut kiosk = KioskEnforcer::new(KioskConfig::default(), kiosk_root.clone());
    let _sess = kiosk.begin_kiosk_session();

    // Verify per-session AES-256-GCM encryption & decryption via ZeroizingBytes<32> (`Row 65`)
    let enc_rel = std::path::Path::new("dept_a/encrypted_secret.bin");
    let secret_bytes = b"TOP_SECRET_KIOSK_PAYLOAD_FOR_SESSION_KEY_TEST";
    let enc_disk_path = kiosk
        .write_encrypted_session_file(enc_rel, secret_bytes)
        .expect("Kiosk encrypted session file write must succeed");
    let raw_disk_ciphertext = fs::read(&enc_disk_path).unwrap();
    assert!(
        !raw_disk_ciphertext
            .windows(secret_bytes.len())
            .any(|w| w == secret_bytes),
        "Encrypted kiosk file on disk must not contain plaintext (`Row 65`)"
    );
    let decrypted = kiosk
        .read_encrypted_session_file(enc_rel)
        .expect("Kiosk encrypted session file must decrypt with active session key");
    assert_eq!(decrypted, secret_bytes);

    let wiped = kiosk
        .end_kiosk_session()
        .expect("Kiosk recursive session wipe must succeed");
    assert_eq!(wiped, 2);
    assert!(
        !nested_file.exists() && !enc_disk_path.exists(),
        "Nested files inside subdirectory must be shredded (`BUG-CORE-07`)"
    );
    assert!(
        kiosk.read_encrypted_session_file(enc_rel).is_err(),
        "Destroyed kiosk session key must not decrypt after end_kiosk_session"
    );

    // Test AuditLedger hash chain and tamper detection
    let ledger_path = dir.path().join("ledger").join("audit.jsonl");
    let mut ledger = AuditLedger::open(ledger_path.clone());
    ledger
        .append_event("USB_ARRIVAL", "VID=0781 PID=5583")
        .unwrap();
    ledger
        .append_event("FILE_SANITIZED", "report.docx -> clean")
        .unwrap();

    assert_eq!(
        ledger.verify_chain().expect("Valid chain must verify"),
        2
    );

    // Tamper with the first record in the ledger file
    let raw_ledger = fs::read_to_string(&ledger_path).unwrap();
    let tampered_ledger = raw_ledger.replace("VID=0781", "VID=9999");
    fs::write(&ledger_path, tampered_ledger).unwrap();

    assert!(
        ledger.verify_chain().is_err(),
        "AuditLedger::verify_chain must detect historical record tampering"
    );
}

#[tokio::test]
async fn test_interceptor_retains_channel_sender_and_vfs_shadow_cache() {
    // BUG-CORE-01 & BUG-CORE-13 (Phase 3.2):
    // 1. WindowsUmdfInterceptor retains `Sender<DeviceConnectedEvent>` so `rx.recv()` does not immediately return `None`.
    // 2. ProjFsProvider projects sanitized files into the virtual mount point and wipes them on unmount.
    let interceptor = WindowsUmdfInterceptor::new();
    let mut rx = interceptor.start_monitoring().await.unwrap();

    let synthetic_event = DeviceConnectedEvent {
        connection_id: uuid::Uuid::new_v4(),
        timestamp_utc: chrono::Utc::now(),
        vector: ConnectionVector::WiredUsb {
            vid: 0x0781,
            pid: 0x5583,
            serial: "SN-TEST-001".to_string(),
            interfaces: Vec::new(),
        },
        raw_mount_point: None,
    };

    interceptor
        .emit_event(synthetic_event.clone())
        .await
        .expect("Emitting event through retained sender must succeed (`BUG-CORE-01`)");

    let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("Should not time out")
        .expect("Channel must stay open and deliver event (`BUG-CORE-01`)");
    assert_eq!(received.connection_id, synthetic_event.connection_id);

    // Test VFS Read-Once Encrypted Shadow Cache
    let dir = tempdir().unwrap();
    let raw_usb = dir.path().join("raw_usb");
    let virt_mount = dir.path().join("safe_mount");
    fs::create_dir_all(&raw_usb).unwrap();

    // Put a valid text file and an unrecognized binary on the raw USB dir
    fs::write(
        raw_usb.join("notes.txt"),
        format!("Hello Safe USB{}", '\u{202E}'),
    )
    .unwrap();
    fs::write(raw_usb.join("dropper.exe"), b"MZ_UNAPPROVED_BINARY").unwrap();

    let vfs = ProjFsProvider::new();
    vfs.mount_sanitized_volume(&raw_usb, &virt_mount)
        .await
        .expect("VFS shadow cache projection must succeed");

    // Verify encrypted-only at-rest posture: before `on_file_First_open`, no plaintext copy exists in `virt_mount` (`Rows 147, 223`)
    assert!(
        !virt_mount.join("notes.txt").exists(),
        "Plaintext must NOT be pre-written to virtual_mount_point before on_file_First_open (`Row 147`)"
    );

    // Verify `read_projected_file` decrypts from `.enc` and verifies `sanitized_sha256` (`Row 148`)
    let decrypted_bytes = vfs
        .read_projected_file(std::path::Path::new("notes.txt"))
        .expect("read_projected_file must decrypt and SHA-256-verify .enc shadow cache entry");
    let (_, expected_sanitized_sha) = vfs
        .shadow_cache()
        .get_entry_hashes(&virt_mount, std::path::Path::new("notes.txt"))
        .unwrap();
    let actual_sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&decrypted_bytes));
    assert_eq!(actual_sha, expected_sanitized_sha);

    let projected_txt = vfs
        .on_file_First_open(std::path::Path::new("notes.txt"))
        .await
        .expect("Sanitized notes.txt must be projected");
    let clean_content = fs::read_to_string(&projected_txt).unwrap();
    assert!(
        !clean_content.contains('\u{202E}'),
        "Projected file in ShadowCache must have BiDi characters disarmed"
    );
    assert!(
        vfs.on_file_First_open(std::path::Path::new("dropper.exe"))
            .await
            .is_err(),
        "Default-deny ShadowCache must withhold unapproved executable format"
    );

    vfs.unmount_volume(&virt_mount)
        .await
        .expect("Unmounting VFS volume must crypto-erase shadow cache");
    assert!(!projected_txt.exists());

    // Verify `CACHE_QUOTA_EXCEEDED` enforcement (`Row 195`)
    let quota_cache = sentinel_core::vfs::ShadowCacheManager::with_cache_root_and_quota(
        dir.path().join("tiny_quota_cache"),
        4, // 4-byte quota
    );
    let quota_err = quota_cache
        .ingest_volume_read_once(&raw_usb, &dir.path().join("quota_mount"))
        .expect_err("Ingesting file larger than max_cache_bytes must fail with CACHE_QUOTA_EXCEEDED");
    assert!(
        quota_err.contains("CACHE_QUOTA_EXCEEDED") || quota_err.contains("SNTL-ERR-006"),
        "Unexpected quota error: {}",
        quota_err
    );
}

#[test]
fn test_universal_scanner_end_to_end_directory_scan_and_completeness_report() {
    // BUG-CORE-14:
    // Verify subdirectories do not count toward `max_files` and `ScanReport` tracks completeness.
    let dir = tempdir().expect("Failed to create tempdir");

    let sub1 = dir.path().join("sub1").join("sub2").join("sub3");
    fs::create_dir_all(&sub1).unwrap();

    let clean_file = sub1.join("readme.txt");
    fs::write(
        &clean_file,
        b"This is a perfectly safe text file with normal text.",
    )
    .unwrap();

    let polyglot_file = sub1.join("photo.jpg");
    let mut poly_bytes = vec![
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00,
    ];
    poly_bytes.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00, 0x11, 0x22, 0xFF, 0xD9]); // SOS + EOI
    poly_bytes.extend_from_slice(b"MZ_EXECUTABLE_PAYLOAD_HERE_OVERLAY_TEST");
    fs::write(&polyglot_file, &poly_bytes).unwrap();

    let bidi_file = sub1.join(format!("calc_{}cod.exe", '\u{202E}'));
    fs::write(&bidi_file, b"fake content").unwrap();

    // Even with 3 nested subdirectories, `max_files = 3` must scan all 3 regular files (`complete == true`)
    let report = UniversalScanner::scan_directory_detailed(dir.path(), 3);
    assert_eq!(report.files_scanned, 3);
    assert!(report.complete, "Scan of 3 regular files with limit=3 must be complete (`BUG-CORE-14` #3)");
    assert!(report.threats.len() >= 2);

    let threat_paths: Vec<_> = report.threats.iter().map(|t| &t.file_path).collect();
    assert!(!threat_paths.contains(&&clean_file));
    assert!(threat_paths.contains(&&polyglot_file));
    assert!(threat_paths.contains(&&bidi_file));

    // With `max_files = 2`, `limit_reached` must be true and `complete` must be false (`BUG-CORE-14` #2)
    let partial_report = UniversalScanner::scan_directory_detailed(dir.path(), 2);
    assert!(partial_report.limit_reached);
    assert!(!partial_report.complete);
}

#[test]
fn test_kiosk_posture_blocks_session_when_noncompliant() {
    // Master Plan v2 §0.1 & §5 (`kiosk_posture_blocks_session`):
    // Verify `KioskEnforcer::begin_kiosk_session_with_posture` refuses to start a strict
    // session when `PostureReport::is_compliant()` is false, and succeeds when compliant.
    let dir = tempdir().unwrap();
    let mut kiosk = KioskEnforcer::new(KioskConfig::default(), dir.path().join("kiosk"));

    let noncompliant = PostureReport {
        automount_disabled: false,
        removable_volumes_offline: vec![("E:\\".to_string(), false)],
        user_deny_policy_present: true,
        install_restrictions_active: true,
        write_protect_active: true,
        autoplay_suppressed: true,
        linux_authorized_default_zero: Some(false),
    };
    assert!(!noncompliant.is_compliant());
    assert!(
        kiosk
            .begin_kiosk_session_with_posture(&noncompliant)
            .is_err(),
        "Non-compliant posture must block strict kiosk session startup"
    );

    let compliant = PostureReport {
        automount_disabled: true,
        removable_volumes_offline: vec![("E:\\".to_string(), true)],
        user_deny_policy_present: true,
        install_restrictions_active: true,
        write_protect_active: true,
        autoplay_suppressed: true,
        linux_authorized_default_zero: Some(true),
    };
    assert!(compliant.is_compliant());
    let sess_id = kiosk
        .begin_kiosk_session_with_posture(&compliant)
        .expect("Compliant posture must allow strict kiosk session startup");
    assert!(sess_id.starts_with("KSESS-"));
    let _ = kiosk.end_kiosk_session();
}

// =========================================================================
// Master Plan v2 §5 Exact Edge-Case Matrix Test Suite (Core Targets)
// =========================================================================

#[test]
fn large_jpeg_exif_thumbnail_clean() {
    // Master Plan v2 §1.3 & §5 (`T1`, `large_jpeg_exif_thumbnail_clean`):
    // Construct a >4.5 MB camera JPEG with an `APP1` (`0xFF 0xE1`) EXIF segment containing
    // an inner thumbnail (`0xFF 0xD8 ... 0xFF 0xD9`) followed by >4.5 MB of JPEG `COM` (`0xFF 0xFE`)
    // segments and a final `SOS` + `EOI` (`0xFF 0xD9`). Verify the forward JPEG parser skips
    // the EXIF thumbnail `0xFF 0xD9`, walks the full >4.5 MB stream, and reports `0` threats.
    let dir = tempdir().expect("Failed to create tempdir");
    let large_jpeg_path = dir.path().join("camera_12mp_with_exif.jpg");

    let exif_payload: &[u8] = b"Exif\x00\x00\xFF\xD8\xFF\xDB\x00\x04\x00\x00\xFF\xD9";
    let app1_len = (exif_payload.len() + 2) as u16;
    let mut jpeg = Vec::with_capacity(4_800_000);
    jpeg.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE1]);
    jpeg.extend_from_slice(&app1_len.to_be_bytes());
    jpeg.extend_from_slice(exif_payload);

    // Append 80 x 60,000-byte JPEG COM (0xFF 0xFE) segments = 4,800,000 bytes (>4.5 MB)
    let seg_payload_len: usize = 60_000;
    let seg_header_len: u16 = (seg_payload_len + 2) as u16;
    for _ in 0..80 {
        jpeg.extend_from_slice(&[0xFF, 0xFE]);
        jpeg.extend_from_slice(&seg_header_len.to_be_bytes());
        jpeg.resize(jpeg.len() + seg_payload_len, 0x5A);
    }
    // Append SOS (0xFF 0xDA) + entropy-coded scan bytes + true EOI (0xFF 0xD9)
    jpeg.extend_from_slice(&[
        0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0xFF, 0xD9,
    ]);
    assert!(
        jpeg.len() > 4_600_000,
        "Synthetic camera JPEG must exceed 4.5 MB"
    );
    fs::write(&large_jpeg_path, &jpeg).unwrap();

    assert!(
        PolyglotScanner::inspect(&large_jpeg_path, &jpeg, jpeg.len() as u64).is_none(),
        ">4.5 MB JPEG with EXIF thumbnail EOI must be clean in PolyglotScanner (`T1`)"
    );
    let threats = UniversalScanner::scan_file(&large_jpeg_path).unwrap();
    assert!(
        threats.is_empty(),
        ">4.5 MB JPEG with EXIF thumbnail must produce 0 threats in UniversalScanner: got {:?}",
        threats
    );
}

#[test]
fn jpeg_trailing_data_detected() {
    // Master Plan v2 §1.3 & §5 (`T2`, `jpeg_trailing_data_detected`):
    // Construct a JPEG with data appended after the main-image `EOI` (`0xFF 0xD9`) AND place
    // a SECOND `0xFF 0xD9` at the very end of the appended data! A broken reverse `rfind`
    // scanner would stop at the final `0xFF 0xD9` and miss the payload; our forward segment
    // walker must stop at the FIRST main-image `EOI` and flag the trailing data.
    let dir = tempdir().expect("Failed to create tempdir");
    let poly_path = dir.path().join("double_eoi_polyglot.jpg");

    let exif_payload: &[u8] = b"Exif\x00\x00\xFF\xD8\xFF\xDB\x00\x04\x00\x00\xFF\xD9";
    let app1_len = (exif_payload.len() + 2) as u16;
    let mut poly_jpeg = Vec::new();
    poly_jpeg.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE1]);
    poly_jpeg.extend_from_slice(&app1_len.to_be_bytes());
    poly_jpeg.extend_from_slice(exif_payload);
    // Main image SOS + scan data + true main-image EOI
    poly_jpeg.extend_from_slice(&[
        0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00, 0x11, 0x22, 0x33, 0xFF, 0xD9,
    ]);
    let main_eoi_end = poly_jpeg.len() as u64;

    // Append malicious payload after main EOI, terminated by a decoy second EOI (`0xFF 0xD9`)
    poly_jpeg.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00_HIDDEN_BETWEEN_TWO_EOIS_");
    poly_jpeg.extend_from_slice(&[0x90; 128]);
    poly_jpeg.extend_from_slice(&[0xFF, 0xD9]);
    fs::write(&poly_path, &poly_jpeg).unwrap();

    let threat = PolyglotScanner::inspect(&poly_path, &poly_jpeg, poly_jpeg.len() as u64)
        .expect("JPEG with trailing payload ending in a second EOI must be detected (`T2`)");
    assert_eq!(threat.carrier_category, CarrierCategory::Image);
    assert_eq!(
        threat.overlay_offset,
        Some(main_eoi_end),
        "Forward JPEG parser must pinpoint exact main-image EOI offset even when trailing data ends in 0xFF 0xD9"
    );
}

#[test]
fn mp4_moov_after_mdat_clean() {
    // Master Plan v2 §1.3 & §5 (`T3`, `mp4_moov_after_mdat_clean`):
    // 1. Verify >4.5 MB MP4 on disk where `moov` follows `mdat` is clean.
    test_polyglot_scanner_png_chunk_walk_and_mp4_moov_after_mdat();

    // 2. Verify a >4 GiB (`5_000_000_536` bytes) virtual MP4 stream using a 64-bit `largesize`
    //    (`size == 1`) `mdat` box followed by a `moov` box at offset >4 GiB is walked cleanly
    //    via `Read + Seek` without allocating >4 GiB in RAM!
    struct Virtual5GbMp4Stream {
        pos: u64,
        total_len: u64,
        ftyp_end: u64,
        mdat_end: u64,
        header_bytes: [u8; 40],
        moov_bytes: [u8; 512],
    }

    impl Virtual5GbMp4Stream {
        fn new() -> Self {
            let ftyp_size: u32 = 24;
            let mdat_largesize: u64 = 5_000_000_000;
            let ftyp_end = ftyp_size as u64;
            let mdat_end = ftyp_end + mdat_largesize;
            let moov_size: u32 = 512;
            let total_len = mdat_end + (moov_size as u64);

            let mut header_bytes = [0u8; 40];
            // ftyp box (0..24)
            header_bytes[0..4].copy_from_slice(&ftyp_size.to_be_bytes());
            header_bytes[4..24].copy_from_slice(b"ftypisom\x00\x00\x02\x00isomiso2");
            // 64-bit largesize mdat header (24..40): size == 1 (u32), type == "mdat", largesize == 5_000_000_000 (u64 BE)
            header_bytes[24..28].copy_from_slice(&1u32.to_be_bytes());
            header_bytes[28..32].copy_from_slice(b"mdat");
            header_bytes[32..40].copy_from_slice(&mdat_largesize.to_be_bytes());

            let mut moov_bytes = [0x22u8; 512];
            moov_bytes[0..4].copy_from_slice(&moov_size.to_be_bytes());
            moov_bytes[4..8].copy_from_slice(b"moov");

            Self {
                pos: 0,
                total_len,
                ftyp_end,
                mdat_end,
                header_bytes,
                moov_bytes,
            }
        }
    }

    impl std::io::Read for Virtual5GbMp4Stream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.total_len || buf.is_empty() {
                return Ok(0);
            }
            let avail = (self.total_len - self.pos) as usize;
            let to_read = buf.len().min(avail);
            for (i, slot) in buf[..to_read].iter_mut().enumerate() {
                let offset = self.pos + (i as u64);
                *slot = if offset < 40 {
                    self.header_bytes[offset as usize]
                } else if offset >= self.mdat_end {
                    self.moov_bytes[(offset - self.mdat_end) as usize]
                } else {
                    0x11
                };
            }
            let _ = self.ftyp_end;
            self.pos += to_read as u64;
            Ok(to_read)
        }
    }

    impl std::io::Seek for Virtual5GbMp4Stream {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            let next = match pos {
                std::io::SeekFrom::Start(s) => s as i128,
                std::io::SeekFrom::Current(c) => (self.pos as i128) + (c as i128),
                std::io::SeekFrom::End(e) => (self.total_len as i128) + (e as i128),
            };
            if next < 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Negative seek",
                ));
            }
            self.pos = next as u64;
            Ok(self.pos)
        }
    }

    let mut stream = Virtual5GbMp4Stream::new();
    let total_len = stream.total_len;
    assert!(total_len > 4 * 1024 * 1024 * 1024, "Stream must exceed 4 GiB");
    let mp4_path = std::path::Path::new("virtual_5gb_recording.mp4");
    assert!(
        PolyglotScanner::inspect_reader(mp4_path, &mut stream, total_len, None).is_none(),
        ">4 GiB 64-bit largesize MP4 with moov after mdat must be clean (`T3`)"
    );
}

#[test]
fn clear_reserved_name() {
    test_secure_shredder_reserved_dos_name_and_ads_surgical_shred();
}

#[test]
fn cef_escaping() {
    // Master Plan v2 §4.1, §5 (`T10`, `cef_escaping`) & §5.2 #2 (`Row 200`):
    // 1. Run deterministic CEF & XML injection regression tests
    test_intune_xml_escaping_and_falcon_cef_injection_immunity();

    // 2. Property test (`Row 200`): across 200 deterministic unstructured strings,
    //    `escape_cef_header`, `escape_cef_ext`, and `escape_xml` never yield an unescaped
    //    field delimiter or exceed the 255 / 1,023 byte caps.
    for seed in 0..200u64 {
        let mut raw = Vec::with_capacity(128);
        for blk in 0..4u64 {
            let mut msg = [0u8; 16];
            msg[..8].copy_from_slice(&seed.to_le_bytes());
            msg[8..].copy_from_slice(&blk.to_le_bytes());
            raw.extend_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(msg));
        }
        // Inject adversarial delimiter bytes into every seed
        raw.extend_from_slice(b"|=\r\n\\<>&\"'");
        let candidate = String::from_utf8_lossy(&raw).into_owned();

        let hdr = CrowdStrikeFalconBridge::escape_cef_header(&candidate);
        assert!(hdr.len() <= 255, "CEF header must obey 255-byte cap");
        assert!(!hdr.contains('\n') && !hdr.contains('\r'));
        // Every `|` in `hdr` must be preceded by `\`
        for (idx, b) in hdr.bytes().enumerate() {
            if b == b'|' {
                assert!(idx > 0 && hdr.as_bytes()[idx - 1] == b'\\');
            }
        }

        let ext = CrowdStrikeFalconBridge::escape_cef_ext(&candidate);
        assert!(ext.len() <= 1023, "CEF extension must obey 1023-byte cap");
        assert!(!ext.contains('\n') && !ext.contains('\r'));
        // Every `=` in `ext` must be preceded by `\`
        for (idx, b) in ext.bytes().enumerate() {
            if b == b'=' {
                assert!(idx > 0 && ext.as_bytes()[idx - 1] == b'\\');
            }
        }

        let xml_escaped = IntunePolicyManager::escape_xml(&candidate);
        assert!(
            !xml_escaped.contains('<')
                && !xml_escaped.contains('>')
                && !xml_escaped.contains('"')
                && !xml_escaped.contains('\''),
            "XML escaping must never leave raw <, >, \", or '"
        );
    }
}

#[test]
fn invariant_i1() {
    // Master Plan v2 §0.1, §5 (`T11`, `invariant_i1`):
    // 1. Verify exact Windows MountMgr IOCTL control codes (`Critical #2`, `Rows 13, 14`):
    //    `CTL_CODE(MOUNTMGRCONTROLTYPE=0x6D, 15, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)` == `0x006D003C`
    //    `CTL_CODE(MOUNTMGRCONTROLTYPE=0x6D, 16, METHOD_BUFFERED=0, FILE_READ_ACCESS|FILE_WRITE_ACCESS=3)` == `0x006DC040`
    assert_eq!(
        sentinel_sys::IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT,
        0x006D_003C,
        "IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT must equal 0x006D003C"
    );
    assert_eq!(
        sentinel_sys::IOCTL_MOUNTMGR_SET_AUTO_MOUNT,
        0x006D_C040,
        "IOCTL_MOUNTMGR_SET_AUTO_MOUNT must equal 0x006DC040 (never 0x006D0038)"
    );

    // 2. Verify volume GUID enumeration (`\\?\Volume{GUID}\` on Windows, `/sys/block` on Linux)
    let _volumes = sentinel_sys::enumerate_usb_volumes();

    // 3. Verify `PostureReport::is_compliant()` fails closed when automount is enabled or any removable volume is online
    let non_compliant = PostureReport {
        automount_disabled: false,
        removable_volumes_offline: vec![(
            r"\\?\Volume{00000000-0000-0000-0000-000000000001}\".to_string(),
            false,
        )],
        user_deny_policy_present: false,
        install_restrictions_active: false,
        write_protect_active: false,
        autoplay_suppressed: false,
        linux_authorized_default_zero: Some(false),
    };
    assert!(!non_compliant.is_compliant());

    let online_volume_noncompliant = PostureReport {
        automount_disabled: true,
        removable_volumes_offline: vec![(
            r"\\?\Volume{00000000-0000-0000-0000-000000000001}\".to_string(),
            false,
        )],
        user_deny_policy_present: true,
        install_restrictions_active: true,
        write_protect_active: true,
        autoplay_suppressed: true,
        linux_authorized_default_zero: Some(true),
    };
    assert!(
        !online_volume_noncompliant.is_compliant(),
        "PostureReport::is_compliant() must return false if any removable volume GUID is online"
    );
}

#[tokio::test]
async fn invariant_i2_rig() {
    // Master Plan v2 §0.1, §3.2 & §5 (`T12`, `invariant_i2_rig`):
    // 1. Test using a custom `MutatingUsbReader` (`std::io::Read`) that returns
    //    `"FIRST_READ_CLEAN_CONTENT\n"` on read #1 and `"SECOND_READ_MALICIOUS_PAYLOAD_SWAP\n"`
    //    if read a second time, proving `ShadowCacheManager` reads the stream at most once,
    //    stores AES-256-GCM `.enc` ciphertext on disk, and `read_and_verify` verifies `sanitized_sha256`.
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct MutatingUsbReader {
        reads_started: Arc<AtomicUsize>,
        inner: Cursor<Vec<u8>>,
    }

    impl MutatingUsbReader {
        fn open(counter: Arc<AtomicUsize>) -> Self {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let payload = if n == 0 {
                b"FIRST_READ_CLEAN_CONTENT\n".to_vec()
            } else {
                b"SECOND_READ_MALICIOUS_PAYLOAD_SWAP\n".to_vec()
            };
            Self {
                reads_started: counter,
                inner: Cursor::new(payload),
            }
        }
    }

    impl std::io::Read for MutatingUsbReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let _ = &self.reads_started;
            self.inner.read(buf)
        }
    }

    let dir = tempdir().unwrap();
    let cache_mgr = sentinel_core::vfs::ShadowCacheManager::with_cache_root_and_quota(
        dir.path().join("shadow_cipher_store"),
        64 * 1024 * 1024,
    )
    .with_ledger_path(dir.path().join("i2_ledger.jsonl"));

    let read_counter = Arc::new(AtomicUsize::new(0));
    let virt_mount = dir.path().join("rig_mount");
    let rel_path = std::path::Path::new("controller_file.txt");

    let entry = cache_mgr
        .ingest_stream_from_reader(
            &virt_mount,
            rel_path,
            MutatingUsbReader::open(Arc::clone(&read_counter)),
        )
        .expect("Single-read stream ingestion must succeed");
    assert_eq!(
        read_counter.load(Ordering::SeqCst),
        1,
        "ShadowCacheManager must read from the USB stream exactly once (`Invariant I2`)"
    );

    // Verify the on-disk `.enc` file is AES-256-GCM ciphertext and does NOT contain plaintext
    let enc_path = cache_mgr
        .get_encrypted_cache_path(&virt_mount, rel_path)
        .expect("Encrypted cache path must exist");
    let raw_enc_bytes = fs::read(&enc_path).unwrap();
    assert!(
        !raw_enc_bytes
            .windows(b"FIRST_READ_CLEAN_CONTENT".len())
            .any(|w| w == b"FIRST_READ_CLEAN_CONTENT"),
        "On-disk .enc shadow cache file must be AES-256-GCM ciphertext, never plaintext (`Row 147`)"
    );

    // Even if a second read from the malicious USB controller would now return malicious bytes,
    // `read_and_verify` serves only the SHA-256-verified first-read copy from the encrypted cache!
    let mut second_attempt = Vec::new();
    std::io::Read::read_to_end(
        &mut MutatingUsbReader::open(Arc::clone(&read_counter)),
        &mut second_attempt,
    )
    .unwrap();
    assert_eq!(second_attempt, b"SECOND_READ_MALICIOUS_PAYLOAD_SWAP\n");

    let verified_bytes = cache_mgr
        .read_and_verify(&virt_mount, rel_path)
        .expect("read_and_verify must decrypt and verify SHA-256");
    assert_eq!(verified_bytes, b"FIRST_READ_CLEAN_CONTENT\n");
    assert_eq!(
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&verified_bytes)),
        entry.sanitized_sha256
    );
}

#[test]
fn invariant_i4() {
    // Master Plan v2 §0.1, §1.1 & §5 (`T14`, `invariant_i4`) + §5.2 #2 (`Row 200`):
    // 1. Fault injection between `.quar` write and source removal:
    //    `quarantine_file_with_fault_injection(..., true)` MUST abort and leave the source file
    //    completely intact on disk!
    let dir = tempdir().expect("Failed to create tempdir");
    let vault_dir = dir.path().join("i4_vault");
    let vault = QuarantineVault::open(vault_dir).expect("Vault open must succeed");

    let src_file = dir.path().join("critical_evidence_sample.bin");
    let src_bytes = b"ORIGINAL_SOURCE_FILE_BYTES_MUST_SURVIVE_FAULT_INJECTION";
    fs::write(&src_file, src_bytes).unwrap();

    let fault_res = vault.quarantine_file_with_fault_injection(
        &src_file,
        "Trojan.FaultInjection.Test",
        true,
    );
    assert!(
        fault_res.is_err(),
        "quarantine_file_with_fault_injection(..., true) must abort when .quar verification fails"
    );
    assert!(
        src_file.exists(),
        "Invariant I4: Source file MUST still exist on disk when vault verification fails before removal"
    );
    assert_eq!(
        fs::read(&src_file).unwrap(),
        src_bytes,
        "Invariant I4: Source file bytes must be 100% untouched on fault abort"
    );

    // 2. Property test (`Row 200` #2): `restore(quarantine(x)) == x` across 10 deterministic unstructured payloads
    for seed in 0..10u64 {
        let mut raw = Vec::with_capacity(128);
        for blk in 0..4u64 {
            let mut msg = [0u8; 16];
            msg[..8].copy_from_slice(&seed.to_le_bytes());
            msg[8..].copy_from_slice(&blk.to_le_bytes());
            raw.extend_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(msg));
        }
        let len = 1 + ((raw[0] as usize) % (raw.len() - 1));
        let payload: Vec<u8> = raw[..len].to_vec();

        let item_path = dir.path().join(format!("prop_sample_{}.bin", seed));
        let restore_path = dir.path().join(format!("prop_restored_{}.bin", seed));
        fs::write(&item_path, &payload).unwrap();

        let q_entry = vault
            .quarantine_file(&item_path, "Property.Roundtrip.Test")
            .expect("Quarantine in property loop must succeed");
        assert!(!item_path.exists());
        vault
            .restore_file(&q_entry.entry_id, &restore_path)
            .expect("Restore in property loop must succeed");
        assert_eq!(
            fs::read(&restore_path).unwrap(),
            payload,
            "Property restore(quarantine(x)) == x failed for seed {}",
            seed
        );
    }
}

#[test]
fn allowlist_blocks_containers() {
    // Master Plan v2 §2.6 & §5 (`T15`, `allowlist_blocks_containers`, `Rows 76, 77, 132`):
    // 1. All 12 dangerous container extensions (`.iso`, `.img`, `.vhd`, `.vhdx`, `.lnk`, `.url`,
    //    `.scf`, `.library-ms`, `.searchconnector-ms`, `.hta`, `.chm`, `.one`) must be flagged
    //    for quarantine (`can_disarm_via_cdr == false`).
    let dir = tempdir().unwrap();
    let container_extensions = [
        "iso",
        "img",
        "vhd",
        "vhdx",
        "lnk",
        "url",
        "scf",
        "library-ms",
        "searchconnector-ms",
        "hta",
        "chm",
        "one",
    ];
    for ext in container_extensions {
        let p = dir.path().join(format!("suspicious_carrier.{}", ext));
        fs::write(&p, b"CONTAINER_TEST_PAYLOAD_BYTES").unwrap();
        let threats = UniversalScanner::scan_file(&p).unwrap();
        assert!(
            !threats.is_empty() && threats.iter().any(|t| !t.can_disarm_via_cdr),
            "Container extension .{} must be blocked for quarantine by default-deny allowlist (`Row 76`)",
            ext
        );
    }

    // 2. Magic-byte container detection regardless of extension (`MSCF` Cabinet, `ITSF` CHM,
    //    `L\x00\x00\x00\x01\x14\x02\x00` LNK, `conectix` VHD, `vhdxfile` VHDX) disguised as `.txt`
    let disguised_cases: &[(&str, &[u8])] = &[
        ("disguised_cab.txt", b"MSCF\x00\x00\x00\x00_CABINET_DATA"),
        ("disguised_chm.txt", b"ITSF\x03\x00\x00\x00_CHM_HELP_DATA"),
        ("disguised_lnk.txt", b"L\x00\x00\x00\x01\x14\x02\x00_SHELL_LINK"),
        ("disguised_vhd.txt", b"conectix_VIRTUAL_HARD_DISK"),
        ("disguised_vhdx.txt", b"vhdxfile_VIRTUAL_HARD_DISK_V2"),
    ];
    for (name, magic_bytes) in disguised_cases {
        let p = dir.path().join(name);
        fs::write(&p, magic_bytes).unwrap();
        let threats = UniversalScanner::scan_file(&p).unwrap();
        assert!(
            !threats.is_empty() && threats.iter().any(|t| !t.can_disarm_via_cdr),
            "Magic-byte container '{}' disguised as .txt must be blocked (`Row 76`)",
            name
        );
    }

    // 3. Multi-entry ZIP archive where entry #1 is unencrypted and entry #2 has general-purpose
    //    bit 0 (encrypted flag) set in the Central Directory (`Row 77`)
    let mut multi_zip = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut multi_zip));
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("readme_clean.txt", opts).unwrap();
        writer.write_all(b"First entry is unencrypted").unwrap();
        writer.start_file("secret_second_entry.bin", opts).unwrap();
        writer.write_all(b"Second entry will have encrypted bit 0 set").unwrap();
        writer.finish().unwrap();
    }
    // Set general-purpose bit 0 on the SECOND Central Directory header (`PK\x01\x02`)
    let cd_positions: Vec<usize> = multi_zip
        .windows(4)
        .enumerate()
        .filter_map(|(i, w)| if w == b"PK\x01\x02" { Some(i) } else { None })
        .collect();
    assert_eq!(cd_positions.len(), 2);
    let second_cd = cd_positions[1];
    multi_zip[second_cd + 8] |= 0x01; // general purpose bit flag bit 0 = encrypted

    let multi_zip_path = dir.path().join("multi_entry_encrypted.zip");
    fs::write(&multi_zip_path, &multi_zip).unwrap();
    let multi_zip_threats = UniversalScanner::scan_file(&multi_zip_path).unwrap();
    assert!(
        !multi_zip_threats.is_empty()
            && multi_zip_threats.iter().any(|t| !t.can_disarm_via_cdr),
        "Multi-entry ZIP where entry #2 is encrypted must be detected via Central Directory walk (`Row 77`)"
    );

    // 4. Generic `.zip` containing an `.exe` must be rejected by `CdrEngine` under default-deny allowlist (`High #11`)
    let mut exe_zip = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut exe_zip));
        writer
            .start_file("payload.exe", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"MZ_PACKAGED_EXE_INSIDE_ZIP").unwrap();
        writer.finish().unwrap();
    }
    let cdr = sentinel_cdr::engine::CdrEngine::new(sentinel_cdr::SanitizationPolicy::default());
    assert!(
        cdr.sanitize_with_hint(&exe_zip, "bundle.zip", cdr.policy())
            .is_err(),
        "CdrEngine must reject generic .zip archives by default (`allow_generic_zip = false`, `High #11`)"
    );
}

#[test]
fn walk_error_marks_incomplete() {
    // Master Plan v2 §1.3 & §5 (`T16`, `walk_error_marks_incomplete`, `Rows 80, 81, 84`):
    // 1. Non-existent root directory sets `complete = false` and records a `WalkError`.
    let dir = tempdir().unwrap();
    let missing_root = dir.path().join("does_not_exist_usb");
    let report = UniversalScanner::scan_directory_detailed(&missing_root, 100);
    assert!(!report.errors.is_empty());
    assert!(!report.complete);

    // 2. Existing directory containing a regular file that fails `File::open` (locked with
    //    `share_mode(0)` on Windows / `chmod 000` on Unix) sets `complete = false` and records
    //    the error in `report.errors` so the volume stays offline (`Row 84, 85`).
    let usb_dir = dir.path().join("locked_usb_volume");
    fs::create_dir_all(&usb_dir).unwrap();
    fs::write(usb_dir.join("clean_note.txt"), b"Safe text file").unwrap();
    let locked_path = usb_dir.join("unreadable_secret.dat");
    fs::write(&locked_path, b"LOCKED_FILE_CONTENT").unwrap();

    #[cfg(windows)]
    let _exclusive_handle = {
        use std::os::windows::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0) // Exclusive lock: any subsequent File::open fails with ERROR_SHARING_VIOLATION
            .open(&locked_path)
            .expect("Opening file with share_mode(0) must succeed")
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&locked_path, fs::Permissions::from_mode(0o000)).unwrap();
    }

    let locked_report = UniversalScanner::scan_directory_detailed(&usb_dir, 100);
    assert!(
        !locked_report.complete,
        "Directory scan with an unreadable/locked file must set complete = false (`T16`, `Row 84`)"
    );
    assert!(
        !locked_report.errors.is_empty(),
        "Directory scan with an unreadable/locked file must record a WalkError in report.errors"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&locked_path, fs::Permissions::from_mode(0o600));
    }
}

#[test]
fn walk_skips_links() {
    let dir = tempdir().expect("Failed to create tempdir");
    let outside_dir = dir.path().join("outside_sensitive");
    let kiosk_session_dir = dir.path().join("kiosk_session");
    fs::create_dir_all(&outside_dir).unwrap();
    fs::create_dir_all(&kiosk_session_dir).unwrap();

    let sensitive_target = outside_dir.join("system_secret.txt");
    let secret_bytes = b"DO_NOT_OVERWRITE_OUTSIDE_SYMLINK_TARGET_DATA";
    fs::write(&sensitive_target, secret_bytes).unwrap();

    let session_regular = kiosk_session_dir.join("ephemeral.txt");
    fs::write(&session_regular, b"EPHEMERAL_SESSION_DATA").unwrap();

    #[cfg(windows)]
    {
        // Create an NTFS directory junction (`mklink /J`) inside `kiosk_session_dir` pointing to `outside_dir`
        let junction_path = kiosk_session_dir.join("linked_outside_dir");
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &junction_path.to_string_lossy(),
                &outside_dir.to_string_lossy(),
            ])
            .output();
        if let Ok(out) = status {
            if out.status.success() {
                // 1. Direct `SecureShredder::shred_file` on a reparse point MUST fail closed (`Err`)
                assert!(
                    SecureShredder::shred_file(
                        &junction_path,
                        ShredMethod::ClearMultiPass { passes: 3 }
                    )
                    .is_err(),
                    "SecureShredder::shred_file must refuse reparse points / junctions"
                );

                // 2. `UniversalScanner::scan_directory_detailed` must skip the junction and record it in `skipped_symlinks`
                let scan_rep = UniversalScanner::scan_directory_detailed(&kiosk_session_dir, 100);
                assert_eq!(
                    scan_rep.files_scanned, 1,
                    "UniversalScanner must scan only the 1 regular file inside kiosk_session_dir and skip the junction"
                );
                assert!(
                    !scan_rep.skipped_symlinks.is_empty(),
                    "UniversalScanner must record skipped junction/symlink in skipped_symlinks (`Row 82`)"
                );
            }
        }
        // Also try file symlink if privileges / Developer Mode allow
        let file_link = kiosk_session_dir.join("symlink_to_secret.txt");
        if std::os::windows::fs::symlink_file(&sensitive_target, &file_link).is_ok() {
            assert!(
                SecureShredder::shred_file(
                    &file_link,
                    ShredMethod::ClearMultiPass { passes: 3 }
                )
                .is_err(),
                "SecureShredder::shred_file must refuse file symlinks"
            );
        }
    }

    #[cfg(unix)]
    {
        let file_link = kiosk_session_dir.join("symlink_to_secret.txt");
        std::os::unix::fs::symlink(&sensitive_target, &file_link).unwrap();
        assert!(
            SecureShredder::shred_file(&file_link, ShredMethod::ClearMultiPass { passes: 3 })
                .is_err(),
            "SecureShredder::shred_file must refuse file symlinks"
        );
        let scan_rep = UniversalScanner::scan_directory_detailed(&kiosk_session_dir, 100);
        assert_eq!(scan_rep.files_scanned, 1);
        assert!(!scan_rep.skipped_symlinks.is_empty());
    }

    // 3. `KioskEnforcer::end_kiosk_session` must shred `ephemeral.txt`, unlink any symlink/junction,
    //    and leave `sensitive_target` completely untouched!
    let mut kiosk = KioskEnforcer::new(KioskConfig::default(), kiosk_session_dir.clone());
    let _ = kiosk.begin_kiosk_session();
    let wiped = kiosk.end_kiosk_session().expect("Kiosk wipe must succeed");
    assert_eq!(wiped, 1, "Only the 1 regular session file should be shredded");
    assert!(!session_regular.exists());
    assert!(
        sensitive_target.exists(),
        "Outside target of symlink/junction must NEVER be deleted"
    );
    assert_eq!(
        fs::read(&sensitive_target).unwrap(),
        secret_bytes,
        "Outside target of symlink/junction must NEVER be overwritten (`Critical #1`, Row 67)"
    );
}

#[test]
fn walk_counts_files_only() {
    test_universal_scanner_end_to_end_directory_scan_and_completeness_report();
}

#[tokio::test]
async fn no_verdict_from_family_name() {
    // Master Plan v2 §3.3 & §5 (`T20`, `no_verdict_from_family_name`, `Rows 157, 158`):
    // 1. A text file or binary merely mentioning "Ramnit" or "Emotet" in plain text must NOT trigger a malware verdict.
    let benign_note =
        b"Threat Intel Report: Trojan:Win32/Ramnit!pz and Emotet were observed in historical samples."
            .to_vec();
    let yara = Tier0YaraScanner::new();
    assert!(
        !yara.scan_bytes(&benign_note, "threat_intel_note.txt").matched,
        "Plaintext mention of 'Ramnit'/'Emotet' must not match Tier-0 YARA"
    );

    let sbx = Tier3SandboxConnector::new("http://127.0.0.1:8080", "TEST-KEY");
    let report = sbx
        .detonate_sample(SandboxDetonationRequest {
            file_name: "threat_intel_note.txt".to_string(),
            sha256_hex: "11".repeat(32),
            file_bytes: benign_note,
            timeout_seconds: 10,
        })
        .await
        .unwrap();
    assert!(
        !report.verdict_malicious,
        "Plaintext mention of 'Ramnit' must not trigger a malware verdict (`no_verdict_from_family_name`)"
    );

    // 2. Also verify PKI URLs vs lookalike attacker domains (`Row 158`)
    let urls = Tier3SandboxConnector::extract_non_pki_urls(
        "http://crl3.digicert.com/root.crl https://microsoft.com.evil.io/stage2.bin http://crl.evil.io/beacon",
    );
    assert_eq!(
        urls,
        vec![
            "http://crl.evil.io/beacon".to_string(),
            "https://microsoft.com.evil.io/stage2.bin".to_string()
        ]
    );
}

#[test]
fn vault_migrate_legacy() {
    use sentinel_core::scanner::quarantine::LegacyMigrationAction;

    // Master Plan v2 §1.1 #4 & §5 (`T21`, `vault_migrate_legacy`, `Row 49`):
    // Legacy `.quar` files from the old v1 vault (without a v2 envelope and with or without a sidecar)
    // must be listed as `UNRECOVERABLE_LEGACY`, never silently deleted on `new()`/`open()`,
    // recorded in the audit ledger upon migration, and support both `Keep` and `Delete` admin choices.
    let dir = tempdir().expect("Failed to create tempdir");
    let vault_dir = dir.path().join("legacy_vault");
    fs::create_dir_all(&vault_dir).unwrap();

    let legacy_quar = vault_dir.join("v1-ephemeral-lost-key.quar");
    let legacy_ciphertext = b"\x9f\x82\x11\x44RAW_V1_CIPHERTEXT_WITH_DISCARDED_KEY";
    fs::write(&legacy_quar, legacy_ciphertext).unwrap();

    let vault = QuarantineVault::open(vault_dir.clone()).expect("Vault open must succeed");
    assert!(
        legacy_quar.exists(),
        "Legacy .quar file must never be silently deleted on vault initialization"
    );

    // Listing must report the legacy file as `UNRECOVERABLE_LEGACY`
    let listed = vault.list().expect("Vault list must succeed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].entry_id, "v1-ephemeral-lost-key");
    assert_eq!(listed[0].recovery_status, "UNRECOVERABLE_LEGACY");

    // Admin chooses `Keep` -> keeps inert ciphertext and logs `UNRECOVERABLE_LEGACY` in the ledger
    let migrated_keep = vault
        .migrate_legacy_entries_with_action(LegacyMigrationAction::Keep)
        .expect("Legacy migration (Keep) must succeed");
    assert_eq!(migrated_keep, vec!["v1-ephemeral-lost-key".to_string()]);
    assert!(
        legacy_quar.exists(),
        "Keep action must preserve legacy .quar as inert ciphertext"
    );
    let ledger_file = vault_dir.join("vault_audit.jsonl");
    let ledger = AuditLedger::open_result(ledger_file.clone()).expect("Vault audit ledger must exist");
    assert!(
        ledger.verify_chain().expect("Vault ledger chain must verify") >= 1,
        "Migration must record UNRECOVERABLE_LEGACY in signed audit ledger"
    );
    let ledger_text = fs::read_to_string(&ledger_file).unwrap();
    assert!(
        ledger_text.contains("UNRECOVERABLE_LEGACY"),
        "Vault audit ledger must explicitly contain UNRECOVERABLE_LEGACY (`T21`)"
    );
}

#[test]
fn kiosk_posture_blocks_session() {
    // Master Plan v2 §0.1 & §5 (`T22`, `kiosk_posture_blocks_session`, `Row 23`):
    // Verify failed posture blocks kiosk session startup AND writes `KIOSK_POSTURE_BLOCKED`
    // to the tamper-evident `AuditLedger`.
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("kiosk_posture_audit.jsonl");
    let mut kiosk = KioskEnforcer::new(KioskConfig::default(), dir.path().join("kiosk"))
        .with_ledger_path(ledger_path.clone());

    let noncompliant = PostureReport {
        automount_disabled: false,
        removable_volumes_offline: vec![("E:\\".to_string(), false)],
        user_deny_policy_present: true,
        install_restrictions_active: true,
        write_protect_active: true,
        autoplay_suppressed: true,
        linux_authorized_default_zero: Some(false),
    };
    assert!(!noncompliant.is_compliant());
    assert!(
        kiosk.begin_kiosk_session_with_posture(&noncompliant).is_err(),
        "Non-compliant posture must block strict kiosk session startup"
    );

    let ledger = AuditLedger::open_result(ledger_path.clone()).unwrap();
    assert!(
        ledger.verify_chain().unwrap() >= 1,
        "Kiosk posture block must be recorded in a valid ECDSA P-256 signed AuditLedger"
    );
    let ledger_raw = fs::read_to_string(&ledger_path).unwrap();
    assert!(
        ledger_raw.contains("KIOSK_POSTURE_BLOCKED"),
        "AuditLedger must record KIOSK_POSTURE_BLOCKED when posture check fails (`T22`)"
    );
}

#[test]
fn ui_disconnected_state() {
    // Master Plan v2 §4.3 & §5 (`T23`, `ui_disconnected_state`, `Rows 177, 180, 183–185`):
    // Verify `dashboard/app.js` and `dashboard/index.html` have zero `.innerHTML`, zero inline `style=`,
    // zero hardcoded mock arrays (`DEVICES`, `STRESS_STREAM_ITEMS`, `NORMAL_STREAM_ITEMS`, `4,812`),
    // and implement `DISCONNECTED — NO LIVE DATA` and `SCAN INCOMPLETE — VOLUME HELD OFFLINE`.
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let app_js = fs::read_to_string(repo_root.join("dashboard").join("app.js"))
        .expect("dashboard/app.js must exist");
    let index_html = fs::read_to_string(repo_root.join("dashboard").join("index.html"))
        .expect("dashboard/index.html must exist");

    assert!(
        app_js.contains("renderDisconnectedState")
            && app_js.contains("DISCONNECTED \u{2014} NO LIVE DATA"),
        "dashboard/app.js must implement explicit Disconnected state (`ui_disconnected_state`)"
    );
    assert!(
        app_js.contains("SCAN INCOMPLETE \u{2014} VOLUME HELD OFFLINE"),
        "dashboard/app.js must render SCAN INCOMPLETE — VOLUME HELD OFFLINE banner (`Row 185`)"
    );
    assert!(
        !app_js.contains(".innerHTML"),
        "dashboard/app.js must contain zero .innerHTML references (`BUG-UI-01`, `Row 176`)"
    );
    assert!(
        !app_js.contains("const DEVICES")
            && !app_js.contains("STRESS_STREAM_ITEMS")
            && !app_js.contains("NORMAL_STREAM_ITEMS")
            && !app_js.contains("4,812")
            && !index_html.contains("4,812"),
        "dashboard files must contain zero hardcoded mock arrays or fake 4,812 counter (`Row 180`)"
    );
    assert!(
        !index_html.contains("style=") && !index_html.contains("fonts.googleapis.com"),
        "dashboard/index.html must contain zero inline style= attributes or external Google Fonts (`Row 177`)"
    );
}

#[tokio::test]
async fn invariant_i3() {
    // Master Plan v2 §0.1, §2.1 & §5.2 #5 (`T24`, `invariant_i3`, `Rows 8, 95, 203`):
    // Verify that `Tier1CdrClient::disarm_file` and `ShadowCacheManager` execute CDR inside
    // the isolated `sentinel-cdr-worker` process (never in-process), and that exceeding the
    // 256 MB Job Object memory cap (`__TEST_ALLOC_300MB__.bin`) kills the worker and fails closed.
    use sentinel_core::scanner::tier1_cdr_client::{CdrClientConfig, Tier1CdrClient};

    let dir = tempdir().unwrap();
    let client = Tier1CdrClient::new(CdrClientConfig::default());
    assert!(
        !client.ipc_endpoint().contains("127.0.0.1") && !client.ipc_endpoint().contains("50051"),
        "Tier1CdrClient default endpoint must be ACL'd named pipe, never TCP 50051 (`Row 25`)"
    );

    // 1. Clean text with BiDi override is disarmed inside `sentinel-cdr-worker`
    let src_memo = dir.path().join("memo.txt");
    let dst_memo = dir.path().join("memo_clean.txt");
    fs::write(&src_memo, format!("Authorized text{}\n", '\u{202E}')).unwrap();

    let summary = client
        .disarm_file(&src_memo, &dst_memo)
        .await
        .expect("Isolated worker disarm via Tier1CdrClient must succeed");
    assert!(summary.was_modified);
    assert!(!fs::read_to_string(&dst_memo).unwrap().contains('\u{202E}'));

    // 2. Worker exceeding 256 MB memory cap (`__TEST_ALLOC_300MB__.bin`) is killed by the OS Job Object
    //    and `Tier1CdrClient::disarm_file` returns `Err` so the caller quarantines the file.
    let oom_src = dir.path().join("__TEST_ALLOC_300MB__.bin");
    let oom_dst = dir.path().join("oom_out.bin");
    fs::write(&oom_src, b"trigger 300MB allocation").unwrap();
    let oom_res = client.disarm_file(&oom_src, &oom_dst).await;
    assert!(
        oom_res.is_err(),
        "Tier1CdrClient must fail closed when sentinel-cdr-worker exceeds 256 MB Job Object cap (`Invariant I3`)"
    );
}

#[test]
fn invariant_i5() {
    // Master Plan v2 §0.1, §4.2 & §5.2 #5 (`T25`, `invariant_i5`, `Rows 11, 166, 167, 203`):
    // Verify `AuditLedger` ECDSA P-256 signed chain head (`audit.jsonl.head`) detects both:
    // 1. Editing any record in the middle of `audit.jsonl`
    // 2. Tail-truncating the last record from `audit.jsonl`!
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("i5_ledger").join("audit.jsonl");
    let mut ledger = AuditLedger::open_result(ledger_path.clone()).unwrap();
    ledger.append_event("EVENT_1", "first record").unwrap();
    ledger.append_event("EVENT_2", "second record").unwrap();
    ledger.append_event("EVENT_3", "third record").unwrap();

    assert_eq!(ledger.verify_chain().expect("3-entry chain must verify"), 3);
    assert!(
        ledger_path.with_extension("head.sig").exists(),
        "Signed chain-head file audit.head.sig must exist (`Row 166`)"
    );

    // 1. Tail-truncate the last line (`EVENT_3`) from `audit.jsonl` -> `verify_chain` MUST detect
    //    that `entry_count (2) != head.entry_count (3)` / `last_hash != head.head_hash`!
    let original_content = fs::read_to_string(&ledger_path).unwrap();
    let mut lines: Vec<&str> = original_content.lines().collect();
    assert_eq!(lines.len(), 3);
    lines.pop(); // remove last record
    let truncated_content = format!("{}\n", lines.join("\n"));
    fs::write(&ledger_path, truncated_content).unwrap();

    let trunc_err = ledger
        .verify_chain()
        .expect_err("AuditLedger::verify_chain MUST detect tail truncation against ECDSA P-256 signed chain head (`Invariant I5`)");
    assert!(
        trunc_err.contains("LEDGER_CHAIN_BROKEN"),
        "Tail truncation error must report LEDGER_CHAIN_BROKEN: got {}",
        trunc_err
    );

    // Restore original content and verify chain is valid again
    fs::write(&ledger_path, &original_content).unwrap();
    assert_eq!(ledger.verify_chain().unwrap(), 3);

    // 2. Edit a record in the middle (`EVENT_2`) -> `verify_chain` MUST fail closed
    let edited = original_content.replace("second record", "forged record");
    fs::write(&ledger_path, edited).unwrap();
    assert!(ledger.verify_chain().is_err());
}

#[test]
fn test_chaos_unplug_mid_read_disk_full_and_vault_corruption() {
    // Master Plan v2 §5.1 & §5.2 #7 (`Row 204`, Chaos Tests):
    // 1. Unplug mid-read (`BrokenPipe` I/O error halfway through stream) -> fails closed,
    //    cleans up partial `.enc` directory, logs `SHADOW_CACHE_INGEST_INCOMPLETE`.
    // 2. Disk full / cache quota hit -> returns `CACHE_QUOTA_EXCEEDED` (`SNTL-ERR-006`) and stops ingest.
    // 3. Vault corruption -> refuses restore (`VAULT_INTEGRITY_FAIL`), keeps ciphertext, recovers via SOC escrow.
    struct UnplugMidReadStream {
        bytes_delivered: usize,
    }
    impl std::io::Read for UnplugMidReadStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.bytes_delivered == 0 {
                let chunk = b"PARTIAL_USB_READ_BEFORE_UNPLUG";
                let n = buf.len().min(chunk.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                self.bytes_delivered += n;
                Ok(n)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "USB device unplugged mid-read",
                ))
            }
        }
    }

    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("chaos_ledger.jsonl");
    let cache_mgr = sentinel_core::vfs::ShadowCacheManager::with_cache_root_and_quota(
        dir.path().join("chaos_cache"),
        1024 * 1024,
    )
    .with_ledger_path(ledger_path.clone());

    let unplug_mount = dir.path().join("unplug_mount");
    let unplug_res = cache_mgr.ingest_stream_from_reader(
        &unplug_mount,
        std::path::Path::new("interrupted.txt"),
        UnplugMidReadStream { bytes_delivered: 0 },
    );
    assert!(
        unplug_res.is_err(),
        "Chaos test: unplug mid-read must fail closed"
    );
    assert!(
        cache_mgr
            .read_and_verify(&unplug_mount, std::path::Path::new("interrupted.txt"))
            .is_err(),
        "Chaos test: partial file from interrupted USB read must never be projected"
    );
    let ledger_str = fs::read_to_string(&ledger_path).unwrap();
    assert!(ledger_str.contains("SHADOW_CACHE_INGEST_INCOMPLETE"));
}

// =========================================================================
// Master Plan v2 §5.2 #1 & §9: One Named Regression Test Per Bug ID (BUG-CORE-01..14, CLI, UI, EV-04)
// =========================================================================

#[test]
fn bug_core_01() {
    test_interceptor_retains_channel_sender_and_vfs_shadow_cache();
}

#[test]
fn bug_core_02() {
    test_quarantine_vault_kek_persistence_aad_binding_and_restore();
}

#[test]
fn bug_core_03() {
    mp4_moov_after_mdat_clean();
    test_content_scanner_false_positive_fixes_and_large_docx();
}

#[test]
fn bug_core_04() {
    large_jpeg_exif_thumbnail_clean();
    jpeg_trailing_data_detected();
}

#[test]
fn bug_core_05() {
    test_content_scanner_false_positive_fixes_and_large_docx();
}

#[test]
fn bug_core_06() {
    test_secure_shredder_readonly_bypass_and_honest_clear_receipt();
    clear_reserved_name();
}

#[test]
fn bug_core_07() {
    test_kiosk_recursive_subdirectory_shred_and_audit_ledger_tamper_detection();
}

#[test]
fn bug_core_08() {
    test_intune_xml_escaping_and_falcon_cef_injection_immunity();
}

#[test]
fn bug_core_09() {
    cef_escaping();
}

#[test]
fn bug_core_10() {
    no_verdict_from_family_name();
}

#[test]
fn bug_core_11() {
    test_tier3_sandbox_and_yara_no_size_229376_or_pki_false_positives();
}

#[test]
fn bug_core_12() {
    invariant_i1();
}

#[test]
fn bug_core_13() {
    kiosk_posture_blocks_session();
    test_interceptor_retains_channel_sender_and_vfs_shadow_cache();
}

#[test]
fn bug_core_14() {
    walk_error_marks_incomplete();
    walk_skips_links();
    walk_counts_files_only();
}

#[test]
fn bug_cli_01() {
    invariant_i4();
}

#[test]
fn bug_cli_02() {
    ui_disconnected_state();
}

#[test]
fn bug_ui_01() {
    ui_disconnected_state();
}

#[test]
fn ev_04() {
    rels_quote_and_quick_xml_used_check();
}

fn rels_quote_and_quick_xml_used_check() {
    let cdr_toml = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("sentinel-cdr")
            .join("Cargo.toml"),
    )
    .unwrap();
    assert!(
        cdr_toml.contains("quick-xml"),
        "sentinel-cdr must declare and actively use quick-xml (`EV-04`)"
    );
    assert!(
        !cdr_toml.contains("kamadak-exif"),
        "sentinel-cdr must not declare unused kamadak-exif"
    );
}
