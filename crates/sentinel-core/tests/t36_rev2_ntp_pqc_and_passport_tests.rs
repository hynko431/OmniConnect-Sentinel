//! T36: Sub-Phase 2.2 Integration Suite — NIST SP 800-88 Rev. 2, CERT-In NTP Telemetry,
//! Hybrid Post-Quantum ML-KEM-768 (`OCESCROW3`), CycloneDX CBOM, & Verifiable CDR Passport (`CSE-14`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

use sentinel_core::enterprise::kiosk::{
    verify_kiosk_passport, AirGappedKioskManager, KioskConfig, PASSPORT_MANIFEST_FILENAME,
    PASSPORT_PUBKEY_FILENAME,
};
use sentinel_core::enterprise::ledger::{create_shared_audit_ledger, AuditLedger};
use sentinel_core::scanner::quarantine::{
    QuarantineVault, HYBRID_ESCROW_V3_JSON_FILENAME, HYBRID_ESCROW_V3_WIRE_FILENAME,
};
use sentinel_core::scanner::secure_shredder::{
    classify_nist_sp800_88_rev2, Nist80088Rev2Category, SecureShredder, ShredMethod,
};
use sentinel_sys::{
    encrypt_kek_for_soc_escrow_hybrid_v3, generate_hybrid_soc_keypair_with_bits,
    query_ntp_sync_status, MediaType, MLKEM768_CT_LEN, MLKEM768_DK_LEN, MLKEM768_EK_LEN,
    OCESCROW3_MAGIC,
};

#[test]
fn test_nist_sp800_88_rev2_usbflash_vs_inception_crypto_erase() {
    let tmp = tempdir().expect("tempdir");
    let ledger_path = tmp.path().join("rev2_audit.jsonl");
    let shared_ledger = create_shared_audit_ledger(&ledger_path).expect("shared ledger");

    // 1. Pre-existing file on simulated wear-leveled UsbFlash -> MUST be Clear, NEVER Purge
    let usb_file = tmp.path().join("usb_spreadsheet.xlsx");
    fs::write(&usb_file, vec![0xA5u8; 8192]).expect("write usb file");

    let usb_receipt = SecureShredder::shred_file_with_media_hint(
        &usb_file,
        ShredMethod::ClearMultiPass { passes: 3 },
        Some(MediaType::UsbFlash),
        Some(&shared_ledger),
    )
    .expect("shred usb file");

    assert!(!usb_file.exists());
    assert_eq!(usb_receipt.nist_standard, "NIST SP 800-88 Rev. 2");
    assert_eq!(usb_receipt.rev2_category, Nist80088Rev2Category::Clear);
    assert!(!usb_receipt.inception_encrypted_dek_destroyed);
    assert!(usb_receipt.media_type.contains("UsbFlash"));
    assert!(usb_receipt
        .sanitization_level
        .contains("NIST SP 800-88 Rev. 2 — Clear"));
    assert!(usb_receipt
        .sanitization_level
        .contains("Flash Wear-Leveling Caveat"));

    // 2. Verify SSD/NVMe classification also honestly reports Clear with wear-leveling caveat
    let (ssd_cat, ssd_dek, ssd_label) =
        classify_nist_sp800_88_rev2(ShredMethod::NIST_CLEAR_THREE_PASS, MediaType::SsdOrFlash);
    assert_eq!(ssd_cat, Nist80088Rev2Category::Clear);
    assert!(!ssd_dek);
    assert!(ssd_label.contains("NIST SP 800-88 Rev. 2 — Clear"));

    // 3. Inception-encrypted ShadowCache / .quar artifact whose DEK was destroyed -> CryptographicErasePurge
    let shadow_chunk = tmp.path().join("shadow_chunk_0001.enc");
    fs::write(&shadow_chunk, vec![0x3Cu8; 4096]).expect("write shadow chunk");

    let purge_receipt = SecureShredder::shred_file_with_media_hint(
        &shadow_chunk,
        ShredMethod::CryptoErase,
        Some(MediaType::SsdOrFlash),
        Some(&shared_ledger),
    )
    .expect("crypto erase shadow chunk");

    assert!(!shadow_chunk.exists());
    assert_eq!(purge_receipt.nist_standard, "NIST SP 800-88 Rev. 2");
    assert_eq!(
        purge_receipt.rev2_category,
        Nist80088Rev2Category::CryptographicErasePurge
    );
    assert!(purge_receipt.inception_encrypted_dek_destroyed);
    assert!(purge_receipt
        .sanitization_level
        .contains("NIST SP 800-88 Rev. 2 — Cryptographic Erase (Purge)"));
}

#[test]
fn test_cert_in_ntp_sync_telemetry_and_tamper_evidence_in_audit_ledger() {
    let ntp = query_ntp_sync_status();
    assert!(
        !ntp.clock_source.trim().is_empty(),
        "OS NTP clock_source must never be empty"
    );

    let tmp = tempdir().expect("tempdir");
    let ledger_path = tmp.path().join("cert_in_ntp_ledger.jsonl");
    let mut ledger = AuditLedger::open_result(&ledger_path).expect("open ledger");

    let rec1 = ledger
        .append_event("USB_DEVICE_ARRIVAL", "VID=0781 PID=5581")
        .expect("append rec1");
    assert!(!rec1.clock_source.is_empty());

    let _head = ledger.emit_worm_checkpoint().expect("worm checkpoint");
    let count = ledger.verify_chain().expect("verify intact chain");
    assert_eq!(count, 2);

    // Inspect raw JSONL on disk to confirm `ntp_synchronized` and `clock_source` are persisted
    let raw_jsonl = fs::read_to_string(&ledger_path).expect("read jsonl");
    assert!(raw_jsonl.contains("\"ntp_synchronized\":"));
    assert!(raw_jsonl.contains("\"clock_source\":"));

    // Tamper ONLY `ntp_synchronized` boolean in record #1 -> verify_chain() MUST fail closed!
    let tampered_jsonl = if raw_jsonl.contains("\"ntp_synchronized\":true") {
        raw_jsonl.replacen("\"ntp_synchronized\":true", "\"ntp_synchronized\":false", 1)
    } else {
        raw_jsonl.replacen("\"ntp_synchronized\":false", "\"ntp_synchronized\":true", 1)
    };
    fs::write(&ledger_path, tampered_jsonl).expect("write tampered jsonl");

    let verify_tampered = ledger.verify_chain();
    assert!(
        verify_tampered.is_err(),
        "Tampering with CERT-In ntp_synchronized field must break SHA-256 ledger hash chain!"
    );
}

#[test]
fn test_ocescrow3_hybrid_mlkem768_dr_roundtrip_and_ind_cca2() {
    // Generate genuine RSA-3072 + FIPS 203 ML-KEM-768 hybrid SOC keypair
    let (pub_bundle, priv_bundle) =
        generate_hybrid_soc_keypair_with_bits(3072).expect("generate 3072-bit + ML-KEM-768");
    assert_eq!(pub_bundle.version, 3);
    assert_eq!(pub_bundle.mlkem768_encapsulation_key.len(), MLKEM768_EK_LEN);
    assert_eq!(
        priv_bundle.mlkem768_decapsulation_key.len(),
        MLKEM768_DK_LEN
    );

    // Verify IND-CCA2 randomized hybrid encapsulation on identical KEK
    let sample_kek = [0x77u8; 32];
    let env1 = encrypt_kek_for_soc_escrow_hybrid_v3(&sample_kek, &pub_bundle, "KEK-TEST-01")
        .expect("enc 1");
    let env2 = encrypt_kek_for_soc_escrow_hybrid_v3(&sample_kek, &pub_bundle, "KEK-TEST-01")
        .expect("enc 2");
    assert_eq!(&env1.ocescrow3_wire_bytes[0..9], OCESCROW3_MAGIC);
    assert_eq!(env1.mlkem768_ciphertext.len(), MLKEM768_CT_LEN);
    assert_ne!(env1.rsa_oaep_ciphertext, env2.rsa_oaep_ciphertext);
    assert_ne!(env1.mlkem768_ciphertext, env2.mlkem768_ciphertext);
    assert_ne!(env1.wrapped_kek_ciphertext, env2.wrapped_kek_ciphertext);

    // Full QuarantineVault DR recovery round-trip via OCESCROW3
    let tmp = tempdir().expect("tempdir");
    let vault_dir = tmp.path().join("vault_pqc");
    let src_malware = tmp.path().join("suspect_firmware.bin");
    let original_payload = b"SENSITIVE_QUARANTINED_OT_PAYLOAD_FOR_FORENSIC_RECOVERY_2026";
    fs::write(&src_malware, original_payload).expect("write payload");

    let entry_id = {
        let vault = QuarantineVault::open(vault_dir.clone()).expect("open vault");
        let escrow_v3 = vault
            .provision_hybrid_soc_escrow_v3(&pub_bundle)
            .expect("provision OCESCROW3");
        assert!(escrow_v3.algorithm.contains("RSA-3072"));
        assert!(escrow_v3.algorithm.contains("ML-KEM-768"));
        assert!(vault_dir.join(HYBRID_ESCROW_V3_JSON_FILENAME).exists());
        assert!(vault_dir.join(HYBRID_ESCROW_V3_WIRE_FILENAME).exists());

        let entry = vault
            .quarantine_file(&src_malware, "YARA:OT_Stux_Test")
            .expect("quarantine file");
        entry.entry_id
    };

    // Simulate total host TPM + classical escrow loss: delete `vault_kek.sealed` and `vault_kek.escrow`
    let _ = fs::remove_file(vault_dir.join("vault_kek.sealed"));
    let _ = fs::remove_file(vault_dir.join("vault_kek.escrow"));

    // Recover vault strictly via Hybrid Post-Quantum OCESCROW3 (`RSA-3072 + ML-KEM-768`)
    let recovered_vault =
        QuarantineVault::recover_from_hybrid_soc_escrow_v3(vault_dir, &priv_bundle)
            .expect("recover vault from OCESCROW3");
    let restored_path = tmp.path().join("restored_firmware.bin");
    recovered_vault
        .restore_file(&entry_id, &restored_path)
        .expect("restore file after OCESCROW3 recovery");
    let restored_bytes = fs::read(&restored_path).expect("read restored");
    assert_eq!(restored_bytes, original_payload);
}

#[test]
fn test_cyclonedx_cbom_inventory_and_schema() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cbom_path = manifest_dir.join("../../sentinel-cbom.cdx.json");
    if !cbom_path.exists() {
        cbom_path = PathBuf::from("sentinel-cbom.cdx.json");
    }
    assert!(
        cbom_path.exists(),
        "sentinel-cbom.cdx.json must exist at repository root"
    );

    let raw = fs::read_to_string(&cbom_path).expect("read cbom");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid CycloneDX JSON");
    assert_eq!(doc["bomFormat"], "CycloneDX");
    assert_eq!(doc["specVersion"], "1.6");

    let components = doc["components"].as_array().expect("components array");
    let names: Vec<&str> = components
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(names.contains(&"ML-KEM-768"));
    assert!(names.contains(&"OCESCROW3-RSA-3072-OAEP-ML-KEM-768-HKDF-SHA256-AES256GCM"));
    assert!(names.contains(&"AES-256-GCM"));
    assert!(names.contains(&"ECDSA-P256-SHA256"));
    assert!(names.contains(&"RSA-3072-OAEP-SHA256"));
    assert!(names.contains(&"HKDF-SHA256"));
    assert!(names.contains(&"HMAC-SHA256"));
    assert!(names.contains(&"TLS-1.3-mTLS"));

    let mlkem = components
        .iter()
        .find(|c| c["name"] == "ML-KEM-768")
        .expect("ML-KEM-768 component");
    assert_eq!(mlkem["cryptoProperties"]["oid"], "2.16.840.1.101.3.4.4.2");
    assert_eq!(
        mlkem["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"],
        3
    );
}

#[test]
fn test_verifiable_cdr_passport_roundtrip_and_single_byte_tamper_rejection() {
    let tmp = tempdir().expect("tempdir");
    let session_dir = tmp.path().join("kiosk_sessions");
    let export_dir = tmp.path().join("sanitized_usb_export");

    let mut kiosk = AirGappedKioskManager::new(KioskConfig::default(), session_dir);
    let (_sess_id, _sub) = kiosk
        .start_kiosk_session("USB-TURBINE-MAINT-07")
        .expect("start kiosk session");

    let batch = vec![
        (
            PathBuf::from("firmware/plc_patch_v4.bin"),
            b"CLEAN_PLC_FIRMWARE_IMAGE_V4".to_vec(),
            "VERIFIED_CLEAN_SIGNED_FIRMWARE".to_string(),
        ),
        (
            PathBuf::from("docs/maintenance_checklist.pdf"),
            b"%PDF-1.7 DISARMED_NO_JS_RECONSTRUCTED".to_vec(),
            "DEEP_CDR_PDF_RECONSTRUCTED".to_string(),
        ),
    ];

    let passport = kiosk
        .export_sanitized_batch_with_passport(
            &export_dir,
            "USB-TURBINE-MAINT-07",
            "POL-OT-IEC62443-SL3",
            42,
            &batch,
        )
        .expect("export batch with passport");

    assert_eq!(passport.sanitized_files.len(), 2);
    assert!(export_dir.join(PASSPORT_MANIFEST_FILENAME).exists());
    let pub_key_path = export_dir.join(PASSPORT_PUBKEY_FILENAME);
    assert!(pub_key_path.exists());
    let trusted_pub_bytes = fs::read(&pub_key_path).expect("read pubkey");

    // 1. Intact verification succeeds with pinned public key
    let verified =
        verify_kiosk_passport(&export_dir, Some(&trusted_pub_bytes)).expect("verify intact");
    assert_eq!(verified.passport_id, passport.passport_id);
    assert_eq!(verified.policy_sequence, 42);

    // Also test via `sentinel verify-passport` CLI binary if built in target/debug
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let cli_exe = if cfg!(windows) {
        workspace_root.join("target/debug/sentinel.exe")
    } else {
        workspace_root.join("target/debug/sentinel")
    };
    if cli_exe.exists() {
        let ok_status = Command::new(&cli_exe)
            .args([
                "verify-passport",
                "--manifest",
                &export_dir
                    .join(PASSPORT_MANIFEST_FILENAME)
                    .to_string_lossy(),
                "--pub-key",
                &pub_key_path.to_string_lossy(),
            ])
            .status()
            .expect("run sentinel verify-passport");
        assert!(
            ok_status.success(),
            "sentinel verify-passport must succeed on intact export"
        );
    }

    // 2. Micro Cold-Eye Gate requirement: modify 1 byte of a sanitized kiosk output file -> MUST fail immediately!
    let target_pdf = export_dir.join("docs/maintenance_checklist.pdf");
    let mut pdf_bytes = fs::read(&target_pdf).expect("read pdf");
    pdf_bytes[10] ^= 0x01;
    fs::write(&target_pdf, &pdf_bytes).expect("write 1-byte tampered pdf");

    let tampered_res = verify_kiosk_passport(&export_dir, Some(&trusted_pub_bytes));
    assert!(
        tampered_res.is_err(),
        "1-byte modification of sanitized output file MUST fail verify_kiosk_passport!"
    );
    assert!(
        tampered_res.unwrap_err().contains("PASSPORT_FILE_TAMPERED"),
        "Expected PASSPORT_FILE_TAMPERED error code"
    );

    if cli_exe.exists() {
        let fail_status = Command::new(&cli_exe)
            .args([
                "verify-passport",
                "--manifest",
                &export_dir
                    .join(PASSPORT_MANIFEST_FILENAME)
                    .to_string_lossy(),
                "--pub-key",
                &pub_key_path.to_string_lossy(),
            ])
            .status()
            .expect("run sentinel verify-passport on tampered export");
        assert!(
            !fail_status.success(),
            "sentinel verify-passport CLI must exit non-zero on 1-byte file modification!"
        );
    }

    let _ = kiosk.end_kiosk_session().expect("end kiosk session");
}
