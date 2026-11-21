//! T36: Sub-Phase 2.2 Integration Suite — NIST SP 800-88 Rev. 2, CERT-In NTP Telemetry,
//! Hybrid Post-Quantum ML-KEM-768 (`OCESCROW3`), CycloneDX CBOM, & Verifiable CDR Passport (`CSE-14`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

use sentinel_core::enterprise::kiosk::{
    verify_kiosk_passport, AirGappedKioskManager, HardwareWriteBlockerState, KioskConfig,
    KioskEnforcer, PostureReport, PASSPORT_MANIFEST_FILENAME, PASSPORT_PUBKEY_FILENAME,
};
use sentinel_core::enterprise::ledger::{create_shared_audit_ledger, AuditLedger};
use sentinel_core::scanner::quarantine::{
    QuarantineVault, HYBRID_ESCROW_V3_JSON_FILENAME, HYBRID_ESCROW_V3_WIRE_FILENAME,
};
use sentinel_core::scanner::secure_shredder::{
    classify_nist_sp800_88_rev2, Nist80088Rev2Category, SecureShredder, ShredMethod,
};
use sentinel_sys::{
    encrypt_kek_for_soc_escrow_hybrid_v3, evaluate_strict_kiosk_key_posture, fips202_sha3_256,
    generate_hybrid_soc_keypair_with_bits, hkdf_sha256_derive_32, query_ntp_sync_status,
    resolve_linux_key_sealing_backend, KeyProtectionPosture, MediaType, MLKEM768_CT_LEN,
    MLKEM768_DK_LEN, MLKEM768_EK_LEN, OCESCROW3_MAGIC, TPM_OAEP_ALLOWED_ALGORITHMS,
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
    assert_eq!(doc["metadata"]["component"]["version"], "0.1.0");

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
    assert!(names.contains(&"SHA-256"));
    assert!(names.contains(&"SHA3-256"));
    assert!(names.contains(&"TLS-1.3-mTLS"));

    // CSE-28 CBOM truthfulness: zero unimplemented `"hardware-tee"` claims and explicit
    // `certificationLevel: ["none"]` on EVERY software cryptographic algorithm component.
    assert!(
        !raw.contains("\"hardware-tee\""),
        "CBOM must not overclaim unimplemented executionEnvironment=hardware-tee"
    );
    assert!(
        raw.contains("SNTLQV03"),
        "CBOM must reflect current SNTLQV03 quarantine envelope format"
    );
    for comp in components {
        let asset_type = comp["cryptoProperties"]["assetType"].as_str().unwrap_or("");
        if asset_type == "algorithm" {
            let cert_levels = comp["cryptoProperties"]["algorithmProperties"]["certificationLevel"]
                .as_array()
                .expect("every algorithm component must declare certificationLevel");
            assert_eq!(
                cert_levels,
                &vec![serde_json::Value::String("none".to_string())],
                "pure-Rust/software algorithm component '{}' must truthfully declare certificationLevel=[\"none\"]",
                comp["name"]
            );
            let exec_env = comp["cryptoProperties"]["algorithmProperties"]["executionEnvironment"]
                .as_str()
                .expect("every algorithm component must declare executionEnvironment");
            assert_eq!(
                exec_env, "software-plain-ram",
                "component '{}' must honestly report software-plain-ram",
                comp["name"]
            );
        }
    }

    let tls = components
        .iter()
        .find(|c| c["name"] == "TLS-1.3-mTLS")
        .expect("TLS-1.3-mTLS component");
    let tls_props = tls["properties"].as_array().expect("TLS properties");
    assert!(
        tls_props.iter().any(|p| {
            p["name"] == "sentinel:mtls_enforced_mode"
                && p["value"] == "conditional_on_client_cert_and_key_fail_closed"
        }),
        "TLS-1.3-mTLS component must honestly document conditional fail-closed mTLS mode"
    );

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
fn test_cse28_readme_truthfulness_audited_crypto_and_strict_kiosk_key_posture() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");

    // 1. README.md truthfulness: unified 0.1.0, NIST SP 800-88 Rev. 2 (zero Rev 1),
    // zero stale RSA-2048-OAEP escrow claims, and all 9 SPDX licenses from deny.toml.
    let readme = fs::read_to_string(workspace_root.join("README.md")).expect("read README.md");
    assert!(
        !readme.contains("NIST SP 800-88 Rev 1") && !readme.contains("Rev%201"),
        "README.md must not retain stale NIST SP 800-88 Rev 1 claims"
    );
    assert!(
        readme.contains("NIST SP 800-88 Rev. 2"),
        "README.md must document NIST SP 800-88 Rev. 2 consistently"
    );
    assert!(
        !readme.contains("RSA-2048-OAEP"),
        "README.md must not claim stale RSA-2048-OAEP escrow"
    );
    assert!(
        readme.contains("0.1.0"),
        "README.md must unify version to 0.1.0"
    );
    assert!(
        !readme.contains("OmniConnect Sentinel (v3)"),
        "README.md must retire mismatched v3 product version label"
    );
    assert!(
        !readme.contains("Linux FUSE3") && !readme.contains("Linux: FUSE3"),
        "README.md must honestly document POSTURE_REDUCED_NO_FUSE instead of active Linux FUSE3"
    );
    assert!(
        readme.contains("ENVELOPE_MAGIC_V3_FULL"),
        "README.md must cite exact SNTLQV03 constant name ENVELOPE_MAGIC_V3_FULL"
    );
    assert!(
        !readme.contains("SYS_request_key"),
        "README.md must reference SYS_keyctl(KEYCTL_SEARCH) / SYS_add_key, not retired SYS_request_key"
    );
    for spdx in [
        "MIT",
        "Apache-2.0",
        "Apache-2.0 WITH LLVM-exception",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Unicode-3.0",
        "Zlib",
        "ISC",
        "CDLA-Permissive-2.0",
    ] {
        assert!(
            readme.contains(spdx),
            "README.md must list SPDX license '{spdx}' from deny.toml"
        );
    }

    // 2. SHA-1 RSA-OAEP fallback retired; SHA-256 exclusively enforced
    assert!(!TPM_OAEP_ALLOWED_ALGORITHMS.is_empty());
    assert!(
        TPM_OAEP_ALLOWED_ALGORITHMS
            .iter()
            .all(|(alg, _)| *alg == "SHA256"),
        "TPM RSA-OAEP must enforce SHA-256 exclusively"
    );

    // 3. Audited SHA3-256 (NIST FIPS 202) and HKDF-SHA256 (RFC 5869) match official vectors
    assert_eq!(
        hex::encode(fips202_sha3_256(b"abc")),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    let okm = hkdf_sha256_derive_32(
        &[0x0bu8; 22],
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ],
        &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
    )
    .expect("audited HKDF-SHA256");
    assert_eq!(
        hex::encode(okm.as_slice()),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    );

    // 4. Linux key sealing backend priority + strict kiosk refusal of file-backed UnixLocalKeyring
    assert_eq!(
        resolve_linux_key_sealing_backend(true, true),
        (KeyProtectionPosture::Tpm2Assisted, None)
    );
    assert_eq!(
        resolve_linux_key_sealing_backend(false, true),
        (
            KeyProtectionPosture::LinuxKernelKeyring,
            Some("POSTURE_REDUCED_NO_TPM")
        )
    );
    assert_eq!(
        resolve_linux_key_sealing_backend(false, false),
        (
            KeyProtectionPosture::UnixLocalKeyring,
            Some("POSTURE_REDUCED_NO_TPM")
        )
    );
    assert!(evaluate_strict_kiosk_key_posture(KeyProtectionPosture::UnixLocalKeyring).is_err());

    let tmp = tempdir().expect("tempdir");
    let ledger_path = tmp.path().join("cse28_kiosk.jsonl");
    let shared_ledger = create_shared_audit_ledger(&ledger_path).expect("shared ledger");
    let mut kiosk = KioskEnforcer::new(KioskConfig::default(), tmp.path().join("kiosk_sess"))
        .with_shared_ledger(shared_ledger);

    let compliant_posture = PostureReport {
        automount_disabled: true,
        removable_volumes_offline: Vec::new(),
        user_deny_policy_present: true,
        install_restrictions_active: true,
        write_protect_active: true,
        autoplay_suppressed: true,
        linux_authorized_default_zero: Some(true),
        hardware_write_blocker: HardwareWriteBlockerState::NotDetected,
    };

    // File-backed `UnixLocalKeyring` (master.seed) MUST be refused fail-closed in strict kiosk mode
    let refused = kiosk.begin_kiosk_session_with_posture_and_key_posture(
        &compliant_posture,
        KeyProtectionPosture::UnixLocalKeyring,
    );
    assert!(
        refused.is_err(),
        "Strict kiosk mode must refuse file-backed UnixLocalKeyring fallback"
    );
    assert!(refused.unwrap_err().contains("POSTURE_REDUCED_NO_TPM"));

    // Verify `KIOSK_POSTURE_BLOCKED` + `POSTURE_REDUCED_NO_TPM` recorded in audit ledger
    let ledger_raw = fs::read_to_string(&ledger_path).expect("read kiosk ledger");
    assert!(ledger_raw.contains("KIOSK_POSTURE_BLOCKED"));
    assert!(ledger_raw.contains("POSTURE_REDUCED_NO_TPM"));
    assert!(ledger_raw.contains("FILE_BACKED_KEY_FALLBACK_REFUSED_IN_STRICT_KIOSK"));

    // Non-swappable Linux kernel keyring MUST be accepted when OS posture is compliant
    let accepted_sess = kiosk
        .begin_kiosk_session_with_posture_and_key_posture(
            &compliant_posture,
            KeyProtectionPosture::LinuxKernelKeyring,
        )
        .expect("LinuxKernelKeyring must be accepted in strict kiosk mode");
    assert!(accepted_sess.starts_with("KSESS-"));
    let _ = kiosk.end_kiosk_session().expect("end kiosk session");

    // Also verify `begin_kiosk_session_with_posture` WITHOUT an attached shared_ledger resolves
    // key posture directly from its default ledger path and records `key_protection_posture`.
    let standalone_ledger = tmp.path().join("standalone_kiosk_ledger.jsonl");
    let mut standalone_kiosk =
        KioskEnforcer::new(KioskConfig::default(), tmp.path().join("standalone_sess"))
            .with_ledger_path(standalone_ledger.clone());
    let standalone_sess = standalone_kiosk
        .begin_kiosk_session_with_posture(&compliant_posture)
        .expect("standalone kiosk with non-file-backed host key posture must start");
    assert!(standalone_sess.starts_with("KSESS-"));
    let standalone_raw = fs::read_to_string(&standalone_ledger).expect("read standalone ledger");
    let has_resolved_key_posture = standalone_raw.lines().any(|line| {
        let Ok(rec) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        let Some(data_str) = rec["data"].as_str() else {
            return false;
        };
        let Ok(data) = serde_json::from_str::<serde_json::Value>(data_str) else {
            return false;
        };
        matches!(
            data["payload"]["key_protection_posture"].as_str(),
            Some("Tpm2Assisted" | "DpapiLocalMachine" | "LinuxKernelKeyring")
        )
    });
    assert!(
        has_resolved_key_posture,
        "begin_kiosk_session_with_posture without shared_ledger must resolve non-null key posture; raw={standalone_raw}"
    );
    let _ = standalone_kiosk
        .end_kiosk_session()
        .expect("end standalone kiosk session");
}

#[test]
fn test_cse29_cross_platform_ci_auditable_gates_shred_oracle_rea_playbook_and_ui_forbid_unsafe() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");

    // 1. Cross-platform `.github/workflows/ci.yml`: Linux + Windows `cargo auditable` + `.dep-v0`
    //    verification + out-of-band anti-forensic loopback shred oracle job.
    let ci_yml = fs::read_to_string(workspace_root.join(".github/workflows/ci.yml"))
        .expect("read .github/workflows/ci.yml");
    assert!(
        ci_yml.contains("windows-auditable-release:") && ci_yml.contains("runs-on: windows-latest"),
        "CI must run cargo-auditable PE release verification on windows-latest"
    );
    assert_eq!(
        ci_yml
            .matches("cargo auditable build --workspace --release --locked")
            .count(),
        2,
        "CI must invoke `cargo auditable build --workspace --release --locked` on BOTH Linux and Windows"
    );
    assert!(
        ci_yml.contains("readelf -S") && ci_yml.contains("verify_auditable_dep_v0.py"),
        "CI must verify .dep-v0 on both ELF (readelf + script) and PE (script)"
    );
    assert!(
        ci_yml.contains("anti-forensic-shred-oracle:")
            && ci_yml.contains("tests/ci_shred_verify_oracle.sh"),
        "CI must include the out-of-band Linux anti-forensic loopback shred verification oracle job"
    );

    // 2. Out-of-band CI loopback shred oracle script (`tests/ci_shred_verify_oracle.sh`)
    let oracle_sh = fs::read_to_string(workspace_root.join("tests/ci_shred_verify_oracle.sh"))
        .expect("read tests/ci_shred_verify_oracle.sh");
    assert!(oracle_sh.contains("mkfs.ext4"));
    assert!(oracle_sh.contains("mkfs.vfat"));
    assert!(oracle_sh.contains("--fill-free-space"));
    assert!(oracle_sh.contains("grep -a"));
    assert!(oracle_sh.contains("strings -n 16"));

    // 3. Offline REA release binary verification playbook
    let rea_doc =
        fs::read_to_string(workspace_root.join("Docs/rea_release_binary_verification_playbook.md"))
            .expect("read Docs/rea_release_binary_verification_playbook.md");
    assert!(rea_doc.contains("inspect_rust_binary"));
    assert!(rea_doc.contains("inspect_pe_resources"));
    assert!(rea_doc.contains(".dep-v0"));
    assert!(rea_doc.contains("GUARD_CF"));

    // 4. `sentinel-ui/src/main.rs` enforces `#![forbid(unsafe_code)]`
    let ui_main = fs::read_to_string(workspace_root.join("sentinel-ui/src/main.rs"))
        .expect("read sentinel-ui/src/main.rs");
    assert!(
        ui_main.contains("#![forbid(unsafe_code)]"),
        "sentinel-ui/src/main.rs must enforce #![forbid(unsafe_code)]"
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
