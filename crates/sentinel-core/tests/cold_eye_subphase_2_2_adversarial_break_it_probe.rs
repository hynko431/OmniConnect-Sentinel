//! Cold-Eye Adversarial "Break-It" Probe for Sub-Phase 2.2 (`CSE-14`)
//!
//! Hostile attacks tested:
//! 1. OCESCROW3 Hybrid Split-Key Attacks:
//!    - Compromised classical RSA key with wrong ML-KEM-768 decapsulation key MUST fail closed.
//!    - Compromised ML-KEM-768 key with wrong classical RSA private key MUST fail closed.
//!    - 1-bit flip in ML-KEM-768 ciphertext (FIPS 203 implicit rejection), RSA ciphertext,
//!      HKDF salt, AES-GCM nonce, wrapped KEK tag, and kek_id AAD MUST all fail closed.
//! 2. CDR Passport Forgery, Post-Signing Implant Injection, & Rogue Signer Attacks:
//!    - Attacker modifies sanitized file AND re-signs `.sentinel-passport.json` with rogue ECDSA P-256 key -> rejected by `--pub-key`!
//!    - Attacker drops an unlisted `autorun.inf` / `implant.exe` into export dir -> rejected (`PASSPORT_UNLISTED_FILE`)!
//!    - Attacker deletes a listed file -> rejected (`PASSPORT_FILE_MISSING`)!
//!    - Attacker tampers with `policy_sequence` or `ntp_synchronized` inside `.sentinel-passport.json` -> signature rejected!

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

use sentinel_core::enterprise::kiosk::{
    verify_kiosk_passport, AirGappedKioskManager, KioskConfig, KioskSanitizationPassport,
    PASSPORT_MANIFEST_FILENAME, PASSPORT_PUBKEY_FILENAME,
};
use sentinel_sys::{
    decrypt_kek_from_soc_escrow_hybrid_v3, decrypt_ocescrow3_wire_envelope,
    encrypt_kek_for_soc_escrow_hybrid_v3, generate_hybrid_soc_keypair_with_bits,
    HybridSocPrivateKeyBundle,
};

#[test]
fn adversarial_ocescrow3_split_key_and_bitflip_resistance() {
    assert!(
        generate_hybrid_soc_keypair_with_bits(2048).is_err(),
        "2048-bit RSA downgrade MUST be rejected for OCESCROW3"
    );
    let (pub_a, priv_a) = generate_hybrid_soc_keypair_with_bits(3072).expect("hybrid keypair A");
    let (_pub_b, priv_b) = generate_hybrid_soc_keypair_with_bits(3072).expect("hybrid keypair B");

    let real_kek = [0xCCu8; 32];
    let escrow = encrypt_kek_for_soc_escrow_hybrid_v3(&real_kek, &pub_a, "KEK-ADV-22")
        .expect("encrypt hybrid v3");

    // Sanity check: genuine bundle A succeeds
    let ok_kek = decrypt_kek_from_soc_escrow_hybrid_v3(&escrow, &priv_a).expect("decrypt A");
    assert_eq!(ok_kek, real_kek);

    // Attack 1: Quantum adversary knows RSA private key A, guesses/substitutes ML-KEM-768 key B
    let classical_only_bundle = HybridSocPrivateKeyBundle {
        rsa_private_blob: priv_a.rsa_private_blob.clone(),
        mlkem768_decapsulation_key: priv_b.mlkem768_decapsulation_key.clone(),
    };
    assert!(
        decrypt_kek_from_soc_escrow_hybrid_v3(&escrow, &classical_only_bundle).is_err(),
        "CRITICAL: Classical RSA private key alone MUST NOT unwrap OCESCROW3 without ML-KEM-768 key!"
    );

    // Attack 2: Lattice break adversary knows ML-KEM-768 key A, substitutes RSA private key B
    let pqc_only_bundle = HybridSocPrivateKeyBundle {
        rsa_private_blob: priv_b.rsa_private_blob.clone(),
        mlkem768_decapsulation_key: priv_a.mlkem768_decapsulation_key.clone(),
    };
    assert!(
        decrypt_kek_from_soc_escrow_hybrid_v3(&escrow, &pqc_only_bundle).is_err(),
        "CRITICAL: ML-KEM-768 key alone MUST NOT unwrap OCESCROW3 without classical RSA private key!"
    );

    // Attack 3: 1-bit flip in ML-KEM-768 ciphertext inside wire envelope (FIPS 203 implicit rejection)
    let mut bad_mlkem_wire = escrow.ocescrow3_wire_bytes.clone();
    let mlkem_offset = 9 + 2 + 16 + 12 + 4 + escrow.rsa_oaep_ciphertext.len() + 100;
    bad_mlkem_wire[mlkem_offset] ^= 0x01;
    assert!(
        decrypt_ocescrow3_wire_envelope(&bad_mlkem_wire, "KEK-ADV-22", &priv_a).is_err(),
        "1-bit mutation in ML-KEM-768 ciphertext must fail AEAD authentication"
    );

    // Attack 4: 1-bit flip in HKDF salt, AES nonce, and GCM tag
    for offset in [12usize, 30usize, escrow.ocescrow3_wire_bytes.len() - 1] {
        let mut mutated = escrow.ocescrow3_wire_bytes.clone();
        mutated[offset] ^= 0x80;
        assert!(
            decrypt_ocescrow3_wire_envelope(&mutated, "KEK-ADV-22", &priv_a).is_err(),
            "1-bit mutation at wire offset {offset} must fail closed"
        );
    }

    // Attack 5: Wrong kek_id AAD binding
    assert!(
        decrypt_ocescrow3_wire_envelope(&escrow.ocescrow3_wire_bytes, "WRONG-KEK-ID", &priv_a)
            .is_err(),
        "Mismatched kek_id AAD must fail closed"
    );

    // Attack 6: Empty `ocescrow3_wire_bytes` bypass attempt (`[CEA-DEFECT-03]`)
    let mut stripped_wire = escrow.clone();
    stripped_wire.ocescrow3_wire_bytes.clear();
    assert!(
        decrypt_kek_from_soc_escrow_hybrid_v3(&stripped_wire, &priv_a).is_err(),
        "Empty ocescrow3_wire_bytes must fail closed unconditionally!"
    );
}

#[test]
fn adversarial_passport_rogue_signer_implant_drop_and_metadata_tamper() {
    let tmp = tempdir().expect("tempdir");
    let kiosk_a_dir = tmp.path().join("kiosk_a");
    let kiosk_rogue_dir = tmp.path().join("kiosk_rogue");
    let export_dir = tmp.path().join("export_station");

    let kiosk_a = AirGappedKioskManager::new(KioskConfig::default(), kiosk_a_dir);
    let batch = vec![(
        PathBuf::from("hmi/config.xml"),
        b"<hmi safe=\"true\"/>".to_vec(),
        "DEEP_CDR_XML_SANITIZED".to_string(),
    )];
    let _passport = kiosk_a
        .export_sanitized_batch_with_passport(
            &export_dir,
            "SCADA-USB-99",
            "POL-STRICT-01",
            10,
            &batch,
        )
        .expect("legit export");

    let legit_pub = fs::read(export_dir.join(PASSPORT_PUBKEY_FILENAME)).expect("read legit pub");

    // Attack 1: Post-signing unlisted implant injection (`autorun.inf`)
    let implant = export_dir.join("autorun.inf");
    fs::write(&implant, b"[AutoRun]\nopen=evil.exe").expect("drop implant");
    let implant_res = verify_kiosk_passport(&export_dir, Some(&legit_pub));
    assert!(implant_res.is_err());
    assert!(implant_res.unwrap_err().contains("PASSPORT_UNLISTED_FILE"));
    fs::remove_file(&implant).expect("cleanup implant");

    // Confirm clean again after removing implant
    assert!(verify_kiosk_passport(&export_dir, Some(&legit_pub)).is_ok());

    // Attack 2: Metadata tamper (`policy_sequence` 10 -> 1) inside `.sentinel-passport.json`
    let manifest_path = export_dir.join(PASSPORT_MANIFEST_FILENAME);
    let orig_manifest = fs::read(&manifest_path).expect("read manifest");
    let mut parsed: KioskSanitizationPassport =
        serde_json::from_slice(&orig_manifest).expect("parse manifest");
    parsed.policy_sequence = 1;
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&parsed).expect("serialize"),
    )
    .expect("write tampered manifest");
    let meta_res = verify_kiosk_passport(&export_dir, Some(&legit_pub));
    assert!(meta_res.is_err());
    assert!(meta_res.unwrap_err().contains("PASSPORT_SIGNATURE_INVALID"));
    fs::write(&manifest_path, &orig_manifest).expect("restore manifest");

    // Attack 3: Rogue signer modifies `hmi/config.xml` AND re-signs `.sentinel-passport.json` with rogue key!
    fs::write(
        export_dir.join("hmi/config.xml"),
        b"<hmi safe=\"false\" backdoor=\"1\"/>",
    )
    .expect("tamper xml");
    let kiosk_rogue = AirGappedKioskManager::new(KioskConfig::default(), kiosk_rogue_dir);
    let _rogue_passport = kiosk_rogue
        .generate_passport_for_directory(&export_dir, "SCADA-USB-99", "POL-STRICT-01", 10, "FORGED")
        .expect("rogue re-sign");

    let rogue_res = verify_kiosk_passport(&export_dir, Some(&legit_pub));
    assert!(
        rogue_res.is_err(),
        "Rogue-signed passport MUST be rejected when verified against pinned kiosk public key!"
    );
    assert!(rogue_res.unwrap_err().contains("PASSPORT_UNTRUSTED_SIGNER"));
}

#[test]
fn adversarial_pubkey_sidecar_smuggling_and_custom_manifest_bypass_rejected() {
    let tmp = tempdir().expect("tempdir");
    let kiosk_dir = tmp.path().join("kiosk_smuggle");
    let export_dir = tmp.path().join("export_smuggle");
    let external_pub_path = tmp.path().join("pinned_kiosk.pub.hex");

    let kiosk = AirGappedKioskManager::new(KioskConfig::default(), kiosk_dir);
    let batch = vec![(
        PathBuf::from("ot/patch.bin"),
        b"SIGNED_CLEAN_PATCH_DATA".to_vec(),
        "VERIFIED_CLEAN".to_string(),
    )];
    let _passport = kiosk
        .export_sanitized_batch_with_passport(&export_dir, "USB-SMUGGLE-01", "POL-01", 7, &batch)
        .expect("export");

    let sidecar_pub_path = export_dir.join(PASSPORT_PUBKEY_FILENAME);
    let pinned_pub_bytes = fs::read(&sidecar_pub_path).expect("read sidecar pub");
    fs::write(&external_pub_path, &pinned_pub_bytes).expect("save external pinned pub");

    // Attack 1 (`[CEA-DEFECT-02]`): Overwrite `.sentinel-passport.pub.hex` with 64 KiB `MZ` PE implant
    let mut mz_implant = b"MZ\x90\x00_SMUGGLED_STAGER_PAYLOAD_".to_vec();
    mz_implant.resize(65_536, 0x90);
    fs::write(&sidecar_pub_path, &mz_implant).expect("overwrite sidecar with MZ implant");

    let smuggle_res = verify_kiosk_passport(&export_dir, Some(&pinned_pub_bytes));
    assert!(
        smuggle_res.is_err(),
        "64 KiB MZ payload smuggled in .sentinel-passport.pub.hex MUST be rejected!"
    );
    assert!(smuggle_res
        .unwrap_err()
        .contains("PASSPORT_PUBKEY_SIDECAR_TAMPERED"));

    // Attack 2: Subtle 250-byte trailing payload smuggled after valid hex in `.sentinel-passport.pub.hex`
    let valid_hex = String::from_utf8_lossy(&pinned_pub_bytes)
        .trim()
        .to_string();
    fs::write(&sidecar_pub_path, format!("{valid_hex}\nSMUGGLED_LINE\n"))
        .expect("write subtle trailing smuggle");
    let subtle_res = verify_kiosk_passport(&export_dir, Some(&pinned_pub_bytes));
    assert!(subtle_res.is_err());
    assert!(subtle_res
        .unwrap_err()
        .contains("PASSPORT_PUBKEY_SIDECAR_TAMPERED"));

    // Restore valid `.sentinel-passport.pub.hex`
    fs::write(&sidecar_pub_path, &pinned_pub_bytes).expect("restore sidecar");
    assert!(verify_kiosk_passport(&export_dir, Some(&pinned_pub_bytes)).is_ok());

    // Attack 3: Custom manifest path (`custom.json`) while an unverified `.sentinel-passport.json` hides in `export_dir`
    let custom_manifest = export_dir.join("custom_passport.json");
    fs::copy(
        export_dir.join(PASSPORT_MANIFEST_FILENAME),
        &custom_manifest,
    )
    .expect("copy custom manifest");
    fs::write(
        export_dir.join(PASSPORT_MANIFEST_FILENAME),
        b"SMUGGLED_UNVERIFIED_DEFAULT_MANIFEST",
    )
    .expect("overwrite default manifest with payload");
    let custom_res = verify_kiosk_passport(&custom_manifest, Some(&pinned_pub_bytes));
    assert!(
        custom_res.is_err(),
        "Unverified .sentinel-passport.json must NOT be blindly skipped when verifying custom_passport.json!"
    );
    assert!(custom_res.unwrap_err().contains("PASSPORT_UNLISTED_FILE"));
}

#[test]
fn adversarial_shred_exclusive_ledger_and_ocescrow3_cli_wire_verification() {
    use sentinel_core::enterprise::ledger::AuditLedger;
    use sentinel_core::scanner::quarantine::{QuarantineVault, HYBRID_ESCROW_V3_WIRE_FILENAME};
    use sentinel_core::scanner::secure_shredder::{
        Nist80088Rev2Category, SecureShredder, ShredMethod,
    };
    use std::process::Command;

    let tmp = tempdir().expect("tempdir");

    // 1. Verify `shred_file_with_ledger` writes EXCLUSIVELY to `custom_ledger` (`[CEA-DEFECT-01]`)
    let custom_ledger = tmp.path().join("isolated_shred_audit.jsonl");
    let cipher_target = tmp.path().join("ephemeral_session_chunk.enc");
    fs::write(&cipher_target, vec![0xEEu8; 4096]).expect("write cipher chunk");

    let receipt = SecureShredder::shred_file_with_ledger(
        &cipher_target,
        ShredMethod::CryptoErase,
        &custom_ledger,
    )
    .expect("shred_file_with_ledger must succeed without touching ProgramData");
    assert!(!cipher_target.exists());
    assert_eq!(
        receipt.rev2_category,
        Nist80088Rev2Category::CryptographicErasePurge
    );
    assert!(custom_ledger.exists(), "custom_ledger must be created");
    let ledger = AuditLedger::open_result(&custom_ledger).expect("open custom ledger");
    assert_eq!(ledger.verify_chain().expect("verify custom ledger"), 1);

    // 2. Verify `QuarantineVault` + `sentinel vault verify-hybrid-escrow-v3` catch corrupted `vault_kek.ocescrow3` (`[CEA-DEFECT-03]`)
    let vault_dir = tmp.path().join("vault_cli_desync");
    let (pub_b, priv_b) = generate_hybrid_soc_keypair_with_bits(3072).expect("hybrid keypair");
    let priv_json_path = tmp.path().join("soc_hybrid_priv.json");
    fs::write(
        &priv_json_path,
        serde_json::to_vec_pretty(&priv_b).expect("serialize priv"),
    )
    .expect("write priv json");

    let vault = QuarantineVault::open(vault_dir.clone()).expect("open vault");
    vault
        .provision_hybrid_soc_escrow_v3(&pub_b)
        .expect("provision hybrid v3");
    drop(vault);

    // Corrupt `vault_kek.ocescrow3` while leaving `vault_kek.escrow.v3.json` untouched
    let wire_path = vault_dir.join(HYBRID_ESCROW_V3_WIRE_FILENAME);
    let orig_wire = fs::read(&wire_path).expect("read orig wire");
    fs::write(&wire_path, b"CORRUPTED_WIRE_ENVELOPE_BYTES").expect("corrupt wire");

    assert!(
        QuarantineVault::recover_from_hybrid_soc_escrow_v3(vault_dir.clone(), &priv_b).is_err(),
        "Library DR recovery must reject corrupted wire file"
    );

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let cli_exe = if cfg!(windows) {
        workspace_root.join("target/debug/sentinel.exe")
    } else {
        workspace_root.join("target/debug/sentinel")
    };
    if cli_exe.exists() {
        let bad_status = Command::new(&cli_exe)
            .args([
                "vault",
                "verify-hybrid-escrow-v3",
                "--vault-dir",
                &vault_dir.to_string_lossy(),
                "--hybrid-priv-key",
                &priv_json_path.to_string_lossy(),
            ])
            .status()
            .expect("invoke cli verify-hybrid-escrow-v3");
        assert!(
            !bad_status.success(),
            "CLI verify-hybrid-escrow-v3 MUST exit non-zero when vault_kek.ocescrow3 is corrupted!"
        );

        // Restore wire file and confirm CLI verification succeeds
        fs::write(&wire_path, &orig_wire).expect("restore wire");
        let ok_status = Command::new(&cli_exe)
            .args([
                "vault",
                "verify-hybrid-escrow-v3",
                "--vault-dir",
                &vault_dir.to_string_lossy(),
                "--hybrid-priv-key",
                &priv_json_path.to_string_lossy(),
            ])
            .status()
            .expect("invoke cli verify-hybrid-escrow-v3 restored");
        assert!(
            ok_status.success(),
            "CLI verify-hybrid-escrow-v3 must succeed when wire file matches JSON"
        );
    }
}

#[test]
fn adversarial_manifest_smuggling_4mib_overflow_ntp_error_tamper_and_junction_rejected() {
    use sentinel_core::enterprise::ledger::AuditLedger;

    let tmp = tempdir().expect("tempdir");
    let kiosk_dir = tmp.path().join("kiosk_p2");
    let export_dir = tmp.path().join("export_p2");

    let kiosk = AirGappedKioskManager::new(KioskConfig::default(), kiosk_dir);
    let batch = vec![(
        PathBuf::from("plc/ladder.bin"),
        b"LADDER_LOGIC_CLEAN_V2".to_vec(),
        "VERIFIED_CLEAN".to_string(),
    )];
    let _passport = kiosk
        .export_sanitized_batch_with_passport(&export_dir, "USB-P2-01", "POL-P2", 3, &batch)
        .expect("export");

    let pub_bytes = fs::read(export_dir.join(PASSPORT_PUBKEY_FILENAME)).expect("read pub");
    let manifest_path = export_dir.join(PASSPORT_MANIFEST_FILENAME);
    let intact_manifest = fs::read(&manifest_path).expect("read intact manifest");

    // 1. Unknown JSON field smuggling inside `.sentinel-passport.json` (`[CEA-DEFECT-01]`)
    let mut json_val: serde_json::Value =
        serde_json::from_slice(&intact_manifest).expect("parse value");
    json_val["smuggled_implant_mz_b64"] =
        serde_json::Value::String("TVqQAAMAAAAEAAAA_UNAUTHENTICATED_STAGER".to_string());
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&json_val).expect("serialize unknown field"),
    )
    .expect("write unknown field manifest");
    let unk_res = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
    assert!(
        unk_res.is_err(),
        "Unknown JSON field smuggling in .sentinel-passport.json MUST be rejected!"
    );
    assert!(unk_res.unwrap_err().contains("PASSPORT_CORRUPT_JSON"));

    // 2. >4 MiB `Read::take` truncation raw MZ binary smuggling (`[CEA-DEFECT-01]`)
    let mut oversized = intact_manifest.clone();
    oversized.resize(4 * 1024 * 1024, b' ');
    oversized.extend_from_slice(b"MZ\x90\x00_RAW_PE_IMPLANT_PAST_4MIB_BOUNDARY");
    fs::write(&manifest_path, &oversized).expect("write >4MiB manifest");
    let over_res = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
    assert!(
        over_res.is_err(),
        ">4 MiB manifest with trailing raw MZ payload MUST fail closed!"
    );
    assert!(over_res
        .unwrap_err()
        .contains("PASSPORT_MANIFEST_TOO_LARGE"));

    // 3. Covert whitespace padding inside <4 MiB `.sentinel-passport.json` (`[CEA-DEFECT-01]`)
    let mut covert_ws = intact_manifest.clone();
    covert_ws.extend_from_slice(b"    \n\n   ");
    fs::write(&manifest_path, &covert_ws).expect("write covert whitespace");
    let ws_res = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
    assert!(
        ws_res.is_err(),
        "Covert whitespace padding inside .sentinel-passport.json MUST fail closed!"
    );
    assert!(ws_res
        .unwrap_err()
        .contains("PASSPORT_MANIFEST_FRAMING_TAMPERED"));

    // 4. Tampering with `passport.ntp_sync.stratum` or `max_error_us` (`[CEA-DEFECT-02]`)
    let mut ntp_tampered: KioskSanitizationPassport =
        serde_json::from_slice(&intact_manifest).expect("parse passport");
    ntp_tampered.ntp_sync.stratum = Some(1);
    ntp_tampered.ntp_sync.max_error_us = Some(999_888_777);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&ntp_tampered).expect("serialize ntp tampered"),
    )
    .expect("write ntp tampered");
    let ntp_p_res = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
    assert!(
        ntp_p_res.is_err(),
        "Tampering with passport ntp_sync.stratum / max_error_us MUST fail signature check!"
    );
    assert!(ntp_p_res
        .unwrap_err()
        .contains("PASSPORT_SIGNATURE_INVALID"));

    // Restore intact manifest and confirm clean
    fs::write(&manifest_path, &intact_manifest).expect("restore manifest");
    assert!(verify_kiosk_passport(&export_dir, Some(&pub_bytes)).is_ok());

    // 5. AuditLedger `ntp_max_error_us` tamper resistance (`[CEA-DEFECT-02]`)
    let ledger_path = tmp.path().join("ntp_err_audit.jsonl");
    let mut ledger = AuditLedger::open_result(&ledger_path).expect("open ledger");
    let rec = ledger
        .append_event("NTP_ERR_BOUND_TEST", "checking max_error_us")
        .expect("append");
    assert_eq!(ledger.verify_chain().expect("verify intact"), 1);

    let raw_jsonl = fs::read_to_string(&ledger_path).expect("read jsonl");
    let tampered_jsonl = if let Some(orig_err) = rec.ntp_max_error_us {
        raw_jsonl.replacen(
            &format!("\"ntp_max_error_us\":{orig_err}"),
            "\"ntp_max_error_us\":888777666",
            1,
        )
    } else {
        raw_jsonl.replacen(
            "\"prev_hash\":",
            "\"ntp_max_error_us\":888777666,\"prev_hash\":",
            1,
        )
    };
    fs::write(&ledger_path, tampered_jsonl).expect("write tampered ntp_max_error_us");
    assert!(
        ledger.verify_chain().is_err(),
        "Tampering with AuditLedger ntp_max_error_us MUST break hash chain!"
    );

    // 6. Windows NTFS directory junction on `export_dir` via `--manifest <junction>/.sentinel-passport.json` (`[CEA-DEFECT-03]`)
    #[cfg(windows)]
    {
        let junction_dir = tmp.path().join("junction_export");
        let mklink_ok = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &junction_dir.to_string_lossy(),
                &export_dir.to_string_lossy(),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if mklink_ok {
            assert!(
                sentinel_sys::create_restricted_dir_atomic(&junction_dir).is_err(),
                "create_restricted_dir_atomic MUST reject existing NTFS directory junction!"
            );
            assert!(
                sentinel_sys::create_restricted_dir_atomic(&junction_dir.join("child")).is_err(),
                "create_restricted_dir_atomic MUST reject child under NTFS directory junction parent!"
            );
            let via_manifest = verify_kiosk_passport(
                &junction_dir.join(PASSPORT_MANIFEST_FILENAME),
                Some(&pub_bytes),
            );
            assert!(
                via_manifest.is_err(),
                "verify_kiosk_passport --manifest <junction>/.sentinel-passport.json MUST reject junction parent!"
            );
            let _ = fs::remove_dir(&junction_dir);
        }
    }
}

#[test]
fn adversarial_pass3_ledger_downgrade_pipe_splice_rsa1024_ads_hexcase_and_dacl_hardlinks() {
    use sentinel_core::enterprise::ledger::AuditLedger;
    use sentinel_sys::HybridSocPublicKeyBundle;

    let tmp = tempdir().expect("tempdir");

    // 1. `[CEA-DEFECT-01]` — AuditLedger v2->v1 downgrade & pipe-delimiter splicing resistance
    let ledger_path = tmp.path().join("pass3_domain_sep.jsonl");
    let mut ledger = AuditLedger::open_result(&ledger_path).expect("open ledger");
    let rec = ledger
        .append_event(
            "USB_INSERT",
            "path=usb_file|ntp=true|src=time.cloudflare.com",
        )
        .expect("append event");
    assert_eq!(ledger.verify_chain().expect("intact verify"), 1);

    // Attack 1A: v2->v1 downgrade attempt (fold NTP fields into `data` and clear NTP fields)
    let err_repr = rec
        .ntp_max_error_us
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string());
    let forged_v1 = serde_json::json!({
        "seq": rec.seq,
        "ts": rec.ts,
        "event": rec.event,
        "data": format!("{}|ntp={}|src={}|err={}", rec.data, rec.ntp_synchronized, rec.clock_source, err_repr),
        "ntp_synchronized": false,
        "clock_source": "",
        "prev_hash": rec.prev_hash,
        "hash": rec.hash,
    });
    fs::write(&ledger_path, format!("{forged_v1}\n")).expect("write forged v1");
    assert!(
        ledger.verify_chain().is_err(),
        "v2->v1 NTP-wipe downgrade MUST fail verify_chain() under domain-separated length framing!"
    );

    // Attack 1B: Pipe-delimiter splice forging `ntp_synchronized = true`
    let forged_splice = serde_json::json!({
        "seq": rec.seq,
        "ts": rec.ts,
        "event": rec.event,
        "data": "path=usb_file",
        "ntp_synchronized": true,
        "clock_source": format!("time.cloudflare.com|ntp={}|src={}", rec.ntp_synchronized, rec.clock_source),
        "ntp_max_error_us": rec.ntp_max_error_us,
        "prev_hash": rec.prev_hash,
        "hash": rec.hash,
    });
    fs::write(&ledger_path, format!("{forged_splice}\n")).expect("write forged splice");
    assert!(
        ledger.verify_chain().is_err(),
        "Pipe-delimiter splice forging ntp_synchronized=true MUST fail verify_chain()!"
    );

    // 2. `[CEA-DEFECT-03]` — Spoofed 1024-bit RSAPUBLICBLOB & zero-padded 1024-bit modulus rejected
    let (valid_pub, _valid_priv) =
        generate_hybrid_soc_keypair_with_bits(3072).expect("valid hybrid");
    let mut spoofed_1024_blob = Vec::new();
    spoofed_1024_blob.extend_from_slice(b"RSA1");
    spoofed_1024_blob.extend_from_slice(&3072u32.to_le_bytes()); // Lied bit_len = 3072
    spoofed_1024_blob.extend_from_slice(&3u32.to_le_bytes()); // cb_exp = 3
    spoofed_1024_blob.extend_from_slice(&128u32.to_le_bytes()); // cb_mod = 128 (1024-bit!)
    spoofed_1024_blob.extend_from_slice(&0u32.to_le_bytes());
    spoofed_1024_blob.extend_from_slice(&0u32.to_le_bytes());
    spoofed_1024_blob.extend_from_slice(&[0x01, 0x00, 0x01]);
    let mut fake_mod_128 = vec![0x81u8; 128];
    fake_mod_128[127] = 0x01;
    spoofed_1024_blob.extend_from_slice(&fake_mod_128);

    let spoofed_bundle = HybridSocPublicKeyBundle {
        version: 3,
        rsa_public_blob: spoofed_1024_blob,
        mlkem768_encapsulation_key: valid_pub.mlkem768_encapsulation_key.clone(),
    };
    assert!(
        encrypt_kek_for_soc_escrow_hybrid_v3(&[0x55; 32], &spoofed_bundle, "KEK-1024-SPOOF")
            .is_err(),
        "Spoofed 1024-bit RSAPUBLICBLOB MUST be rejected by OCESCROW3!"
    );

    // Also test 1024-bit modulus zero-padded inside a 384-byte (3072-bit) buffer
    let mut zero_padded_blob = Vec::new();
    zero_padded_blob.extend_from_slice(b"RSA1");
    zero_padded_blob.extend_from_slice(&3072u32.to_le_bytes());
    zero_padded_blob.extend_from_slice(&3u32.to_le_bytes());
    zero_padded_blob.extend_from_slice(&384u32.to_le_bytes());
    zero_padded_blob.extend_from_slice(&0u32.to_le_bytes());
    zero_padded_blob.extend_from_slice(&0u32.to_le_bytes());
    zero_padded_blob.extend_from_slice(&[0x01, 0x00, 0x01]);
    zero_padded_blob.extend_from_slice(&[0x00u8; 256]); // 256 leading zero bytes!
    zero_padded_blob.extend_from_slice(&fake_mod_128);
    let padded_bundle = HybridSocPublicKeyBundle {
        version: 3,
        rsa_public_blob: zero_padded_blob,
        mlkem768_encapsulation_key: valid_pub.mlkem768_encapsulation_key,
    };
    assert!(
        encrypt_kek_for_soc_escrow_hybrid_v3(&[0x55; 32], &padded_bundle, "KEK-PAD-SPOOF").is_err(),
        "Leading-zero-padded 1024-bit modulus inside 384-byte RSAPUBLICBLOB MUST be rejected!"
    );

    // 3. `[CEA-DEFECT-04]` — Passport hex-case covert channel & NTFS ADS implant smuggling rejected
    let kiosk_dir = tmp.path().join("kiosk_p3");
    let export_dir = tmp.path().join("export_p3");
    let kiosk = AirGappedKioskManager::new(KioskConfig::default(), kiosk_dir);
    let batch = vec![(
        PathBuf::from("scada/plc.bin"),
        b"CLEAN_SCADA_IMAGE_BYTES".to_vec(),
        "VERIFIED_CLEAN".to_string(),
    )];
    let _pass = kiosk
        .export_sanitized_batch_with_passport(&export_dir, "USB-P3-01", "POL-P3", 11, &batch)
        .expect("export p3");
    let pub_bytes = fs::read(export_dir.join(PASSPORT_PUBKEY_FILENAME)).expect("read pub");
    let manifest_path = export_dir.join(PASSPORT_MANIFEST_FILENAME);
    let orig_manifest = fs::read(&manifest_path).expect("read manifest");

    // Attack 3A-i: Uppercase `public_key_blob_hex` rejected by signed `CanonicalPassportSignable`
    let mut upper_pub_pass: KioskSanitizationPassport =
        serde_json::from_slice(&orig_manifest).expect("parse");
    upper_pub_pass.public_key_blob_hex = upper_pub_pass.public_key_blob_hex.to_ascii_uppercase();
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&upper_pub_pass).expect("serialize"),
    )
    .expect("write upper pub manifest");
    let upper_pub_res = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
    assert!(upper_pub_res.is_err());
    assert!(upper_pub_res
        .unwrap_err()
        .contains("PASSPORT_SIGNATURE_INVALID"));

    // Attack 3A-ii: Uppercase `ecdsa_p256_signature_hex` covert channel rejected by canonical framing check
    let mut upper_sig_pass: KioskSanitizationPassport =
        serde_json::from_slice(&orig_manifest).expect("parse");
    upper_sig_pass.ecdsa_p256_signature_hex =
        upper_sig_pass.ecdsa_p256_signature_hex.to_ascii_uppercase();
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&upper_sig_pass).expect("serialize"),
    )
    .expect("write upper sig manifest");
    let upper_res = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
    assert!(
        upper_res.is_err(),
        "Uppercase hex covert channel in .sentinel-passport.json MUST be rejected!"
    );
    assert!(upper_res
        .unwrap_err()
        .contains("PASSPORT_MANIFEST_FRAMING_TAMPERED"));
    fs::write(&manifest_path, &orig_manifest).expect("restore manifest");

    // Attack 3B: NTFS ADS hidden executable stream (`scada/plc.bin:implant.exe`) on Windows
    #[cfg(windows)]
    {
        let ads_target = format!("{}:implant.exe", export_dir.join("scada/plc.bin").display());
        if fs::write(&ads_target, b"MZ\x90\x00_HIDDEN_NTFS_ADS_IMPLANT").is_ok() {
            let ads_res = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
            assert!(
                ads_res.is_err(),
                "Hidden NTFS ADS implant on sanitized file MUST be rejected by verify_kiosk_passport!"
            );
            assert!(ads_res.unwrap_err().contains("PASSPORT_UNLISTED_ADS"));
            let _ = fs::remove_file(&ads_target);
        }
    }

    // 4. `[CEA-DEFECT-02]` — Hardlink squatting & pre-existing unrestricted DACL remediation
    let squat_file = tmp.path().join("squatted.key");
    let hardlink_alias = tmp.path().join("attacker_alias.key");
    fs::write(&squat_file, b"squat").expect("write squat");
    if fs::hard_link(&squat_file, &hardlink_alias).is_ok() {
        assert!(
            sentinel_sys::create_restricted_file_handle_atomic(&squat_file).is_err(),
            "Hardlink squatting (n_links > 1) MUST be rejected by create_restricted_file_handle_atomic!"
        );
        let _ = fs::remove_file(&hardlink_alias);
    }

    #[cfg(windows)]
    {
        let unres_dir = tmp.path().join("preexisting_unrestricted_dir");
        fs::create_dir_all(&unres_dir).expect("create unres dir");
        let unres_dir_str = unres_dir.to_string_lossy();
        let _ = std::process::Command::new("icacls")
            .args([unres_dir_str.as_ref(), "/grant", "Everyone:(OI)(CI)F"])
            .output();
        sentinel_sys::create_restricted_dir_atomic(&unres_dir)
            .expect("remediate pre-existing dir DACL");
        if let Ok(out) = std::process::Command::new("icacls")
            .arg(&unres_dir)
            .output()
        {
            let acl_text = String::from_utf8_lossy(&out.stdout);
            assert!(
                !acl_text.contains("Everyone:"),
                "create_restricted_dir_atomic MUST strip Everyone:(F) from pre-existing dir! Got: {acl_text}"
            );
        }
    }
}

#[test]
fn adversarial_pass4_pubkey_smuggle_low_s_malleability_unlisted_dirs_and_fips203_modulus_checks() {
    use sentinel_core::enterprise::kiosk::extract_p256_xy_coordinates;
    use sentinel_sys::HybridSocPublicKeyBundle;

    let tmp = tempdir().expect("tempdir");
    let kiosk_dir = tmp.path().join("kiosk_p4");
    let export_dir = tmp.path().join("export_p4");

    let kiosk = AirGappedKioskManager::new(KioskConfig::default(), kiosk_dir);
    let batch = vec![(
        PathBuf::from("safe/report.pdf"),
        b"%PDF-1.7 CLEAN_REPORT".to_vec(),
        "DEEP_CDR_PDF".to_string(),
    )];
    let passport = kiosk
        .export_sanitized_batch_with_passport(&export_dir, "USB-P4-01", "POL-P4", 21, &batch)
        .expect("export p4");
    let pub_bytes = fs::read(export_dir.join(PASSPORT_PUBKEY_FILENAME)).expect("read pub");
    let manifest_path = export_dir.join(PASSPORT_MANIFEST_FILENAME);
    let orig_manifest = fs::read(&manifest_path).expect("read manifest");

    // 1A. `[CEA-DEFECT-01]` — 91B `MZ\x90\x00...` stager smuggling inside `public_key_blob_hex` / `extract_p256_xy_coordinates`
    let xy = extract_p256_xy_coordinates(&hex::decode(&passport.public_key_blob_hex).expect("hex"))
        .expect("extract xy");
    let mut smuggled_91 = b"MZ\x90\x00_SMUGGLED_STAGER_26B!!".to_vec();
    smuggled_91.push(0x04);
    smuggled_91.extend_from_slice(&xy);
    assert_eq!(smuggled_91.len(), 91);
    assert!(
        extract_p256_xy_coordinates(&smuggled_91).is_err(),
        "91B arbitrary MZ prefix MUST be rejected by RFC 5480 SPKI OID check!"
    );

    // 1B. `[CEA-DEFECT-01]` — `ECS1[4..8] = MZ\x90\x00` header malleability & `ECS1 -> SEC1` swap
    let mut bad_ecs1 = b"ECS1MZ\x90\x00".to_vec();
    bad_ecs1.extend_from_slice(&xy);
    assert!(
        extract_p256_xy_coordinates(&bad_ecs1).is_err(),
        "ECS1 with non-32 cb_key header MUST be rejected!"
    );
    let mut sec1_65 = vec![0x04u8];
    sec1_65.extend_from_slice(&xy);
    let mut sec1_swapped = passport.clone();
    sec1_swapped.public_key_blob_hex = hex::encode(&sec1_65);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&sec1_swapped).expect("serialize"),
    )
    .expect("write sec1 swap");
    fs::write(
        export_dir.join(PASSPORT_PUBKEY_FILENAME),
        format!("{}\n", sec1_swapped.public_key_blob_hex),
    )
    .expect("write sidecar");
    assert!(
        verify_kiosk_passport(&export_dir, None).is_err(),
        "ECS1 -> SEC1 public_key_blob_hex swap MUST fail closed even without --pub-key!"
    );
    fs::write(&manifest_path, &orig_manifest).expect("restore manifest");
    fs::write(export_dir.join(PASSPORT_PUBKEY_FILENAME), &pub_bytes).expect("restore pub");

    // 2. `[CEA-DEFECT-02]` — ECDSA P-256 `(r, n - s)` high-S signature malleability rejected!
    // P-256 group order n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    let n_order: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];
    let orig_sig = hex::decode(&passport.ecdsa_p256_signature_hex).expect("sig hex");
    let mut malleable_sig = [0u8; 64];
    malleable_sig[0..32].copy_from_slice(&orig_sig[0..32]);
    // Compute s' = n - s in big-endian
    let mut borrow: i32 = 0;
    for i in (0..32).rev() {
        let diff = (n_order[i] as i32) - (orig_sig[32 + i] as i32) - borrow;
        if diff < 0 {
            malleable_sig[32 + i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            malleable_sig[32 + i] = diff as u8;
            borrow = 0;
        }
    }
    let mut malleable_pass = passport.clone();
    malleable_pass.ecdsa_p256_signature_hex = hex::encode(malleable_sig);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&malleable_pass).expect("serialize malleable"),
    )
    .expect("write malleable");
    assert!(
        verify_kiosk_passport(&export_dir, Some(&pub_bytes)).is_err(),
        "ECDSA P-256 (r, n - s) high-S malleable twin MUST be rejected fail-closed!"
    );
    fs::write(&manifest_path, &orig_manifest).expect("restore manifest");
    assert!(verify_kiosk_passport(&export_dir, Some(&pub_bytes)).is_ok());

    // 3. `[CEA-DEFECT-03]` — Post-signing unlisted directory (`autorun.inf/`) & Unicode Bidi directory rejected!
    let autorun_dir = export_dir.join("autorun.inf");
    fs::create_dir(&autorun_dir).expect("plant autorun.inf dir");
    let unl_dir_res = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
    assert!(
        unl_dir_res.is_err(),
        "Post-signing unlisted directory autorun.inf/ MUST be rejected!"
    );
    assert!(unl_dir_res
        .unwrap_err()
        .contains("PASSPORT_UNLISTED_DIRECTORY"));
    fs::remove_dir(&autorun_dir).expect("remove autorun.inf dir");

    let bidi_dir = export_dir.join("bidi_\u{202E}_smuggle");
    if fs::create_dir(&bidi_dir).is_ok() {
        let bidi_res = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
        assert!(
            bidi_res.is_err(),
            "Bidi override directory MUST be rejected!"
        );
        let _ = fs::remove_dir(&bidi_dir);
    }

    // 4. `[CEA-DEFECT-04]` — OCESCROW3 metadata forgery, unknown JSON fields, & FIPS 203 §7.2/§7.3 modulus/hash checks
    let (pub_h, priv_h) = generate_hybrid_soc_keypair_with_bits(3072).expect("hybrid keypair");
    let valid_escrow =
        encrypt_kek_for_soc_escrow_hybrid_v3(&[0x33; 32], &pub_h, "KEK-P4").expect("enc");

    let mut forged_alg = valid_escrow.clone();
    forged_alg.algorithm = "FAKE-DOWNGRADED-ALG-SPOOF".to_string();
    assert!(
        decrypt_kek_from_soc_escrow_hybrid_v3(&forged_alg, &priv_h).is_err(),
        "Forged OCESCROW3 algorithm string MUST be rejected!"
    );

    let mut forged_fp = valid_escrow.clone();
    forged_fp.soc_mlkem768_fingerprint = "ffffffffffffffffffffffffffffffff".to_string();
    assert!(
        decrypt_kek_from_soc_escrow_hybrid_v3(&forged_fp, &priv_h).is_err(),
        "Forged OCESCROW3 ML-KEM fingerprint MUST be rejected!"
    );

    // Unknown JSON field on HybridSocEscrowBlobV3
    let mut escrow_val = serde_json::to_value(&valid_escrow).expect("to value");
    escrow_val["smuggled_unknown_field"] = serde_json::Value::String("implant".to_string());
    assert!(
        serde_json::from_value::<sentinel_sys::HybridSocEscrowBlobV3>(escrow_val).is_err(),
        "HybridSocEscrowBlobV3 MUST reject unknown JSON fields!"
    );

    // FIPS 203 §7.2 non-canonical EK coefficient (4095 >= q = 3329)
    let mut non_canonical_ek = pub_h.mlkem768_encapsulation_key.clone();
    non_canonical_ek[0] = 0xFF;
    non_canonical_ek[1] = 0xFF;
    non_canonical_ek[2] = 0xFF;
    let bad_ek_bundle = HybridSocPublicKeyBundle {
        version: 3,
        rsa_public_blob: pub_h.rsa_public_blob.clone(),
        mlkem768_encapsulation_key: non_canonical_ek,
    };
    assert!(
        encrypt_kek_for_soc_escrow_hybrid_v3(&[0x33; 32], &bad_ek_bundle, "KEK-BAD-EK").is_err(),
        "Non-canonical ML-KEM-768 EK (coeff 4095 >= 3329) MUST fail FIPS 203 §7.2 check!"
    );

    // FIPS 203 §7.3 corrupted H(ek) inside DK (`dk[2336..2368]`)
    let mut bad_h_dk = priv_h.mlkem768_decapsulation_key.clone();
    bad_h_dk[2340] ^= 0x01;
    let bad_dk_bundle = HybridSocPrivateKeyBundle {
        rsa_private_blob: priv_h.rsa_private_blob.clone(),
        mlkem768_decapsulation_key: bad_h_dk,
    };
    assert!(
        decrypt_kek_from_soc_escrow_hybrid_v3(&valid_escrow, &bad_dk_bundle).is_err(),
        "Corrupted H(ek) inside ML-KEM-768 DK MUST fail FIPS 203 §7.3 check!"
    );
}
