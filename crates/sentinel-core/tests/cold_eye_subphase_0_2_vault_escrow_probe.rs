//! Cold-Eye Compliance Auditor - Sub-Phase 0.2 Quarantine Vault & CLI Escrow Break-It Probe

use sentinel_core::error::DegradationEvent;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_sys::{
    default_soc_rsa_private_blob, default_soc_rsa_public_blob, generate_soc_rsa_keypair,
    SocEscrowBlob,
};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

fn create_temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cold_eye_vault_{prefix}_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&dir);
    dir
}

#[test]
fn probe_adversarial_vault_recovery_and_cli_verify_escrow() {
    let vault_dir = create_temp_dir("audit_test");
    let test_payload_path = vault_dir.join("scada_firmware.bin");
    let test_payload = b"CRITICAL_SCADA_FIRMWARE_IMAGE_BYTE_FOR_BYTE_INTEGRITY_CHECK_2026";
    fs::write(&test_payload_path, test_payload).expect("write test payload");

    // 1. Provision Vault with genuine SOC public key
    let (soc_pub, soc_priv) = generate_soc_rsa_keypair().expect("generate fresh SOC keypair");
    let vault = QuarantineVault::open_with_soc_public_key(vault_dir.clone(), &soc_pub)
        .expect("open vault with SOC public key");
    let initial_kek_id = vault.kek_id().to_string();

    // Quarantine the payload
    let q_entry = vault
        .quarantine_file(&test_payload_path, "MALWARE-DROPPER-01")
        .expect("quarantine file");

    let sealed_path = vault_dir.join("vault_kek.sealed");
    let escrow_path = vault_dir.join("vault_kek.escrow");
    assert!(sealed_path.exists());
    assert!(escrow_path.exists());

    // Save private key to disk for CLI verification test
    let priv_key_path = vault_dir.join("soc_offline.key");
    fs::write(&priv_key_path, &soc_priv).expect("write soc private key");

    // 2. Test CLI verify-escrow command on valid vault
    let cli_path = if cfg!(windows) {
        PathBuf::from("t/debug/sentinel.exe")
    } else {
        PathBuf::from("t/debug/sentinel")
    };

    if cli_path.exists() {
        let output = Command::new(&cli_path)
            .args([
                "vault",
                "verify-escrow",
                "--vault-dir",
                vault_dir.to_str().unwrap(),
                "--soc-priv-key",
                priv_key_path.to_str().unwrap(),
            ])
            .output()
            .expect("execute sentinel vault verify-escrow");
        assert!(
            output.status.success(),
            "CLI verify-escrow must succeed on valid escrow. Stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Offline SOC RSA escrow verified successfully"));

        // CLI verify-escrow with WRONG private key must fail
        let (_wrong_pub, wrong_priv) = generate_soc_rsa_keypair().expect("wrong keypair");
        let wrong_priv_path = vault_dir.join("wrong_offline.key");
        fs::write(&wrong_priv_path, &wrong_priv).expect("write wrong key");

        let bad_output = Command::new(&cli_path)
            .args([
                "vault",
                "verify-escrow",
                "--vault-dir",
                vault_dir.to_str().unwrap(),
                "--soc-priv-key",
                wrong_priv_path.to_str().unwrap(),
            ])
            .output()
            .expect("execute sentinel vault verify-escrow with wrong key");
        assert!(
            !bad_output.status.success(),
            "CLI verify-escrow must exit with non-zero on wrong private key"
        );
    }

    // 3. Catastrophic destruction: wipe vault_kek.sealed
    fs::remove_file(&sealed_path).expect("wipe vault_kek.sealed");
    assert!(!sealed_path.exists());

    // Normal open now creates a NEW key instead of opening old vault
    // But recovery with wrong key MUST fail
    let (_wrong_pub, wrong_priv) = generate_soc_rsa_keypair().expect("wrong keypair");
    let wrong_recovery = QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &wrong_priv);
    assert!(
        wrong_recovery.is_err(),
        "Escrow recovery with wrong private key must fail"
    );

    // Tampered escrow ciphertext MUST fail
    let original_escrow_bytes = fs::read(&escrow_path).expect("read escrow");
    let mut escrow_blob: SocEscrowBlob = serde_json::from_slice(&original_escrow_bytes).unwrap();
    escrow_blob.rsa_oaep_ciphertext[20] ^= 0x42;
    fs::write(&escrow_path, serde_json::to_vec(&escrow_blob).unwrap()).unwrap();

    let tampered_ct_recovery =
        QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &soc_priv);
    assert!(
        tampered_ct_recovery.is_err(),
        "Escrow recovery with tampered ciphertext must fail"
    );

    // Tampered KEK ID in escrow MUST fail
    escrow_blob = serde_json::from_slice(&original_escrow_bytes).unwrap();
    escrow_blob.kek_id = "TAMPERED-ID-0000".to_string();
    fs::write(&escrow_path, serde_json::to_vec(&escrow_blob).unwrap()).unwrap();

    let tampered_id_recovery =
        QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &soc_priv);
    assert!(
        tampered_id_recovery.is_err(),
        "Escrow recovery with mismatched KEK ID must fail"
    );

    // Restore genuine escrow bytes
    fs::write(&escrow_path, &original_escrow_bytes).unwrap();

    // 4. Genuine recovery
    let recovered_vault = QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &soc_priv)
        .expect("genuine escrow recovery must succeed");
    assert_eq!(recovered_vault.kek_id(), initial_kek_id);
    assert!(
        sealed_path.exists(),
        "vault_kek.sealed must be re-sealed and re-created"
    );

    // Restore payload from recovered vault
    let restored_file = vault_dir.join("restored_firmware.bin");
    recovered_vault
        .restore_file(&q_entry.entry_id, &restored_file)
        .expect("restore file from recovered vault");
    let restored_bytes = fs::read(&restored_file).expect("read restored bytes");
    assert_eq!(
        restored_bytes, test_payload,
        "Quarantined payload restored after escrow recovery must match byte-for-byte"
    );

    // 5. Verify ledger audit trail contains VAULT_ESCROW_RECOVERED
    let ledger_path = vault_dir.join("vault_audit.jsonl");
    let ledger_content = fs::read_to_string(&ledger_path).expect("read audit ledger");
    assert!(
        ledger_content.contains("VAULT_ESCROW_RECOVERED"),
        "Ledger must record VAULT_ESCROW_RECOVERED event"
    );

    // 6. Test Unconfigured SOC public key degradation
    let unconf_dir = create_temp_dir("unconf_test");
    let unconf_vault = QuarantineVault::open_with_soc_public_key(unconf_dir.clone(), &[])
        .expect("open vault without SOC public key");
    assert_eq!(
        unconf_vault.degradation_event(),
        Some(DegradationEvent::SocEscrowUnconfigured)
    );
    assert!(!unconf_dir.join("vault_kek.escrow").exists());
    let _ = fs::remove_dir_all(&unconf_dir);

    // 7. Verify default SOC blobs are genuine
    assert_eq!(&default_soc_rsa_public_blob()[0..4], b"RSA1");
    assert_eq!(&default_soc_rsa_private_blob()[0..4], b"RSA2");

    let _ = fs::remove_dir_all(&vault_dir);
}
