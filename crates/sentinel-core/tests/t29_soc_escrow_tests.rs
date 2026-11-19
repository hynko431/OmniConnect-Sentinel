//! Integration tests for Test Gate T29: SOC Offline RSA-3072+ OAEP Escrow Recovery & Security.
//!
//! Validates Master Plan v2 Sub-Phase 0.2 (CSE-01, CSE-04, CEA-DEFECT-02, CEA-DEFECT-03):
//! - Full round-trip escrow recovery after master key loss
//! - Decryption and restoration of quarantined artifacts
//! - Rejection of invalid / tampered RSA keys, unknown JSON fields, and corrupted escrow envelopes
//! - Honest SocEscrowUnconfigured when calling `QuarantineVault::open` without configured SOC key

use sentinel_core::error::DegradationEvent;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_sys::{generate_soc_rsa_keypair, generate_soc_rsa_keypair_software, SocEscrowBlob};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

fn create_temp_vault_dir(prefix: &str) -> PathBuf {
    let tmp = std::env::temp_dir().join(format!("sentinel_test_vault_{prefix}_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&tmp);
    tmp
}

#[test]
fn test_t29_soc_escrow_full_roundtrip_recovery_after_vault_wipe() {
    let vault_dir = create_temp_vault_dir("roundtrip");
    let test_file_path = vault_dir.join("confidential_payload.bin");
    let original_payload = b"GENUINE-AIR-GAPPED-SCADA-PAYLOAD-FOR-RECOVERY-T29";
    fs::write(&test_file_path, original_payload).expect("write test file");

    // 1. Provision a new Quarantine Vault with a genuine RSA-3072 SOC public key
    let (soc_pub, soc_priv) = generate_soc_rsa_keypair().expect("generate RSA-3072 keypair");
    assert!(!soc_pub.is_empty(), "SOC public key blob must not be empty");
    assert_eq!(&soc_pub[0..4], b"RSA1", "Must have CNG RSA1 magic");
    assert_eq!(&soc_priv[0..4], b"RSA2", "Must have CNG RSA2 magic");

    let vault = QuarantineVault::open_with_soc_public_key(vault_dir.clone(), &soc_pub)
        .expect("open vault with genuine SOC RSA-3072 public key");
    let initial_kek_id = vault.kek_id().to_string();

    // 2. Verify vault_kek.sealed and vault_kek.escrow both exist and unknown JSON fields are rejected
    let sealed_path = vault_dir.join("vault_kek.sealed");
    let escrow_path = vault_dir.join("vault_kek.escrow");
    assert!(sealed_path.exists(), "vault_kek.sealed must exist");
    assert!(escrow_path.exists(), "vault_kek.escrow must exist");
    let escrow_val: serde_json::Value =
        serde_json::from_slice(&fs::read(&escrow_path).expect("read escrow")).expect("parse json");
    assert_eq!(escrow_val["algorithm"], "RSA-3072-OAEP-SHA256");
    let mut smuggled = escrow_val;
    smuggled["unexpected_field"] = serde_json::json!("evil");
    assert!(
        serde_json::from_value::<SocEscrowBlob>(smuggled).is_err(),
        "SocEscrowBlob must reject unknown JSON fields"
    );

    // 3. Quarantine an artifact into the vault
    let entry = vault
        .quarantine_file(&test_file_path, "TEST-THREAT-ESCROW-01")
        .expect("quarantine file");
    assert!(entry.original_path.contains("confidential_payload.bin"));

    // 4. Simulate catastrophic host / TPM / DPAPI master key destruction
    // Wipe vault_kek.sealed from disk
    fs::remove_file(&sealed_path).expect("delete vault_kek.sealed");
    assert!(!sealed_path.exists());

    // 5. Execute SOC Escrow Recovery using genuine offline private RSA-3072 blob
    let recovered_vault = QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &soc_priv)
        .expect("offline SOC escrow recovery must succeed");

    // 6. Verify recovered Master KEK matches original KEK ID
    assert_eq!(
        recovered_vault.kek_id(),
        initial_kek_id,
        "Recovered KEK ID must match original KEK ID"
    );
    assert!(
        sealed_path.exists(),
        "vault_kek.sealed must be re-sealed and re-persisted after recovery"
    );

    // 7. Verify the quarantined artifact can be successfully restored from the recovered vault
    let restore_dest = vault_dir.join("restored_payload.bin");
    let restored_path = recovered_vault
        .restore_file(&entry.entry_id, &restore_dest)
        .expect("restore quarantined file from recovered vault");
    let restored_bytes = fs::read(&restored_path).expect("read restored file");
    assert_eq!(
        restored_bytes, original_payload,
        "Restored payload must be bit-for-bit identical to original payload"
    );

    let _ = fs::remove_dir_all(&vault_dir);
}

#[test]
fn test_t29_soc_escrow_adversarial_rejections() {
    let vault_dir = create_temp_vault_dir("adversarial");
    let (soc_pub, soc_priv) = generate_soc_rsa_keypair().expect("generate RSA-3072 keypair");
    let vault =
        QuarantineVault::open_with_soc_public_key(vault_dir.clone(), &soc_pub).expect("open vault");
    let _ = vault.kek_id();

    let escrow_path = vault_dir.join("vault_kek.escrow");
    assert!(escrow_path.exists());

    // 1. Adversarial Test: Recovery with WRONG RSA private key must be rejected
    let (_other_pub, other_priv) =
        generate_soc_rsa_keypair_software().expect("generate different RSA keypair");
    let wrong_key_recovery =
        QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &other_priv);
    assert!(
        wrong_key_recovery.is_err(),
        "Escrow recovery using an unrelated RSA private key must fail"
    );

    // 2. Adversarial Test: Tampered ciphertext in escrow envelope must fail
    let raw_escrow = fs::read(&escrow_path).expect("read escrow");
    let mut escrow_blob: SocEscrowBlob =
        serde_json::from_slice(&raw_escrow).expect("parse escrow JSON");
    if let Some(byte) = escrow_blob.rsa_oaep_ciphertext.get_mut(10) {
        *byte ^= 0xFF; // Tamper ciphertext
    }
    let tampered_json = serde_json::to_vec_pretty(&escrow_blob).expect("serialize tampered");
    fs::write(&escrow_path, tampered_json).expect("write tampered escrow");

    let tampered_ct_recovery =
        QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &soc_priv);
    assert!(
        tampered_ct_recovery.is_err(),
        "Escrow recovery with tampered ciphertext must fail"
    );

    // 3. Adversarial Test: Tampered KEK ID in escrow envelope must fail
    escrow_blob = serde_json::from_slice(&raw_escrow).expect("re-parse genuine escrow");
    escrow_blob.kek_id = "TAMPERED-KEK-ID-999".to_string();
    let tampered_id_json = serde_json::to_vec_pretty(&escrow_blob).expect("serialize");
    fs::write(&escrow_path, tampered_id_json).expect("write tampered id escrow");

    let tampered_id_recovery =
        QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &soc_priv);
    assert!(
        tampered_id_recovery.is_err(),
        "Escrow recovery with mismatched KEK ID must fail"
    );

    let _ = fs::remove_dir_all(&vault_dir);
}

#[test]
fn test_t29_soc_escrow_unconfigured_degradation_event() {
    let vault_dir = create_temp_vault_dir("unconfigured");

    // 1. Explicit empty SOC key must report SocEscrowUnconfigured without fake escrow
    let vault = QuarantineVault::open_with_soc_public_key(vault_dir.clone(), &[])
        .expect("open vault without SOC public key");
    assert_eq!(
        vault.degradation_event(),
        Some(DegradationEvent::SocEscrowUnconfigured),
        "Must record SocEscrowUnconfigured degradation event"
    );
    let escrow_path = vault_dir.join("vault_kek.escrow");
    assert!(
        !escrow_path.exists(),
        "vault_kek.escrow must NOT be created when SOC key is unconfigured"
    );

    // 2. QuarantineVault::open() without configured SOC key env/files must ALSO honestly report
    //    SocEscrowUnconfigured and NEVER synthesize an unrecoverable ephemeral RAM RSA keypair
    let vault_dir_open = create_temp_vault_dir("open_unconfigured");
    if std::env::var_os("SENTINEL_SOC_HYBRID_PUBKEY_PATH").is_none()
        && std::env::var_os("SENTINEL_SOC_RSA_PUBKEY_PATH").is_none()
    {
        let opened = QuarantineVault::open(vault_dir_open.clone()).expect("open unconfigured");
        assert_eq!(
            opened.degradation_event(),
            Some(DegradationEvent::SocEscrowUnconfigured)
        );
        assert!(!vault_dir_open.join("vault_kek.escrow").exists());
        // Reopening unescrowed vault must preserve SocEscrowUnconfigured
        let reopened = QuarantineVault::open(vault_dir_open.clone()).expect("reopen unconfigured");
        assert_eq!(
            reopened.degradation_event(),
            Some(DegradationEvent::SocEscrowUnconfigured)
        );
    }

    // 3. Reopening an unescrowed vault with a valid RSA-3072+ public key must retro-provision
    //    vault_kek.escrow and clear SocEscrowUnconfigured, while incomplete OCESCROW3 missing .ocescrow3
    //    must still report SocEscrowUnconfigured.
    let (soc_pub, soc_priv) = sentinel_sys::generate_soc_rsa_keypair().expect("RSA-3072 keygen");
    let reprovisioned = QuarantineVault::open_with_soc_public_key(vault_dir.clone(), &soc_pub)
        .expect("reopen unescrowed vault with SOC key");
    assert!(vault_dir.join("vault_kek.escrow").exists());
    assert_ne!(
        reprovisioned.degradation_event(),
        Some(sentinel_core::error::DegradationEvent::SocEscrowUnconfigured)
    );
    let recovered = QuarantineVault::recover_from_soc_escrow(vault_dir.clone(), &soc_priv)
        .expect("recover retro-provisioned vault");
    assert_eq!(recovered.kek_id(), reprovisioned.kek_id());

    let dir_v3_partial = create_temp_vault_dir("v3_partial");
    let v3_base = QuarantineVault::open_with_soc_public_key(dir_v3_partial.clone(), &[])
        .expect("open unescrowed v3 base");
    let (v3_pub, _) = sentinel_sys::generate_hybrid_soc_keypair_v3().expect("v3 keygen");
    v3_base
        .provision_hybrid_soc_escrow_v3(&v3_pub)
        .expect("provision ocescrow3");
    // Delete wire file to simulate missing .ocescrow3 binary envelope
    let _ = fs::remove_file(dir_v3_partial.join("vault_kek.ocescrow3"));
    let reopened_partial = QuarantineVault::open_with_soc_public_key(dir_v3_partial.clone(), &[])
        .expect("reopen partial ocescrow3");
    assert_eq!(
        reopened_partial.degradation_event(),
        Some(DegradationEvent::SocEscrowUnconfigured),
        "Incomplete OCESCROW3 missing .ocescrow3 wire file MUST report SocEscrowUnconfigured"
    );

    let _ = fs::remove_dir_all(&dir_v3_partial);
    let _ = fs::remove_dir_all(&vault_dir);
    let _ = fs::remove_dir_all(&vault_dir_open);
}
