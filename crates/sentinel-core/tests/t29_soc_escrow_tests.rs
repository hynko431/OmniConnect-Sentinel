//! Integration tests for Test Gate T29: SOC Offline RSA-2048 OAEP Escrow Recovery & Security.
//!
//! Validates Master Plan v2 Sub-Phase 0.2 (CSE-01, CSE-04):
//! - Full round-trip escrow recovery after master key loss
//! - Decryption and restoration of quarantined artifacts
//! - Rejection of invalid / tampered RSA keys and corrupted escrow envelopes
//! - Degradation event emission on unconfigured SOC public key

use sentinel_core::error::DegradationEvent;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_sys::{
    default_soc_rsa_private_blob, default_soc_rsa_public_blob, generate_soc_rsa_keypair_software,
    SocEscrowBlob,
};
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

    // 1. Provision a new Quarantine Vault with default genuine SOC RSA public key
    let soc_pub = default_soc_rsa_public_blob();
    assert!(!soc_pub.is_empty(), "SOC public key blob must not be empty");
    assert_eq!(&soc_pub[0..4], b"RSA1", "Must have CNG RSA1 magic");

    let vault = QuarantineVault::open_with_soc_public_key(vault_dir.clone(), &soc_pub)
        .expect("open vault with genuine SOC RSA public key");
    let initial_kek_id = vault.kek_id().to_string();

    // 2. Verify vault_kek.sealed and vault_kek.escrow both exist
    let sealed_path = vault_dir.join("vault_kek.sealed");
    let escrow_path = vault_dir.join("vault_kek.escrow");
    assert!(sealed_path.exists(), "vault_kek.sealed must exist");
    assert!(escrow_path.exists(), "vault_kek.escrow must exist");

    // 3. Quarantine an artifact into the vault
    let entry = vault
        .quarantine_file(&test_file_path, "TEST-THREAT-ESCROW-01")
        .expect("quarantine file");
    assert!(entry.original_path.contains("confidential_payload.bin"));

    // 4. Simulate catastrophic host / TPM / DPAPI master key destruction
    // Wipe vault_kek.sealed from disk
    fs::remove_file(&sealed_path).expect("delete vault_kek.sealed");
    assert!(!sealed_path.exists());

    // 5. Execute SOC Escrow Recovery using genuine offline private RSA blob
    let soc_priv = default_soc_rsa_private_blob();
    assert_eq!(&soc_priv[0..4], b"RSA2", "Must have CNG RSA2 magic");

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
    let soc_pub = default_soc_rsa_public_blob();
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

    let soc_priv = default_soc_rsa_private_blob();
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

    // Provision with empty SOC RSA public key blob
    let vault = QuarantineVault::open_with_soc_public_key(vault_dir.clone(), &[])
        .expect("open vault without SOC public key");

    // Degradation event must be recorded
    assert_eq!(
        vault.degradation_event(),
        Some(DegradationEvent::SocEscrowUnconfigured),
        "Must record SocEscrowUnconfigured degradation event"
    );

    // vault_kek.escrow must NOT have been written
    let escrow_path = vault_dir.join("vault_kek.escrow");
    assert!(
        !escrow_path.exists(),
        "vault_kek.escrow must NOT be created when SOC key is unconfigured"
    );

    let _ = fs::remove_dir_all(&vault_dir);
}
