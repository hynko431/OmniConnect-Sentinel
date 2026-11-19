//! Test Gate T28: Pinned Enterprise Policy Root Trust Anchor & Anti-Rollback Enforcement (`CSE-03`)
//!
//! Validates Master Plan v2 §1.1, §2.1 & §4.2 (Sub-Phase 0.4):
//! 1. Pinned Enterprise Root Keys: Only policies signed by authorized pinned enterprise roots (Primary / DR) are accepted.
//! 2. Zero-Trust for Envelope Signer Key: Attacker-supplied or self-signed public keys in the envelope are strictly rejected.
//! 3. Cryptographic Signature Integrity: Tampered payloads or forged signatures are rejected.
//! 4. Monotonic Anti-Rollback: Downgrading policy versions (even if signed by genuine enterprise root) is rejected.
//! 5. Sealed Vault Floor Persistence: Version floor is persisted in hardware-sealed `policy_version.sealed`.
//! 6. Fail-Closed Lockdown: Any tampering, self-signed key, or rollback attempt engages strict Ring 3 hardware lockdown.

use sentinel_core::enterprise::intune::{
    default_enterprise_root_public_keys, IntuneMdmPolicy, IntunePolicyManager, SignedPolicyBundle,
};
use sentinel_core::enterprise::ledger::AuditLedger;
use sentinel_sys::{generate_raw_ecdsa_p256_keypair, validate_p256_uncompressed_point};
use tempfile::tempdir;

#[test]
fn test_t28_primary_and_dr_root_keys_genuine_and_verifiable() {
    let roots = default_enterprise_root_public_keys();
    assert!(
        roots.len() >= 2,
        "Must have at least 2 pinned enterprise root public keys (Primary & DR)"
    );
    assert_ne!(
        roots[0], roots[1],
        "Primary and DR root keys must be distinct"
    );
    for r in &roots {
        assert_eq!(r.len(), 72);
        assert_eq!(&r[0..8], b"ECS1\x20\x00\x00\x00");
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&r[8..72]);
        validate_p256_uncompressed_point(&sec1)
            .expect("Default pinned public key must be valid P-256 curve point");
    }

    // Generate ephemeral test enterprise Primary & DR root keypairs via OsRng
    // (production binaries never ship private-key derivation seeds)
    let (pub1, priv1) = generate_raw_ecdsa_p256_keypair().expect("Primary test keygen");
    let (pub2, priv2) = generate_raw_ecdsa_p256_keypair().expect("Backup test keygen");

    // Test signing with Primary root
    let mut pol = IntuneMdmPolicy {
        version: 3,
        ..Default::default()
    };
    let bundle1 = SignedPolicyBundle::sign(pol.clone(), &priv1, &pub1).expect("Primary sign");
    bundle1
        .verify_signature(&pub1)
        .expect("Must verify against primary test root");

    // Test signing with DR root
    pol.version = 4;
    let bundle2 = SignedPolicyBundle::sign(pol, &priv2, &pub2).expect("Backup sign");
    bundle2
        .verify_signature(&pub2)
        .expect("Must verify against backup test root");
}

#[test]
fn test_t28_valid_signed_policy_advances_and_seals_version() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let (pub1, priv1) = generate_raw_ecdsa_p256_keypair().expect("test root keygen");
    let mut mgr = IntunePolicyManager::new()
        .with_vault_dir(vault_dir.clone())
        .with_ledger_path(ledger_path.clone())
        .with_pinned_root_public_keys(vec![pub1.clone()]);

    assert_eq!(mgr.policy().version, 2);

    let mut new_policy = mgr.policy().clone();
    new_policy.version = 5;
    new_policy.policy_id = "MDM-ENTERPRISE-PROD-V5".to_string();
    new_policy.max_sanitization_file_size_mb = 120;

    let bundle = SignedPolicyBundle::sign(new_policy, &priv1, &pub1).expect("sign");
    let applied = mgr
        .apply_signed_bundle(&bundle)
        .expect("Valid signed bundle must apply");

    assert_eq!(applied.version, 5);
    assert_eq!(applied.policy_id, "MDM-ENTERPRISE-PROD-V5");
    assert_eq!(applied.max_sanitization_file_size_mb, 120);

    // Verify sealed floor was written to disk
    assert!(vault_dir.join("policy_version.sealed").exists());
    assert_eq!(mgr.load_sealed_version().expect("load sealed version"), 5);

    // Verify audit ledger record and cryptographic hash chain
    let ledger = AuditLedger::open(&ledger_path);
    assert!(ledger.verify_chain().is_ok());
    let raw_ledger = std::fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(raw_ledger.contains("POLICY_UPDATED"));
}

#[test]
fn test_t28_self_signed_untrusted_key_rejected_and_lockdown() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let mut mgr = IntunePolicyManager::new()
        .with_vault_dir(vault_dir)
        .with_ledger_path(ledger_path.clone());

    // Attacker generates their own private ECDSA P-256 keypair
    let (attacker_pub, attacker_priv) = sentinel_sys::generate_raw_ecdsa_p256_keypair()
        .expect("Attacker key generation should succeed");

    let mut evil_policy = mgr.policy().clone();
    evil_policy.version = 100;
    evil_policy.enforce_usb_zero_trust = false; // Attacker tries to disable Zero Trust
    evil_policy.allowed_hardware_ids = vec!["*".to_string()]; // Allow all peripherals

    let evil_bundle =
        SignedPolicyBundle::sign(evil_policy, &attacker_priv, &attacker_pub).expect("sign evil");

    let res = mgr.apply_signed_bundle(&evil_bundle);
    assert!(
        res.is_err(),
        "Policy signed by unpinned attacker key MUST be rejected!"
    );

    // Verify lockdown state
    assert_eq!(mgr.policy().enforcement_mode, "LOCKDOWN_STRICT");
    assert_eq!(mgr.policy().version, 0);
    assert!(mgr.policy().enforce_usb_zero_trust);
    assert!(mgr.policy().allowed_hardware_ids.is_empty());

    // Verify ledger audit trail and hash chain integrity
    let ledger = AuditLedger::open(&ledger_path);
    assert!(ledger.verify_chain().is_ok());
    let raw_ledger = std::fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(
        raw_ledger.contains("POLICY_LOCKDOWN_ENGAGED")
            || raw_ledger.contains("POLICY_TAMPER_REJECTED")
    );
}

#[test]
fn test_t28_tampered_signature_and_payload_rejected() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let (pub1, priv1) = generate_raw_ecdsa_p256_keypair().expect("test root keygen");
    let mut mgr = IntunePolicyManager::new()
        .with_vault_dir(vault_dir)
        .with_ledger_path(ledger_path)
        .with_pinned_root_public_keys(vec![pub1.clone()]);

    let mut pol = mgr.policy().clone();
    pol.version = 10;
    let legitimate_bundle = SignedPolicyBundle::sign(pol, &priv1, &pub1).expect("sign");

    // 1. Bit-flip in signature
    let mut tampered_sig_bundle = legitimate_bundle.clone();
    let mut sig_bytes = hex::decode(&tampered_sig_bundle.signature_hex).unwrap();
    sig_bytes[5] ^= 0xFF;
    tampered_sig_bundle.signature_hex = hex::encode(sig_bytes);

    assert!(mgr.apply_signed_bundle(&tampered_sig_bundle).is_err());

    // 2. Tamper payload while keeping original signature
    let mut tampered_payload_bundle = legitimate_bundle.clone();
    tampered_payload_bundle.policy.enforce_usb_zero_trust = false;
    assert!(mgr.apply_signed_bundle(&tampered_payload_bundle).is_err());
}

#[test]
fn test_t28_monotonic_rollback_rejected_and_sealed_floor_enforced() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let (pub1, priv1) = generate_raw_ecdsa_p256_keypair().expect("test root keygen");

    // 1. First manager instance applies v10
    {
        let mut mgr = IntunePolicyManager::new()
            .with_vault_dir(vault_dir.clone())
            .with_ledger_path(ledger_path.clone())
            .with_pinned_root_public_keys(vec![pub1.clone()]);

        let mut v10 = mgr.policy().clone();
        v10.version = 10;
        let b10 = SignedPolicyBundle::sign(v10, &priv1, &pub1).expect("sign v10");
        mgr.apply_signed_bundle(&b10).expect("v10 must succeed");
        assert_eq!(mgr.policy().version, 10);
    }

    // 2. Second manager instance simulates restart - reads sealed version floor
    let mut mgr2 = IntunePolicyManager::new()
        .with_vault_dir(vault_dir)
        .with_ledger_path(ledger_path)
        .with_pinned_root_public_keys(vec![pub1.clone()]);

    assert_eq!(
        mgr2.load_sealed_version().expect("load sealed version"),
        10,
        "Sealed version floor must persist across restarts"
    );

    // Attacker replays genuine enterprise root-signed v9 or v10
    let mut v9 = mgr2.policy().clone();
    v9.version = 9;
    let b9 = SignedPolicyBundle::sign(v9, &priv1, &pub1).expect("sign v9");

    let res = mgr2.apply_signed_bundle(&b9);
    assert!(
        res.is_err(),
        "Rollback attack (version 9 <= active floor 10) must be rejected!"
    );

    let err_str = res.err().unwrap().to_string();
    assert!(
        err_str.contains("rollback rejected"),
        "Error must specify rollback rejection: {err_str}"
    );
}

#[test]
fn test_t28_sealed_floor_tampering_triggers_lockdown_and_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let (pub1, priv1) = generate_raw_ecdsa_p256_keypair().expect("test root keygen");

    // 1. Establish policy at v10
    {
        let mut mgr = IntunePolicyManager::new()
            .with_vault_dir(vault_dir.clone())
            .with_ledger_path(ledger_path.clone())
            .with_pinned_root_public_keys(vec![pub1.clone()]);

        let mut v10 = mgr.policy().clone();
        v10.version = 10;
        let b10 = SignedPolicyBundle::sign(v10, &priv1, &pub1).expect("sign v10");
        mgr.apply_signed_bundle(&b10).expect("v10 must apply");
        assert_eq!(mgr.policy().version, 10);
    }

    // 2. Tamper/corrupt the sealed floor file
    let sealed_path = vault_dir.join("policy_version.sealed");
    assert!(sealed_path.exists());
    std::fs::write(&sealed_path, b"CORRUPTED_BYTES_ATTACKER_TAMPER").expect("write corruption");

    // 3. New manager instance encounters corrupted sealed file
    let mut mgr2 = IntunePolicyManager::new()
        .with_vault_dir(vault_dir.clone())
        .with_ledger_path(ledger_path.clone())
        .with_pinned_root_public_keys(vec![pub1.clone()]);

    assert!(
        mgr2.load_sealed_version().is_err(),
        "Corrupted sealed version file must return Err, never silent fallback"
    );

    // 4. Attempting to apply even a valid signed policy bundle when vault is corrupted must fail closed
    let mut v5 = mgr2.policy().clone();
    v5.version = 5;
    let b5 = SignedPolicyBundle::sign(v5, &priv1, &pub1).expect("sign v5");

    let res = mgr2.apply_signed_bundle(&b5);
    assert!(
        res.is_err(),
        "Must reject policy application when sealed floor is corrupted"
    );

    // Verify fail closed lockdown was engaged
    assert_eq!(mgr2.policy().enforcement_mode, "LOCKDOWN_STRICT");
    assert_eq!(mgr2.policy().version, 0);
    assert!(mgr2.policy().enforce_usb_zero_trust);
    assert!(mgr2.policy().allowed_hardware_ids.is_empty());
}

#[test]
fn test_t28_legacy_leaked_seed_keys_and_smuggled_fields_rejected() {
    use sha2::{Digest, Sha256};

    let roots = default_enterprise_root_public_keys();
    for legacy_seed_literal in [
        b"OMNICONNECT-ENTERPRISE-ROOT-POLICY-CA-PRIMARY-V2".as_slice(),
        b"OMNICONNECT-ENTERPRISE-ROOT-POLICY-CA-BACKUP-DR-V2".as_slice(),
    ] {
        let digest: [u8; 32] = Sha256::digest(legacy_seed_literal).into();
        let (legacy_pub, legacy_priv) =
            sentinel_sys::generate_ecdsa_p256_keypair_from_seed(&digest)
                .expect("derive legacy key in test");
        assert!(!roots.contains(&legacy_pub));

        let dir = tempdir().expect("tempdir");
        let mut mgr = IntunePolicyManager::new().with_vault_dir(dir.path().to_path_buf());
        let evil_pol = IntuneMdmPolicy {
            version: 999,
            enforce_usb_zero_trust: false,
            ..Default::default()
        };
        let bundle = SignedPolicyBundle::sign(evil_pol, &legacy_priv, &legacy_pub).expect("sign");
        assert!(
            mgr.apply_signed_bundle(&bundle).is_err(),
            "Bundle signed with removed legacy seed MUST be rejected"
        );
        assert_eq!(mgr.policy().enforcement_mode, "LOCKDOWN_STRICT");
        assert!(mgr.policy().enforce_usb_zero_trust);
    }

    // Unknown JSON fields rejected (`CEA-DEFECT-02`)
    let mut pol_json = serde_json::to_value(IntuneMdmPolicy::default()).expect("ser");
    pol_json["smuggled"] = serde_json::json!("evil");
    assert!(serde_json::from_value::<IntuneMdmPolicy>(pol_json).is_err());

    let (pub_k, priv_k) = generate_raw_ecdsa_p256_keypair().expect("keygen");
    let bundle =
        SignedPolicyBundle::sign(IntuneMdmPolicy::default(), &priv_k, &pub_k).expect("sign");
    let mut bundle_json = serde_json::to_value(bundle).expect("ser");
    bundle_json["smuggled"] = serde_json::json!(123);
    assert!(serde_json::from_value::<SignedPolicyBundle>(bundle_json).is_err());
}
