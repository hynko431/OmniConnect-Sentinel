//! Independent Adversarial Cold-Eye Master Audit Break-It Probe
//! Evaluates all four Phase 0 Critical Vulnerabilities (CSE-01, CSE-04, CSE-02, CSE-03)
#![allow(unused_imports)]

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use tempfile::tempdir;

use sentinel_sys::crypto_seal::{
    generate_ecdsa_p256_keypair_software, sign_ecdsa_p256_digest_software,
    unix_authenticated_seal_with_secret, unix_authenticated_unseal_with_secret,
};
use sentinel_sys::{
    decrypt_kek_from_soc_escrow, default_soc_rsa_private_blob, default_soc_rsa_public_blob,
    encrypt_kek_for_soc_escrow, generate_raw_ecdsa_p256_keypair, generate_soc_rsa_keypair,
    parse_rsa_private_key, parse_rsa_public_key, verify_ecdsa_p256_digest, KeyProtectionPosture,
    SealedKeyBlob, SocEscrowBlob,
};

use sentinel_core::enterprise::intune::{
    backup_enterprise_root_keypair, default_enterprise_root_public_keys,
    primary_enterprise_root_keypair, IntuneMdmPolicy, IntunePolicyManager, SignedPolicyBundle,
};
use sentinel_core::error::{DegradationEvent, SentinelError};
use sentinel_core::scanner::quarantine::QuarantineVault;

#[test]
fn probe_adversarial_cse01_ecdsa_and_ocsl2_forgery_rejection() {
    // 1. Genuine software keypair
    let (pub_blob, priv_blob) = generate_ecdsa_p256_keypair_software().expect("software keypair");
    let test_digest: [u8; 32] = Sha256::digest(b"Adversarial Audit Target Message #1").into();

    let genuine_sig =
        sign_ecdsa_p256_digest_software(&priv_blob, &test_digest).expect("signing must succeed");
    assert_eq!(genuine_sig.len(), 64);

    // Genuine verification must pass
    assert!(
        verify_ecdsa_p256_digest(&pub_blob, &test_digest, &genuine_sig).expect("verify"),
        "Genuine ECDSA P-256 signature must verify"
    );

    // ADVERSARIAL FORGERY 1: Duplicate SHA-256 hash shortcut (old CSE-01 shim)
    let pub_x = &pub_blob[8..40];
    let mut fake_hasher = Sha256::new();
    fake_hasher.update(b"ECDSA-P256-UNIX-SIG:");
    fake_hasher.update(pub_x);
    fake_hasher.update(test_digest);
    let fake_d = fake_hasher.finalize();
    let mut fake_sig = [0u8; 64];
    fake_sig[..32].copy_from_slice(&fake_d);
    fake_sig[32..].copy_from_slice(&fake_d);

    let fake_verified =
        verify_ecdsa_p256_digest(&pub_blob, &test_digest, &fake_sig).unwrap_or(false);
    assert!(
        !fake_verified,
        "CRITICAL: fake SHA256 signature shortcut must be rejected!"
    );

    // ADVERSARIAL FORGERY 2: Single-bit flip in signature
    for bit_idx in [0, 15, 31, 32, 63] {
        let mut tampered = genuine_sig.clone();
        tampered[bit_idx] ^= 0x01;
        assert!(
            !verify_ecdsa_p256_digest(&pub_blob, &test_digest, &tampered).unwrap_or(false),
            "Tampered signature byte {bit_idx} must fail verification"
        );
    }

    // ADVERSARIAL OCSL2 ENVELOPE: Tampered AAD and ciphertext
    let master_secret = [0x77u8; 32];
    let raw_key = [0x88u8; 32];
    let entropy = b"EntropyAAD-Test-2026";
    let kek_id = "test-audit-kek";

    let sealed = unix_authenticated_seal_with_secret(&raw_key, &master_secret, entropy, kek_id)
        .expect("seal");
    assert!(
        sealed.starts_with(b"OCSL2"),
        "Must use OCSL2 envelope magic"
    );

    // Unseal genuine
    let unsealed = unix_authenticated_unseal_with_secret(&sealed, &master_secret, entropy, kek_id)
        .expect("unseal");
    assert_eq!(unsealed, raw_key);

    // Tampered ciphertext must fail AEAD verification
    let mut tampered_sealed = sealed.clone();
    let end = tampered_sealed.len() - 1;
    tampered_sealed[end] ^= 0x01;
    assert!(
        unix_authenticated_unseal_with_secret(&tampered_sealed, &master_secret, entropy, kek_id)
            .is_err(),
        "Tampered ciphertext must fail AEAD authentication"
    );

    // Tampered entropy / AAD must fail AEAD verification
    assert!(
        unix_authenticated_unseal_with_secret(&sealed, &master_secret, b"WrongEntropy", kek_id)
            .is_err(),
        "Mismatched entropy tag in AAD must fail AEAD authentication"
    );
}

#[test]
fn probe_adversarial_cse04_soc_escrow_semiprime_and_vault_fail_closed() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");

    // 1. Generate genuine RSA-2048 keypair
    let (soc_pub, soc_priv) = generate_soc_rsa_keypair().expect("genuine RSA keypair");
    let _parsed_pub = parse_rsa_public_key(&soc_pub).expect("parse public key");

    // 2. Open vault with SOC public key
    let vault = QuarantineVault::open_with_soc_public_key(vault_dir.clone(), &soc_pub)
        .expect("open vault with genuine SOC public key");
    let initial_kek_id = vault.kek_id().to_string();

    let sealed_path = vault_dir.join("vault_kek.sealed");
    let escrow_path = vault_dir.join("vault_kek.escrow");
    assert!(sealed_path.exists(), "vault_kek.sealed must exist");
    assert!(escrow_path.exists(), "vault_kek.escrow must exist");

    // Escrow decryption test
    let escrow_data = fs::read(&escrow_path).expect("read escrow");
    let escrow_blob: SocEscrowBlob =
        serde_json::from_slice(&escrow_data).expect("parse escrow JSON");
    assert_eq!(escrow_blob.algorithm, "RSA-2048-OAEP-SHA256");

    let recovered_kek =
        decrypt_kek_from_soc_escrow(&escrow_blob, &soc_priv).expect("decrypt escrow");
    let mut hasher = Sha256::new();
    hasher.update(b"SENTINEL-KEK-ID-V2:");
    hasher.update(recovered_kek.as_slice());
    let computed_id = &hex::encode(hasher.finalize())[..16];
    assert_eq!(
        computed_id, initial_kek_id,
        "Recovered KEK ID must match vault KEK ID"
    );

    // Escrow decryption with WRONG private key must fail
    let (_, wrong_priv) = generate_soc_rsa_keypair().expect("wrong keypair");
    assert!(
        decrypt_kek_from_soc_escrow(&escrow_blob, &wrong_priv).is_err(),
        "Escrow decryption with wrong private key must fail closed"
    );

    // 3. Vault Integrity Fail-Closed: Tamper with vault_kek.sealed
    let mut tampered_sealed = fs::read(&sealed_path).expect("read sealed");
    tampered_sealed[10] ^= 0xFF;
    fs::write(&sealed_path, &tampered_sealed).expect("write tampered sealed");

    // Opening tampered vault MUST FAIL and MUST NOT regenerate or overwrite vault_kek.sealed!
    let open_res = QuarantineVault::open(vault_dir.clone());
    assert!(
        open_res.is_err(),
        "QuarantineVault::open MUST FAIL on tampered sealed KEK"
    );

    let sealed_after_failure = fs::read(&sealed_path).expect("read sealed after fail");
    assert_eq!(
        sealed_after_failure, tampered_sealed,
        "QuarantineVault::open MUST NEVER overwrite or regenerate tampered vault_kek.sealed"
    );

    // 4. Test unconfigured SOC escrow triggers DegradationEvent::SocEscrowUnconfigured
    let dir2 = tempdir().expect("tempdir2");
    let vault_dir2 = dir2.path().join(".sentinel_vault");
    let vault_unconfigured = QuarantineVault::open_with_soc_public_key(vault_dir2.clone(), &[])
        .expect("open without SOC key");
    assert_eq!(
        vault_unconfigured.degradation_event(),
        Some(DegradationEvent::SocEscrowUnconfigured),
        "Must record DegradationEvent::SocEscrowUnconfigured when SOC public key is empty"
    );
}

#[test]
fn probe_adversarial_cse03_intune_policy_rollback_and_untrusted_keys() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("policy_audit_ledger_v2.jsonl");

    let (pub1, priv1) = primary_enterprise_root_keypair();
    let (pub2, priv2) = backup_enterprise_root_keypair();

    let mut mgr = IntunePolicyManager::new()
        .with_vault_dir(vault_dir.clone())
        .with_ledger_path(ledger_path);

    // Baseline: version 2
    assert_eq!(mgr.policy().version, 2);

    // 1. Apply legitimate policy version 3 via Primary Key
    let mut pol3 = mgr.policy().clone();
    pol3.version = 3;
    let b3 = SignedPolicyBundle::sign(pol3, &priv1, &pub1).expect("sign b3");
    let res3 = mgr.apply_signed_bundle(&b3);
    assert!(
        res3.is_ok(),
        "Legitimate policy version 3 must apply successfully"
    );
    assert_eq!(mgr.policy().version, 3);

    // 2. Monotonic Rollback Attack: Try to re-apply version 2 or version 3
    let mut pol_rollback = mgr.policy().clone();
    pol_rollback.version = 2; // Downgrade
    let b_rollback = SignedPolicyBundle::sign(pol_rollback, &priv1, &pub1).expect("sign rollback");
    let res_rollback = mgr.apply_signed_bundle(&b_rollback);
    assert!(res_rollback.is_err(), "Policy rollback must be rejected");

    // Replay attack (same version 3) must also be rejected
    let res_replay = mgr.apply_signed_bundle(&b3);
    assert!(
        res_replay.is_err(),
        "Policy replay of identical version must be rejected"
    );

    // 3. Self-Signed / Untrusted Key Attack: Attacker generates fresh ECDSA keypair
    let (att_pub, att_priv) = generate_raw_ecdsa_p256_keypair().expect("attacker keypair");
    let mut evil_pol = mgr.policy().clone();
    evil_pol.version = 50;
    evil_pol.enforce_usb_zero_trust = false; // Disable Zero Trust!
    let evil_bundle = SignedPolicyBundle::sign(evil_pol, &att_priv, &att_pub).expect("sign evil");

    let res_evil = mgr.apply_signed_bundle(&evil_bundle);
    assert!(
        res_evil.is_err(),
        "Untrusted / self-signed key must be rejected"
    );

    // CRITICAL: Must have entered fail-closed lockdown!
    assert_eq!(
        mgr.policy().enforcement_mode,
        "LOCKDOWN_STRICT",
        "Untrusted key attack must trigger fail-closed lockdown (LOCKDOWN_STRICT)"
    );
    assert_eq!(mgr.policy().version, 0, "Lockdown policy version must be 0");
    assert!(
        mgr.policy().allowed_hardware_ids.is_empty(),
        "Lockdown allowed_hardware_ids must be empty"
    );

    // 4. Sealed Floor Tampering Probe:
    let sealed_floor_path = vault_dir.join("policy_version.sealed");
    if sealed_floor_path.exists() {
        let mut raw_sealed = fs::read(&sealed_floor_path).expect("read sealed floor");
        raw_sealed[15] ^= 0xEE; // Corrupt sealed blob
        fs::write(&sealed_floor_path, &raw_sealed).expect("write corrupted sealed floor");

        let pol4 = IntuneMdmPolicy {
            version: 999,
            ..Default::default()
        };
        let b4 = SignedPolicyBundle::sign(pol4, &priv2, &pub2).expect("sign b4");

        let res_tampered = mgr.apply_signed_bundle(&b4);
        assert!(
            res_tampered.is_err(),
            "Tampered sealed floor must fail closed and block policy application"
        );
        assert_eq!(mgr.policy().enforcement_mode, "LOCKDOWN_STRICT");
    }
}
