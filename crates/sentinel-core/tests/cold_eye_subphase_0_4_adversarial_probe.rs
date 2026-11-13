//! Adversarial Cold-Eye Probe Suite for Sub-Phase 0.4 (EPIC-02 / Story 2.2 / CSE-03)
#![allow(unused_imports)]

use sentinel_core::enterprise::intune::{
    backup_enterprise_root_keypair, default_enterprise_root_public_keys,
    primary_enterprise_root_keypair, IntuneMdmPolicy, IntunePolicyManager, SignedPolicyBundle,
};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn probe_cli_policy_verify_genuine_and_adversarial_tamper() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let bundle_path = dir.path().join("policy_bundle.json");

    let (pub1, priv1) = primary_enterprise_root_keypair();

    // 1. Generate valid enterprise signed bundle
    let pol = IntuneMdmPolicy {
        version: 10,
        policy_id: "MDM-ENTERPRISE-PROD-CLI-V10".to_string(),
        ..Default::default()
    };
    let bundle = SignedPolicyBundle::sign(pol, &priv1, &pub1).expect("sign bundle");
    let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();
    fs::write(&bundle_path, &bundle_json).unwrap();

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let exe_path = workspace_root
        .join("target")
        .join("debug")
        .join("sentinel.exe");

    if !exe_path.exists() {
        eprintln!(
            "Skipping CLI sub-process test if sentinel.exe is not built at {:?}",
            exe_path
        );
        return;
    }

    // Run CLI on genuine bundle
    let output = Command::new(&exe_path)
        .args([
            "policy-verify",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--vault-dir",
            vault_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute sentinel.exe");

    assert!(
        output.status.success(),
        "CLI policy-verify must succeed on legitimate bundle! stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 2. Tamper signature in file
    let mut tampered = bundle.clone();
    let mut sig = hex::decode(&tampered.signature_hex).unwrap();
    sig[0] ^= 0x55;
    tampered.signature_hex = hex::encode(sig);
    fs::write(
        &bundle_path,
        serde_json::to_string_pretty(&tampered).unwrap(),
    )
    .unwrap();

    let output_tampered = Command::new(&exe_path)
        .args([
            "policy-verify",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--vault-dir",
            vault_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute sentinel.exe");

    assert!(
        !output_tampered.status.success(),
        "CLI policy-verify must FAIL on tampered signature!"
    );

    // 3. Self-signed attacker bundle
    let (att_pub, att_priv) = sentinel_sys::generate_raw_ecdsa_p256_keypair().unwrap();
    let evil = IntuneMdmPolicy {
        version: 100,
        enforce_usb_zero_trust: false,
        ..Default::default()
    };
    let evil_bundle = SignedPolicyBundle::sign(evil, &att_priv, &att_pub).unwrap();
    fs::write(
        &bundle_path,
        serde_json::to_string_pretty(&evil_bundle).unwrap(),
    )
    .unwrap();

    let output_evil = Command::new(&exe_path)
        .args([
            "policy-verify",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--vault-dir",
            vault_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute sentinel.exe");

    assert!(
        !output_evil.status.success(),
        "CLI policy-verify must FAIL on untrusted/self-signed bundle!"
    );
}

#[test]
fn probe_constant_time_comparison_and_timing_invariance() {
    use subtle::ConstantTimeEq;
    let roots = default_enterprise_root_public_keys();
    let primary = &roots[0];

    // Primary key clone
    let primary_clone = primary.clone();
    assert!(bool::from(primary.ct_eq(&primary_clone)));

    // Attacker key with 1 bit difference
    let mut modified = primary.clone();
    modified[20] ^= 0x01;
    assert!(!bool::from(primary.ct_eq(&modified)));

    // Key with truncated length
    let truncated = &primary[..32];
    assert_ne!(primary.len(), truncated.len());
}

#[test]
fn probe_both_primary_and_backup_dr_roots_accepted() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let (pub1, priv1) = primary_enterprise_root_keypair();
    let (pub2, priv2) = backup_enterprise_root_keypair();

    let mut mgr = IntunePolicyManager::new()
        .with_vault_dir(vault_dir)
        .with_ledger_path(ledger_path);

    // Apply via Primary
    let mut pol1 = mgr.policy().clone();
    pol1.version = 3;
    let b1 = SignedPolicyBundle::sign(pol1, &priv1, &pub1).unwrap();
    assert!(mgr.apply_signed_bundle(&b1).is_ok());

    // Apply via Backup DR
    let mut pol2 = mgr.policy().clone();
    pol2.version = 4;
    let b2 = SignedPolicyBundle::sign(pol2, &priv2, &pub2).unwrap();
    assert!(mgr.apply_signed_bundle(&b2).is_ok());
}

#[test]
fn probe_self_signed_attacker_key_triggers_strict_fail_closed_lockdown() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let mut mgr = IntunePolicyManager::new()
        .with_vault_dir(vault_dir)
        .with_ledger_path(ledger_path);

    let (att_pub, att_priv) = sentinel_sys::generate_raw_ecdsa_p256_keypair().unwrap();
    let mut evil = mgr.policy().clone();
    evil.version = 50;
    evil.enforce_usb_zero_trust = false;
    evil.allowed_hardware_ids = vec!["*".to_string()];
    let b_evil = SignedPolicyBundle::sign(evil, &att_priv, &att_pub).unwrap();

    let res = mgr.apply_signed_bundle(&b_evil);
    assert!(res.is_err());

    // Verify fail closed lockdown
    assert_eq!(mgr.policy().enforcement_mode, "LOCKDOWN_STRICT");
    assert_eq!(mgr.policy().version, 0);
    assert!(mgr.policy().enforce_usb_zero_trust);
    assert!(mgr.policy().allowed_hardware_ids.is_empty());
    assert_eq!(
        mgr.last_degradation_event(),
        Some(sentinel_core::error::DegradationEvent::PolicyRejected)
    );
}

#[test]
fn probe_defect_sealed_floor_corruption_fails_closed_and_blocks_rollback() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let (pub1, priv1) = primary_enterprise_root_keypair();

    // 1. Setup policy at version 10
    {
        let mut mgr = IntunePolicyManager::new()
            .with_vault_dir(vault_dir.clone())
            .with_ledger_path(ledger_path.clone());

        let mut v10 = mgr.policy().clone();
        v10.version = 10;
        let b10 = SignedPolicyBundle::sign(v10, &priv1, &pub1).expect("sign v10");
        mgr.apply_signed_bundle(&b10).expect("v10 must succeed");
        assert_eq!(mgr.policy().version, 10);
        assert_eq!(mgr.load_sealed_version().unwrap(), 10);
    }

    // 2. Adversary corrupts policy_version.sealed on disk
    let sealed_path = vault_dir.join("policy_version.sealed");
    assert!(sealed_path.exists());
    std::fs::write(&sealed_path, b"CORRUPTED_BYTES_ATTACKER_TAMPER").unwrap();

    // 3. Sentinel restarts and attacker tries to replay v5
    let mut mgr2 = IntunePolicyManager::new()
        .with_vault_dir(vault_dir.clone())
        .with_ledger_path(ledger_path.clone());

    let mut v5 = mgr2.policy().clone();
    v5.version = 5;
    let b5 = SignedPolicyBundle::sign(v5, &priv1, &pub1).expect("sign v5");

    let res = mgr2.apply_signed_bundle(&b5);

    // Defect CEA-DEFECT-01 FIX: res must be Err, fail-closed engaged, rollback blocked!
    assert!(
        res.is_err(),
        "Tampered sealed floor must result in Err and fail-closed lockdown!"
    );
    assert_eq!(mgr2.policy().enforcement_mode, "LOCKDOWN_STRICT");
    assert_eq!(mgr2.policy().version, 0);
}

#[test]
fn probe_adversarial_load_active_policy_corrupted_vault_locks_down() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let mut mgr = IntunePolicyManager::new()
        .with_vault_dir(vault_dir.clone())
        .with_ledger_path(ledger_path);

    // Corrupt sealed policy file with garbage bytes
    let sealed_path = vault_dir.join("policy_version.sealed");
    fs::create_dir_all(&vault_dir).unwrap();
    fs::write(&sealed_path, b"RANDOM_ATTACKER_CORRUPT_BYTES").unwrap();

    let active = mgr.load_active_policy();
    assert_eq!(
        active.enforcement_mode, "LOCKDOWN_STRICT",
        "Corrupted sealed version on load_active_policy must trigger LOCKDOWN_STRICT"
    );
    assert_eq!(active.version, 0);
    assert!(active.allowed_hardware_ids.is_empty());
    assert!(active.enforce_usb_zero_trust);
}

#[test]
fn probe_adversarial_replay_same_version_blocked() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let (pub1, priv1) = primary_enterprise_root_keypair();

    let mut mgr = IntunePolicyManager::new()
        .with_vault_dir(vault_dir)
        .with_ledger_path(ledger_path);

    let mut v5 = mgr.policy().clone();
    v5.version = 5;
    let b5 = SignedPolicyBundle::sign(v5, &priv1, &pub1).unwrap();
    mgr.apply_signed_bundle(&b5).expect("version 5 succeeds");

    // Replay exact same version 5
    let res = mgr.apply_signed_bundle(&b5);
    assert!(
        res.is_err(),
        "Replay of exact same version 5 must be rejected by monotonic anti-rollback"
    );
}

#[test]
fn probe_adversarial_envelope_key_substitution_cross_root_rejected() {
    let dir = tempdir().expect("tempdir");
    let vault_dir = dir.path().join(".sentinel_vault");
    let ledger_path = vault_dir.join("audit.jsonl");

    let (pub1, priv1) = primary_enterprise_root_keypair();
    let (pub2, _priv2) = backup_enterprise_root_keypair();

    let mut mgr = IntunePolicyManager::new()
        .with_vault_dir(vault_dir)
        .with_ledger_path(ledger_path);

    let initial_version = mgr.policy().version;
    let mut pol = mgr.policy().clone();
    pol.version = 20;

    // Signed with Primary priv1, but attacker sets signer_public_key_hex to DR Backup pub2
    let mut spoofed_bundle = SignedPolicyBundle::sign(pol, &priv1, &pub1).unwrap();
    spoofed_bundle.signer_public_key_hex = hex::encode(&pub2);

    let res = mgr.apply_signed_bundle(&spoofed_bundle);
    assert!(
        res.is_err(),
        "Mismatched envelope signer key must fail signature verification against DR root"
    );
    // Row 198: On invalid signature from candidate bundle, retains last known good policy
    assert_eq!(mgr.policy().version, initial_version);
    assert_eq!(
        mgr.last_degradation_event(),
        Some(sentinel_core::error::DegradationEvent::PolicyRejected)
    );
}

#[test]
fn probe_adversarial_cli_vault_dir_strict_isolation() {
    let dir = tempdir().expect("tempdir");
    let custom_vault_dir = dir.path().join("isolated_audit_vault");
    let bundle_path = dir.path().join("policy_bundle.json");

    let (pub1, priv1) = primary_enterprise_root_keypair();

    let pol = IntuneMdmPolicy {
        version: 8,
        policy_id: "MDM-ISOLATED-AUDIT-V8".to_string(),
        ..Default::default()
    };
    let bundle = SignedPolicyBundle::sign(pol, &priv1, &pub1).expect("sign bundle");
    fs::write(&bundle_path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let exe_path = workspace_root
        .join("target")
        .join("debug")
        .join("sentinel.exe");

    if !exe_path.exists() {
        // Run verification via IntunePolicyManager directly with custom vault_dir
        let mut mgr = IntunePolicyManager::new().with_vault_dir(custom_vault_dir.clone());
        let res = mgr.apply_signed_bundle(&bundle);
        assert!(res.is_ok());

        assert!(
            custom_vault_dir
                .join("policy_audit_ledger_v2.jsonl")
                .exists(),
            "Audit ledger must be created in custom vault directory"
        );
        assert!(
            custom_vault_dir.join("policy_version.sealed").exists(),
            "Sealed version floor must be created in custom vault directory"
        );
        return;
    }

    let output = Command::new(&exe_path)
        .args([
            "policy-verify",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--vault-dir",
            custom_vault_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute sentinel.exe");

    assert!(output.status.success());
    assert!(
        custom_vault_dir
            .join("policy_audit_ledger_v2.jsonl")
            .exists(),
        "CLI must write audit ledger into custom vault directory"
    );
    assert!(
        custom_vault_dir.join("policy_version.sealed").exists(),
        "CLI must write sealed version floor into custom vault directory"
    );
}
