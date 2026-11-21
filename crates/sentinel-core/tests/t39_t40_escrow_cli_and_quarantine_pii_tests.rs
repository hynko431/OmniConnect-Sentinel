//! Behavioral & Adversarial Verification Suite for Master Security Hardening Plan v3
//! Sub-Phase 0.2 (`CSE-16`, `F-16`): `T39` and `T40`.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use sentinel_core::enterprise::ledger::AuditLedger;
use sentinel_core::scanner::quarantine::{
    QuarantineEnvelopeHeader, QuarantineVault, ENVELOPE_MAGIC_V2_FULL, ENVELOPE_MAGIC_V3_FULL,
    ENVELOPE_VERSION, ENVELOPE_VERSION_V3,
};
use sentinel_sys::{generate_hybrid_soc_keypair_with_bits, generate_soc_rsa_keypair};
use tempfile::tempdir;

#[test]
fn t39_core_escrow_recovery_with_shared_ledger_sync_and_tamper_rejection() {
    let tmp = tempdir().expect("tempdir");

    // 1. Classical RSA-3072 recovery logs directly to unified SharedAuditLedger
    let rsa_vault_dir = tmp.path().join("rsa_vault");
    let ledger_path = tmp.path().join("unified_recovery_ledger.jsonl");
    let shared_ledger = Arc::new(Mutex::new(
        AuditLedger::open_result(&ledger_path).expect("open ledger"),
    ));
    let (rsa_pub, rsa_priv) = generate_soc_rsa_keypair().expect("rsa keypair");
    let src = tmp.path().join("erp_export.bin");
    fs::write(&src, b"ERP_SENSITIVE_RECOVERY_BYTES_T39").expect("write src");

    let vault = QuarantineVault::open_with_soc_public_key(rsa_vault_dir.clone(), &rsa_pub)
        .expect("open vault")
        .with_shared_ledger(shared_ledger.clone());
    let entry = vault
        .quarantine_file(&src, "T39.Core.RSA")
        .expect("quarantine");
    drop(vault);

    // Destroy `vault_kek.sealed` and recover with shared ledger attached
    fs::remove_file(rsa_vault_dir.join("vault_kek.sealed")).expect("remove sealed KEK");
    let recovered = QuarantineVault::recover_from_soc_escrow_with_shared_ledger(
        rsa_vault_dir.clone(),
        &rsa_priv,
        Some(shared_ledger.clone()),
    )
    .expect("recover rsa escrow");

    let restored = tmp.path().join("erp_restored.bin");
    recovered
        .restore_file(&entry.entry_id, &restored)
        .expect("restore after rsa recovery");
    assert_eq!(
        fs::read(&restored).expect("read restored"),
        b"ERP_SENSITIVE_RECOVERY_BYTES_T39"
    );

    // 2. Hybrid PQC OCESCROW3 recovery logs directly to unified SharedAuditLedger
    let pqc_vault_dir = tmp.path().join("pqc_vault");
    let (pqc_pub, pqc_priv) = generate_hybrid_soc_keypair_with_bits(3072).expect("hybrid keypair");
    let src2 = tmp.path().join("plc_ladder.bin");
    fs::write(&src2, b"PLC_LADDER_LOGIC_T39_PQC").expect("write src2");

    let pqc_vault = QuarantineVault::open(pqc_vault_dir.clone())
        .expect("open pqc vault")
        .with_shared_ledger(shared_ledger.clone());
    pqc_vault
        .provision_hybrid_soc_escrow_v3(&pqc_pub)
        .expect("provision hybrid escrow");
    let entry2 = pqc_vault
        .quarantine_file(&src2, "T39.Core.PQC")
        .expect("quarantine pqc");
    drop(pqc_vault);

    fs::remove_file(pqc_vault_dir.join("vault_kek.sealed")).expect("remove pqc sealed KEK");
    let recovered_pqc = QuarantineVault::recover_from_hybrid_soc_escrow_v3_with_shared_ledger(
        pqc_vault_dir.clone(),
        &pqc_priv,
        Some(shared_ledger.clone()),
    )
    .expect("recover pqc escrow");

    let restored2 = tmp.path().join("plc_restored.bin");
    recovered_pqc
        .restore_file(&entry2.entry_id, &restored2)
        .expect("restore after pqc recovery");
    assert_eq!(
        fs::read(&restored2).expect("read restored2"),
        b"PLC_LADDER_LOGIC_T39_PQC"
    );

    // Verify unified ledger contains both recovery events and verifies intact
    let log_text = fs::read_to_string(&ledger_path).expect("read unified ledger");
    assert!(log_text.contains("VAULT_ESCROW_RECOVERED"));
    assert!(log_text.contains("VAULT_HYBRID_PQC_ESCROW_V3_RECOVERED"));
    let final_ledger = AuditLedger::open_result(&ledger_path).expect("reopen ledger");
    assert!(final_ledger.verify_chain().expect("verify chain") >= 6);
}

#[test]
fn t40_quarantine_v3_header_minimizes_pii_and_preserves_v2_compatibility() {
    let tmp = tempdir().expect("tempdir");
    let vault_dir = tmp.path().join("vault_pii");
    let sensitive_dir = tmp.path().join("alice_smith_HR_Confidential");
    fs::create_dir_all(&sensitive_dir).expect("create sensitive dir");

    let pii_file = sensitive_dir.join("ExecutivePayroll2026_SSN_999.xlsx");
    let payload = b"CONFIDENTIAL_PAYROLL_PAYLOAD_T40_VERIFY";
    fs::write(&pii_file, payload).expect("write pii file");

    let vault = QuarantineVault::open(vault_dir.clone()).expect("open vault");
    let entry = vault
        .quarantine_file(&pii_file, "T40.PII.Test")
        .expect("quarantine pii file");

    // In-memory caller receives the original path
    assert!(entry
        .original_path
        .contains("ExecutivePayroll2026_SSN_999.xlsx"));
    assert_eq!(entry.encryption_algorithm, "AES-256-GCM-HKDF-SHA256-V3");

    // 1. Inspect raw `.quar` bytes on disk: ZERO plaintext PII substrings permitted (`CSE-16`, `F-16`)
    let raw_quar = fs::read(Path::new(&entry.vault_file_path)).expect("read raw .quar");
    let raw_lossy = String::from_utf8_lossy(&raw_quar);
    for forbidden in [
        "alice_smith",
        "HR_Confidential",
        "ExecutivePayroll2026",
        "SSN_999",
    ] {
        assert!(
            !raw_lossy.contains(forbidden),
            "Raw .quar header on disk leaked plaintext PII substring '{forbidden}'"
        );
    }

    // 2. Parsed `SNTLQV03` header has version 3, tokenized `original_path`, and encrypted metadata fields
    let (header, _header_json, _ct) =
        QuarantineVault::parse_envelope(&raw_quar).expect("parse SNTLQV03 envelope");
    assert_eq!(&header.magic, ENVELOPE_MAGIC_V3_FULL);
    assert_eq!(header.version, ENVELOPE_VERSION_V3);
    assert!(
        header.original_path.len() == 64
            && header.original_path.chars().all(|c| c.is_ascii_hexdigit()),
        "On-disk header.original_path must be a 64-hex HMAC-SHA256 token, got '{}'",
        header.original_path
    );
    assert!(header.encrypted_original_path_hex.is_some());
    assert!(header.meta_nonce.is_some());

    // 3. Authenticated `vault.list()` decrypts the real path cleanly and `restore_file()` succeeds
    let listed = vault.list().expect("list vault entries");
    assert_eq!(listed.len(), 1);
    assert!(
        listed[0]
            .original_path
            .contains("ExecutivePayroll2026_SSN_999.xlsx"),
        "Authenticated vault.list() must decrypt SNTLQV03 original_path, got '{}'",
        listed[0].original_path
    );
    assert_eq!(listed[0].encryption_algorithm, "AES-256-GCM-HKDF-SHA256-V3");

    let restored = tmp.path().join("restored_payroll.xlsx");
    vault
        .restore_file(&entry.entry_id, &restored)
        .expect("restore SNTLQV03 file");
    assert_eq!(fs::read(&restored).expect("read restored"), payload);

    // 4. Tampering with `encrypted_original_path_hex` in the header fails AEAD AAD verification
    let mut tampered = raw_quar.clone();
    let needle = header
        .encrypted_original_path_hex
        .as_deref()
        .expect("enc path hex");
    if let Some(pos) = tampered
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())
    {
        tampered[pos] = if tampered[pos] == b'0' { b'1' } else { b'0' };
    }
    fs::write(&entry.vault_file_path, &tampered).expect("write tampered .quar");
    assert!(
        vault
            .restore_file(&entry.entry_id, &tmp.path().join("should_fail.xlsx"))
            .is_err(),
        "Tampered SNTLQV03 encrypted_original_path_hex must fail AAD authentication"
    );

    // 5. Legacy `SNTLQV02` (`version: 2`) backward-compatibility check + mismatched magic/version rejection
    let v2_header = QuarantineEnvelopeHeader {
        magic: *ENVELOPE_MAGIC_V2_FULL,
        version: ENVELOPE_VERSION,
        kek_id: "0123456789abcdef".to_string(),
        file_salt: [0x11u8; 32],
        nonce: [0x22u8; 12],
        original_path: "legacy_v2_file.bin".to_string(),
        original_size: 4,
        sha256_plaintext: "a".repeat(64),
        threat_name: "Legacy.V2.Test".to_string(),
        threat_score: 90,
        quarantined_at_unix: 1_700_000_000,
        entry_id: "legacy-v2-id".to_string(),
        quarantined_at_utc: "2026-01-01T00:00:00Z".to_string(),
        recovery_status: "RECOVERABLE".to_string(),
        encrypted_original_path_hex: None,
        meta_nonce: None,
    };
    let v2_json = serde_json::to_vec(&v2_header).expect("serialize v2 header");
    let mut v2_wire = Vec::new();
    v2_wire.extend_from_slice(&(v2_json.len() as u32).to_le_bytes());
    v2_wire.extend_from_slice(&v2_json);
    v2_wire.extend_from_slice(&[0u8; 20]);
    let (parsed_v2, _, _) =
        QuarantineVault::parse_envelope(&v2_wire).expect("legacy SNTLQV02 must still parse");
    assert_eq!(parsed_v2.version, ENVELOPE_VERSION);

    // Mismatched magic (`SNTLQV03`) + version (`2`) must fail closed
    let mut bad_header = v2_header;
    bad_header.magic = *ENVELOPE_MAGIC_V3_FULL;
    let bad_json = serde_json::to_vec(&bad_header).expect("serialize bad header");
    let mut bad_wire = Vec::new();
    bad_wire.extend_from_slice(&(bad_json.len() as u32).to_le_bytes());
    bad_wire.extend_from_slice(&bad_json);
    bad_wire.extend_from_slice(&[0u8; 20]);
    assert!(
        QuarantineVault::parse_envelope(&bad_wire).is_err(),
        "Mismatched magic/version envelope must be rejected"
    );
}
