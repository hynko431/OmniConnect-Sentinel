//! Cold-Eye Compliance Auditor - Sub-Phase 1.4 Adversarial Break-It Probe
//! Hostile testing of SSRF validation, single-root WORM audit ledger,
//! CRLF injection guards, and SIEM spool AEAD integrity.

#![allow(unused_imports, unused_variables)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use sentinel_core::enterprise::falcon::{CrowdStrikeFalconBridge, FalconTelemetryEvent};
use sentinel_core::enterprise::ledger::{
    create_shared_audit_ledger, tokenize_path_for_privacy, AuditLedger, AuditSubsystem,
};
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::secure_shredder::{SecureShredder, ShredMethod};
use sentinel_core::scanner::tier3_sandbox::{validate_crlf_safe, validate_egress_ip};

fn make_probe_dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("cold_eye_p14_{name}_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&p);
    p
}

#[test]
fn probe_1_ledger_total_truncation_bypass_vulnerability() {
    let dir = make_probe_dir("truncation_probe");
    let ledger_path = dir.join("test_audit.jsonl");

    let mut ledger = AuditLedger::open_result(&ledger_path).expect("Init ledger");
    ledger.append_event("BOOT_EVENT", "System started").unwrap();
    ledger.append_event("CONFIG_LOAD", "Policy loaded").unwrap();
    ledger
        .append_event("USER_LOGIN", "Admin authenticated")
        .unwrap();
    ledger.sign_chain_head().unwrap();

    // Verify un-tampered ledger validates 3 records
    assert_eq!(ledger.verify_chain().unwrap(), 3);

    // Hostile Action: Attacker truncates the ledger file to 0 bytes
    // (wiping all evidence of login, while the signed chain head file remains)
    fs::write(&ledger_path, b"").expect("Truncate ledger file to 0 bytes");

    let verify_res = ledger.verify_chain();
    println!("Total truncation verify_chain result: {:?}", verify_res);

    // SECURITY INVARIANT: If the signed head checkpoint exists with head_seq > 0,
    // an empty ledger file MUST fail closed (Err), NOT return Ok(0)!
    assert!(
        verify_res.is_err(),
        "CRITICAL VULNERABILITY: verify_chain() returned Ok(0) when the ledger was truncated to 0 bytes! Attacker wiped evidence undetected!"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn probe_2_multi_root_audit_ledger_fragmentation() {
    let dir = make_probe_dir("multi_root_probe");
    let unified_ledger_file = dir.join("unified_audit.jsonl");
    let default_shred_ledger = dir.join("shred_audit_ledger_v2.jsonl");

    // Point shred ledger to our test directory default
    std::env::set_var("SENTINEL_SHRED_LEDGER_PATH", &default_shred_ledger);

    let shared_ledger = create_shared_audit_ledger(&unified_ledger_file).unwrap();

    // 1. Open QuarantineVault with shared_ledger
    let vault_dir = dir.join("vault");
    fs::create_dir_all(&vault_dir).unwrap();
    let vault = QuarantineVault::open(vault_dir.clone())
        .expect("Open QuarantineVault")
        .with_shared_ledger(shared_ledger.clone());

    // 2. Quarantine an infected file (which executes source shredding via SecureShredder)
    let infected_file = dir.join("malware.exe");
    fs::write(&infected_file, b"MALWARE_STRING_FOR_TESTING").unwrap();
    let _entry = vault
        .quarantine_file(&infected_file, "TEST-VIRUS")
        .expect("Quarantine file");

    // 3. Inspect unified ledger: Does it contain the shredding event?
    let unified_content = fs::read_to_string(&unified_ledger_file).unwrap_or_default();
    println!("Unified Ledger Content:\n{}", unified_content);

    // 4. Inspect shred ledger: Did SecureShredder write to a separate multi-root ledger?
    let shred_content = fs::read_to_string(&default_shred_ledger).unwrap_or_default();
    println!("Shred Ledger Content:\n{}", shred_content);

    // Verify whether shredding was logged to the unified ledger or fragmented to a second ledger
    let shred_in_unified =
        unified_content.contains("SHRED_RECEIPT") || unified_content.contains("SecureShredder");
    let shred_in_separate = !shred_content.is_empty();

    println!("Shred receipt in unified ledger: {}", shred_in_unified);
    println!(
        "Shred receipt in separate shred ledger: {}",
        shred_in_separate
    );

    assert!(
        shred_in_unified,
        "MULTI-ROOT LEDGER DEFECT: Shredding receipt was NOT logged to the unified SharedAuditLedger!"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn probe_3_ssrf_ipv4_compatible_ipv6_bypass() {
    // RFC 4291 §2.5.5.1: IPv4-compatible IPv6 addresses: ::127.0.0.1, ::169.254.169.254, ::10.0.0.1
    let ipv4_compat_loopback = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x7f00, 0x0001)); // ::127.0.0.1
    let ipv4_compat_metadata = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe)); // ::169.254.169.254
    let ipv4_compat_private = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0a00, 0x0001)); // ::10.0.0.1

    let res_loopback = validate_egress_ip(ipv4_compat_loopback);
    let res_metadata = validate_egress_ip(ipv4_compat_metadata);
    let res_private = validate_egress_ip(ipv4_compat_private);

    println!("validate_egress_ip(::127.0.0.1) result: {:?}", res_loopback);
    println!(
        "validate_egress_ip(::169.254.169.254) result: {:?}",
        res_metadata
    );
    println!("validate_egress_ip(::10.0.0.1) result: {:?}", res_private);

    assert!(
        res_loopback.is_err(),
        "SSRF BYPASS: IPv4-compatible IPv6 loopback (::127.0.0.1) was permitted by validate_egress_ip!"
    );
    assert!(
        res_metadata.is_err(),
        "SSRF BYPASS: IPv4-compatible IPv6 IMDS metadata (::169.254.169.254) was permitted by validate_egress_ip!"
    );
    assert!(
        res_private.is_err(),
        "SSRF BYPASS: IPv4-compatible IPv6 private IP (::10.0.0.1) was permitted by validate_egress_ip!"
    );
}

#[test]
fn probe_4_siem_spool_aead_tamper_detection() {
    let dir = make_probe_dir("spool_probe");
    let spool_path = dir.join("siem_spool.sealed");

    let falcon = CrowdStrikeFalconBridge::with_spool_path(
        "offline://siem.corporate.local",
        spool_path.clone(),
    );
    let event = FalconTelemetryEvent {
        severity: 7,
        signature_id: "SIG-PROBE-01".to_string(),
        name: "Malicious Detonation".to_string(),
        device_vendor_id: "VID".to_string(),
        device_product_id: "PID".to_string(),
        serial_number: "SN".to_string(),
        file_sha256: Some("abcdef1234567890".to_string()),
        action_taken: "Quarantine".to_string(),
        details: "Probe details".to_string(),
    };
    falcon.emit_alert(&event).unwrap();

    // Verify un-tampered read succeeds
    let records = falcon.read_spool_records().unwrap();
    assert_eq!(records.len(), 1);

    // Hostile Action: Corrupt a byte in the encrypted ciphertext
    let mut raw_bytes = fs::read(&spool_path).unwrap();
    assert!(raw_bytes.len() > 16);
    let last_idx = raw_bytes.len() - 1;
    raw_bytes[last_idx] ^= 0xFF; // Bit-flip AEAD auth tag
    fs::write(&spool_path, &raw_bytes).unwrap();

    // Hostile Read: Must fail closed with authentication failure
    let tampered_read = falcon.read_spool_records();
    assert!(
        tampered_read.is_err(),
        "AEAD INTEGRITY VIOLATION: Corrupted SIEM spool was read without triggering authentication error!"
    );
    assert!(
        tampered_read
            .unwrap_err()
            .contains("AEAD authentication failed"),
        "Error must indicate AEAD failure"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn probe_5_crlf_injection_full_ascii_control_spectrum() {
    // Ensure all control characters 0x00..=0x1F and 0x7F are rejected
    for byte in 0u8..=0x1Fu8 {
        let input = format!("token{}suffix", byte as char);
        let res = validate_crlf_safe("test_header", &input);
        assert!(
            res.is_err(),
            "Control character 0x{:02x} was incorrectly accepted by validate_crlf_safe",
            byte
        );
    }

    let del_input = format!("token{}suffix", 0x7Fu8 as char);
    assert!(
        validate_crlf_safe("test_header", &del_input).is_err(),
        "DEL 0x7F was incorrectly accepted"
    );

    // Printable ASCII 0x20..=0x7E should be accepted
    let valid_input = "Bearer-Clean-Token-12345_!@#$%^&*()_+~`";
    assert!(validate_crlf_safe("test_header", valid_input).is_ok());
}
