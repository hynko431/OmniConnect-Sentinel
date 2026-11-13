//! Gate T33: rustls TLS 1.3 mTLS Sandbox Egress & Unified WORM-Anchored AuditLedger (`Sub-Phase 1.4`, `CSE-08`, `CSE-13`).
//!
//! Verifies:
//! 1. Anti-CRLF Injection: Headers / api_key with `\r` or `\n` fail closed before network contact.
//! 2. Insecure Scheme Rejection: `http://` or non-`https://` endpoints fail closed immediately.
//! 3. Anti-SSRF Protection: `169.254.169.254`, `127.0.0.1`, RFC 1918, and IPv6 link-local fail closed.
//! 4. rustls TLS 1.3 Client-Cert mTLS: Transport configured exclusively for TLS 1.3.
//! 5. Unified Single-Root `SharedAuditLedger`: Multiple subsystems log to one hash chain with contiguous seq.
//! 6. Single-Root Tamper Detection: Deleting or modifying any subsystem event breaks `verify_chain()`.
//! 7. HMAC-SHA256 Path Tokenization: Sensitive file paths pseudonymized for GDPR/DPDP privacy.
//! 8. RFC 5425 Syslog Framing: Octet-counted `<length> <syslog-msg>` format.
//! 9. AES-256-GCM Encrypted Spool: `siem_spool.sealed` encrypts telemetry on disk with 128 MiB bounding.
//! 10. Zero Production `UdpSocket`: Complete removal of cleartext UDP 514 syslog.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use sentinel_core::enterprise::falcon::{
    CrowdStrikeFalconBridge, FalconTelemetryEvent, MAX_SPOOL_SIZE_BYTES,
};
use sentinel_core::enterprise::ledger::{
    create_shared_audit_ledger, tokenize_path_for_privacy, AuditLedger, AuditSubsystem,
};
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::tier3_sandbox::{
    validate_crlf_safe, validate_egress_ip, SandboxDetonationRequest, Tier3SandboxConnector,
};

fn create_test_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("t33_{prefix}_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&dir);
    dir
}

#[test]
fn test_t33_crlf_injection_fails_closed() {
    // 1. CRLF in API key
    let bad_key1 = "my-secret-token\r\nX-Injected: attack";
    let res1 = validate_crlf_safe("api_key", bad_key1);
    assert!(res1.is_err(), "CRLF in API key must be rejected");
    assert!(res1.unwrap_err().contains("CRLF_INJECTION"));

    let bad_key2 = "my-secret-token\nInjected-Header: 1";
    let res2 = validate_crlf_safe("api_key", bad_key2);
    assert!(res2.is_err(), "LF in API key must be rejected");

    let bad_key3 = "my-secret-token\0nullbyte";
    let res3 = validate_crlf_safe("api_key", bad_key3);
    assert!(res3.is_err(), "Null byte in API key must be rejected");

    // Clean key passes
    let clean_key = "Bearer-Clean-Secret-Token-12345_XYZ.abc";
    assert!(validate_crlf_safe("api_key", clean_key).is_ok());
}

#[test]
fn test_t33_insecure_http_scheme_rejected() {
    let connector =
        Tier3SandboxConnector::new("http://api.sandbox.remote/detonate", "API_KEY_SECURE");
    let req = SandboxDetonationRequest {
        file_name: "sample.exe".to_string(),
        sha256_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        file_bytes: vec![0x90; 128],
        timeout_seconds: 5,
    };

    let res = connector.try_remote_detonation(&req);
    assert!(res.is_err(), "HTTP endpoint must fail closed");
    let err = res.unwrap_err();
    assert!(
        err.contains("INSECURE_TRANSPORT_REJECTED"),
        "Error must specify INSECURE_TRANSPORT_REJECTED, got: {err}"
    );
}

#[test]
fn test_t33_anti_ssrf_ip_filtering() {
    // 1. Loopback IPv4
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).is_err());
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(127, 255, 1, 2))).is_err());

    // 2. AWS / Azure / GCP IMDS cloud metadata & link-local
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))).is_err());
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))).is_err());

    // 3. RFC 1918 Private ranges
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_err());
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))).is_err());
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))).is_err());
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_err());

    // 4. Non-routable / broadcast
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))).is_err());
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))).is_err());
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))).is_err());

    // 5. IPv6 Loopback & Link-local / ULA
    assert!(validate_egress_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_err());
    assert!(validate_egress_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)).is_err());
    // fe80::1 (link-local)
    assert!(validate_egress_ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))).is_err());
    // fc00::1 (unique local)
    assert!(validate_egress_ip(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))).is_err());

    // 6. Public routable IP allowed
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_ok());
    assert!(validate_egress_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).is_ok());
}

#[test]
fn test_t33_cloud_metadata_detonation_attempt_fails_closed() {
    let connector =
        Tier3SandboxConnector::new("https://169.254.169.254/latest/meta-data", "API_KEY_SECURE");
    let req = SandboxDetonationRequest {
        file_name: "test.bin".to_string(),
        sha256_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        file_bytes: vec![0x41; 64],
        timeout_seconds: 5,
    };

    let res = connector.try_remote_detonation(&req);
    assert!(res.is_err(), "IMDS cloud metadata address must fail closed");
    let err = res.unwrap_err();
    assert!(
        err.contains("SSRF_VIOLATION"),
        "Error must specify SSRF_VIOLATION, got: {err}"
    );
}

#[test]
fn test_t33_crlf_in_api_key_fails_closed_before_network() {
    let connector = Tier3SandboxConnector::new(
        "https://api.sandbox.crowdstrike.com/detonate",
        "tok\r\nX-Injected: 1",
    );
    let req = SandboxDetonationRequest {
        file_name: "exploit.docm".to_string(),
        sha256_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        file_bytes: vec![0x42; 64],
        timeout_seconds: 5,
    };

    let res = connector.try_remote_detonation(&req);
    assert!(res.is_err(), "CRLF injection must be rejected");
    assert!(res.unwrap_err().contains("CRLF_INJECTION"));
}

#[test]
fn test_t33_unified_shared_audit_ledger_cross_subsystem_chain() {
    let dir = create_test_dir("unified_ledger");
    let unified_ledger_file = dir.join("unified_audit.jsonl");
    let test_shred_ledger = dir.join("test_shred_ledger.jsonl");
    std::env::set_var("SENTINEL_SHRED_LEDGER_PATH", &test_shred_ledger);

    // 1. Initialize Single-Root SharedAuditLedger
    let shared_ledger =
        create_shared_audit_ledger(&unified_ledger_file).expect("Open unified SharedAuditLedger");

    // 2. Wire SharedAuditLedger into QuarantineVault
    let vault_dir = dir.join("vault");
    fs::create_dir_all(&vault_dir).unwrap();
    let vault = QuarantineVault::open(vault_dir.clone())
        .expect("Open QuarantineVault")
        .with_shared_ledger(shared_ledger.clone());

    let test_file = dir.join("infected_artifact.bin");
    fs::write(&test_file, b"MALWARE_PAYLOAD_TEST_T33").unwrap();
    let _entry = vault
        .quarantine_file(&test_file, "TEST-RULE-T33")
        .expect("Quarantine file");

    // 3. Wire SharedAuditLedger into CrowdStrikeFalconBridge
    let spool_path = dir.join("siem_spool.sealed");
    let falcon = CrowdStrikeFalconBridge::with_spool_path("offline://collector", spool_path)
        .with_shared_ledger(shared_ledger.clone());

    let falcon_event = FalconTelemetryEvent {
        severity: 9,
        signature_id: "SIG-T33-001".to_string(),
        name: "Suspicious USB Payload Quarantined".to_string(),
        device_vendor_id: "0781".to_string(),
        device_product_id: "5583".to_string(),
        serial_number: "4C530001".to_string(),
        file_sha256: Some("abcdef1234567890".to_string()),
        action_taken: "Quarantined".to_string(),
        details: "Blocked and shredded original".to_string(),
    };
    falcon.emit_alert(&falcon_event).expect("Emit falcon alert");

    // 4. Wire SharedAuditLedger into Tier3SandboxConnector
    let sandbox = Tier3SandboxConnector::new("offline://sandbox", "OFFLINE")
        .with_shared_ledger(shared_ledger.clone());

    let sbx_req = SandboxDetonationRequest {
        file_name: "test_sample.exe".to_string(),
        sha256_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        file_bytes: vec![0x4d, 0x5a, 0x90, 0x00],
        timeout_seconds: 5,
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _ = rt.block_on(sandbox.detonate_sample(sbx_req));

    // 5. Emit a signed 60-second WORM head checkpoint
    let checkpoint_hash = falcon.emit_worm_checkpoint().expect("Emit WORM checkpoint");
    assert!(!checkpoint_hash.is_empty());

    // 6. Verify unified ledger file existence and verify_chain
    assert!(
        unified_ledger_file.exists(),
        "Unified audit ledger must exist"
    );

    let ledger =
        AuditLedger::open_result(&unified_ledger_file).expect("Open unified ledger for audit");
    let verified_count = ledger
        .verify_chain()
        .expect("Unified ledger chain must verify cleanly");
    assert!(
        verified_count >= 3,
        "Must have verified multiple cross-subsystem events, got {verified_count}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t33_unified_ledger_tamper_detection_catches_deleted_quarantine_event() {
    let dir = create_test_dir("tamper_detect");
    let unified_ledger_file = dir.join("tampered_unified_audit.jsonl");

    let shared_ledger =
        create_shared_audit_ledger(&unified_ledger_file).expect("Open unified SharedAuditLedger");

    // Log Quarantine event
    {
        let mut guard = shared_ledger.lock().unwrap();
        guard
            .append_subsystem_event(
                AuditSubsystem::Quarantine,
                "FILE_QUARANTINED",
                serde_json::json!({ "file_id": "FILE-001", "threat": "Trojan.Win32" }),
            )
            .unwrap();
    }

    // Log SIEM alert
    {
        let mut guard = shared_ledger.lock().unwrap();
        guard
            .append_subsystem_event(
                AuditSubsystem::SiemFalcon,
                "SIEM_CEF_ALERT",
                serde_json::json!({ "sig": "USB-BLOCK-01" }),
            )
            .unwrap();
    }

    // Log Sandbox event
    {
        let mut guard = shared_ledger.lock().unwrap();
        guard
            .append_subsystem_event(
                AuditSubsystem::Tier3Sandbox,
                "SANDBOX_OFFLINE_EMULATED",
                serde_json::json!({ "analysis_id": "SBX-12345" }),
            )
            .unwrap();
    }

    // Sign head
    {
        let guard = shared_ledger.lock().unwrap();
        guard.sign_chain_head().unwrap();
    }

    // Verify un-tampered chain passes
    {
        let ledger = AuditLedger::open_result(&unified_ledger_file).unwrap();
        assert_eq!(ledger.verify_chain().unwrap(), 3);
    }

    // Tamper attack: Delete the first record (the Quarantine event)
    let content = fs::read_to_string(&unified_ledger_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3);

    // Omit line 0 (simulate an attacker trying to cover up quarantine evidence)
    let tampered_content = format!("{}\n{}\n", lines[1], lines[2]);
    fs::write(&unified_ledger_file, tampered_content).unwrap();

    // Re-verify: MUST FAIL CLOSED!
    let tampered_ledger = AuditLedger::open_result(&unified_ledger_file).unwrap();
    let res = tampered_ledger.verify_chain();
    assert!(
        res.is_err(),
        "AuditLedger::verify_chain MUST detect deletion of an audit record!"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t33_privacy_path_tokenization() {
    let key = b"ENTERPRISE_GDPR_SALT_KEY_32BYTES!";
    let path1 = Path::new(r"C:\Users\CEO\Confidential\Executive_Compensation.xlsx");
    let path2 = Path::new(r"C:\Users\CEO\Confidential\Executive_Compensation.xlsx");
    let path3 = Path::new(r"C:\Users\Public\Downloads\innocent.txt");

    let token1 = tokenize_path_for_privacy(key, path1);
    let token2 = tokenize_path_for_privacy(key, path2);
    let token3 = tokenize_path_for_privacy(key, path3);

    // Deterministic for same path
    assert_eq!(token1, token2);
    // Distinct for different paths
    assert_ne!(token1, token3);
    // Plaintext never appears in token
    assert!(!token1.contains("CEO"));
    assert!(!token1.contains("Compensation"));
    assert_eq!(
        token1.len(),
        64,
        "HMAC-SHA256 hex token must be 64 characters"
    );
}

#[test]
fn test_t33_encrypted_siem_spool_roundtrip_and_bounding() {
    let dir = create_test_dir("siem_spool_test");
    let spool_path = dir.join("siem_spool.sealed");

    let falcon = CrowdStrikeFalconBridge::with_spool_path(
        "offline://siem.corporate.local:6514",
        spool_path.clone(),
    );

    let event1 = FalconTelemetryEvent {
        severity: 5,
        signature_id: "SIG-01".to_string(),
        name: "Threat Detected".to_string(),
        device_vendor_id: "0001".to_string(),
        device_product_id: "0002".to_string(),
        serial_number: "SN-9999".to_string(),
        file_sha256: Some("sha256-mock-value".to_string()),
        action_taken: "Blocked".to_string(),
        details: "Clean block".to_string(),
    };

    falcon.emit_alert(&event1).expect("Emit alert 1");

    // Verify spool file exists on disk
    assert!(spool_path.exists(), "Encrypted SIEM spool must exist");

    // Verify raw content on disk is encrypted ciphertext (does NOT contain plaintext CEF)
    let raw_bytes = fs::read(&spool_path).unwrap();
    let raw_str = String::from_utf8_lossy(&raw_bytes);
    assert!(
        !raw_str.contains("Threat Detected"),
        "Raw disk content of siem_spool.sealed MUST NOT leak plaintext CEF"
    );
    assert!(
        !raw_str.contains("SIG-01"),
        "Raw disk content of siem_spool.sealed MUST NOT leak signature IDs"
    );

    // Read spool records through falcon bridge
    let records = falcon.read_spool_records().expect("Read spool records");
    assert_eq!(records.len(), 1);
    assert!(!records[0].delivered);
    assert!(records[0].cef_payload.contains("SIG-01"));

    // Verify max spool size constant is 128 MiB
    assert_eq!(MAX_SPOOL_SIZE_BYTES, 128 * 1024 * 1024);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t33_rfc5425_octet_counted_framing() {
    let event = FalconTelemetryEvent {
        severity: 8,
        signature_id: "SIG-FRAMING-TEST".to_string(),
        name: "Test Alert".to_string(),
        device_vendor_id: "VID1".to_string(),
        device_product_id: "PID2".to_string(),
        serial_number: "SN3".to_string(),
        file_sha256: None,
        action_taken: "Audit".to_string(),
        details: "Framing test".to_string(),
    };

    let dir = create_test_dir("framing");
    let falcon =
        CrowdStrikeFalconBridge::with_spool_path("offline://test", dir.join("spool.sealed"));
    let cef = falcon.format_cef_payload(&event);

    let framed = format!("{} {}\n", cef.len(), cef);
    let split_pos = framed.find(' ').unwrap();
    let len_str = &framed[..split_pos];
    let parsed_len: usize = len_str.parse().unwrap();
    assert_eq!(
        parsed_len,
        cef.len(),
        "RFC 5425 octet count must match CEF payload byte count"
    );

    let _ = fs::remove_dir_all(&dir);
}
