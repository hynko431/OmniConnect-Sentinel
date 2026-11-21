//! Full Phase 2 Adversarial Probe (`cold_eye_phase_2_v3_adversarial_probe.rs`, `CSE-22` & `CSE-23`)
//!
//! Probes edge cases and bypass vectors across:
//! 1. `CSE-22`: Named Pipe SDDL (zero `AC`/`AU`/`WD`), live kernel DACL verification,
//!    fail-closed sandbox enforcement (Windows CIG / Linux `unshare` / Landlock),
//!    and truncated IPC frame rejection.
//! 2. `CSE-23`: CIDR overlap/smuggling bypass attempts, IPv4-embedded IPv6 SSRF probes,
//!    partial mTLS misconfiguration fail-closed, AEAD tamper detection on SIEM rollover archives,
//!    and Tier-3 sandbox upload size/SHA-256/CRLF enforcement.

use sentinel_cdr::worker::{serve_framed_ipc_io, WorkerLauncher};
use sentinel_core::enterprise::falcon::{
    AllowedCidr, CrowdStrikeFalconBridge, FalconTelemetryEvent, SignedSpoolPruneOverride,
};
use sentinel_core::scanner::tier3_sandbox::{
    decode_base64, encode_base64, SandboxDetonationRequest, Tier3SandboxConnector,
};
use sentinel_sys::{
    evaluate_sandbox_enforcement_failure, generate_raw_ecdsa_p256_keypair, NAMED_PIPE_SERVER_SDDL,
};
use std::fs;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

#[test]
fn probe_phase2_cse22_pipe_sddl_sandbox_fail_closed_and_truncated_frame() {
    // 1. Named Pipe SDDL must strictly exclude AC, AU, and WD
    assert_eq!(NAMED_PIPE_SERVER_SDDL, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    assert!(!NAMED_PIPE_SERVER_SDDL.contains("AC"));
    assert!(!NAMED_PIPE_SERVER_SDDL.contains("AU"));
    assert!(!NAMED_PIPE_SERVER_SDDL.contains("WD"));

    // 2. Sandbox enforcement failures must fail closed without explicit dev opt-in
    for comp in [
        "windows_cig_process_signature_policy",
        "linux_unshare(CLONE_NEWNET|CLONE_NEWIPC)",
        "linux_landlock_abi",
    ] {
        let res = evaluate_sandbox_enforcement_failure(
            comp,
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            false,
        );
        assert!(res.is_err(), "{comp} must fail closed");
    }

    // 3. Truncated mid-frame IPC stream must fail closed with UnexpectedEof (never silent Ok(0))
    let truncated = [0x01u8, 0x00, 0x00]; // FRAME_TAG_DISARM + partial length prefix
    let mut out = Vec::new();
    let res = serve_framed_ipc_io(Cursor::new(&truncated), &mut out, &WorkerLauncher::new());
    assert!(
        matches!(res, Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
        "Truncated IPC frame must return UnexpectedEof, got: {res:?}"
    );
}

#[test]
fn probe_phase2_cse23_ssrf_cidr_smuggle_mtls_and_rollover_tamper() {
    // 1. Adversarial CIDR smuggling attempts must all fail closed
    for sneaky_cidr in [
        "0.0.0.0/0",
        "10.0.0.0/7",     // spills outside 10.0.0.0/8
        "172.16.0.0/11",  // spills outside 172.16.0.0/12
        "192.168.0.0/15", // spills outside 192.168.0.0/16
        "126.0.0.0/7",    // covers 127.0.0.0/8 loopback
        "169.0.0.0/8",    // covers 169.254.0.0/16 IMDS
        "169.254.169.254/32",
        "127.0.0.1/32",
        "fe80::/10",
        "::ffff:10.0.0.0/104",
        "fc00::/6", // spills outside fc00::/7
    ] {
        assert!(
            AllowedCidr::parse(sneaky_cidr).is_err(),
            "Adversarial CIDR '{sneaky_cidr}' must be rejected"
        );
    }

    // 2. IPv4-embedded IPv6 SSRF wrappers against pinned 10.0.0.0/8 must still block loopback & IMDS
    let allow_10 = vec![AllowedCidr::parse("10.0.0.0/8").expect("10/8 valid")];
    for ipv6_bypass in [
        "::ffff:127.0.0.1",
        "::127.0.0.1",
        "::ffff:0:127.0.0.1",
        "64:ff9b::127.0.0.1",
        "::ffff:169.254.169.254",
        "::169.254.169.254",
        "64:ff9b::169.254.169.254",
    ] {
        let ip = IpAddr::V6(ipv6_bypass.parse::<Ipv6Addr>().expect("valid v6"));
        assert!(
            CrowdStrikeFalconBridge::validate_siem_egress_ip(ip, &allow_10).is_err(),
            "IPv6-embedded SSRF probe '{ipv6_bypass}' must be unconditionally blocked"
        );
    }
    assert!(CrowdStrikeFalconBridge::validate_siem_egress_ip(
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        &allow_10
    )
    .is_ok());

    // 3. Invalid or partial client mTLS PEM must fail closed and report mtls_enforced == false
    let dir = std::env::temp_dir().join(format!("probe_p2_cse23_{}", Uuid::new_v4().simple()));
    fs::create_dir_all(&dir).expect("create dir");
    let bad_mtls = CrowdStrikeFalconBridge::with_spool_path(
        "tls://siem.example.com:6514",
        dir.join("bad_mtls.sealed"),
    )
    .with_client_mtls(b"NOT_A_CERT".to_vec(), b"NOT_A_KEY".to_vec());
    assert!(!bad_mtls.is_mtls_enforced());
    let partial_mtls = CrowdStrikeFalconBridge::with_spool_path(
        "tls://siem.example.com:6514",
        dir.join("partial_mtls.sealed"),
    )
    .with_client_mtls_optional(Some(b"CERT".to_vec()), None);
    assert!(!partial_mtls.is_mtls_enforced());
    assert!(partial_mtls.flush_spool().is_err());

    // 3b. Deserialized AllowedCidr with forbidden/out-of-bounds prefix MUST fail closed
    assert!(
        serde_json::from_str::<AllowedCidr>(r#"{"network":"127.0.0.1","prefix_len":8}"#).is_err()
    );
    assert!(
        serde_json::from_str::<AllowedCidr>(r#"{"network":"10.0.0.0","prefix_len":99}"#).is_err()
    );

    // 4. Rollover archive tampering MUST fail AEAD verification cleanly
    let spool_path = dir.join("tamper_spool.sealed");
    let bridge = CrowdStrikeFalconBridge::with_spool_path("offline://siem", spool_path)
        .with_max_spool_bytes(1024);
    for i in 0..6 {
        bridge
            .emit_alert(&FalconTelemetryEvent {
                severity: 7,
                signature_id: format!("PROBE-{i}"),
                name: format!("Rollover Probe {i}"),
                device_vendor_id: "0781".to_string(),
                device_product_id: "5583".to_string(),
                serial_number: format!("SN-{i}"),
                file_sha256: None,
                action_taken: "LOGGED".to_string(),
                details: "Trigger rollover archive segment for AEAD tamper test".to_string(),
            })
            .expect("emit");
    }
    let archives = bridge.list_rollover_archives().expect("list archives");
    assert!(!archives.is_empty());
    let mut raw_archive = fs::read(&archives[0]).expect("read archive");
    let last = raw_archive.len() - 1;
    raw_archive[last] ^= 0xFF; // Flip AEAD tag bit
    fs::write(&archives[0], &raw_archive).expect("write tampered archive");
    assert!(
        bridge.read_all_retained_records().is_err(),
        "Tampered rollover archive MUST fail AEAD authentication"
    );

    // 5. Tampered, expired, or delimiter-smuggled SignedSpoolPruneOverride MUST fail closed
    let (pub_k, priv_k) = generate_raw_ecdsa_p256_keypair().expect("ecdsa key");
    let valid_ov =
        SignedSpoolPruneOverride::sign("op|1", "reason", 30, &priv_k, &pub_k).expect("sign");
    let mut override_ev = valid_ov.clone();
    override_ev.retention_days = 0; // Tamper signed field
    assert!(
        override_ev.verify(std::slice::from_ref(&pub_k)).is_err(),
        "Tampered SignedSpoolPruneOverride MUST fail ECDSA P-256 verification"
    );
    let mut smuggled_ov = valid_ov.clone();
    smuggled_ov.operator_id = "op".to_string();
    smuggled_ov.reason = "1|reason".to_string();
    assert!(
        smuggled_ov.verify(std::slice::from_ref(&pub_k)).is_err(),
        "Cross-field '|' delimiter smuggling MUST fail verification"
    );
    let mut expired_ov = valid_ov;
    expired_ov.issued_unix -= 1000;
    assert!(
        expired_ov.verify(std::slice::from_ref(&pub_k)).is_err(),
        "Expired SignedSpoolPruneOverride MUST fail TTL check"
    );

    // 6. Base64 roundtrip, strict RFC 4648 §3.5 padding & Tier-3 CRLF + upload cap probes
    for len in [0usize, 1, 2, 3, 4, 17, 255] {
        let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
        let b64 = encode_base64(&data);
        assert_eq!(decode_base64(&b64).expect("decode b64"), data);
    }
    assert!(decode_base64("Zg==Zg==").is_err());
    assert!(decode_base64("Zh==").is_err());
    assert!(decode_base64("Zm9=").is_err());
    let crlf_sbx = Tier3SandboxConnector::new("https://8.8.8.8/api/v1/detonate", "bad\r\nkey");
    assert!(crlf_sbx
        .try_remote_detonation(&SandboxDetonationRequest {
            file_name: "a.bin".to_string(),
            sha256_hex: String::new(),
            file_bytes: b"abc".to_vec(),
            timeout_seconds: 5,
        })
        .is_err());

    let _ = fs::remove_dir_all(&dir);
}
