//! Test Gates T51 & T52 (`CSE-23` — SIEM Spool Drain, Private CIDR Allowlist, Real TLS 1.3 mTLS,
//! CERT-In 180-Day Sealed Rollover & Tier-3 Remote Sandbox Bounded Payload Upload).

use rustls::server::WebPkiClientVerifier;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener};
use std::sync::Arc;
use uuid::Uuid;

use sentinel_core::enterprise::falcon::{
    AllowedCidr, CrowdStrikeFalconBridge, FalconTelemetryEvent, SignedSpoolPruneOverride,
    SIEM_RETENTION_DAYS,
};
use sentinel_core::enterprise::ledger::create_shared_audit_ledger;
use sentinel_core::scanner::tier3_sandbox::{
    decode_base64, encode_base64, SandboxDetonationReport, SandboxDetonationRequest,
    Tier3SandboxConnector,
};
use sentinel_sys::{generate_raw_ecdsa_p256_keypair, sign_ecdsa_p256_with_private_blob};

// ---------------------------------------------------------------------------
// Minimal Pure-Rust ASN.1 DER + X.509 v3 ECDSA P-256 Test PKI Generator
// (Zero extra crate dependencies; works 100% offline with rustls TLS 1.3 + WebPkiClientVerifier)
// ---------------------------------------------------------------------------

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + content.len());
    out.push(tag);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_seq(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    der_tlv(0x30, &body)
}

fn der_set(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    der_tlv(0x31, &body)
}

fn der_uint(bytes: &[u8]) -> Vec<u8> {
    let trimmed = match bytes.iter().position(|&b| b != 0) {
        Some(idx) => &bytes[idx..],
        None => &[0u8],
    };
    let mut val = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        val.push(0x00);
    }
    val.extend_from_slice(trimmed);
    der_tlv(0x02, &val)
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut val = Vec::with_capacity(bytes.len() + 1);
    val.push(0x00); // 0 unused bits
    val.extend_from_slice(bytes);
    der_tlv(0x03, &val)
}

fn der_oid(encoded_body: &[u8]) -> Vec<u8> {
    der_tlv(0x06, encoded_body)
}

fn der_cn(cn: &str) -> Vec<u8> {
    // OID 2.5.4.3 (commonName) = 55 04 03
    let atv = der_seq(&[der_oid(&[0x55, 0x04, 0x03]), der_tlv(0x0C, cn.as_bytes())]);
    der_seq(&[der_set(&[atv])])
}

fn wrap_pem(label: &str, der: &[u8]) -> Vec<u8> {
    let b64 = encode_base64(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("ascii b64"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}

struct TestP256Key {
    priv_blob: Vec<u8>,
    sec1_pub: [u8; 65],
    scalar_d: [u8; 32],
}

impl TestP256Key {
    fn generate() -> Self {
        let (pub_blob, priv_blob) =
            generate_raw_ecdsa_p256_keypair().expect("generate P-256 keypair");
        let mut sec1_pub = [0u8; 65];
        let mut scalar_d = [0u8; 32];
        assert_eq!(pub_blob.len(), 72, "BCRYPT_ECCPUBLIC_BLOB must be 72 bytes");
        assert_eq!(
            priv_blob.len(),
            104,
            "BCRYPT_ECCPRIVATE_BLOB must be 104 bytes"
        );
        sec1_pub[0] = 0x04;
        sec1_pub[1..65].copy_from_slice(&pub_blob[8..72]);
        scalar_d.copy_from_slice(&priv_blob[72..104]);
        Self {
            priv_blob,
            sec1_pub,
            scalar_d,
        }
    }

    fn sec1_private_key_pem(&self) -> Vec<u8> {
        // RFC 5915 ECPrivateKey
        // OID prime256v1 (1.2.840.10045.3.1.7) = 2A 86 48 CE 3D 03 01 07
        let curve_oid = der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
        let der = der_seq(&[
            der_uint(&[1]),
            der_tlv(0x04, &self.scalar_d),
            der_tlv(0xA0, &curve_oid),
            der_tlv(0xA1, &der_bit_string(&self.sec1_pub)),
        ]);
        wrap_pem("EC PRIVATE KEY", &der)
    }

    fn sign_der(&self, tbs: &[u8]) -> Vec<u8> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(tbs));
        let raw_sig =
            sign_ecdsa_p256_with_private_blob(&self.priv_blob, &digest).expect("ECDSA P-256 sign");
        assert_eq!(raw_sig.len(), 64);
        der_seq(&[der_uint(&raw_sig[..32]), der_uint(&raw_sig[32..64])])
    }
}

#[derive(Clone, Copy)]
enum TestCertRole {
    Ca,
    Server,
    Client,
}

fn build_x509_v3_cert_pem(
    serial: u8,
    issuer_cn: &str,
    subject_cn: &str,
    subject_key: &TestP256Key,
    issuer_key: &TestP256Key,
    role: TestCertRole,
) -> Vec<u8> {
    let is_ca = matches!(role, TestCertRole::Ca);
    let is_server = matches!(role, TestCertRole::Server);
    let is_client = matches!(role, TestCertRole::Client);
    // OID ecdsa-with-SHA256 (1.2.840.10045.4.3.2) = 2A 86 48 CE 3D 04 03 02
    let sig_alg = der_seq(&[der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])]);
    // SPKI: id-ecPublicKey (1.2.840.10045.2.1) + prime256v1 (1.2.840.10045.3.1.7)
    let spki = der_seq(&[
        der_seq(&[
            der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
            der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
        ]),
        der_bit_string(&subject_key.sec1_pub),
    ]);
    let validity = der_seq(&[
        der_tlv(0x17, b"240101000000Z"),
        der_tlv(0x17, b"350101000000Z"),
    ]);

    let mut exts = Vec::new();
    // BasicConstraints (OID 2.5.29.19 = 55 1D 13)
    let bc_val = if is_ca {
        der_seq(&[der_tlv(0x01, &[0xFF])])
    } else {
        der_seq(&[])
    };
    exts.push(der_seq(&[
        der_oid(&[0x55, 0x1D, 0x13]),
        der_tlv(0x01, &[0xFF]), // critical = true
        der_tlv(0x04, &bc_val),
    ]));

    // KeyUsage (OID 2.5.29.15 = 55 1D 0F)
    let ku_bits = if is_ca {
        // keyCertSign (bit 5) + cRLSign (bit 6) => 0x06 with 1 unused bit
        der_tlv(0x03, &[0x01, 0x06])
    } else {
        // digitalSignature (bit 0) => 0x80 with 7 unused bits
        der_tlv(0x03, &[0x07, 0x80])
    };
    exts.push(der_seq(&[
        der_oid(&[0x55, 0x1D, 0x0F]),
        der_tlv(0x01, &[0xFF]),
        der_tlv(0x04, &ku_bits),
    ]));

    // ExtendedKeyUsage (OID 2.5.29.37 = 55 1D 25)
    if is_server || is_client {
        let mut eku_oids = Vec::new();
        if is_server {
            // id-kp-serverAuth (1.3.6.1.5.5.7.3.1) = 2B 06 01 05 05 07 03 01
            eku_oids.push(der_oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]));
        }
        if is_client {
            // id-kp-clientAuth (1.3.6.1.5.5.7.3.2) = 2B 06 01 05 05 07 03 02
            eku_oids.push(der_oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]));
        }
        exts.push(der_seq(&[
            der_oid(&[0x55, 0x1D, 0x25]),
            der_tlv(0x04, &der_seq(&eku_oids)),
        ]));
    }

    // SubjectAltName (OID 2.5.29.17 = 55 1D 11)
    if is_server {
        let san = der_seq(&[
            der_tlv(0x82, b"localhost"),    // dNSName
            der_tlv(0x87, &[127, 0, 0, 1]), // iPAddress 127.0.0.1
        ]);
        exts.push(der_seq(&[
            der_oid(&[0x55, 0x1D, 0x11]),
            der_tlv(0x04, &san),
        ]));
    } else if is_client {
        let san = der_seq(&[der_tlv(0x82, b"sentinel-client.local")]);
        exts.push(der_seq(&[
            der_oid(&[0x55, 0x1D, 0x11]),
            der_tlv(0x04, &san),
        ]));
    }

    let tbs = der_seq(&[
        der_tlv(0xA0, &der_uint(&[2])), // v3
        der_uint(&[serial]),
        sig_alg.clone(),
        der_cn(issuer_cn),
        validity,
        der_cn(subject_cn),
        spki,
        der_tlv(0xA3, &der_seq(&exts)),
    ]);

    let sig_der = issuer_key.sign_der(&tbs);
    let cert_der = der_seq(&[tbs, sig_alg, der_bit_string(&sig_der)]);
    wrap_pem("CERTIFICATE", &cert_der)
}

struct TestMtlsPki {
    ca_cert_pem: Vec<u8>,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

impl TestMtlsPki {
    fn generate() -> Self {
        let ca_key = TestP256Key::generate();
        let srv_key = TestP256Key::generate();
        let cli_key = TestP256Key::generate();

        let ca_cert_pem = build_x509_v3_cert_pem(
            1,
            "OmniConnect Test Root CA",
            "OmniConnect Test Root CA",
            &ca_key,
            &ca_key,
            TestCertRole::Ca,
        );
        let server_cert_pem = build_x509_v3_cert_pem(
            2,
            "OmniConnect Test Root CA",
            "localhost",
            &srv_key,
            &ca_key,
            TestCertRole::Server,
        );
        let client_cert_pem = build_x509_v3_cert_pem(
            3,
            "OmniConnect Test Root CA",
            "sentinel-client.local",
            &cli_key,
            &ca_key,
            TestCertRole::Client,
        );

        Self {
            ca_cert_pem,
            server_cert_pem,
            server_key_pem: srv_key.sec1_private_key_pem(),
            client_cert_pem,
            client_key_pem: cli_key.sec1_private_key_pem(),
        }
    }

    fn build_mtls_server_config(&self) -> Arc<ServerConfig> {
        let mut client_roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&self.ca_cert_pem).flatten() {
            client_roots.add(cert).expect("add test CA root");
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .expect("build mTLS client verifier");

        let server_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(&self.server_cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .expect("parse server cert");
        let server_key =
            PrivateKeyDer::from_pem_slice(&self.server_key_pem).expect("parse server key");

        let cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, server_key)
            .expect("build TLS 1.3 mTLS ServerConfig");
        Arc::new(cfg)
    }
}

#[test]
fn t51_siem_spool_drains_on_reconnect_private_cidr_mtls_and_no_silent_eviction() {
    // 1. Operator-pinned RFC 1918 / IPv6 ULA CIDR allowlist validation (`CSE-23`)
    let cidr_10 = AllowedCidr::parse("10.20.0.0/16").expect("RFC 1918 10.20.0.0/16 allowed");
    let cidr_192 = AllowedCidr::parse("192.168.50.10/32").expect("RFC 1918 /32 allowed");
    let cidr_ula = AllowedCidr::parse("fd12:3456::/48").expect("IPv6 ULA allowed");
    let allowlist = vec![cidr_10, cidr_192, cidr_ula];

    // Prohibited CIDRs MUST be rejected at parse time
    for forbidden in [
        "127.0.0.0/8",
        "126.0.0.0/7",
        "169.254.0.0/16",
        "169.0.0.0/8",
        "0.0.0.0/0",
        "8.8.8.0/24",
        "::1/128",
        "fe80::/10",
        "::/0",
    ] {
        assert!(
            AllowedCidr::parse(forbidden).is_err(),
            "Prohibited CIDR '{forbidden}' MUST be rejected"
        );
    }

    // Pinned internal SIEM IPs permitted; unpinned RFC 1918 & all loopback/IMDS/link-local rejected
    assert!(CrowdStrikeFalconBridge::validate_siem_egress_ip(
        IpAddr::V4(Ipv4Addr::new(10, 20, 5, 8)),
        &allowlist
    )
    .is_ok());
    assert!(CrowdStrikeFalconBridge::validate_siem_egress_ip(
        IpAddr::V4(Ipv4Addr::new(192, 168, 50, 10)),
        &allowlist
    )
    .is_ok());
    assert!(CrowdStrikeFalconBridge::validate_siem_egress_ip(
        IpAddr::V6("fd12:3456::1".parse::<Ipv6Addr>().expect("v6")),
        &allowlist
    )
    .is_ok());

    assert!(CrowdStrikeFalconBridge::validate_siem_egress_ip(
        IpAddr::V4(Ipv4Addr::new(10, 99, 1, 1)),
        &allowlist
    )
    .is_err());
    for always_blocked in [
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        IpAddr::V6("::1".parse::<Ipv6Addr>().expect("v6")),
        IpAddr::V6("fe80::1".parse::<Ipv6Addr>().expect("v6")),
        IpAddr::V6("::ffff:169.254.169.254".parse::<Ipv6Addr>().expect("v6")),
        IpAddr::V6("::ffff:127.0.0.1".parse::<Ipv6Addr>().expect("v6")),
    ] {
        assert!(
            CrowdStrikeFalconBridge::validate_siem_egress_ip(always_blocked, &allowlist).is_err(),
            "Address {always_blocked} must ALWAYS be unconditionally blocked"
        );
    }

    // 2. CERT-In 180-day Spool Protection: Sealed Rollover Segments + 80% High-Watermark Alert
    let dir = std::env::temp_dir().join(format!("t51_siem_{}", Uuid::new_v4().simple()));
    fs::create_dir_all(&dir).expect("create test dir");
    let ledger_path = dir.join("unified_audit.jsonl");
    let shared_ledger = create_shared_audit_ledger(&ledger_path).expect("create shared ledger");
    let spool_path = dir.join("siem_spool.sealed");

    // Start offline with a small active segment cap (1024 bytes) to trigger 80% alert + sealed rollover
    let offline_bridge = CrowdStrikeFalconBridge::with_spool_path(
        "offline://siem.corp.local:6514",
        spool_path.clone(),
    )
    .with_shared_ledger(shared_ledger.clone())
    .with_max_spool_bytes(1024);
    assert!(!offline_bridge.is_mtls_enforced());

    let total_alerts = 8usize;
    for i in 0..total_alerts {
        offline_bridge
            .emit_alert(&FalconTelemetryEvent {
                severity: 8,
                signature_id: format!("T51-ALERT-{i:02}"),
                name: format!("Offline USB Alert #{i}"),
                device_vendor_id: "0x0781".to_string(),
                device_product_id: "0x5583".to_string(),
                serial_number: format!("SN-T51-{i:02}"),
                file_sha256: None,
                action_taken: "BLOCKED_OFFLINE".to_string(),
                details: format!("Buffered CERT-In retention payload sequence number {i}"),
            })
            .expect("emit offline alert");
    }

    let archives = offline_bridge
        .list_rollover_archives()
        .expect("list rollover archives");
    assert!(
        !archives.is_empty(),
        "Exceeding active segment cap must seal older records into rollover archive segments"
    );

    let retained_all = offline_bridge
        .read_all_retained_records()
        .expect("read all retained records");
    assert_eq!(
        retained_all.len(),
        total_alerts,
        "CERT-In protection must preserve 100% of records (<180 days) with ZERO silent eviction!"
    );

    let ledger_text = fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(
        ledger_text.contains("SIEM_SPOOL_HIGH_WATERMARK"),
        "AuditLedger must contain SIEM_SPOOL_HIGH_WATERMARK alert at >=80% capacity"
    );
    assert!(
        ledger_text.contains("SIEM_SPOOL_ROLLOVER_ARCHIVED"),
        "AuditLedger must contain SIEM_SPOOL_ROLLOVER_ARCHIVED event"
    );

    // Refusing <180-day pruning without signed operator override
    let early_prune_err = offline_bridge
        .prune_expired_records(30)
        .expect_err("Pruning <180 days without signed operator override must fail closed");
    assert!(early_prune_err.contains("CERT_IN_RETENTION_VIOLATION"));
    assert_eq!(SIEM_RETENTION_DAYS, 180);

    // 3. Reconnect with REAL TLS 1.3 Client-Cert mTLS & verify `flush_spool()` drains ALL 8 records
    //    (both rollover archives and active spool!)
    let pki = TestMtlsPki::generate();
    let srv_cfg = pki.build_mtls_server_config();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock TLS 1.3 mTLS SIEM server");
    let port = listener.local_addr().expect("local addr").port();

    // First verify that connecting WITHOUT client cert fails against mTLS-enforcing server
    let srv_cfg_reject = srv_cfg.clone();
    let listener_clone = listener.try_clone().expect("clone listener");
    let reject_thread = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener_clone.accept() {
            let mut conn = rustls::ServerConnection::new(srv_cfg_reject).expect("server conn");
            let mut tls = rustls::Stream::new(&mut conn, &mut stream);
            let mut buf = [0u8; 64];
            let _ = tls.read(&mut buf);
            let _ = tls.conn.complete_io(tls.sock);
        }
    });
    let no_mtls_bridge = CrowdStrikeFalconBridge::with_spool_path(
        format!("tls://127.0.0.1:{port}"),
        spool_path.clone(),
    )
    .with_custom_ca(pki.ca_cert_pem.clone())
    .with_allow_loopback_for_testing(true);
    assert!(!no_mtls_bridge.is_mtls_enforced());
    let no_mtls_res = no_mtls_bridge.send_rfc5425_syslog("CEF:0|ShouldFailNoClientCert");
    assert!(
        no_mtls_res.is_err(),
        "Server requiring mTLS must reject client without client cert"
    );
    let _ = reject_thread.join();

    // Now accept all 8 flushed RFC 5425 mTLS connections and verify received CEF messages
    let server_thread = std::thread::spawn(move || -> Vec<String> {
        let mut received = Vec::new();
        for _ in 0..total_alerts {
            let (mut stream, _) = listener.accept().expect("accept mTLS SIEM connection");
            let mut conn = rustls::ServerConnection::new(srv_cfg.clone()).expect("server conn");
            let mut tls = rustls::Stream::new(&mut conn, &mut stream);
            let mut buf = Vec::new();
            let _ = tls.read_to_end(&mut buf);
            let has_client_cert = tls
                .conn
                .peer_certificates()
                .map(|c| !c.is_empty())
                .unwrap_or(false);
            assert!(
                has_client_cert,
                "Server must have verified client mTLS certificate"
            );
            tls.conn.send_close_notify();
            let _ = tls.flush();
            received.push(String::from_utf8_lossy(&buf).into_owned());
        }
        received
    });

    let mtls_bridge = CrowdStrikeFalconBridge::with_spool_path(
        format!("tls://127.0.0.1:{port}"),
        spool_path.clone(),
    )
    .with_shared_ledger(shared_ledger.clone())
    .with_custom_ca(pki.ca_cert_pem.clone())
    .with_client_mtls(pki.client_cert_pem.clone(), pki.client_key_pem.clone())
    .with_max_spool_bytes(1024)
    .with_allow_loopback_for_testing(true);
    assert!(
        mtls_bridge.is_mtls_enforced(),
        "Bridge with valid client cert + key must truthfully report mtls_enforced = true"
    );

    let flushed = mtls_bridge
        .flush_spool()
        .expect("flush_spool must drain archived + active records over TLS 1.3 mTLS");
    assert_eq!(
        flushed, total_alerts,
        "flush_spool must deliver all {total_alerts} buffered records across rollover archives + active spool"
    );

    let server_frames = server_thread.join().expect("server thread");
    assert_eq!(server_frames.len(), total_alerts);
    for (idx, frame) in server_frames.iter().enumerate() {
        assert!(
            frame.contains(&format!("T51-ALERT-{idx:02}")),
            "Expected ordered RFC 5425 CEF frame #{idx}, got: {frame}"
        );
    }

    // Subsequent flush must be a clean no-op (0 undelivered remaining)
    assert_eq!(mtls_bridge.flush_spool().expect("second flush"), 0);
    assert!(mtls_bridge
        .read_all_retained_records()
        .expect("read retained")
        .iter()
        .all(|r| r.delivered));

    // Verify signed operator prune override workflow
    let (op_pub, op_priv) = generate_raw_ecdsa_p256_keypair().expect("operator ECDSA key");
    let override_ev = SignedSpoolPruneOverride::sign(
        "secops-admin-01",
        "Authorized test retention override",
        0,
        &op_priv,
        &op_pub,
    )
    .expect("sign override");
    let untrusted_err =
        mtls_bridge.prune_records_with_signed_override(&override_ev, &[vec![0xAA; 65]]);
    assert!(
        untrusted_err.is_err(),
        "Override signed by unpinned key must fail closed"
    );
    let _ = mtls_bridge
        .prune_records_with_signed_override(&override_ev, &[op_pub])
        .expect("Pinned valid ECDSA P-256 override must be accepted");

    let final_ledger = fs::read_to_string(&ledger_path).expect("read final ledger");
    assert!(final_ledger.contains("SIEM_SPOOL_FLUSHED"));
    assert!(
        final_ledger.contains(r#"\"mtls_enforced\":true"#)
            || final_ledger.contains(r#""mtls_enforced":true"#)
    );
    assert!(final_ledger.contains("SIEM_SPOOL_OPERATOR_PRUNE_OVERRIDE"));
    shared_ledger
        .lock()
        .expect("lock ledger")
        .verify_chain()
        .expect("Unified ledger chain must remain 100% valid");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn t52_tier3_sandbox_transmits_payload_bytes_verified_by_mock_tls_server() {
    let dir = std::env::temp_dir().join(format!("t52_sandbox_{}", Uuid::new_v4().simple()));
    fs::create_dir_all(&dir).expect("create test dir");
    let ledger_path = dir.join("t52_ledger.jsonl");
    let shared_ledger = create_shared_audit_ledger(&ledger_path).expect("create shared ledger");

    let pki = TestMtlsPki::generate();
    // Tier3SandboxConnector reads combined cert+key PEM file
    let mut combined_client_pem = pki.client_cert_pem.clone();
    combined_client_pem.extend_from_slice(&pki.client_key_pem);
    let client_pem_path = dir.join("client_mtls.pem");
    fs::write(&client_pem_path, &combined_client_pem).expect("write client mTLS PEM");

    let sample_bytes =
        b"MZ\x90\x00\x03\x00\x00\x00T52_REAL_BINARY_DETONATION_SAMPLE_PAYLOAD_9F8E7D6C".to_vec();
    let sample_sha256 = hex::encode(Sha256::digest(&sample_bytes));

    // 1. Upload cap enforcement BEFORE network contact
    let capped_connector =
        Tier3SandboxConnector::new("https://127.0.0.1:4443/api/v1/detonate", "KEY-T52")
            .with_max_upload_bytes(16)
            .with_allow_loopback_for_testing(true);
    let cap_err = capped_connector
        .try_remote_detonation(&SandboxDetonationRequest {
            file_name: "oversized.exe".to_string(),
            sha256_hex: sample_sha256.clone(),
            file_bytes: sample_bytes.clone(),
            timeout_seconds: 5,
        })
        .expect_err("Sample exceeding max_upload_bytes must fail closed before network");
    assert!(cap_err.contains("SANDBOX_UPLOAD_SIZE_EXCEEDED"));

    // 2. SHA-256 mismatch rejection BEFORE network contact
    let bad_hash_err =
        Tier3SandboxConnector::new("https://127.0.0.1:4443/api/v1/detonate", "KEY-T52")
            .with_allow_loopback_for_testing(true)
            .try_remote_detonation(&SandboxDetonationRequest {
                file_name: "tampered.exe".to_string(),
                sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                file_bytes: sample_bytes.clone(),
                timeout_seconds: 5,
            })
            .expect_err("Mismatched SHA-256 must fail closed before transmission");
    assert!(bad_hash_err.contains("SANDBOX_PAYLOAD_SHA256_MISMATCH"));

    // 3. Live Mock TLS 1.3 mTLS Sandbox Server verifying exact uploaded bytes & SHA-256
    let srv_cfg = pki.build_mtls_server_config();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock TLS 1.3 sandbox server");
    let port = listener.local_addr().expect("local addr").port();

    let expected_bytes = sample_bytes.clone();
    let expected_sha = sample_sha256.clone();
    let server_thread = std::thread::spawn(move || -> (Vec<u8>, String, bool) {
        let (mut tcp, _) = listener.accept().expect("accept sandbox client");
        let mut conn = rustls::ServerConnection::new(srv_cfg).expect("server conn");
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

        // Read HTTP headers + Content-Length body
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        let body_start;
        let content_len;
        loop {
            let n = tls.read(&mut chunk).expect("read http headers");
            assert!(n > 0, "unexpected EOF reading headers");
            raw.extend_from_slice(&chunk[..n]);
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                body_start = pos + 4;
                let hdrs = String::from_utf8_lossy(&raw[..pos]);
                content_len = hdrs
                    .lines()
                    .find_map(|line| {
                        let (k, v) = line.split_once(':')?;
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            v.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .expect("Content-Length header present");
                break;
            }
        }
        while raw.len() < body_start + content_len {
            let n = tls.read(&mut chunk).expect("read http body");
            assert!(n > 0, "unexpected EOF reading body");
            raw.extend_from_slice(&chunk[..n]);
        }

        let peer_cert_present = tls
            .conn
            .peer_certificates()
            .map(|c| !c.is_empty())
            .unwrap_or(false);
        let req_headers = String::from_utf8_lossy(&raw[..body_start]).into_owned();
        assert!(req_headers.starts_with("POST /api/v1/detonate HTTP/1.1\r\n"));
        assert!(req_headers.contains("Authorization: Bearer T52-SANDBOX-KEY\r\n"));

        let body_json: serde_json::Value =
            serde_json::from_slice(&raw[body_start..body_start + content_len])
                .expect("valid JSON upload body");
        assert_eq!(body_json["payload_encoding"].as_str(), Some("base64"));
        assert_eq!(
            body_json["sha256_hex"].as_str(),
            Some(expected_sha.as_str())
        );
        assert_eq!(body_json["mtls_enforced"].as_bool(), Some(true));
        let b64 = body_json["payload_base64"]
            .as_str()
            .expect("payload_base64 field MUST be transmitted");
        let decoded_bytes = decode_base64(b64).expect("valid RFC 4648 base64 payload");
        assert_eq!(
            decoded_bytes, expected_bytes,
            "Mock TLS server must receive exact uploaded binary sample bytes"
        );
        let verified_sha = hex::encode(Sha256::digest(&decoded_bytes));
        assert_eq!(verified_sha, expected_sha);

        let report_body = serde_json::to_string(&SandboxDetonationReport {
            analysis_id: "SBX-REMOTE-T52-OK".to_string(),
            verdict_malicious: true,
            threat_score: 94,
            threat_family: Some("Win32.T52VerifiedSample".to_string()),
            mitre_attack_ttps: vec!["T1055".to_string()],
            behavioral_indicators: vec!["Verified real payload detonation".to_string()],
            network_iocs: vec![],
            is_emulated: false,
            degradation_event: None,
        })
        .expect("serialize report");
        let http_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            report_body.len(),
            report_body
        );
        tls.write_all(http_resp.as_bytes()).expect("write response");
        tls.conn.send_close_notify();
        tls.flush().expect("flush response");

        (decoded_bytes, verified_sha, peer_cert_present)
    });

    let connector = Tier3SandboxConnector::new(
        format!("https://127.0.0.1:{port}/api/v1/detonate"),
        "T52-SANDBOX-KEY",
    )
    .with_custom_ca(pki.ca_cert_pem)
    .with_mtls_cert(client_pem_path)
    .with_shared_ledger(shared_ledger.clone())
    .with_allow_loopback_for_testing(true);

    let report = connector
        .try_remote_detonation(&SandboxDetonationRequest {
            file_name: "payload_sample.exe".to_string(),
            sha256_hex: sample_sha256.clone(),
            file_bytes: sample_bytes.clone(),
            timeout_seconds: 10,
        })
        .expect("Tier3SandboxConnector must transmit full payload over TLS 1.3 mTLS");

    assert_eq!(report.analysis_id, "SBX-REMOTE-T52-OK");
    assert!(report.verdict_malicious);
    assert_eq!(report.threat_score, 94);
    assert!(!report.is_emulated);

    let (received_bytes, received_sha, peer_cert_ok) = server_thread.join().expect("server thread");
    assert_eq!(received_bytes, sample_bytes);
    assert_eq!(received_sha, sample_sha256);
    assert!(
        peer_cert_ok,
        "Mock TLS server must verify client mTLS certificate"
    );

    let ledger_text = fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(ledger_text.contains("SANDBOX_REMOTE_DETONATION"));
    assert!(ledger_text.contains(&sample_sha256));
    shared_ledger
        .lock()
        .expect("lock ledger")
        .verify_chain()
        .expect("Ledger chain valid");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn t51_cse23_hardening_flush_error_propagation_mtls_fail_closed_rollover_and_override_security() {
    let dir = std::env::temp_dir().join(format!("t51_hardening_{}", Uuid::new_v4().simple()));
    fs::create_dir_all(&dir).expect("create test dir");
    let ledger_path = dir.join("hardening_ledger.jsonl");
    let shared_ledger = create_shared_audit_ledger(&ledger_path).expect("create shared ledger");
    let spool_path = dir.join("siem_spool.sealed");

    // 1. AllowedCidr custom validated Deserialize rejects invalid/private-bypass JSON objects
    for bad_json in [
        r#"{"network":"127.0.0.1","prefix_len":8}"#,
        r#"{"network":"10.0.0.0","prefix_len":0}"#,
        r#"{"network":"10.0.0.0","prefix_len":99}"#,
        r#"{"network":"169.254.0.0","prefix_len":16}"#,
        r#""127.0.0.0/8""#,
        r#""0.0.0.0/0""#,
    ] {
        assert!(
            serde_json::from_str::<AllowedCidr>(bad_json).is_err(),
            "Invalid AllowedCidr JSON '{bad_json}' MUST fail deserialization"
        );
    }
    let ok_cidr: AllowedCidr =
        serde_json::from_str(r#"{"network":"10.20.0.0","prefix_len":16}"#).expect("valid obj cidr");
    assert_eq!(ok_cidr.network(), IpAddr::V4(Ipv4Addr::new(10, 20, 0, 0)));
    assert_eq!(ok_cidr.prefix_len(), 16);

    // 2. Partial mTLS / TLS config error / corrupt CA PEM fail closed EVEN on empty spool
    let pki = TestMtlsPki::generate();
    let partial_mtls = CrowdStrikeFalconBridge::with_spool_path(
        "tls://siem.example.com:6514",
        dir.join("empty_partial.sealed"),
    )
    .with_client_mtls_optional(Some(pki.client_cert_pem.clone()), None);
    assert!(!partial_mtls.is_mtls_enforced());
    assert!(partial_mtls
        .flush_spool()
        .expect_err("Partial mTLS must fail closed in flush_spool")
        .contains("MTLS_CONFIG_ERROR"));

    let cfg_err_bridge = CrowdStrikeFalconBridge::with_spool_path(
        "tls://siem.example.com:6514",
        dir.join("empty_cfg_err.sealed"),
    )
    .with_tls_config_error("unreadable PEM");
    assert!(!cfg_err_bridge.is_mtls_enforced());
    assert!(cfg_err_bridge
        .flush_spool()
        .expect_err("tls_config_error must fail closed in flush_spool")
        .contains("MTLS_CONFIG_ERROR"));

    let bad_ca_bridge = CrowdStrikeFalconBridge::with_spool_path(
        "tls://siem.example.com:6514",
        dir.join("empty_bad_ca.sealed"),
    )
    .with_custom_ca(b"NOT A VALID PEM".to_vec());
    assert!(bad_ca_bridge
        .flush_spool()
        .expect_err("Corrupt custom CA PEM must fail closed")
        .contains("MTLS_CONFIG_ERROR"));

    // 3. Case-insensitive OFFLINE:// endpoint is recognized cleanly
    let upper_offline = CrowdStrikeFalconBridge::with_spool_path(
        "  OFFLINE://siem.corp.local:6514  ",
        spool_path.clone(),
    )
    .with_shared_ledger(shared_ledger.clone())
    .with_max_spool_bytes(1024);
    assert_eq!(upper_offline.flush_spool().expect("uppercase offline"), 0);

    // Emit 3 records offline into active spool (below rollover or across segments)
    for i in 0..3 {
        upper_offline
            .emit_alert(&FalconTelemetryEvent {
                severity: 8,
                signature_id: format!("FIFO-{i:02}"),
                name: format!("FIFO Event {i}"),
                device_vendor_id: "0x0781".to_string(),
                device_product_id: "0x5583".to_string(),
                serial_number: format!("SN-FIFO-{i:02}"),
                file_sha256: None,
                action_taken: "BUFFERED".to_string(),
                details: "FIFO order & error propagation verification".to_string(),
            })
            .expect("emit offline");
    }

    // 4. flush_spool() MUST propagate SSRF errors (never return Ok(0)!)
    let ssrf_bridge =
        CrowdStrikeFalconBridge::with_spool_path("tls://169.254.169.254:6514", spool_path.clone());
    let ssrf_err = ssrf_bridge
        .flush_spool()
        .expect_err("SSRF target MUST return Err from flush_spool(), never Ok(0)");
    assert!(
        ssrf_err.contains("SSRF_VIOLATION"),
        "Expected SSRF_VIOLATION, got: {ssrf_err}"
    );

    // 5. Partial delivery + strict FIFO stop-on-error (accept 1 frame, reject next -> persist #0, return Err)
    let srv_cfg = pki.build_mtls_server_config();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind one-shot mTLS server");
    let port = listener.local_addr().expect("addr").port();
    let one_shot_server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept first frame");
        let mut conn = rustls::ServerConnection::new(srv_cfg).expect("server conn");
        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf);
        tls.conn.send_close_notify();
        let _ = tls.flush();
        // Drop listener immediately so record #1 fails to connect
        drop(listener);
        String::from_utf8_lossy(&buf).into_owned()
    });

    let ledger_before = fs::read_to_string(&ledger_path).unwrap_or_default();
    let hw_before = ledger_before.matches("SIEM_SPOOL_HIGH_WATERMARK").count();

    let partial_flush_bridge = CrowdStrikeFalconBridge::with_spool_path(
        format!("tls://127.0.0.1:{port}"),
        spool_path.clone(),
    )
    .with_shared_ledger(shared_ledger.clone())
    .with_custom_ca(pki.ca_cert_pem.clone())
    .with_client_mtls(pki.client_cert_pem.clone(), pki.client_key_pem.clone())
    .with_allow_loopback_for_testing(true);

    let partial_res = partial_flush_bridge.flush_spool();
    assert!(
        partial_res.is_err(),
        "flush_spool must propagate transport error when remaining records cannot be sent"
    );
    let first_frame = one_shot_server.join().expect("one-shot server");
    assert!(first_frame.contains("FIFO-00"));

    let retained_after = partial_flush_bridge
        .read_all_retained_records()
        .expect("read retained after partial flush");
    assert_eq!(retained_after.len(), 3);
    assert!(
        retained_after[0].delivered,
        "First record must be persisted as delivered"
    );
    assert!(
        !retained_after[1].delivered,
        "Second record must remain undelivered"
    );
    assert!(
        !retained_after[2].delivered,
        "Third record must remain undelivered (FIFO preserved)"
    );

    let ledger_after = fs::read_to_string(&ledger_path).expect("read ledger");
    let hw_after = ledger_after.matches("SIEM_SPOOL_HIGH_WATERMARK").count();
    assert_eq!(
        hw_after, hw_before,
        "flush_spool must NOT emit spurious SIEM_SPOOL_HIGH_WATERMARK alerts during drain"
    );

    // 6. Restart-safe rollover archive naming: zero-padded 20-digit timestamp + unique random suffix
    for i in 3..10 {
        upper_offline
            .emit_alert(&FalconTelemetryEvent {
                severity: 7,
                signature_id: format!("ROLL-{i:02}"),
                name: format!("Rollover uniqueness #{i}"),
                device_vendor_id: "0x0781".to_string(),
                device_product_id: "0x5583".to_string(),
                serial_number: format!("SN-R-{i:02}"),
                file_sha256: None,
                action_taken: "ARCHIVED".to_string(),
                details: "Ensure zero overwrite across rapid same-second rollovers".to_string(),
            })
            .expect("emit rollover");
    }
    let archives = upper_offline
        .list_rollover_archives()
        .expect("list rollover archives");
    assert!(archives.len() >= 2, "Expected multiple rollover archives");
    for a in &archives {
        let name = a.file_name().expect("filename").to_string_lossy();
        let tail = name
            .strip_prefix("siem_spool.archive.")
            .and_then(|s| s.strip_suffix(".sealed"))
            .expect("canonical archive name");
        let parts: Vec<&str> = tail.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "Archive name must have ts.seq.rand parts: {name}"
        );
        assert_eq!(
            parts[0].len(),
            20,
            "Timestamp must be 20-digit zero-padded: {name}"
        );
        assert_eq!(
            parts[1].len(),
            8,
            "Sequence must be 8-digit zero-padded: {name}"
        );
        assert_eq!(
            parts[2].len(),
            8,
            "Random suffix must be 8 hex chars: {name}"
        );
    }
    assert_eq!(
        upper_offline
            .read_all_retained_records()
            .expect("read all")
            .len(),
        10,
        "100% of records across all rollover archives + active spool must survive"
    );

    // 7. SignedSpoolPruneOverride expiry, future skew, empty nonce, negative retention,
    //    cross-field '|' delimiter smuggling, and replay protection
    let (op_pub, op_priv) = generate_raw_ecdsa_p256_keypair().expect("operator key");
    assert!(
        SignedSpoolPruneOverride::sign("op1", "bad", -1, &op_priv, &op_pub).is_err(),
        "Negative retention_days must be rejected at sign time"
    );

    let valid_ov = SignedSpoolPruneOverride::sign("op|a", "b", 10, &op_priv, &op_pub)
        .expect("sign valid override");

    // Cross-field delimiter smuggling: shifting `|` from operator_id to reason MUST fail signature verify
    let mut smuggled = valid_ov.clone();
    smuggled.operator_id = "op".to_string();
    smuggled.reason = "a|b".to_string();
    assert!(
        smuggled.verify(std::slice::from_ref(&op_pub)).is_err(),
        "Length-prefixed digest MUST reject cross-field '|' delimiter smuggling"
    );

    // Expired override
    let mut expired = valid_ov.clone();
    expired.issued_unix -= 901;
    assert!(expired
        .verify(std::slice::from_ref(&op_pub))
        .expect_err("Expired override must fail")
        .contains("OVERRIDE_EXPIRED"));

    // Future-skewed override
    let mut future = valid_ov.clone();
    future.issued_unix += 61;
    assert!(future
        .verify(std::slice::from_ref(&op_pub))
        .expect_err("Future-skewed override must fail")
        .contains("OVERRIDE_FUTURE_SKEW"));

    // Empty nonce & negative retention
    let mut empty_nonce = valid_ov.clone();
    empty_nonce.nonce = "   ".to_string();
    assert!(empty_nonce.verify(std::slice::from_ref(&op_pub)).is_err());

    let mut neg_ret = valid_ov.clone();
    neg_ret.retention_days = -5;
    assert!(neg_ret.verify(std::slice::from_ref(&op_pub)).is_err());

    // Replay protection: first consume succeeds, second exact replay fails with OVERRIDE_REPLAY_REJECTED
    let _ = upper_offline
        .prune_records_with_signed_override(&valid_ov, std::slice::from_ref(&op_pub))
        .expect("first valid override accepted");
    let replay_err = upper_offline
        .prune_records_with_signed_override(&valid_ov, std::slice::from_ref(&op_pub))
        .expect_err("replayed override MUST fail closed");
    assert!(
        replay_err.contains("OVERRIDE_REPLAY_REJECTED"),
        "Expected OVERRIDE_REPLAY_REJECTED, got: {replay_err}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn t52_cse23_hardening_base_url_default_path_strict_base64_and_http_status_limits() {
    // 1. Strict RFC 4648 §3.5 canonical decode_base64
    assert_eq!(decode_base64("Zg==").expect("canonical 1 byte"), b"f");
    assert_eq!(decode_base64("Zm8=").expect("canonical 2 bytes"), b"fo");
    assert_eq!(decode_base64("Zm9v").expect("canonical 3 bytes"), b"foo");
    for bad_b64 in [
        "Zg==Zg==", // mid-stream double padding
        "Zm9=Zg==", // mid-stream single padding
        "Zh==",     // non-zero trailing pad bits (4 LSBs)
        "Zm9=",     // non-zero trailing pad bits (2 LSBs)
        "Zg=A",     // invalid '=' followed by non-'='
        "abc",      // non-multiple of 4
    ] {
        assert!(
            decode_base64(bad_b64).is_err(),
            "Non-canonical/malformed base64 '{bad_b64}' MUST be rejected"
        );
    }

    let dir = std::env::temp_dir().join(format!("t52_hardening_{}", Uuid::new_v4().simple()));
    fs::create_dir_all(&dir).expect("create test dir");
    let pki = TestMtlsPki::generate();
    let mut combined_client_pem = pki.client_cert_pem.clone();
    combined_client_pem.extend_from_slice(&pki.client_key_pem);
    let client_pem_path = dir.join("client_mtls.pem");
    fs::write(&client_pem_path, &combined_client_pem).expect("write client PEM");

    let sample_bytes = b"T52_DEFAULT_PATH_AND_STATUS_GUARD_PAYLOAD".to_vec();
    let sample_sha = hex::encode(Sha256::digest(&sample_bytes));

    // 2. Missing mTLS cert path fails closed BEFORE TCP connect
    let missing_cert_err = Tier3SandboxConnector::new("https://127.0.0.1:1", "KEY-T52")
        .with_mtls_cert(dir.join("does_not_exist.pem"))
        .with_allow_loopback_for_testing(true)
        .try_remote_detonation(&SandboxDetonationRequest {
            file_name: "sample.bin".to_string(),
            sha256_hex: sample_sha.clone(),
            file_bytes: sample_bytes.clone(),
            timeout_seconds: 5,
        })
        .expect_err("Missing client cert must fail before TCP connect");
    assert!(
        missing_cert_err.contains("Failed reading client mTLS certificate"),
        "Expected cert read error before TCP connect, got: {missing_cert_err}"
    );

    // 3. Base URL without path ("https://127.0.0.1:{port}") MUST POST to "/api/v1/detonate",
    //    "HTTP/1.1 2000 Error" MUST be rejected, and >64 KiB response MUST return SANDBOX_RESPONSE_TOO_LARGE
    let srv_cfg = pki.build_mtls_server_config();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock TLS server");
    let port = listener.local_addr().expect("addr").port();

    let server_thread = std::thread::spawn(move || -> Vec<String> {
        let mut request_lines = Vec::new();
        for case_idx in 0..3 {
            let (mut tcp, _) = listener.accept().expect("accept client");
            let mut conn = rustls::ServerConnection::new(srv_cfg.clone()).expect("server conn");
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            let mut body_start = 0usize;
            let mut content_len = 0usize;
            loop {
                let n = tls.read(&mut chunk).expect("read hdrs");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
                if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    body_start = pos + 4;
                    let hdrs = String::from_utf8_lossy(&raw[..pos]);
                    request_lines.push(hdrs.lines().next().unwrap_or_default().to_string());
                    content_len = hdrs
                        .lines()
                        .find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    break;
                }
            }
            while raw.len() < body_start + content_len {
                let n = tls.read(&mut chunk).expect("read body");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
            }

            let http_resp = match case_idx {
                0 => {
                    let body = serde_json::to_string(&SandboxDetonationReport {
                        analysis_id: "SBX-DEFAULT-PATH-OK".to_string(),
                        verdict_malicious: false,
                        threat_score: 0,
                        threat_family: None,
                        mitre_attack_ttps: vec![],
                        behavioral_indicators: vec![],
                        network_iocs: vec![],
                        is_emulated: false,
                        degradation_event: None,
                    })
                    .expect("json");
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                }
                1 => {
                    // Malformed 4-digit status code "2000" MUST be rejected
                    "HTTP/1.1 2000 Error\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                        .to_string()
                }
                _ => {
                    // > 64 KiB response MUST fail with SANDBOX_RESPONSE_TOO_LARGE
                    let oversized = "A".repeat(70 * 1024);
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        oversized.len(),
                        oversized
                    )
                }
            };
            let _ = tls.write_all(http_resp.as_bytes());
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
        request_lines
    });

    // Base URL with NO path!
    let connector = Tier3SandboxConnector::new(format!("https://127.0.0.1:{port}"), "KEY-T52")
        .with_custom_ca(pki.ca_cert_pem)
        .with_mtls_cert(client_pem_path)
        .with_allow_loopback_for_testing(true);

    let req = SandboxDetonationRequest {
        file_name: "sample.bin".to_string(),
        sha256_hex: sample_sha,
        file_bytes: sample_bytes,
        timeout_seconds: 5,
    };

    // Case 0: succeeds via default /api/v1/detonate
    let ok_report = connector
        .try_remote_detonation(&req)
        .expect("base URL must default to /api/v1/detonate");
    assert_eq!(ok_report.analysis_id, "SBX-DEFAULT-PATH-OK");

    // Case 1: "HTTP/1.1 2000 Error" rejected
    let status_err = connector
        .try_remote_detonation(&req)
        .expect_err("HTTP/1.1 2000 Error MUST be rejected");
    assert!(
        status_err.contains("2000"),
        "Expected rejection of HTTP/1.1 2000 Error, got: {status_err}"
    );

    // Case 2: >64 KiB response rejected explicitly
    let big_err = connector
        .try_remote_detonation(&req)
        .expect_err(">64 KiB response MUST fail with SANDBOX_RESPONSE_TOO_LARGE");
    assert!(
        big_err.contains("SANDBOX_RESPONSE_TOO_LARGE"),
        "Expected SANDBOX_RESPONSE_TOO_LARGE, got: {big_err}"
    );

    let observed_req_lines = server_thread.join().expect("server thread");
    assert_eq!(observed_req_lines.len(), 3);
    assert_eq!(
        observed_req_lines[0], "POST /api/v1/detonate HTTP/1.1",
        "Base URL without path must route to /api/v1/detonate"
    );

    let _ = fs::remove_dir_all(&dir);
}
