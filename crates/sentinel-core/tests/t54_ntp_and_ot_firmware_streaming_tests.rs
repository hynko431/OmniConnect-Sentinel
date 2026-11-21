//! T54: Honest Air-Gapped NTP / IRIG-B / PTP Clock Attestation (`CSE-26`)
//! & OT Large-File Streaming / Signed Firmware Passthrough (`CSE-27`) Tests.

use sentinel_sys::{
    evaluate_airgap_hardware_clock_attestation, parse_airgap_clock_config_str,
    parse_w32tm_status_output, parse_w32tm_status_output_with_tz_offset, query_ntp_sync_status,
    AirgapHardwareClockAttestation, NTP_MAX_STALE_AGE_SECS,
};

#[test]
fn t54_cse26_honest_airgapped_ntp_w32tm_cmos_stale_and_irig_b_ptp() {
    // Fixed reference UTC timestamp: 2026-11-21 12:00:00 UTC -> 1795262400
    let now_utc =
        sentinel_sys::parse_rfc3339_utc_unix("2026-11-21T12:00:00Z").expect("parse ref utc");

    // 1. Air-gapped Windows kiosk running W32Time on Local CMOS Clock MUST report
    //    ntp_synchronized == false and stratum == None (NEVER fabricate stratum: Some(2)!)
    let cmos_stdout = "\
Leap Indicator: 3(not synchronized)
Stratum: 0 (unspecified)
Precision: -23 (119.209ns per tick)
Root Delay: 0.0000000s
Root Dispersion: 0.0000000s
ReferenceId: 0x00000000 (unspecified)
Last Successful Sync Time: unspecified
Source: Local CMOS Clock
Poll Interval: 10 (1024s)
";
    let cmos_status =
        parse_w32tm_status_output(cmos_stdout, now_utc).expect("parse cmos w32tm output");
    assert!(
        !cmos_status.ntp_synchronized,
        "Local CMOS Clock MUST report ntp_synchronized = false"
    );
    assert_eq!(
        cmos_status.stratum, None,
        "Local CMOS Clock MUST NOT fabricate stratum Some(2)"
    );
    assert!(cmos_status.clock_source.contains("Local CMOS Clock"));

    // 2. Free-running System Clock (even if Stratum claims 1) MUST report unsynchronized
    let freerunning_stdout = "\
Stratum: 1 (primary reference - syncd by radio clock)
Last Successful Sync Time: 2026-11-21 11:55:00
Source: Free-running System Clock
Root Dispersion: 0.0100000s
";
    let fr_status = parse_w32tm_status_output(freerunning_stdout, now_utc)
        .expect("parse free-running w32tm output");
    assert!(!fr_status.ntp_synchronized);
    assert_eq!(fr_status.stratum, None);

    // 3. Stale Last Successful Sync Time (> 24h old: 2026-11-20 10:00:00 = 26h ago) MUST report
    //    ntp_synchronized == false and stratum == None!
    let stale_stdout = "\
Leap Indicator: 0(no warning)
Stratum: 3 (secondary reference - syncd by (S)NTP)
Root Dispersion: 0.0425000s
Last Successful Sync Time: 2026-11-20 10:00:00
Source: time.windows.com,0x9
";
    let stale_status =
        parse_w32tm_status_output(stale_stdout, now_utc).expect("parse stale w32tm output");
    assert!(
        !stale_status.ntp_synchronized,
        "Stale Last Successful Sync Time (>24h) MUST fail closed to ntp_synchronized = false"
    );
    assert_eq!(stale_status.stratum, None);
    assert_eq!(stale_status.max_error_us, Some(42_500));

    // 4. Fresh genuine NTP sync (10 minutes ago, Stratum 3, Root Dispersion 0.0312500s) MUST report
    //    honest ntp_synchronized == true and actual parsed stratum == Some(3)
    let fresh_stdout = "\
Leap Indicator: 0(no warning)
Stratum: 3 (secondary reference - syncd by (S)NTP)
Root Dispersion: 0.0312500s
Last Successful Sync Time: 11/21/2026 11:50:00 AM
Source: ntp01.plant.local,0x9
";
    let fresh_status =
        parse_w32tm_status_output(fresh_stdout, now_utc).expect("parse fresh w32tm output");
    assert!(fresh_status.ntp_synchronized);
    assert_eq!(fresh_status.stratum, Some(3));
    assert_eq!(fresh_status.max_error_us, Some(31_250));
    assert!(fresh_status.clock_source.contains("ntp01.plant.local"));

    // 5. Local timezone offset conversion (+05:30 IST = +19,800s): 21-11-2026 17:20:00 IST == 11:50:00 UTC
    let ist_stdout = "\
Stratum: 2 (secondary reference - syncd by (S)NTP)
Root Dispersion: 0.0120000s
Last Successful Sync Time: 21-11-2026 17:20:00
Source: dc01.corp.local
";
    let ist_status = parse_w32tm_status_output_with_tz_offset(ist_stdout, now_utc, 5 * 3600 + 1800)
        .expect("parse IST w32tm output");
    assert!(ist_status.ntp_synchronized);
    assert_eq!(ist_status.stratum, Some(2));
    assert_eq!(ist_status.max_error_us, Some(12_000));

    // 6. Explicit Air-Gapped Hardware Clock Attestation (`IRIG-B` & IEEE-1588 `PTP`)
    let irig_json = format!(
        r#"{{"protocol":"IRIG-B","device_id":"Meinberg-PCIe-IRIG0","stratum":1,"locked":true,"last_locked_unix":{},"max_error_us":25}}"#,
        now_utc - 60
    );
    let irig_cfg = parse_airgap_clock_config_str(&irig_json).expect("parse IRIG-B JSON");
    let irig_status = evaluate_airgap_hardware_clock_attestation(&irig_cfg, now_utc)
        .expect("evaluate IRIG-B status");
    assert!(irig_status.ntp_synchronized);
    assert_eq!(irig_status.stratum, Some(1));
    assert_eq!(irig_status.max_error_us, Some(25));
    assert_eq!(
        irig_status.clock_source,
        "HardwareClock(IRIG-B):Meinberg-PCIe-IRIG0"
    );

    // Key=value PTP hardware clock configuration
    let ptp_kv = format!(
        "protocol=PTP\ndevice_id=ptp0-grandmaster\nstratum=2\nlocked=true\nlast_locked_unix={}\nmax_error_us=5\n",
        now_utc - 30
    );
    let ptp_cfg = parse_airgap_clock_config_str(&ptp_kv).expect("parse PTP kv");
    let ptp_status =
        evaluate_airgap_hardware_clock_attestation(&ptp_cfg, now_utc).expect("evaluate PTP status");
    assert!(ptp_status.ntp_synchronized);
    assert_eq!(ptp_status.stratum, Some(2));
    assert_eq!(
        ptp_status.clock_source,
        "HardwareClock(PTP):ptp0-grandmaster"
    );

    // Stale (> 24h) or unlocked hardware receiver MUST report ntp_synchronized == false and stratum == None
    let stale_irig = AirgapHardwareClockAttestation {
        last_locked_unix: now_utc - NTP_MAX_STALE_AGE_SECS - 10,
        ..irig_cfg.clone()
    };
    let stale_irig_status = evaluate_airgap_hardware_clock_attestation(&stale_irig, now_utc)
        .expect("evaluate stale IRIG-B");
    assert!(!stale_irig_status.ntp_synchronized);
    assert_eq!(stale_irig_status.stratum, None);

    let unlocked_irig = AirgapHardwareClockAttestation {
        locked: false,
        ..irig_cfg
    };
    let unlocked_status = evaluate_airgap_hardware_clock_attestation(&unlocked_irig, now_utc)
        .expect("evaluate unlocked IRIG-B");
    assert!(!unlocked_status.ntp_synchronized);
    assert_eq!(unlocked_status.stratum, None);

    // Unsupported protocol or unknown config key MUST fail closed (None)
    assert!(
        parse_airgap_clock_config_str(
            r#"{"protocol":"IRIG-B","device_id":"x","stratum":1,"locked":true,"last_locked_unix":100,"max_error_us":5,"smuggled":true}"#
        )
        .is_none(),
        "Unknown field in airgap clock config MUST fail closed"
    );
    let invalid_proto = AirgapHardwareClockAttestation {
        protocol: "MOCK_CLOCK".to_string(),
        device_id: "fake0".to_string(),
        stratum: 1,
        locked: true,
        last_locked_unix: now_utc,
        max_error_us: 1,
    };
    assert!(evaluate_airgap_hardware_clock_attestation(&invalid_proto, now_utc).is_none());

    // 7. Live OS query must never panic and must stay truthful on CMOS fallback
    let live_ntp = query_ntp_sync_status();
    assert!(!live_ntp.clock_source.trim().is_empty());
    if live_ntp.clock_source.contains("Local CMOS Clock") {
        assert!(!live_ntp.ntp_synchronized);
        assert_eq!(live_ntp.stratum, None);
    }
}

fn build_verified_worker_launcher_for_t54() -> sentinel_cdr::WorkerLauncher {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let worker_name = if cfg!(windows) {
        "sentinel-cdr-worker.exe"
    } else {
        "sentinel-cdr-worker"
    };
    let current_exe = std::env::current_exe().expect("current_exe");
    let profile_dir = current_exe
        .ancestors()
        .skip(1)
        .find(|a| {
            matches!(
                a.file_name().and_then(|n| n.to_str()),
                Some("debug" | "release")
            )
        })
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| workspace_root.join("target").join("debug"));
    let worker_exe = profile_dir.join(worker_name);
    if !worker_exe.is_file() {
        let mut cmd = std::process::Command::new("cargo");
        cmd.current_dir(workspace_root).args([
            "build",
            "-p",
            "sentinel-cdr",
            "--bin",
            "sentinel-cdr-worker",
            "--offline",
        ]);
        if profile_dir.file_name().and_then(|n| n.to_str()) == Some("release") {
            cmd.arg("--release");
        }
        let status = cmd.status().expect("build sentinel-cdr-worker for t54");
        assert!(status.success(), "building sentinel-cdr-worker failed");
    }
    let default_launcher = sentinel_cdr::WorkerLauncher::new().with_worker_bin(worker_exe.clone());
    match default_launcher.sanitize_isolated(sentinel_cdr::WorkerRequest {
        file_name: "probe.txt".to_string(),
        policy: sentinel_cdr::SanitizationPolicy::default(),
        raw_bytes: b"probe".to_vec(),
    }) {
        Ok(_) => default_launcher,
        Err(err)
            if cfg!(windows)
                && (err.to_string().contains("os error 87")
                    || err.to_string().contains("CreateProcessW failed")) =>
        {
            sentinel_cdr::WorkerLauncher::new()
                .with_worker_bin(worker_exe)
                .with_sandbox_config(sentinel_sys::JobSandboxConfig {
                    enable_appcontainer: false,
                    ..Default::default()
                })
        }
        Err(err) => panic!("Unexpected CDR worker probe failure: {err}"),
    }
}

#[test]
fn t54_cse27_streaming_large_firmware_passthrough_and_unsigned_rejection() {
    use sentinel_core::enterprise::ledger::create_shared_audit_ledger;
    use sentinel_core::scanner::tier0_yara::{DynamicYaraRule, SignedRulePack, Tier0YaraScanner};
    use sentinel_core::vfs::{
        OtLargeFirmwarePolicy, ShadowCacheManager, VendorFirmwareSignatureManifest,
        OT_FIRMWARE_SIG_SUFFIX,
    };
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    let tmp = tempfile::tempdir().expect("tempdir");
    let raw_usb = tmp.path().join("ot_usb_volume");
    let virt_mount = tmp.path().join("ot_virtual_mount");
    let cache_root = tmp.path().join("ot_shadow_cache");
    let ledger_path = tmp.path().join("ot_streaming_ledger.jsonl");
    let yara_dir = tmp.path().join("offline_yara_packs");
    std::fs::create_dir_all(&raw_usb).expect("mkdir raw_usb");
    std::fs::create_dir_all(&yara_dir).expect("mkdir yara_dir");

    let (vendor_pub, vendor_priv) =
        sentinel_sys::generate_raw_ecdsa_p256_keypair().expect("vendor keypair");
    let (yara_pub, yara_priv) =
        sentinel_sys::generate_raw_ecdsa_p256_keypair().expect("yara keypair");

    // Persist a signed offline YARA rule pack catching an OT PLC trojan marker (`PLC_STUX_TROJAN_MARKER`)
    let ot_marker = b"PLC_STUX_TROJAN_MARKER_2026";
    let signed_pack = SignedRulePack::sign(
        "OT-ICS-PACK-01",
        2,
        vec![DynamicYaraRule {
            id: "YARA_OT_PLC_TROJAN".to_string(),
            description: "Detects unauthorized PLC ladder-logic implant marker".to_string(),
            required_markers_hex: vec![hex::encode(ot_marker)],
            min_matches: 1,
            requires_pe_header: false,
        }],
        &yara_priv,
        &yara_pub,
    )
    .expect("sign yara pack");
    std::fs::write(
        yara_dir.join("001_ot_ics_v2.json"),
        serde_json::to_string_pretty(&signed_pack).expect("serialize pack"),
    )
    .expect("write yara pack");

    let shared_ledger = create_shared_audit_ledger(&ledger_path).expect("ledger");
    let mut yara_scanner = Tier0YaraScanner::new().with_shared_ledger(shared_ledger.clone());
    let loaded = yara_scanner
        .load_persisted_signed_rule_packs(&yara_dir, std::slice::from_ref(&yara_pub))
        .expect("load signed offline YARA pack");
    assert_eq!(loaded, 1);

    // 1. Large (512 KiB = 8 x 64 KiB streaming chunks) validly signed vendor PLC firmware bundle
    let mut valid_fw = vec![0x42u8; 512 * 1024];
    valid_fw[..16].copy_from_slice(b"SIEMENS_PLC_FW5\0");
    let valid_fw_sha = hex::encode(Sha256::digest(&valid_fw));
    let valid_fw_path = raw_usb.join("siemens_plc_fw_v5.bin");
    std::fs::write(&valid_fw_path, &valid_fw).expect("write valid fw");
    let valid_sig = VendorFirmwareSignatureManifest::sign(
        "Siemens Energy OT",
        "siemens_plc_fw_v5.bin",
        valid_fw.len() as u64,
        &valid_fw_sha,
        &vendor_priv,
        &vendor_pub,
    )
    .expect("sign valid fw");
    std::fs::write(
        format!("{}{}", valid_fw_path.display(), OT_FIRMWARE_SIG_SUFFIX),
        serde_json::to_string_pretty(&valid_sig).expect("serialize valid sig"),
    )
    .expect("write valid sig");

    // 2. Large (300 KiB) unsigned opaque binary -> MUST be withheld WITHOUT aborting the USB volume!
    let unsigned_blob = vec![0x99u8; 300 * 1024];
    std::fs::write(raw_usb.join("unsigned_opaque_blob.bin"), &unsigned_blob)
        .expect("write unsigned blob");

    // 3. Large (300 KiB) 1-byte tampered signed firmware -> MUST fail signature verification and be withheld!
    let mut tampered_fw = vec![0x55u8; 300 * 1024];
    let orig_tampered_sha = hex::encode(Sha256::digest(&tampered_fw));
    let tampered_sig = VendorFirmwareSignatureManifest::sign(
        "Siemens Energy OT",
        "tampered_plc_fw.bin",
        tampered_fw.len() as u64,
        &orig_tampered_sha,
        &vendor_priv,
        &vendor_pub,
    )
    .expect("sign pre-tamper fw");
    tampered_fw[200_000] ^= 0x01; // Flip 1 byte past chunk #3
    let tampered_fw_path = raw_usb.join("tampered_plc_fw.bin");
    std::fs::write(&tampered_fw_path, &tampered_fw).expect("write tampered fw");
    std::fs::write(
        format!("{}{}", tampered_fw_path.display(), OT_FIRMWARE_SIG_SUFFIX),
        serde_json::to_string_pretty(&tampered_sig).expect("serialize tampered sig"),
    )
    .expect("write tampered sig");

    // 4. Large (300 KiB) validly signed firmware containing a YARA trojan marker spanning a 64 KiB chunk boundary -> MUST be blocked by streaming YARA!
    let mut infected_fw = vec![0x33u8; 300 * 1024];
    let boundary_offset = 65_530; // spans across 64 KiB boundary (65536)!
    infected_fw[boundary_offset..boundary_offset + ot_marker.len()].copy_from_slice(ot_marker);
    let infected_sha = hex::encode(Sha256::digest(&infected_fw));
    let infected_fw_path = raw_usb.join("infected_signed_fw.bin");
    std::fs::write(&infected_fw_path, &infected_fw).expect("write infected fw");
    let infected_sig = VendorFirmwareSignatureManifest::sign(
        "Siemens Energy OT",
        "infected_signed_fw.bin",
        infected_fw.len() as u64,
        &infected_sha,
        &vendor_priv,
        &vendor_pub,
    )
    .expect("sign infected fw");
    std::fs::write(
        format!("{}{}", infected_fw_path.display(), OT_FIRMWARE_SIG_SUFFIX),
        serde_json::to_string_pretty(&infected_sig).expect("serialize infected sig"),
    )
    .expect("write infected sig");

    // 5. Clean small sibling document proving no whole-USB abort occurs
    std::fs::write(
        raw_usb.join("maintenance_notes.txt"),
        b"Turbine maintenance step 1: verify signed PLC firmware.\n",
    )
    .expect("write notes");

    let ot_policy = OtLargeFirmwarePolicy {
        allowlisted_vendor_p256_keys: vec![vendor_pub],
        ..OtLargeFirmwarePolicy::default()
    };
    let shadow_cache = ShadowCacheManager::with_cache_root_and_quota(cache_root, 16 * 1024 * 1024)
        .with_large_file_stream_threshold(128 * 1024) // trigger O(64 KiB) streaming above 128 KiB
        .with_ot_firmware_policy(ot_policy)
        .with_yara_scanner(Arc::new(yara_scanner))
        .with_worker_launcher(build_verified_worker_launcher_for_t54())
        .with_shared_ledger(shared_ledger);

    let projected_count = shadow_cache
        .ingest_volume_read_once(&raw_usb, &virt_mount)
        .expect("CSE-27: large files MUST NOT abort whole-USB ingestion");
    assert_eq!(
        projected_count, 2,
        "Only verified signed PLC firmware + clean maintenance_notes.txt must be projected"
    );

    // Stream-decrypt the 512 KiB verified PLC firmware in O(64 KiB) RAM and assert exact byte-for-byte match
    let mut streamed_out = Vec::new();
    let written = shadow_cache
        .stream_projected_file_to_writer(
            &virt_mount,
            std::path::Path::new("siemens_plc_fw_v5.bin"),
            &mut streamed_out,
        )
        .expect("stream decrypt verified PLC firmware");
    assert_eq!(written, valid_fw.len() as u64);
    assert_eq!(streamed_out, valid_fw);

    // Clean sibling file also projected intact
    let notes_bytes = shadow_cache
        .read_projected_file(&virt_mount, std::path::Path::new("maintenance_notes.txt"))
        .expect("read projected sibling txt");
    assert!(String::from_utf8_lossy(&notes_bytes).contains("Turbine maintenance"));

    // Unsigned, 1-byte tampered, and YARA-infected large files MUST NOT be projected and MUST be withheld
    for blocked in [
        "unsigned_opaque_blob.bin",
        "tampered_plc_fw.bin",
        "infected_signed_fw.bin",
    ] {
        assert!(
            shadow_cache
                .read_projected_file(&virt_mount, std::path::Path::new(blocked))
                .is_err(),
            "Blocked large file '{blocked}' must NOT exist in projected ShadowCache"
        );
    }
    let withheld = shadow_cache.take_withheld_threats(&virt_mount);
    assert!(
        withheld
            .iter()
            .any(|t| t.threat_name == "UNSIGNED_LARGE_OPAQUE_BINARY"),
        "Unsigned/tampered large files must be recorded as UNSIGNED_LARGE_OPAQUE_BINARY"
    );
    assert!(
        withheld
            .iter()
            .any(|t| t.threat_name == "YARA_OT_PLC_TROJAN"),
        "Cross-64KiB-boundary YARA trojan in signed firmware must be caught and withheld"
    );

    let ledger_text = std::fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(ledger_text.contains("OT_LARGE_FIRMWARE_VERIFIED_PASSTHROUGH"));
    assert!(ledger_text.contains("OT_LARGE_FILE_UNSIGNED_REJECTED"));
    assert!(ledger_text.contains("SHADOW_CACHE_THREAT_WITHHELD"));

    shadow_cache
        .teardown_session(&virt_mount)
        .expect("teardown shadow session");
}

#[test]
fn t54_cse27_persisted_signed_offline_yara_packs_and_pluggable_av_adapters() {
    use sentinel_core::enterprise::ledger::create_shared_audit_ledger;
    use sentinel_core::scanner::av_adapter::{
        build_icap_respmod_header, parse_icap_respmod_response, validate_icap_target_addr,
        CliAvAdapter, ExternalAvScannerAdapter, IcapAvAdapter,
    };
    use sentinel_core::scanner::tier0_yara::{DynamicYaraRule, SignedRulePack, Tier0YaraScanner};
    use sentinel_core::scanner::universal_scanner::UniversalScanner;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};

    let tmp = tempfile::tempdir().expect("tempdir");
    let ledger_path = tmp.path().join("yara_av_ledger.jsonl");
    let shared_ledger = create_shared_audit_ledger(&ledger_path).expect("ledger");

    let (root_pub, root_priv) = sentinel_sys::generate_raw_ecdsa_p256_keypair().expect("root");
    let (rogue_pub, rogue_priv) = sentinel_sys::generate_raw_ecdsa_p256_keypair().expect("rogue");

    // 1. Unsigned pack MUST fail closed (zero unsigned rule loading!)
    let unsigned_dir = tmp.path().join("unsigned_yara");
    std::fs::create_dir_all(&unsigned_dir).expect("mkdir unsigned");
    std::fs::write(
        unsigned_dir.join("unsigned_rules.json"),
        r#"{"pack_id":"UNTRUSTED","version":2,"rules":[]}"#,
    )
    .expect("write unsigned");
    let mut scanner = Tier0YaraScanner::new().with_shared_ledger(shared_ledger.clone());
    assert!(
        scanner
            .load_persisted_signed_rule_packs(&unsigned_dir, std::slice::from_ref(&root_pub))
            .is_err(),
        "Unsigned offline YARA rule pack MUST fail closed"
    );

    // 2. Rogue-signed pack MUST fail closed
    let rogue_dir = tmp.path().join("rogue_yara");
    std::fs::create_dir_all(&rogue_dir).expect("mkdir rogue");
    let rogue_pack = SignedRulePack::sign(
        "ROGUE-PACK",
        2,
        vec![DynamicYaraRule {
            id: "ROGUE_RULE".to_string(),
            description: "rogue".to_string(),
            required_markers_hex: vec![hex::encode(b"ROGUE")],
            min_matches: 1,
            requires_pe_header: false,
        }],
        &rogue_priv,
        &rogue_pub,
    )
    .expect("sign rogue");
    std::fs::write(
        rogue_dir.join("rogue.json"),
        serde_json::to_string_pretty(&rogue_pack).expect("ser"),
    )
    .expect("write rogue");
    assert!(
        scanner
            .load_persisted_signed_rule_packs(&rogue_dir, std::slice::from_ref(&root_pub))
            .is_err(),
        "Untrusted-signer offline YARA pack MUST fail closed"
    );

    // 3. Monotonic signed packs (v2 then v3) load cleanly; downgrade (v2 again) fails closed
    let valid_dir = tmp.path().join("valid_yara");
    std::fs::create_dir_all(&valid_dir).expect("mkdir valid");
    let p2 = SignedRulePack::sign(
        "ENT-OT-PACK",
        2,
        vec![DynamicYaraRule {
            id: "YARA_CUSTOM_OT_V2".to_string(),
            description: "OT custom rule v2".to_string(),
            required_markers_hex: vec![hex::encode(b"CUSTOM_MODBUS_IMPLANT_V2")],
            min_matches: 1,
            requires_pe_header: false,
        }],
        &root_priv,
        &root_pub,
    )
    .expect("sign v2");
    let p3 = SignedRulePack::sign(
        "ENT-OT-PACK",
        3,
        vec![DynamicYaraRule {
            id: "YARA_CUSTOM_OT_V3".to_string(),
            description: "OT custom rule v3".to_string(),
            required_markers_hex: vec![hex::encode(b"CUSTOM_DNP3_IMPLANT_V3")],
            min_matches: 1,
            requires_pe_header: false,
        }],
        &root_priv,
        &root_pub,
    )
    .expect("sign v3");
    std::fs::write(
        valid_dir.join("01_v2.json"),
        serde_json::to_string_pretty(&p2).expect("ser v2"),
    )
    .expect("write v2");
    std::fs::write(
        valid_dir.join("02_v3.json"),
        serde_json::to_string_pretty(&p3).expect("ser v3"),
    )
    .expect("write v3");

    let loaded = scanner
        .load_persisted_signed_rule_packs(&valid_dir, std::slice::from_ref(&root_pub))
        .expect("load monotonic v2+v3 packs");
    assert_eq!(loaded, 2);
    assert_eq!(scanner.rule_pack_version(), 3);
    assert!(
        scanner.apply_signed_rule_pack(&p2, &root_pub).is_err(),
        "Rollback from v3 to v2 MUST fail closed"
    );

    // 4. Pluggable AV CLI & ICAP Adapter Verification (live loopback RFC 3507 ICAP mock server)
    assert!(
        CliAvAdapter::new("clamav", std::path::PathBuf::from("clamdscan"), vec![]).is_err(),
        "CliAvAdapter MUST reject relative binary path to prevent PATH hijacking"
    );
    let imds_addr: SocketAddr = "169.254.169.254:1344".parse().expect("imds addr");
    assert!(
        validate_icap_target_addr(imds_addr, &[]).is_err(),
        "ICAP adapter MUST block SSRF to cloud metadata 169.254.169.254"
    );
    let hdr = build_icap_respmod_header("127.0.0.1", 1344, "avscan", "plc.bin", 42)
        .expect("build icap header");
    assert!(hdr.starts_with("RESPMOD icap://127.0.0.1:1344/avscan ICAP/1.0\r\n"));
    let clean_parsed =
        parse_icap_respmod_response("mock-icap", "ICAP/1.0 204 No Modification\r\n\r\n")
            .expect("parse 204");
    assert!(!clean_parsed.infected);
    let inf_parsed = parse_icap_respmod_response(
        "mock-icap",
        "ICAP/1.0 200 OK\r\nX-Infection-Found: Type=0; Resolution=2; Threat=OT.Modbus.Worm;\r\n\r\n",
    )
    .expect("parse infected");
    assert!(inf_parsed.infected);
    assert_eq!(inf_parsed.signature_name.as_deref(), Some("OT.Modbus.Worm"));

    // Live loopback ICAP TCP server integration with UniversalScanner::scan_file_with_scanner_and_av
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock icap");
    let server_addr = listener.local_addr().expect("local addr");
    let srv_handle = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut full_req = Vec::new();
            let mut req_buf = [0u8; 4096];
            while let Ok(n) = sock.read(&mut req_buf) {
                if n == 0 {
                    break;
                }
                full_req.extend_from_slice(&req_buf[..n]);
                if full_req.windows(7).any(|w| w == b"\r\n0\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(
                b"ICAP/1.0 200 OK\r\nISTag: \"SENTINEL-MOCK\"\r\nX-Infection-Found: Type=0; Resolution=2; Threat=ICAP.OT.Dropper.A;\r\n\r\n",
            );
            let _ = sock.flush();
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
    });

    let sample_file = tmp.path().join("dnp3_sample.bin");
    std::fs::write(&sample_file, b"HEADER_OK_CUSTOM_DNP3_IMPLANT_V3_END").expect("write sample");

    let icap = IcapAvAdapter::new("LoopbackICAP", server_addr, "avscan", vec![])
        .expect("init loopback icap");
    let adapters: Vec<&dyn ExternalAvScannerAdapter> = vec![&icap];
    let threats =
        UniversalScanner::scan_file_with_scanner_and_av(&sample_file, &scanner, &adapters)
            .expect("scan with offline YARA + ICAP adapter");
    let _ = srv_handle.join();

    assert!(
        threats.iter().any(|t| t.threat_name == "YARA_CUSTOM_OT_V3"),
        "UniversalScanner MUST match persisted signed offline YARA rule v3"
    );
    assert!(
        threats
            .iter()
            .any(|t| t.threat_name == "EXTERNAL_AV_LoopbackICAP:ICAP.OT.Dropper.A"),
        "UniversalScanner MUST surface pluggable ICAP AV infection verdict; actual threats={threats:?}"
    );
}

#[test]
fn t54_cse27_physical_bay1_ro_bay2_rw_hardware_write_blocker_posture() {
    use sentinel_core::enterprise::kiosk::{KioskConfig, KioskEnforcer};
    use sentinel_sys::{
        detect_hardware_write_blocker_state, HardwareWriteBlockerState, PostureReport,
        UsbVolumeInfo, BUS_TYPE_USB,
    };
    use std::path::PathBuf;

    let bay1_ro = UsbVolumeInfo {
        volume_guid_path: r"\\?\Volume{BAY1-0000-0000-0000-000000000001}\".to_string(),
        mount_points: vec![PathBuf::from(r"E:\")],
        physical_drive_number: Some(1),
        bus_type: BUS_TYPE_USB,
        is_removable_media: true,
        is_offline: true,
        is_readonly: true,
        usb_device_instance_id: Some(r"USB\VID_0781&PID_5583\BAY1_RO".to_string()),
        usb_device_desc: Some("Hardware Write-Blocker Bay 1".to_string()),
    };
    let bay2_rw = UsbVolumeInfo {
        volume_guid_path: r"\\?\Volume{BAY2-0000-0000-0000-000000000002}\".to_string(),
        mount_points: vec![PathBuf::from(r"F:\")],
        physical_drive_number: Some(2),
        bus_type: BUS_TYPE_USB,
        is_removable_media: true,
        is_offline: true,
        is_readonly: false,
        usb_device_instance_id: Some(r"USB\VID_0951&PID_1666\BAY2_RW".to_string()),
        usb_device_desc: Some("Sanitized Export Bay 2".to_string()),
    };

    // 1. Default without bay hints MUST honestly report NotDetected
    assert_eq!(
        detect_hardware_write_blocker_state(None, None, &[bay1_ro.clone(), bay2_rw.clone()]),
        HardwareWriteBlockerState::NotDetected
    );

    // 2. Verified Bay-1 RO + Bay-2 RW reports DualBayVerified and passes kiosk compliance
    let dual = detect_hardware_write_blocker_state(
        Some(r"USB\VID_0781&PID_5583\BAY1_RO"),
        Some(r"USB\VID_0951&PID_1666\BAY2_RW"),
        &[bay1_ro.clone(), bay2_rw.clone()],
    );
    assert!(matches!(
        dual,
        HardwareWriteBlockerState::DualBayVerified { .. }
    ));
    assert!(
        KioskEnforcer::format_hardware_write_blocker_banner(&dual).contains("DUAL_BAY_VERIFIED")
    );

    // 3. Bay-1 reporting WRITABLE (write-blocker disengaged!) MUST return Faulted and block Kiosk startup!
    let mut bay1_writable = bay1_ro.clone();
    bay1_writable.is_readonly = false;
    let faulted = detect_hardware_write_blocker_state(
        Some(r"USB\VID_0781&PID_5583\BAY1_RO"),
        Some(r"USB\VID_0951&PID_1666\BAY2_RW"),
        &[bay1_writable, bay2_rw.clone()],
    );
    assert!(matches!(faulted, HardwareWriteBlockerState::Faulted { .. }));

    let faulted_posture = PostureReport {
        automount_disabled: true,
        removable_volumes_offline: vec![],
        user_deny_policy_present: true,
        install_restrictions_active: true,
        write_protect_active: true,
        autoplay_suppressed: true,
        linux_authorized_default_zero: Some(true),
        hardware_write_blocker: faulted,
    };
    assert!(
        !faulted_posture.is_compliant(),
        "Faulted hardware write-blocker MUST fail PostureReport::is_compliant()"
    );
    assert!(!faulted_posture.is_compliant_for_linux());

    let tmp = tempfile::tempdir().expect("tempdir");
    let ledger_path = tmp.path().join("hw_wb_kiosk_ledger.jsonl");
    let mut kiosk = KioskEnforcer::new(KioskConfig::default(), tmp.path().join("kiosk_sess"))
        .with_ledger_path(ledger_path.clone());
    assert!(
        kiosk
            .begin_kiosk_session_with_posture(&faulted_posture)
            .is_err(),
        "Faulted hardware write-blocker MUST block strict kiosk session startup"
    );
    let ledger_text = std::fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(ledger_text.contains("KIOSK_POSTURE_BLOCKED"));
    assert!(ledger_text.contains("hardware_write_blocker"));

    // 4. Bay-1 / Bay-2 alias collision MUST return Faulted
    let aliased = detect_hardware_write_blocker_state(
        Some(r"USB\VID_0781&PID_5583\BAY1_RO"),
        Some(r"USB\VID_0781&PID_5583\BAY1_RO"),
        &[bay1_ro],
    );
    assert!(matches!(aliased, HardwareWriteBlockerState::Faulted { .. }));
}

#[test]
fn t54_cse27_pass2_quota_isolation_short_read_overlap_truncated_icap_and_ipv6() {
    use sentinel_core::scanner::av_adapter::{
        build_icap_respmod_header, parse_icap_respmod_response, ExternalAvScannerAdapter,
        IcapAvAdapter,
    };
    use sentinel_core::scanner::tier0_yara::{DynamicYaraRule, SignedRulePack, Tier0YaraScanner};
    use sentinel_core::vfs::{
        OtLargeFirmwarePolicy, ShadowCacheManager, VendorFirmwareSignatureManifest,
        OT_FIRMWARE_SIG_SUFFIX,
    };
    use sentinel_sys::generate_raw_ecdsa_p256_keypair;
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::net::TcpListener;
    use std::path::Path;

    // 1. Short partial reads (< 4 KiB, 10 bytes per read) splitting a 27-byte marker across 3 reads
    //    MUST still trigger YARA in BOTH `StreamingYaraAccumulator::update` AND `scan_reader`!
    struct TenBytePartialReader<'a> {
        inner: Cursor<&'a [u8]>,
    }
    impl Read for TenBytePartialReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let cap = buf.len().min(10);
            self.inner.read(&mut buf[..cap])
        }
    }
    impl Seek for TenBytePartialReader<'_> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let yara_dir = tmp.path().join("short_chunk_yara_packs");
    std::fs::create_dir_all(&yara_dir).expect("mkdir yara dir");
    let (yara_pub, yara_priv) = generate_raw_ecdsa_p256_keypair().expect("yara keypair");
    let ot_marker = b"PLC_STUX_TROJAN_MARKER_2026";
    let pack = SignedRulePack::sign(
        "OT-SHORT-CHUNK-01",
        2,
        vec![DynamicYaraRule {
            id: "YARA_SHORT_CHUNK_MARKER".to_string(),
            description: "Multi-chunk short read boundary test".to_string(),
            required_markers_hex: vec![hex::encode(ot_marker)],
            min_matches: 1,
            requires_pe_header: false,
        }],
        &yara_priv,
        &yara_pub,
    )
    .expect("sign short chunk pack");
    std::fs::write(
        yara_dir.join("001_short_chunk.json"),
        serde_json::to_string_pretty(&pack).expect("json pack"),
    )
    .expect("write pack");

    let mut yara = Tier0YaraScanner::new();
    let loaded = yara
        .load_persisted_signed_rule_packs(&yara_dir, std::slice::from_ref(&yara_pub))
        .expect("load short chunk pack");
    assert_eq!(loaded, 1);

    let mut split_payload = vec![0x41u8; 5000];
    split_payload.extend_from_slice(ot_marker);
    split_payload.extend_from_slice(&[0x42u8; 5000]);

    // 1a. StreamingYaraAccumulator with 10-byte updates
    let mut acc = yara.begin_streaming_scan();
    for piece in split_payload.chunks(10) {
        acc.update(piece);
    }
    let (acc_res, _, _) = acc.finalize_with_digest();
    assert!(
        acc_res.matched && acc_res.rule_name.as_deref() == Some("YARA_SHORT_CHUNK_MARKER"),
        "StreamingYaraAccumulator MUST catch 27-byte marker split across 10-byte reads"
    );

    // 1b. Tier0YaraScanner::scan_reader with 10-byte partial reads
    let mut partial = TenBytePartialReader {
        inner: Cursor::new(&split_payload),
    };
    let reader_res = yara.scan_reader(&mut partial, "split_firmware.bin");
    assert!(
        reader_res.matched && reader_res.rule_name.as_deref() == Some("YARA_SHORT_CHUNK_MARKER"),
        "Tier0YaraScanner::scan_reader MUST catch 27-byte marker split across 10-byte reads"
    );

    // 2. Truncated ICAP response headers MUST fail closed (never treated as CLEAN),
    //    and IPv6 hosts MUST be bracketed per RFC 3986 / RFC 3507.
    let v6_hdr = build_icap_respmod_header("::1", 1344, "avscan", "plc.bin", 12)
        .expect("build IPv6 icap header");
    assert!(
        v6_hdr.starts_with("RESPMOD icap://[::1]:1344/avscan ICAP/1.0\r\n")
            && v6_hdr.contains("Host: [::1]:1344\r\n"),
        "IPv6 ICAP host literal MUST be RFC 3986 bracketed; got: {v6_hdr}"
    );
    assert!(
        parse_icap_respmod_response("mock-icap", "ICAP/1.0 200 OK\r\n").is_err(),
        "Truncated ICAP header missing CRLFCRLF MUST fail closed!"
    );

    let trunc_sample = tmp.path().join("trunc_sample.bin");
    std::fs::write(&trunc_sample, b"SAMPLE_BYTES").expect("write trunc sample");
    let trunc_listener = TcpListener::bind("127.0.0.1:0").expect("bind trunc icap");
    let trunc_addr = trunc_listener.local_addr().expect("trunc addr");
    let trunc_srv = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = trunc_listener.accept() {
            let mut req = Vec::new();
            let mut buf = [0u8; 2048];
            while let Ok(n) = sock.read(&mut buf) {
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(7).any(|w| w == b"\r\n0\r\n\r\n") {
                    break;
                }
            }
            // Deliberately drop socket mid-header before `\r\n\r\n` and before X-Infection-Found
            let _ = sock.write_all(b"ICAP/1.0 200 OK\r\nISTag: \"PARTIAL\"");
            let _ = sock.flush();
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
    });
    let trunc_icap =
        IcapAvAdapter::new("TruncICAP", trunc_addr, "avscan", vec![]).expect("init trunc icap");
    assert!(
        trunc_icap.scan_file_path(&trunc_sample).is_err(),
        "Live ICAP server truncating header before CRLFCRLF MUST fail closed!"
    );
    let _ = trunc_srv.join();

    // 3. Quota isolation when `max_cache_bytes == large_file_stream_threshold_bytes` (default parity):
    //    a verified > threshold PLC firmware MUST NOT consume `max_cache_bytes` and abort sibling files,
    //    AND cumulative streamed firmware cap MUST reject a second firmware exceeding the cumulative budget per-file,
    //    AND unpinned Authenticode PE passthrough MUST fail closed without re-reading USB!
    let usb_root = tmp.path().join("usb_quota_parity");
    let cache_root = tmp.path().join("cache_quota_parity");
    let mount_root = tmp.path().join("mount_quota_parity");
    std::fs::create_dir_all(&usb_root).expect("usb dir");
    std::fs::create_dir_all(&cache_root).expect("cache dir");
    std::fs::create_dir_all(&mount_root).expect("mount dir");

    let (vendor_pub, vendor_priv) = generate_raw_ecdsa_p256_keypair().expect("vendor keypair");

    // 3a. Signed 512 KiB PLC firmware #1 (exceeds 256 KiB threshold AND 256 KiB max_cache_bytes!)
    let fw1_bytes = vec![0x5Au8; 512 * 1024];
    let fw1_sha = hex::encode(Sha256::digest(&fw1_bytes));
    let fw1_path = usb_root.join("01_siemens_plc.fw");
    std::fs::write(&fw1_path, &fw1_bytes).expect("write fw1");
    let m1 = VendorFirmwareSignatureManifest::sign(
        "Siemens-OT",
        "01_siemens_plc.fw",
        fw1_bytes.len() as u64,
        &fw1_sha,
        &vendor_priv,
        &vendor_pub,
    )
    .expect("sign fw1");
    std::fs::write(
        usb_root.join(format!("01_siemens_plc.fw{OT_FIRMWARE_SIG_SUFFIX}")),
        serde_json::to_vec_pretty(&m1).expect("json m1"),
    )
    .expect("write m1");

    // 3b. Signed 512 KiB PLC firmware #2 pushing cumulative streamed bytes (1024 KiB) over 768 KiB cap
    let fw2_bytes = vec![0x6Bu8; 512 * 1024];
    let fw2_sha = hex::encode(Sha256::digest(&fw2_bytes));
    let fw2_path = usb_root.join("02_overflow_plc.fw");
    std::fs::write(&fw2_path, &fw2_bytes).expect("write fw2");
    let m2 = VendorFirmwareSignatureManifest::sign(
        "Siemens-OT",
        "02_overflow_plc.fw",
        fw2_bytes.len() as u64,
        &fw2_sha,
        &vendor_priv,
        &vendor_pub,
    )
    .expect("sign fw2");
    std::fs::write(
        usb_root.join(format!("02_overflow_plc.fw{OT_FIRMWARE_SIG_SUFFIX}")),
        serde_json::to_vec_pretty(&m2).expect("json m2"),
    )
    .expect("write m2");

    // 3c. Large PE without sidecar + unpinned Authenticode -> MUST be rejected per-file (fail-closed)
    let mut unpinned_pe = vec![0x00u8; 300 * 1024];
    unpinned_pe[0..2].copy_from_slice(b"MZ");
    unpinned_pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    unpinned_pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    std::fs::write(usb_root.join("03_unpinned_installer.bin"), &unpinned_pe).expect("write pe");

    // 3d. Small clean sibling file that MUST still pass CDR & cache despite fw1 > max_cache_bytes!
    std::fs::write(
        usb_root.join("99_operator_readme.txt"),
        b"Shift handover clean notes.\n",
    )
    .expect("write sibling txt");

    let ot_policy = OtLargeFirmwarePolicy {
        allowlisted_vendor_p256_keys: vec![vendor_pub],
        allow_authenticode_pe_passthrough: true,
        allowlisted_authenticode_sha256: Vec::new(), // unpinned -> must refuse PE fail-closed
        max_streamed_firmware_bytes: 900 * 1024, // allows 1x 512 KiB fw + leaves 388 KiB to test 300 KiB unpinned PE rejection, while rejecting 2nd 512 KiB fw cumulative
        ..OtLargeFirmwarePolicy::default()
    };
    let launcher = build_verified_worker_launcher_for_t54();
    // Crucial parity test: `max_cache_bytes == large_file_stream_threshold_bytes == 256 KiB`!
    let manager = ShadowCacheManager::with_cache_root_and_quota(cache_root, 256 * 1024)
        .with_large_file_stream_threshold(256 * 1024)
        .with_ot_firmware_policy(ot_policy)
        .with_worker_launcher(launcher);

    let projected = manager
        .ingest_volume_read_once(&usb_root, &mount_root)
        .expect("USB session MUST NOT abort with CacheQuotaExceeded after >threshold firmware");
    assert_eq!(
        projected, 2,
        "Expected exactly 2 projected files (1 signed firmware + 1 small clean sibling)"
    );
    let sibling_bytes = manager
        .read_projected_file(&mount_root, Path::new("99_operator_readme.txt"))
        .expect("small sibling file MUST still project cleanly");
    assert_eq!(sibling_bytes, b"Shift handover clean notes.\n");

    let withheld = manager.take_withheld_threats(&mount_root);
    assert!(
        withheld
            .iter()
            .any(|t| t.threat_name == "OVERSIZED_OT_STREAM_REJECTED"),
        "Cumulative OT firmware cap breach MUST withhold second firmware per-file; withheld={withheld:?}"
    );
    assert!(
        withheld.iter().any(|t| {
            t.threat_name == "UNSIGNED_LARGE_OPAQUE_BINARY"
                && t.technical_details
                    .contains("allowlisted_authenticode_sha256")
        }),
        "Unpinned Authenticode PE passthrough MUST fail closed; withheld={withheld:?}"
    );
}
