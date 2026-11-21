//! Cold-Eye Phase 3 Adversarial Probe (`CSE-24` .. `CSE-27`, `T53` .. `T54`)
//!
//! Independently attempts adversarial bypasses against every Phase 3 security invariant:
//! 1. `CSE-24`: USB topology misattribution, global `DenyUnspecified=1` regression, empty registry deny subkeys.
//! 2. `CSE-25`: Linux sysfs traversal/symlink leaf escapes, udev injection & malformed `PID_` widening,
//!    `/dev/sdb1` vs `/dev/sdb10` boundary confusion, unwritable `ATTR{ro}="1"` rules.
//! 3. `CSE-26`: `BreakGlassToken` cross-field delimiter smuggling, future pre-minting, corrupted nonce
//!    store reset attempt, unsigned Intune OMA-URI XML, spoofed CMOS/stale `w32tm` NTP output.
//! 4. `CSE-27`: Filename-swap replay on `VendorFirmwareSignatureManifest`, unsigned offline YARA pack
//!    smuggling, ICAP SSRF to cloud metadata `169.254.169.254:1344`, and faulted Bay-1 write-blocker.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sentinel_core::enterprise::intune::{BreakGlassToken, IntunePolicyManager};
use sentinel_core::scanner::av_adapter::validate_icap_target_addr;
use sentinel_core::scanner::tier0_yara::Tier0YaraScanner;
use sentinel_core::vfs::VendorFirmwareSignatureManifest;
use sentinel_sys::{
    attribute_volume_to_pnp_device, collect_linux_mount_points_for_target,
    detect_hardware_write_blocker_state, generate_raw_ecdsa_p256_keypair,
    parse_airgap_clock_config_str, parse_w32tm_status_output, render_linux_udev_usb_storage_rules,
    resolve_linux_usb_authorized_sysfs_path, validate_linux_sysfs_leaf_target,
    verify_linux_udev_rules_content, verify_scoped_storage_registry_lists,
    HardwareWriteBlockerState, PostureReport, UsbPnpDeviceInfo, UsbVolumeInfo, BUS_TYPE_USB,
};

#[test]
fn probe_phase3_cse24_cse25_topology_sysfs_and_udev_hardening() {
    // CSE-24: Unattributed volume MUST return None (never guess pnp_devices[0]!)
    let yubikey = UsbPnpDeviceInfo {
        instance_id: r"USB\VID_1050&PID_0407\YUBI01".to_string(),
        vid: 0x1050,
        pid: 0x0407,
        serial: "YUBI01".to_string(),
        interface_classes: vec![0x03, 0x0B],
        child_instance_ids: vec![],
        has_mass_storage: false,
        has_hid_input: true,
        is_composite_hid_storage: false,
    };
    let unattributed_vol = UsbVolumeInfo {
        volume_guid_path: r"\\?\Volume{00000000-0000-0000-0000-000000000099}\".to_string(),
        mount_points: vec![PathBuf::from(r"G:\")],
        physical_drive_number: Some(9),
        bus_type: BUS_TYPE_USB,
        is_removable_media: true,
        is_offline: true,
        is_readonly: true,
        usb_device_instance_id: None,
        usb_device_desc: None,
    };
    assert!(
        attribute_volume_to_pnp_device(&unattributed_vol, &[yubikey]).is_none(),
        "Unattributed volume MUST fail closed to None rather than guessing first PnP device"
    );

    // CSE-24: Global DenyUnspecified=1 or missing WPD GUID MUST fail scoped compliance
    assert!(!verify_scoped_storage_registry_lists(
        true,
        true,
        true,
        &[
            r"USBSTOR\*".to_string(),
            r"USB\Class_08".to_string(),
            r"WPD\*".to_string(),
            r"USB\MS_COMP_MTP".to_string(),
        ],
        &["{eec5ad98-8080-425f-922a-dabf3de3f69a}".to_string()],
    ));

    // CSE-25: Sysfs traversal, symlink leaf, /dev/sdb1 vs /dev/sdb10, malformed PID_ widening, and ATTR{ro}
    assert!(resolve_linux_usb_authorized_sysfs_path("1-2/../../etc/passwd", true).is_err());
    assert!(
        validate_linux_sysfs_leaf_target(Path::new("/sys/devices/pci0000:00/usb1/1-2"), true)
            .is_err()
    );
    assert!(validate_linux_sysfs_leaf_target(Path::new("/tmp/fake_sys"), false).is_err());

    let mounts = "/dev/sdb10 /mnt/p10 vfat rw 0 0\n/dev/sdb1 /mnt/p1 vfat rw 0 0\n";
    assert_eq!(
        collect_linux_mount_points_for_target(Path::new("/dev/sdb1"), mounts),
        vec![PathBuf::from("/mnt/p1")]
    );

    let rules = render_linux_udev_usb_storage_rules(&[
        r"USB\VID_CAFE&PID_BADZ".to_string(),
        r"USB\VID_FEED&PID_1111\SER*INJ".to_string(),
        "0781:5583:SER_OK_01".to_string(),
    ]);
    assert!(
        !rules.contains("cafe"),
        "Malformed PID must not widen to vendor rule"
    );
    assert!(
        !rules.contains("feed"),
        "Globbed serial must not widen to model rule"
    );
    assert!(rules.contains("ATTRS{serial}==\"SER_OK_01\""));
    assert!(verify_linux_udev_rules_content(&rules));
    assert!(!verify_linux_udev_rules_content(
        "ATTR{bInterfaceClass}==\"08\", ATTR{authorized}=\"0\"\nSUBSYSTEM==\"block\", ENV{ID_BUS}==\"usb\", ATTR{ro}=\"1\"\nENV{ID_MTP_DEVICE}==\"1\"\n"
    ));
}

#[test]
fn probe_phase3_cse26_cse27_break_glass_smuggling_ntp_yara_icap_and_hw_wb() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (root_pub, root_priv) = generate_raw_ecdsa_p256_keypair().expect("root keypair");
    let now_unix = sentinel_sys::now_unix_secs();

    // CSE-26 Attack A: Cross-field delimiter smuggling on BreakGlassToken MUST produce distinct digests
    let tok_a = BreakGlassToken {
        token_id: "BG|op:admin".to_string(),
        operator_id: "x".to_string(),
        incident_ticket: "INC-1".to_string(),
        scope: "kiosk".to_string(),
        target_device_id: None,
        issued_at_unix: now_unix - 10,
        expires_at_unix: now_unix + 300,
        nonce: "0123456789ABCDEF0123456789ABCDEF".to_string(),
        signer_public_key_hex: hex::encode(&root_pub),
        signature_hex: String::new(),
    };
    let tok_b = BreakGlassToken {
        token_id: "BG".to_string(),
        operator_id: "op:admin|x".to_string(),
        ..tok_a.clone()
    };
    assert_ne!(
        tok_a.signing_digest(),
        tok_b.signing_digest(),
        "Length-prefixed BreakGlassToken canonical digest must prevent cross-field delimiter smuggling"
    );

    // CSE-26 Attack B: Future pre-minted token (> 60s skew) MUST fail closed
    let future_tok = BreakGlassToken {
        issued_at_unix: now_unix + 120,
        expires_at_unix: now_unix + 600,
        ..tok_a.clone()
    }
    .sign(&root_priv, &root_pub)
    .expect("sign future token");
    let nonce_store = tmp.path().join("probe_nonces.json");
    assert!(
        future_tok
            .verify(std::slice::from_ref(&root_pub), &nonce_store, now_unix)
            .is_err(),
        "Future-dated BreakGlassToken (>60s skew) MUST fail closed"
    );

    // CSE-26 Attack C: Corrupted nonce replay store MUST fail closed (never silently reset!)
    std::fs::write(&nonce_store, b"{corrupt_json_nonce_store").expect("write corrupt store");
    let valid_tok = tok_a.sign(&root_priv, &root_pub).expect("sign valid token");
    let corrupt_err = valid_tok
        .verify(std::slice::from_ref(&root_pub), &nonce_store, now_unix)
        .expect_err("Corrupted break-glass nonce replay store MUST fail closed");
    assert!(corrupt_err
        .to_string()
        .contains("BREAK_GLASS_NONCE_STORE_CORRUPT"));

    // CSE-26 Attack D: Unsigned Intune OMA-URI XML & spoofed CMOS / stale w32tm output
    let unsigned_oma = "<SyncBody><Replace><Item><Target><LocURI>./Device/Vendor/MSFT/Policy/Config/OmniConnectSentinel/EnforcementMode</LocURI></Target><Data>AUDIT_ONLY</Data></Item></Replace></SyncBody>";
    let mut intune = IntunePolicyManager::new()
        .with_vault_dir(tmp.path().join("intune_probe"))
        .with_pinned_root_public_keys(vec![root_pub.clone()]);
    assert!(intune
        .apply_signed_oma_uri_profile_xml(unsigned_oma)
        .is_err());

    let spoofed_cmos =
        "Stratum: 2\nLast Successful Sync Time: 2026-11-21 11:55:00\nSource: Local CMOS Clock\n";
    let cmos_parsed = parse_w32tm_status_output(spoofed_cmos, now_unix).expect("parse");
    assert!(!cmos_parsed.ntp_synchronized && cmos_parsed.stratum.is_none());
    assert!(parse_airgap_clock_config_str(
        r#"{"protocol":"IRIG-B","device_id":"d","stratum":1,"locked":true,"last_locked_unix":1,"max_error_us":1,"extra":1}"#
    )
    .is_none());

    // CSE-27 Attack A: Filename-swap replay on VendorFirmwareSignatureManifest MUST fail closed
    let fw_sig = VendorFirmwareSignatureManifest::sign(
        "ABB Robotics",
        "plc_good.bin",
        65536,
        "a".repeat(64),
        &root_priv,
        &root_pub,
    )
    .expect("sign fw");
    assert!(
        fw_sig
            .verify_against_allowlist(
                "evil_renamed.bin",
                65536,
                &"a".repeat(64),
                std::slice::from_ref(&root_pub)
            )
            .is_err(),
        "Filename-swap replay on VendorFirmwareSignatureManifest MUST fail closed"
    );

    // CSE-27 Attack B: Unsigned YARA rule pack smuggling & ICAP SSRF to cloud IMDS
    let yara_smuggle_dir = tmp.path().join("yara_smuggle");
    std::fs::create_dir_all(&yara_smuggle_dir).expect("mkdir");
    std::fs::write(
        yara_smuggle_dir.join("evil.json"),
        r#"{"pack_id":"P","version":99,"rules":[],"signature_hex":"00","signer_public_key_hex":"00"}"#,
    )
    .expect("write");
    let mut yara = Tier0YaraScanner::new();
    assert!(yara
        .load_persisted_signed_rule_packs(&yara_smuggle_dir, std::slice::from_ref(&root_pub))
        .is_err());

    let metadata_addr: SocketAddr = "169.254.169.254:1344".parse().expect("addr");
    assert!(validate_icap_target_addr(metadata_addr, &[]).is_err());

    // CSE-27 Attack C: Faulted Bay-1 write-blocker MUST fail posture compliance
    let writable_bay1 = UsbVolumeInfo {
        volume_guid_path: r"\\?\Volume{BAY1-FAULT}\".to_string(),
        mount_points: vec![],
        physical_drive_number: Some(1),
        bus_type: BUS_TYPE_USB,
        is_removable_media: true,
        is_offline: true,
        is_readonly: false,
        usb_device_instance_id: Some("BAY1_HW".to_string()),
        usb_device_desc: None,
    };
    let wb = detect_hardware_write_blocker_state(Some("BAY1_HW"), None, &[writable_bay1]);
    assert!(matches!(wb, HardwareWriteBlockerState::Faulted { .. }));
    let posture = PostureReport {
        automount_disabled: true,
        removable_volumes_offline: vec![],
        user_deny_policy_present: true,
        install_restrictions_active: true,
        write_protect_active: true,
        autoplay_suppressed: true,
        linux_authorized_default_zero: Some(true),
        hardware_write_blocker: wb,
    };
    assert!(!posture.is_compliant());
    assert!(!posture.is_compliant_for_linux());
}
