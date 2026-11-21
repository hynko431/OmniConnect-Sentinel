//! Test Gate T53 (`CSE-24`, `CSE-25`, `CSE-26`):
//! - `CSE-24`: Exact Windows SetupAPI / `CM_Get_Parent` & Linux `/sys/block/<dev>/device`
//!   volume-to-USB topology attribution (zero `pnp_devices.first()` guesswork) and class-scoped
//!   `USBSTOR` / `WPD` storage install restrictions (zero global `DenyUnspecified=1`).

use std::path::{Path, PathBuf};

use sentinel_cdr::{SanitizationPolicy, WorkerLauncher, WorkerRequest};
use sentinel_core::enterprise::ledger::create_shared_audit_ledger;
use sentinel_core::error::DegradationEvent;
use sentinel_core::vfs::{FuseProvider, ShadowCacheManager, VirtualFileSystemProvider};
use sentinel_sys::{
    attribute_volume_to_pnp_device, build_windows_scoped_storage_install_policy,
    collect_linux_mount_points_for_target, collect_linux_mount_points_for_volume_and_dev,
    enumerate_usb_pnp_devices, enumerate_usb_volumes, extract_linux_usb_bus_port_from_sysfs_path,
    is_valid_linux_usb_bus_port, is_valid_linux_usb_interface_id,
    normalize_linux_block_device_name, parse_windows_usb_vid_pid_serial,
    render_linux_udev_usb_storage_rules, resolve_linux_mount_block_device_from_proc_mounts,
    resolve_linux_usb_authorized_sysfs_path, resolve_windows_ancestor_usb_instance,
    validate_linux_sysfs_leaf_target, verify_linux_udev_rules_content,
    verify_scoped_storage_registry_lists, JobSandboxConfig, PostureReport, UsbPnpDeviceInfo,
    UsbVolumeInfo, BUS_TYPE_USB, LINUX_BLKROSET_IOCTL, LINUX_UDEV_RULES_PATH,
    MAX_USB_TOPOLOGY_HOPS, REMOVABLE_STORAGE_POLICY_CLASS_GUIDS, SCOPED_STORAGE_DENY_CLASS_GUIDS,
    SCOPED_STORAGE_DENY_DEVICE_IDS, WPD_DEVICE_SETUP_CLASS_GUID,
};

fn build_verified_worker_launcher_for_t53() -> WorkerLauncher {
    let exe_name = if cfg!(windows) {
        "sentinel-cdr-worker.exe"
    } else {
        "sentinel-cdr-worker"
    };
    let current_exe = std::env::current_exe().expect("current_exe");
    let deps_dir = current_exe.parent().expect("deps dir");
    let profile_dir = deps_dir.parent().unwrap_or(deps_dir);
    let mut worker_bin = profile_dir.join(exe_name);
    if !worker_bin.is_file() {
        let alt = deps_dir.join(exe_name);
        if alt.is_file() {
            worker_bin = alt;
        }
    }
    let default_launcher = WorkerLauncher::new().with_worker_bin(worker_bin.clone());
    match default_launcher.sanitize_isolated(WorkerRequest {
        file_name: "probe.txt".to_string(),
        policy: SanitizationPolicy::default(),
        raw_bytes: b"probe".to_vec(),
    }) {
        Ok(_) => default_launcher,
        Err(err)
            if cfg!(windows)
                && (err.to_string().contains("os error 87")
                    || err.to_string().contains("CreateProcessW failed")) =>
        {
            WorkerLauncher::new()
                .with_worker_bin(worker_bin)
                .with_sandbox_config(JobSandboxConfig {
                    enable_appcontainer: false,
                    ..Default::default()
                })
        }
        Err(err) => panic!("Unexpected CDR worker probe failure: {err}"),
    }
}

#[test]
fn t53_cse24_windows_ancestor_topology_attribution_never_picks_wrong_device() {
    // 1. Multi-hop PnP ancestor chain: Volume -> USBSTOR Disk -> Composite MI_00 -> Parent USB Device -> Root Hub
    let chain = vec![
        r"STORAGE\VOLUME\{12345678-0000-0000-0000-100000000000}".to_string(),
        r"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C5300011234567890&0".to_string(),
        r"USB\VID_0781&PID_5583&MI_00\6&1A2B3C4D&0&0000".to_string(),
        r"USB\VID_0781&PID_5583\4C5300011234567890".to_string(),
        r"USB\ROOT_HUB30\4&11223344&0&0".to_string(),
    ];
    let attr =
        resolve_windows_ancestor_usb_instance(&chain, Some("SanDisk Ultra USB 3.0".to_string()))
            .expect("must resolve parent USB device across composite MI_00");
    assert_eq!(
        attr.instance_id,
        r"USB\VID_0781&PID_5583\4C5300011234567890"
    );
    assert_eq!(attr.vid, 0x0781);
    assert_eq!(attr.pid, 0x5583);
    assert_eq!(attr.serial, "4C5300011234567890");
    assert_eq!(attr.hops, 3);
    assert!(attr.hops < MAX_USB_TOPOLOGY_HOPS);

    // 2. Non-USB internal NVMe/SATA chain MUST return None (never misattributed as USB)
    let nvme_chain = vec![
        r"SCSI\DISK&VEN_NVME&PROD_SAMSUNG_SSD_980\5&12345&0&000000".to_string(),
        r"PCI\VEN_144D&DEV_A80A&SUBSYS_A801144D&REV_00\4&112233&0&00E0".to_string(),
    ];
    assert!(
        resolve_windows_ancestor_usb_instance(&nvme_chain, None).is_none(),
        "Internal NVMe disk must never resolve to a USB ancestor"
    );

    // 3. Multi-device attribution: a YubiKey/dock appears FIRST in `pnp_devices`, while the arrived
    //    volume belongs to the SECOND flash drive (same-system multi-USB regression for F-03).
    let pnp_devices = vec![
        UsbPnpDeviceInfo {
            instance_id: r"USB\VID_1050&PID_0407\YUBIKEY-001".to_string(),
            vid: 0x1050,
            pid: 0x0407,
            serial: "YUBIKEY-001".to_string(),
            interface_classes: vec![0x03, 0x0B],
            child_instance_ids: vec![],
            has_mass_storage: false,
            has_hid_input: true,
            is_composite_hid_storage: false,
        },
        UsbPnpDeviceInfo {
            instance_id: r"USB\VID_0781&PID_5583\STICK-ALPHA".to_string(),
            vid: 0x0781,
            pid: 0x5583,
            serial: "STICK-ALPHA".to_string(),
            interface_classes: vec![0x08],
            child_instance_ids: vec![],
            has_mass_storage: true,
            has_hid_input: false,
            is_composite_hid_storage: false,
        },
        UsbPnpDeviceInfo {
            instance_id: r"USB\VID_0781&PID_5583\STICK-BETA".to_string(),
            vid: 0x0781,
            pid: 0x5583,
            serial: "STICK-BETA".to_string(),
            interface_classes: vec![0x08, 0x03],
            child_instance_ids: vec![r"USB\VID_0781&PID_5583&MI_00\7&998877&0&0000".to_string()],
            has_mass_storage: true,
            has_hid_input: true,
            is_composite_hid_storage: true,
        },
    ];

    let vol_beta = UsbVolumeInfo {
        volume_guid_path: r"\\?\Volume{bbbbbbbb-0000-0000-0000-000000000002}\".to_string(),
        mount_points: vec![PathBuf::from(r"F:\")],
        physical_drive_number: Some(2),
        bus_type: BUS_TYPE_USB,
        is_removable_media: true,
        is_offline: true,
        is_readonly: true,
        usb_device_instance_id: Some(r"USB\VID_0781&PID_5583\STICK-BETA".to_string()),
        usb_device_desc: Some("USB Mass Storage Device".to_string()),
    };
    let matched = attribute_volume_to_pnp_device(&vol_beta, &pnp_devices)
        .expect("must attribute volume strictly to STICK-BETA");
    assert_eq!(matched.serial, "STICK-BETA");
    assert_eq!(matched.vid, 0x0781);
    assert!(matched.is_composite_hid_storage);

    // Volume without topology attribution MUST return None — NEVER silently blaming pnp_devices[0] (YubiKey!)
    let unattributed_vol = UsbVolumeInfo {
        volume_guid_path: r"\\?\Volume{cccccccc-0000-0000-0000-000000000003}\".to_string(),
        mount_points: vec![],
        physical_drive_number: None,
        bus_type: BUS_TYPE_USB,
        is_removable_media: true,
        is_offline: true,
        is_readonly: true,
        usb_device_instance_id: None,
        usb_device_desc: None,
    };
    assert!(
        attribute_volume_to_pnp_device(&unattributed_vol, &pnp_devices).is_none(),
        "Unattributed volume must NEVER fall back to pnp_devices.first()!"
    );

    // Cross-platform VID/PID/serial parser validation (including multi-byte UTF-8 safety & empty trailing serial)
    let parsed = parse_windows_usb_vid_pid_serial(r"USB\VID_0951&PID_1666\AA0011223344")
        .expect("parse VID/PID/serial");
    assert_eq!(parsed, (0x0951, 0x1666, "AA0011223344".to_string()));
    assert_eq!(
        parse_windows_usb_vid_pid_serial("USB\\VID_07\u{20AC}&PID_1234\\SN"),
        None,
        "Malformed multi-byte UTF-8 straddling VID slice MUST return None without panicking"
    );
    let trailing_slash = parse_windows_usb_vid_pid_serial(r"USB\VID_0951&PID_1666\")
        .expect("trailing slash yields UNKNOWN serial");
    assert_eq!(trailing_slash, (0x0951, 0x1666, "UNKNOWN".to_string()));
}

#[test]
fn t53_cse24_linux_sysfs_block_topology_and_proc_mounts_attribution() {
    // 1. Canonical Linux sysfs USB bus-port syntax validation (`^[0-9]+-[0-9]+(\.[0-9]+)*$`)
    for valid in ["1-2", "1-2.3", "2-1.4.2", "10-12.3.1"] {
        assert!(
            is_valid_linux_usb_bus_port(valid),
            "Valid Linux USB bus-port '{valid}' must be accepted"
        );
    }
    for invalid in [
        "",
        "usb1",
        "1-2:1.0",
        "USB\\VID_0781&PID_5583\\SN01",
        "../1-2",
        "1-",
        "-2",
        "1-2.",
        "1-2..3",
        "a-2",
        "1-2/authorized",
    ] {
        assert!(
            !is_valid_linux_usb_bus_port(invalid),
            "Invalid Linux USB bus-port '{invalid}' must be rejected"
        );
    }

    // 2. Canonical `/sys/block/<dev>/device` walk selects the DEEPEST USB device bus-port (not parent hub!)
    let sysfs_deep = Path::new(
        "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2.3/1-2.3:1.0/host2/target2:0:0/2:0:0:0",
    );
    assert_eq!(
        extract_linux_usb_bus_port_from_sysfs_path(sysfs_deep).as_deref(),
        Some("1-2.3")
    );
    let sysfs_non_usb =
        Path::new("/sys/devices/pci0000:00/0000:00:1d.0/0000:04:00.0/nvme/nvme0/nvme0n1");
    assert_eq!(
        extract_linux_usb_bus_port_from_sysfs_path(sysfs_non_usb),
        None
    );

    // 3. Block device partition normalization
    assert_eq!(
        normalize_linux_block_device_name("/dev/sdb1").as_deref(),
        Some("sdb")
    );
    assert_eq!(
        normalize_linux_block_device_name("/dev/sda12").as_deref(),
        Some("sda")
    );
    assert_eq!(
        normalize_linux_block_device_name("/dev/nvme0n1p2").as_deref(),
        Some("nvme0n1")
    );
    assert_eq!(
        normalize_linux_block_device_name("/dev/mmcblk0p1").as_deref(),
        Some("mmcblk0")
    );
    assert_eq!(
        normalize_linux_block_device_name("/dev/loop0").as_deref(),
        Some("loop0"),
        "Unpartitioned /dev/loop0 must NEVER be mangled to 'loo'"
    );
    assert_eq!(
        normalize_linux_block_device_name("/dev/loop0p1").as_deref(),
        Some("loop0")
    );
    assert_eq!(normalize_linux_block_device_name("../etc/passwd"), None);

    // 4. `/proc/mounts` parser with escaped spaces, overmounts (topmost wins), and invalid octal safety
    let proc_mounts = "\
/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n\
/dev/sdb1 /run/media/operator/PLANT\\040USB\\040DRIVE vfat ro,nosuid,nodev,noexec 0 0\n\
/dev/sdc1 /media/usb_second exfat rw,nosuid,nodev 0 0\n\
/dev/sdd1 /media/usb_second vfat ro,nosuid,nodev 0 0\n\
/dev/sde1 /media/bad\\777octal vfat ro 0 0\n";
    assert_eq!(
        resolve_linux_mount_block_device_from_proc_mounts(
            Path::new("/run/media/operator/PLANT USB DRIVE"),
            proc_mounts
        )
        .as_deref(),
        Some("/dev/sdb1")
    );
    assert_eq!(
        resolve_linux_mount_block_device_from_proc_mounts(
            Path::new("/media/usb_second"),
            proc_mounts
        )
        .as_deref(),
        Some("/dev/sdd1"),
        "Topmost overmount at duplicate path must win"
    );
    assert_eq!(
        resolve_linux_mount_block_device_from_proc_mounts(
            Path::new("/media/bad\\777octal"),
            proc_mounts
        )
        .as_deref(),
        Some("/dev/sde1")
    );
}

#[test]
fn t53_cse24_scoped_storage_install_policy_never_sets_global_deny_unspecified() {
    let allow = vec![r"USB\VID_0781&PID_5583*".to_string()];
    let spec = build_windows_scoped_storage_install_policy(&allow);

    // Global DenyUnspecified MUST be false so USB-C docks, webcams, YubiKeys, headsets, and HMI stay working
    assert!(
        !spec.deny_unspecified,
        "CSE-24 MUST disable global DenyUnspecified=1 to avoid bricking non-storage USB peripherals"
    );
    assert_eq!(
        spec.deny_device_ids,
        SCOPED_STORAGE_DENY_DEVICE_IDS
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
    );
    assert!(spec.deny_device_ids.iter().any(|id| id == r"USBSTOR\*"));
    assert!(spec.deny_device_ids.iter().any(|id| id == r"USB\Class_08"));
    assert!(spec.deny_device_ids.iter().any(|id| id == r"WPD\*"));

    assert_eq!(
        spec.deny_device_class_guids,
        SCOPED_STORAGE_DENY_CLASS_GUIDS
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
    );
    assert!(spec
        .deny_device_class_guids
        .iter()
        .any(|g| g.eq_ignore_ascii_case(WPD_DEVICE_SETUP_CLASS_GUID)));
    assert_eq!(
        spec.removable_storage_class_guids.len(),
        REMOVABLE_STORAGE_POLICY_CLASS_GUIDS.len()
    );
    assert_eq!(spec.allow_device_ids, allow);

    // Ensure non-storage device setup class GUIDs (HID, Keyboard, Mouse, Camera, USB Hub, SmartCard) are NOT denied
    for non_storage_guid in [
        "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}", // HIDClass
        "{4d36e96b-e325-11ce-bfc1-08002be10318}", // Keyboard
        "{4d36e96f-e325-11ce-bfc1-08002be10318}", // Mouse
        "{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}", // Camera
        "{36fc9e60-c465-11cf-8056-444553540000}", // USB Controllers/Hubs
        "{50dd5230-ba8a-11d1-bf5d-0000f805f530}", // SmartCardReader (YubiKey)
    ] {
        assert!(
            !spec
                .deny_device_class_guids
                .iter()
                .any(|g| g.eq_ignore_ascii_case(non_storage_guid)),
            "Non-storage class GUID {non_storage_guid} MUST NOT be blocked by scoped storage policy"
        );
    }

    // Posture verifier MUST reject empty/partial subkeys even when parent toggles are 1, and MUST
    // reject global DenyUnspecified=1 (zero false positives)
    assert!(verify_scoped_storage_registry_lists(
        false,
        true,
        true,
        &spec.deny_device_ids,
        &spec.deny_device_class_guids,
    ));
    assert!(
        !verify_scoped_storage_registry_lists(false, true, true, &[], &[]),
        "Empty DenyDeviceIDs/DenyDeviceClasses subkeys MUST NOT pass compliance"
    );
    assert!(
        !verify_scoped_storage_registry_lists(
            true,
            true,
            true,
            &spec.deny_device_ids,
            &spec.deny_device_class_guids,
        ),
        "Global DenyUnspecified=1 MUST fail CSE-24 class-scoped compliance"
    );
    assert!(
        !verify_scoped_storage_registry_lists(
            false,
            true,
            true,
            &[r"USBSTOR\*".to_string()],
            &spec.deny_device_class_guids,
        ),
        "Incomplete DenyDeviceIDs missing WPD/Class_08 entries MUST fail compliance"
    );

    // Smoke-test live OS enumeration paths (must never panic on non-admin or headless hosts)
    let _vols = enumerate_usb_volumes();
    let _devs = enumerate_usb_pnp_devices();
}

#[tokio::test]
async fn t53_cse25_linux_sysfs_bus_port_validation_udev_rules_mount_controls_and_fuse_fallback() {
    // 1. Canonical Linux sysfs bus-port & interface path validation rejects Windows USB\VID_... & traversal
    assert_eq!(
        resolve_linux_usb_authorized_sysfs_path("1-2.3", false)
            .expect("valid bus-port")
            .to_string_lossy(),
        "/sys/bus/usb/devices/1-2.3/authorized"
    );
    assert!(resolve_linux_usb_authorized_sysfs_path("1-2.3:1.0", false).is_err());
    assert_eq!(
        resolve_linux_usb_authorized_sysfs_path("1-2.3:1.0", true)
            .expect("valid interface id")
            .to_string_lossy(),
        "/sys/bus/usb/devices/1-2.3:1.0/authorized"
    );
    assert!(is_valid_linux_usb_interface_id("2-1.4:1.2"));
    for bad in [
        r"USB\VID_0781&PID_5583\SN001",
        "../1-2",
        "1-2/authorized",
        "usb1",
        "",
        "1-2:abc",
    ] {
        assert!(
            resolve_linux_usb_authorized_sysfs_path(bad, true).is_err(),
            "Malformed/Windows Linux sysfs ID '{bad}' MUST fail closed"
        );
    }

    // 1b. Linux sysfs leaf attribute validation allows canonical /sys/devices/... parents (even when
    //     reached through kernel symlinks under /sys/bus/usb/devices or /sys/block/<dev>/device),
    //     while rejecting symlinked leaf files and paths escaping /sys/devices/.
    assert!(validate_linux_sysfs_leaf_target(
        Path::new("/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2.3"),
        false
    )
    .is_ok());
    assert!(
        validate_linux_sysfs_leaf_target(
            Path::new("/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2.3"),
            true
        )
        .is_err(),
        "Symlinked sysfs leaf attribute MUST fail closed"
    );
    assert!(
        validate_linux_sysfs_leaf_target(Path::new("/etc"), false).is_err(),
        "Sysfs attribute outside /sys/devices/ MUST fail closed"
    );

    // 2. Linux BLKROSET constant (`_IO(0x12, 93)` = 0x125D), mount target collection & udev rules
    assert_eq!(LINUX_BLKROSET_IOCTL, 0x125D);
    assert_eq!(
        LINUX_UDEV_RULES_PATH,
        "/etc/udev/rules.d/99-omniconnect-sentinel.rules"
    );

    let proc_mounts = "\
/dev/nvme0n1p2 / ext4 rw 0 0\n\
/dev/sdb1 /media/usb_root vfat rw 0 0\n\
/dev/sdb2 /media/usb_root/nested exfat rw 0 0\n\
/dev/sdb10 /media/usb_part10 exfat rw 0 0\n";
    let targets = collect_linux_mount_points_for_target(Path::new("/dev/sdb"), proc_mounts);
    assert_eq!(
        targets,
        vec![
            PathBuf::from("/media/usb_root/nested"),
            PathBuf::from("/media/usb_part10"),
            PathBuf::from("/media/usb_root"),
        ],
        "Nested mounts must be ordered deepest-first for clean umount2(MNT_DETACH)"
    );
    let part1_targets = collect_linux_mount_points_for_target(Path::new("/dev/sdb1"), proc_mounts);
    assert_eq!(
        part1_targets,
        vec![PathBuf::from("/media/usb_root")],
        "Targeting /dev/sdb1 must match ONLY /dev/sdb1 and NEVER /dev/sdb10 or /dev/sdb2"
    );
    // Symlink /dev/disk/by-id/... + bind-mount resolution must find ALL mounts backed by canonical /dev/sdb1
    let proc_mounts_bind = "\
/dev/sdb1 /media/usb_root vfat rw 0 0\n\
/dev/sdb1 /mnt/bind_copy/deep vfat rw 0 0\n\
/dev/sdb10 /media/usb_part10 exfat rw 0 0\n";
    let symlink_targets = collect_linux_mount_points_for_volume_and_dev(
        Path::new("/dev/disk/by-id/usb-SanDisk_Ultra-0:0-part1"),
        Some(Path::new("/dev/sdb1")),
        proc_mounts_bind,
    );
    assert_eq!(
        symlink_targets,
        vec![
            PathBuf::from("/mnt/bind_copy/deep"),
            PathBuf::from("/media/usb_root"),
        ],
        "Canonicalized /dev symlink lookup must collect all mounts (deepest first) without hitting /dev/sdb10"
    );

    let rules = render_linux_udev_usb_storage_rules(&[
        r"USB\VID_0781&PID_5583*".to_string(),
        r"USB\VID_0781&PID_5583\4C5300011234567890".to_string(),
        r"USB\VID_0951&*".to_string(),
        r"USB\VID_DEAD&PID_ZZZZ".to_string(), // Malformed PID MUST fail closed (never widen to vendor dead!)
        r"USB\VID_BEEF&PID_1234\BAD*GLOB".to_string(), // Malformed/globbed serial MUST fail closed
        "bad\",RUN+=\"/bin/sh".to_string(),   // Injection attempt must be ignored cleanly
    ]);
    assert!(verify_linux_udev_rules_content(&rules));
    // Verify parent-walking ATTRS{idVendor}/ATTRS{idProduct}/ATTRS{serial} across both SUBSYSTEM=="usb" and SUBSYSTEM=="block"
    assert!(rules.contains(
        "SUBSYSTEM==\"usb\", SUBSYSTEMS==\"usb\", ATTRS{idVendor}==\"0781\", ATTRS{idProduct}==\"5583\", ENV{OMNICONNECT_ALLOWED}=\"1\""
    ));
    assert!(rules.contains(
        "SUBSYSTEM==\"block\", SUBSYSTEMS==\"usb\", ATTRS{idVendor}==\"0781\", ATTRS{idProduct}==\"5583\", ENV{OMNICONNECT_ALLOWED}=\"1\""
    ));
    assert!(rules.contains(
        "SUBSYSTEM==\"usb\", SUBSYSTEMS==\"usb\", ATTRS{idVendor}==\"0781\", ATTRS{idProduct}==\"5583\", ATTRS{serial}==\"4C5300011234567890\", ENV{OMNICONNECT_ALLOWED}=\"1\""
    ));
    assert!(rules.contains(
        "SUBSYSTEM==\"block\", SUBSYSTEMS==\"usb\", ATTRS{idVendor}==\"0781\", ATTRS{idProduct}==\"5583\", ATTRS{serial}==\"4C5300011234567890\", ENV{OMNICONNECT_ALLOWED}=\"1\""
    ));
    assert!(rules.contains("ATTRS{idVendor}==\"0951\""));
    assert!(
        !rules.contains("dead"),
        "Malformed PID_ZZZZ MUST fail closed and MUST NOT emit a vendor-wide rule for dead"
    );
    assert!(
        !rules.contains("beef"),
        "Malformed/globbed serial MUST fail closed and MUST NOT emit a model-wide rule for beef"
    );
    // Verify blockdev --setro (NEVER unwritable kernel DEVICE_ATTR_RO ATTR{ro}="1")
    assert!(rules.contains("RUN+=\"/sbin/blockdev --setro $devnode\""));
    assert!(
        !rules.contains("ATTR{ro}=\"1\""),
        "Unwritable kernel sysfs ATTR{{ro}}=\"1\" must NOT be emitted"
    );
    assert!(
        !verify_linux_udev_rules_content(
            "ATTR{bInterfaceClass}==\"08\", ATTR{authorized}=\"0\"\nSUBSYSTEM==\"block\", ENV{ID_BUS}==\"usb\", ATTR{ro}=\"1\", ENV{UDISKS_IGNORE}=\"1\"\nENV{ID_MTP_DEVICE}==\"1\"\n"
        ),
        "Rules containing unwritable ATTR{{ro}}=\"1\" must fail verification"
    );
    assert!(
        !rules.contains("/bin/sh"),
        "Malformed udev rule injection MUST be stripped"
    );
    assert!(
        !verify_linux_udev_rules_content("# empty file\n"),
        "Empty udev rules file MUST fail verification"
    );

    // 2b. Linux PostureReport compliance MUST require udev storage rules (zero silent drift bypass)
    let compliant_linux = PostureReport {
        automount_disabled: true,
        removable_volumes_offline: vec![("/dev/sdb".to_string(), true)],
        user_deny_policy_present: true,
        install_restrictions_active: true,
        write_protect_active: true,
        autoplay_suppressed: true,
        linux_authorized_default_zero: Some(true),
        hardware_write_blocker: Default::default(),
    };
    assert!(compliant_linux.is_compliant_for_linux());
    let missing_udev_linux = PostureReport {
        user_deny_policy_present: false,
        install_restrictions_active: false,
        ..compliant_linux
    };
    assert!(
        !missing_udev_linux.is_compliant_for_linux(),
        "Missing Linux udev policy MUST fail PostureReport compliance"
    );

    // 3. FuseVfsProvider honestly reports is_native_fuse_supported() == false, emits explicit
    //    POSTURE_REDUCED_NO_FUSE degradation event in AuditLedger, never shells out to bindfs,
    //    materializes clean sanitized output, and retains withheld threats
    assert!(
        !FuseProvider::is_native_fuse_supported(),
        "is_native_fuse_supported() must return false while delegating to StagingFolderProvider"
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let raw_usb = tmp.path().join("raw_usb");
    let virt_mount = tmp.path().join("safe_mount");
    let cache_root = tmp.path().join("shadow_cache");
    let ledger_path = tmp.path().join("fuse_ledger.jsonl");
    std::fs::create_dir_all(&raw_usb).expect("mkdir raw_usb");
    std::fs::write(raw_usb.join("report.txt"), b"Clean OT maintenance log\n").expect("write txt");
    // Defender-safe non-disarmable Windows LNK shell-link payload flagged by UniversalScanner
    let mut lnk_bytes = vec![
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    lnk_bytes.extend_from_slice(b"powershell.exe -EncodedCommand ZQBjAGgAbwA=");
    std::fs::write(raw_usb.join("payload.lnk"), &lnk_bytes).expect("write threat lnk");

    let shared_ledger = create_shared_audit_ledger(&ledger_path).expect("ledger");
    let shadow_cache = ShadowCacheManager::with_cache_root_and_quota(cache_root, 32 * 1024 * 1024)
        .with_worker_launcher(build_verified_worker_launcher_for_t53())
        .with_shared_ledger(shared_ledger.clone());
    let fuse_provider = FuseProvider::with_shadow_cache(shadow_cache);

    assert_eq!(
        DegradationEvent::PostureReducedNoFuse.event_code(),
        "POSTURE_REDUCED_NO_FUSE"
    );
    assert!(!fuse_provider.is_native_fuse_active());
    assert!(fuse_provider
        .provider_name()
        .contains("POSTURE_REDUCED_NO_FUSE"));

    fuse_provider
        .mount_sanitized_volume(&raw_usb, &virt_mount)
        .await
        .expect("FuseVfsProvider fallback mount must succeed");

    let withheld = fuse_provider.take_withheld_threats(&virt_mount);
    assert!(
        !withheld.is_empty(),
        "Withheld LNK threat MUST be returned for QuarantineVault ingestion"
    );
    assert!(
        virt_mount.join("report.txt").exists(),
        "Sanitized clean file must be projected read-only"
    );
    assert!(
        !virt_mount.join("payload.lnk").exists(),
        "Malicious LNK payload must NOT be projected into sanitized mount"
    );

    let ledger_text = std::fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(
        ledger_text.contains("POSTURE_REDUCED_NO_FUSE"),
        "AuditLedger MUST record explicit POSTURE_REDUCED_NO_FUSE degradation event"
    );

    fuse_provider
        .unmount_volume(&virt_mount)
        .await
        .expect("unmount must teardown session cleanly");
}

#[test]
fn t53_cse26_break_glass_token_cli_replay_expiry_intune_dynamic_reg_scm_and_session0() {
    use sentinel_core::enterprise::intune::{
        BreakGlassToken, IntuneMdmPolicy, IntunePolicyManager, SignedPolicyBundle,
        BREAK_GLASS_MAX_TTL_SECS, INTUNE_POLICY_MANAGER_REG_SUBKEY,
    };
    use sentinel_core::interceptor::PendingDeviceConfirmationManager;
    use sentinel_sys::{
        build_scm_status, decode_utf16_reg_sz_bytes, generate_raw_ecdsa_p256_keypair,
        resolve_appcontainer_strategy_for_session, scm_control_triggers_shutdown,
        AppContainerSessionStrategy, MAX_REGISTRY_STRING_BYTES, SENTINEL_WINDOWS_SERVICE_NAME,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STOPPED, SERVICE_STOP_PENDING,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let (root_pub, root_priv) = generate_raw_ecdsa_p256_keypair().expect("root keypair");
    let (rogue_pub, rogue_priv) = generate_raw_ecdsa_p256_keypair().expect("rogue keypair");
    let now_unix = chrono::Utc::now().timestamp();
    let nonce_store = tmp.path().join("break_glass_nonces.json");

    // 1. Valid BreakGlassToken verification + replay prevention + expiry + TTL + untrusted signer + tamper
    let valid_token = BreakGlassToken {
        token_id: "BG-2026-0001".to_string(),
        operator_id: "ot-chief-engineer@plant.local".to_string(),
        incident_ticket: "INC-2026-4419".to_string(),
        scope: "emergency_kiosk_override".to_string(),
        target_device_id: None,
        issued_at_unix: now_unix - 10,
        expires_at_unix: now_unix + 900,
        nonce: "A1B2C3D4E5F60718293A4B5C6D7E8F90".to_string(),
        signer_public_key_hex: String::new(),
        signature_hex: String::new(),
    }
    .sign(&root_priv, &root_pub)
    .expect("sign valid break-glass token");

    let outcome = valid_token
        .verify(std::slice::from_ref(&root_pub), &nonce_store, now_unix)
        .expect("valid signed break-glass token must verify");
    assert_eq!(outcome.token_id, "BG-2026-0001");
    assert_eq!(outcome.incident_ticket, "INC-2026-4419");
    assert_eq!(outcome.nonce_sha256.len(), 64);

    // Replay of identical nonce MUST fail closed
    let replay_err = valid_token
        .verify(std::slice::from_ref(&root_pub), &nonce_store, now_unix)
        .expect_err("replayed break-glass token nonce MUST fail closed");
    assert!(
        replay_err.to_string().contains("BREAK_GLASS_NONCE_REPLAY"),
        "expected BREAK_GLASS_NONCE_REPLAY, got: {replay_err}"
    );

    // 1-byte tampered scope MUST fail signature verification
    let mut tampered = valid_token.clone();
    tampered.nonce = "B1B2C3D4E5F60718293A4B5C6D7E8F91".to_string();
    tampered.scope = "full_admin_bypass".to_string();
    assert!(
        tampered
            .verify(std::slice::from_ref(&root_pub), &nonce_store, now_unix)
            .is_err(),
        "tampered BreakGlassToken MUST fail closed"
    );

    // Untrusted rogue root key MUST fail closed
    let rogue_token = BreakGlassToken {
        token_id: "BG-ROGUE-01".to_string(),
        operator_id: "attacker".to_string(),
        incident_ticket: "INC-0".to_string(),
        scope: "emergency".to_string(),
        target_device_id: None,
        issued_at_unix: now_unix - 5,
        expires_at_unix: now_unix + 300,
        nonce: "C1C2C3D4E5F60718293A4B5C6D7E8F92".to_string(),
        signer_public_key_hex: String::new(),
        signature_hex: String::new(),
    }
    .sign(&rogue_priv, &rogue_pub)
    .expect("sign rogue");
    let rogue_err = rogue_token
        .verify(std::slice::from_ref(&root_pub), &nonce_store, now_unix)
        .expect_err("untrusted signer MUST fail closed");
    assert!(rogue_err
        .to_string()
        .contains("BREAK_GLASS_UNTRUSTED_SIGNER"));

    // Expired token MUST fail closed
    let expired_token = BreakGlassToken {
        token_id: "BG-EXP-01".to_string(),
        operator_id: "op".to_string(),
        incident_ticket: "INC-1".to_string(),
        scope: "emergency".to_string(),
        target_device_id: None,
        issued_at_unix: now_unix - 1_200,
        expires_at_unix: now_unix - 1,
        nonce: "D1D2C3D4E5F60718293A4B5C6D7E8F93".to_string(),
        signer_public_key_hex: String::new(),
        signature_hex: String::new(),
    }
    .sign(&root_priv, &root_pub)
    .expect("sign expired");
    let exp_err = expired_token
        .verify(std::slice::from_ref(&root_pub), &nonce_store, now_unix)
        .expect_err("expired break-glass token MUST fail closed");
    assert!(exp_err.to_string().contains("BREAK_GLASS_EXPIRED"));

    // Over-long TTL (> 4h) MUST fail closed
    let immortal_token = BreakGlassToken {
        token_id: "BG-IMMORTAL-01".to_string(),
        operator_id: "op".to_string(),
        incident_ticket: "INC-2".to_string(),
        scope: "emergency".to_string(),
        target_device_id: None,
        issued_at_unix: now_unix - 5,
        expires_at_unix: now_unix + BREAK_GLASS_MAX_TTL_SECS + 600,
        nonce: "E1E2C3D4E5F60718293A4B5C6D7E8F94".to_string(),
        signer_public_key_hex: String::new(),
        signature_hex: String::new(),
    }
    .sign(&root_priv, &root_pub)
    .expect("sign immortal");
    let ttl_err = immortal_token
        .verify(std::slice::from_ref(&root_pub), &nonce_store, now_unix)
        .expect_err("break-glass TTL > 4h MUST fail closed");
    assert!(ttl_err.to_string().contains("BREAK_GLASS_TTL_EXCEEDED"));

    // 2. End-to-end CLI `sentinel break-glass --token <PATH>` execution + AuditLedger BREAK_GLASS_ACTIVATED + replay rejection
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let cli_exe = if cfg!(windows) {
        workspace_root.join("target/debug/sentinel.exe")
    } else {
        workspace_root.join("target/debug/sentinel")
    };
    assert!(
        cli_exe.exists(),
        "sentinel CLI binary must be built at {} before running CSE-26 break-glass CLI test",
        cli_exe.display()
    );
    let cli_token = BreakGlassToken {
        token_id: "BG-CLI-2026-99".to_string(),
        operator_id: "substation-lead".to_string(),
        incident_ticket: "INC-OT-9901".to_string(),
        scope: "kiosk_emergency_transfer".to_string(),
        target_device_id: None,
        issued_at_unix: now_unix - 5,
        expires_at_unix: now_unix + 600,
        nonce: "F1F2C3D4E5F60718293A4B5C6D7E8F95".to_string(),
        signer_public_key_hex: String::new(),
        signature_hex: String::new(),
    }
    .sign(&root_priv, &root_pub)
    .expect("sign cli token");
    let cli_token_path = tmp.path().join("break_glass_token.json");
    let cli_root_path = tmp.path().join("enterprise_root.pub");
    let cli_nonce_store = tmp.path().join("cli_nonces.json");
    let cli_ledger_path = tmp.path().join("cli_break_glass_ledger.jsonl");
    std::fs::write(
        &cli_token_path,
        serde_json::to_string_pretty(&cli_token).expect("serialize token"),
    )
    .expect("write token");
    std::fs::write(&cli_root_path, &root_pub).expect("write root pub");

    let ok_out = std::process::Command::new(&cli_exe)
        .args([
            "break-glass",
            "--token",
            &cli_token_path.to_string_lossy(),
            "--root-key",
            &cli_root_path.to_string_lossy(),
            "--nonce-store",
            &cli_nonce_store.to_string_lossy(),
            "--ledger",
            &cli_ledger_path.to_string_lossy(),
        ])
        .output()
        .expect("run sentinel break-glass");
    assert!(
        ok_out.status.success(),
        "sentinel break-glass must succeed on valid signed token; stderr={}",
        String::from_utf8_lossy(&ok_out.stderr)
    );
    let ledger_after_ok = std::fs::read_to_string(&cli_ledger_path).expect("read cli ledger");
    assert!(
        ledger_after_ok.contains("BREAK_GLASS_ACTIVATED")
            && ledger_after_ok.contains("BG-CLI-2026-99")
            && ledger_after_ok.contains("INC-OT-9901"),
        "AuditLedger MUST record BREAK_GLASS_ACTIVATED metadata"
    );

    // Replaying the exact same token file via CLI MUST exit non-zero and log BREAK_GLASS_REJECTED
    let replay_out = std::process::Command::new(&cli_exe)
        .args([
            "break-glass",
            "--token",
            &cli_token_path.to_string_lossy(),
            "--root-key",
            &cli_root_path.to_string_lossy(),
            "--nonce-store",
            &cli_nonce_store.to_string_lossy(),
            "--ledger",
            &cli_ledger_path.to_string_lossy(),
        ])
        .output()
        .expect("run sentinel break-glass replay");
    assert!(
        !replay_out.status.success(),
        "replayed sentinel break-glass CLI invocation MUST fail closed with non-zero exit code"
    );
    assert!(
        String::from_utf8_lossy(&replay_out.stderr).contains("BREAK_GLASS_NONCE_REPLAY"),
        "stderr must report BREAK_GLASS_NONCE_REPLAY"
    );
    let ledger_after_replay = std::fs::read_to_string(&cli_ledger_path).expect("read ledger");
    assert!(ledger_after_replay.contains("BREAK_GLASS_REJECTED"));

    // 3. PendingDeviceConfirmationManager MUST propagate OS enable_device_node errors (no swallowing!)
    let confirm_mgr = PendingDeviceConfirmationManager::new(tmp.path().join("confirm_state.json"));
    let fake_dev = r"USB\VID_DEAD&PID_CAFE\NO_SUCH_NODE_T53";
    let chal = confirm_mgr
        .request_user_presence_challenge_extended(fake_dev)
        .expect("issue challenge");
    assert!(
        confirm_mgr
            .confirm_device_with_challenge(fake_dev, &chal.challenge_token)
            .is_err(),
        "CSE-26: confirm_device_with_challenge MUST propagate enable_device_node Err"
    );
    assert!(!confirm_mgr.is_confirmed(fake_dev));

    // 4. Dynamic registry read (>1,024 UTF-16 chars) & Intune SignedPolicyBundleJson OMA-URI roundtrip
    const {
        assert!(MAX_REGISTRY_STRING_BYTES >= 1024 * 1024);
    }
    assert_eq!(
        INTUNE_POLICY_MANAGER_REG_SUBKEY,
        r"SOFTWARE\Microsoft\PolicyManager\current\device\OmniConnectSentinel"
    );
    let long_str = "A".repeat(4096);
    let mut wide: Vec<u16> = long_str.encode_utf16().collect();
    wide.push(0);
    let decoded = decode_utf16_reg_sz_bytes(&wide, (wide.len() * 2) as u32);
    assert_eq!(decoded.len(), 4096);
    assert_eq!(decoded, long_str);

    let custom_policy = IntuneMdmPolicy {
        policy_id: "MDM-INTUNE-SIGNED-XML-003".to_string(),
        version: 3,
        allowed_hardware_ids: vec![r"USB\VID_0781&PID_5583\SER001".to_string()],
        ..IntuneMdmPolicy::default()
    };
    let signed_bundle =
        SignedPolicyBundle::sign(custom_policy.clone(), &root_priv, &root_pub).expect("sign pol");
    let signed_xml = IntunePolicyManager::export_signed_oma_uri_profile_xml(&signed_bundle)
        .expect("export signed oma-uri xml");
    assert!(signed_xml.contains("SignedPolicyBundleJson"));

    let mut intune_mgr = IntunePolicyManager::new()
        .with_vault_dir(tmp.path().join("intune_vault"))
        .with_pinned_root_public_keys(vec![root_pub.clone()]);
    let applied = intune_mgr
        .apply_signed_oma_uri_profile_xml(&signed_xml)
        .expect("apply signed Intune OMA-URI XML");
    assert_eq!(applied, custom_policy);

    // Unsigned OMA-URI profile XML MUST fail closed
    let unsigned_xml = intune_mgr.export_oma_uri_profile_xml();
    assert!(
        intune_mgr
            .apply_signed_oma_uri_profile_xml(&unsigned_xml)
            .is_err(),
        "Unsigned Intune OMA-URI XML lacking SignedPolicyBundleJson MUST be rejected fail-closed"
    );

    // 5. Windows SCM status state machine & Session 0 AppContainer profile derivation
    assert_eq!(SENTINEL_WINDOWS_SERVICE_NAME, "OmniConnectSentinel");
    assert!(scm_control_triggers_shutdown(SERVICE_CONTROL_STOP));
    assert!(scm_control_triggers_shutdown(SERVICE_CONTROL_SHUTDOWN));
    assert!(!scm_control_triggers_shutdown(SERVICE_CONTROL_INTERROGATE));
    let start_pending = build_scm_status(SERVICE_START_PENDING, 0, 0, 1, 10_000);
    assert_eq!(start_pending.controls_accepted, 0);
    let running = build_scm_status(SERVICE_RUNNING, 0, 0, 0, 0);
    assert_eq!(
        running.controls_accepted,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    );
    let stop_pending = build_scm_status(SERVICE_STOP_PENDING, 0, 0, 1, 10_000);
    assert_eq!(stop_pending.controls_accepted, 0);
    let stopped = build_scm_status(SERVICE_STOPPED, 0, 0, 0, 0);
    assert_eq!(stopped.current_state, SERVICE_STOPPED);

    assert_eq!(
        resolve_appcontainer_strategy_for_session(0),
        AppContainerSessionStrategy::DirectDeriveSessionZero
    );
    assert_eq!(
        resolve_appcontainer_strategy_for_session(1),
        AppContainerSessionStrategy::CreateOrDeriveInteractive
    );
    #[cfg(windows)]
    {
        assert!(
            sentinel_sys::verify_appcontainer_sid_derivation().expect("derive sid"),
            "Windows AppContainer SID derivation must succeed and pass IsValidSid"
        );
    }
}
