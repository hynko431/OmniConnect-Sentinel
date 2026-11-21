//! T34: IEC 62443 SL-3 Kiosk Path Traversal, ADS, DOS Device, & Zone Policy Tests
//!
//! Verifies:
//! 1. Complete rejection of path traversal (`..`, parent navigation) (`CSE-11`).
//! 2. Absolute and drive-letter prefix rejection (`C:\`, `\\server\share`, `/etc/passwd`).
//! 3. Rejection of NTFS Alternate Data Streams (`:`).
//! 4. Rejection of ASCII control characters (< 0x20, 0x7F).
//! 5. Rejection of Unicode bidirectional override smuggling (`\u{202E}`, `\u{202A}`, etc.).
//! 6. Rejection of DOS legacy device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
//! 7. Acceptance and normalization of strictly valid relative subpaths.
//! 8. Strict validation of media identifiers (`^[A-Za-z0-9_-]{1,64}$`).
//! 9. End-to-end Kiosk session file encryption and path isolation enforcement.
//! 10. Presence and integrity of `config/iec62443_kiosk_zone.yaml` SL-3 specification.

use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

use sentinel_core::enterprise::kiosk::{
    is_valid_media_id, sanitize_strict_relative_subpath, AirGappedKioskManager, KioskConfig,
    KioskPathError,
};

#[test]
fn test_path_traversal_dot_dot_rejection() {
    let bad_paths = [
        "../secret.txt",
        "..",
        "sub/../../etc/passwd",
        "a/b/../c/../../d",
        "dir/..",
        "nested/sub/../../../root.txt",
    ];

    for bad in &bad_paths {
        let res = sanitize_strict_relative_subpath(Path::new(bad));
        assert!(
            matches!(res, Err(KioskPathError::PathTraversal(_))),
            "Expected PathTraversal for '{bad}', got: {res:?}"
        );
    }
}

#[test]
fn test_absolute_and_drive_prefix_rejection() {
    let abs_paths = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:/Windows/System32/cmd.exe",
        "D:\\data.bin",
        "\\\\server\\share\\malware.exe",
        "/etc/shadow",
        "/tmp/bad.sh",
        "\\Windows\\temp",
    ];

    for abs in &abs_paths {
        let res = sanitize_strict_relative_subpath(Path::new(abs));
        assert!(
            matches!(
                res,
                Err(KioskPathError::AbsolutePath(_))
                    | Err(KioskPathError::AlternateDataStream(_))
                    | Err(KioskPathError::PathTraversal(_))
            ),
            "Expected AbsolutePath/ADS/Traversal rejection for '{abs}', got: {res:?}"
        );
    }
}

#[test]
fn test_ntfs_alternate_data_stream_rejection() {
    let ads_paths = [
        "clean.txt:hidden.exe",
        "invoice.pdf::$DATA",
        "folder/file.docx:malicious_zone_id",
        "data:stream",
        "file.txt:stream:$INDEX_ALLOCATION",
    ];

    for ads in &ads_paths {
        let res = sanitize_strict_relative_subpath(Path::new(ads));
        assert!(
            matches!(res, Err(KioskPathError::AlternateDataStream(_))),
            "Expected AlternateDataStream for '{ads}', got: {res:?}"
        );
    }
}

#[test]
fn test_control_character_rejection() {
    let ctrl_paths = [
        "evil\x00file.txt",
        "test\r\nfile.txt",
        "dir/name\x07with_bell.pdf",
        "payload\x1F.bin",
        "del\x7Fchar.doc",
    ];

    for ctrl in &ctrl_paths {
        let res = sanitize_strict_relative_subpath(Path::new(ctrl));
        assert!(
            matches!(res, Err(KioskPathError::ControlCharacter(_))),
            "Expected ControlCharacter for '{ctrl}', got: {res:?}"
        );
    }
}

#[test]
fn test_unicode_bidi_override_smuggling_rejection() {
    let bidi_paths = [
        "report\u{202E}fdp.exe",    // RLO (Right-to-Left Override)
        "safe_\u{202A}_bad.pdf",    // LRE
        "test_\u{202B}_rtl.docx",   // RLE
        "data\u{202C}pop.bin",      // PDF (Pop Directional Format)
        "file\u{202D}override.txt", // LRO
        "\u{2066}payload\u{2069}",  // LRI / PDI
        "\u{2067}payload\u{2069}",  // RLI / PDI
        "\u{2068}payload\u{2069}",  // FSI / PDI
    ];

    for bidi in &bidi_paths {
        let res = sanitize_strict_relative_subpath(Path::new(bidi));
        assert!(
            matches!(res, Err(KioskPathError::BidiOverride(_))),
            "Expected BidiOverride for '{bidi}', got: {res:?}"
        );
    }
}

#[test]
fn test_dos_legacy_device_name_rejection() {
    let dos_paths = [
        "CON",
        "con.txt",
        "sub/PRN",
        "prn.pdf",
        "AUX",
        "aux.doc",
        "NUL",
        "nul.tar.gz",
        "COM1",
        "com2.dat",
        "COM9.txt",
        "LPT1",
        "lpt5.log",
        "nested/deep/LPT9.bin",
    ];

    for dos in &dos_paths {
        let res = sanitize_strict_relative_subpath(Path::new(dos));
        assert!(
            matches!(res, Err(KioskPathError::DosDeviceName(_, _))),
            "Expected DosDeviceName for '{dos}', got: {res:?}"
        );
    }
}

#[test]
fn test_valid_relative_paths_succeed() {
    let valid_paths = [
        "documents/report.pdf",
        "data/2026/q1/metrics.csv",
        "file.txt",
        "deeply/nested/folder/structure/item.bin",
        "sanitized_firmware.bin",
        "scada_update_v2.tar",
    ];

    for valid in &valid_paths {
        let res = sanitize_strict_relative_subpath(Path::new(valid));
        assert!(res.is_ok(), "Expected success for '{valid}', got: {res:?}");
        let sanitized = res.unwrap();
        assert!(!sanitized.is_absolute());
    }
}

#[test]
fn test_empty_path_rejection() {
    let empty_paths = ["", "   ", " \t \n "];
    for empty in &empty_paths {
        let res = sanitize_strict_relative_subpath(Path::new(empty));
        assert!(
            matches!(
                res,
                Err(KioskPathError::EmptyPath(_)) | Err(KioskPathError::ControlCharacter(_))
            ),
            "Expected EmptyPath or ControlCharacter for '{empty}', got: {res:?}"
        );
    }
}

#[test]
fn test_media_id_regex_validation() {
    let valid_ids = [
        "USB-MEDIA-01",
        "SCADA_MAINT_DRIVE_09",
        "flash-stick-abc-123",
        "MEDIA1",
        "a",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64 chars
    ];

    for valid in &valid_ids {
        assert!(
            is_valid_media_id(valid),
            "Expected valid media_id for '{valid}'"
        );
    }

    let invalid_ids = [
        "",                                                                  // empty
        "USB MEDIA 01",                                                      // spaces
        "USB$MEDIA",                                                         // special char $
        "../../evil",                                                        // path traversal
        "media/slash",                                                       // path slash
        "media\\backslash",                                                  // backslash
        "media:ads",                                                         // colon
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefX", // 65 chars (> 64)
    ];

    for invalid in &invalid_ids {
        assert!(
            !is_valid_media_id(invalid),
            "Expected invalid media_id for '{invalid}'"
        );
    }
}

#[test]
fn test_kiosk_session_path_enforcement() {
    let tmp = tempdir().expect("tempdir");
    let session_dir = tmp.path().join("sessions");
    let mut manager = AirGappedKioskManager::new(KioskConfig::default(), session_dir);

    // Initial session with valid media_id
    let session_res = manager.start_kiosk_session("USB-SECURE-01");
    assert!(session_res.is_ok(), "Session start failed: {session_res:?}");

    // Writing valid file succeeds
    let test_data = b"IEC 62443 Kiosk Sanitized Payload";
    let write_res = manager.write_encrypted_session_file(Path::new("clean/report.bin"), test_data);
    assert!(write_res.is_ok(), "Write valid file failed: {write_res:?}");

    // Reading valid file matches
    let read_res = manager.read_encrypted_session_file(Path::new("clean/report.bin"));
    assert!(read_res.is_ok(), "Read valid file failed: {read_res:?}");
    assert_eq!(read_res.unwrap(), test_data);

    // Writing path traversal fails closed
    let traversal_write =
        manager.write_encrypted_session_file(Path::new("../escape.bin"), test_data);
    assert!(
        traversal_write.is_err(),
        "Traversal write must fail closed!"
    );

    // Reading path traversal fails closed
    let traversal_read = manager.read_encrypted_session_file(Path::new("../../etc/shadow"));
    assert!(traversal_read.is_err(), "Traversal read must fail closed!");

    // Writing DOS device fails closed
    let dos_write = manager.write_encrypted_session_file(Path::new("con.txt"), test_data);
    assert!(dos_write.is_err(), "DOS device write must fail closed!");

    // Starting session with invalid media_id fails closed
    let bad_session = manager.start_kiosk_session("../../bad-media");
    assert!(
        bad_session.is_err(),
        "Session start with path traversal media_id must fail closed!"
    );
}

#[test]
fn test_iec62443_kiosk_zone_specification() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut config_path = manifest_dir.join("../../config/iec62443_kiosk_zone.yaml");
    if !config_path.exists() {
        config_path = PathBuf::from("config/iec62443_kiosk_zone.yaml");
    }
    assert!(
        config_path.exists(),
        "config/iec62443_kiosk_zone.yaml must exist"
    );

    let content = fs::read_to_string(&config_path).expect("read iec62443_kiosk_zone.yaml");
    assert!(
        content.contains("Z4-DMZ-KIOSK"),
        "Zone name Z4-DMZ-KIOSK missing"
    );
    assert!(
        content.contains("security_level: 3") || content.contains("security_level: \"SL-3\""),
        "SL-3 rating missing"
    );
    assert!(
        content.contains("sanitize_strict_relative_subpath"),
        "Path sanitization reference missing"
    );
    assert!(
        content.contains("fail_closed: true"),
        "Fail-closed posture missing"
    );
}
