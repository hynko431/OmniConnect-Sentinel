//! Cold-Eye Phase 2 Master Cross-Component Adversarial Break-It Probe
//!
//! Regression & hostile verification suite covering all Phase 2 Master cross-component invariants:
//! 1. `[CEA-DEFECT-01]` — CDR Passport & `sanitize_strict_relative_subpath` rejection of leading/trailing
//!    ASCII whitespace (`safe/ report.pdf`), Unicode NBSP (`U+00A0`), zero-width characters (`U+200B`, `U+FEFF`),
//!    `.` (`CurDir`), and double slashes, enforcing a 1-to-1 bijection in `verify_kiosk_passport`.
//! 2. `[CEA-DEFECT-02]` — Cross-component unified `AuditLedger` sequence & hash-chain linearizability
//!    under interleaved `SharedAuditLedger` (`QuarantineVault`, `CrowdStrikeFalconBridge`), transient
//!    path-based `AuditLedger` (`KioskEnforcer`, `SecureShredder`), and concurrent threads.
//! 3. `[CEA-DEFECT-03]` — `ShadowCacheManager::teardown_session` fail-closed error reporting (`Err`)
//!    when any hydrated file or subdirectory inside `projection_root` or `shadow_cipher_dir` is locked
//!    or unremovable during session teardown.
//! 4. `[CEA-DEFECT-04]` — `PendingDeviceConfirmationManager` unconditional 300s TTL enforcement
//!    (rejecting `expires_at_unix <= 0`, `created_at_unix <= 0`, and `> 300s` window skew),
//!    `#[serde(deny_unknown_fields)]` rejection of legacy `challenge_code` injection, and immediate
//!    shredding/removal of superseded `.token` secret files upon USB re-enumeration.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::tempdir;

use sentinel_core::enterprise::falcon::{CrowdStrikeFalconBridge, FalconTelemetryEvent};
use sentinel_core::enterprise::kiosk::{
    sanitize_strict_relative_subpath, verify_kiosk_passport, AirGappedKioskManager, KioskConfig,
    PASSPORT_PUBKEY_FILENAME,
};
use sentinel_core::enterprise::ledger::{create_shared_audit_ledger, AuditLedger, AuditSubsystem};
use sentinel_core::interceptor::PendingDeviceConfirmationManager;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::secure_shredder::{SecureShredder, ShredMethod};
use sentinel_core::vfs::ShadowCacheManager;

#[test]
fn cea_phase2_defect01_passport_whitespace_nbsp_and_invisible_implant_rejected() {
    // 1. Direct sanitizer hostile matrix
    let hostile_paths = [
        ".",
        "./safe/report.pdf",
        "safe/./report.pdf",
        "safe//report.pdf",
        "safe\\\\report.pdf",
        "safe/",
        "safe\\",
        "/safe/report.pdf",
        "\\safe\\report.pdf",
        "safe/ report.pdf",
        "safe/report.pdf ",
        " safe/report.pdf",
        "safe /report.pdf",
        "safe/report.pdf\u{00A0}",
        "safe/\u{00A0}/report.pdf",
        "safe/report\u{00A0}v2.pdf",
        "safe/report\u{200B}.pdf",
        "safe/report\u{FEFF}.pdf",
        "safe/report\u{2060}.pdf",
        "safe/report\u{00AD}.pdf",
        "safe/report\u{3000}.pdf",
    ];
    for bad in &hostile_paths {
        let res = sanitize_strict_relative_subpath(Path::new(bad));
        assert!(
            res.is_err(),
            "Hostile relative subpath {bad:?} MUST be rejected fail-closed, got: {res:?}"
        );
    }

    // 2. End-to-end signed CDR passport verification against post-signing whitespace/NBSP implants
    let tmp = tempdir().expect("tempdir");
    let kiosk_dir = tmp.path().join("kiosk_d01");
    let export_dir = tmp.path().join("export_d01");
    let kiosk = AirGappedKioskManager::new(KioskConfig::default(), kiosk_dir);

    let batch = vec![(
        PathBuf::from("safe/report.pdf"),
        b"%PDF-1.7 VERIFIED CLEAN PAYLOAD".to_vec(),
        "DEEP_CDR_PDF".to_string(),
    )];
    let _passport = kiosk
        .export_sanitized_batch_with_passport(&export_dir, "USB-D01-01", "POL-D01", 1, &batch)
        .expect("export batch");
    let pub_bytes = fs::read(export_dir.join(PASSPORT_PUBKEY_FILENAME)).expect("read pubkey");

    // Baseline clean passport MUST verify
    assert!(verify_kiosk_passport(&export_dir, Some(&pub_bytes)).is_ok());

    // Attack 1A: Unlisted malware at `safe/ report.pdf` (leading ASCII space)
    let implant_1a = export_dir.join("safe").join(" report.pdf");
    if fs::write(&implant_1a, b"MZ\x90\x00_LEADING_SPACE_IMPLANT").is_ok() {
        let res_1a = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
        assert!(
            res_1a.is_err(),
            "Attack 1A ('safe/ report.pdf') MUST be rejected by verify_kiosk_passport!"
        );
        let _ = fs::remove_file(&implant_1a);
    }
    assert!(verify_kiosk_passport(&export_dir, Some(&pub_bytes)).is_ok());

    // Attack 1B: Unlisted malware at `safe/report.pdf\u{00A0}` (trailing Unicode NBSP)
    let implant_1b = export_dir.join("safe").join("report.pdf\u{00A0}");
    if fs::write(&implant_1b, b"MZ\x90\x00_TRAILING_NBSP_IMPLANT").is_ok() {
        let res_1b = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
        assert!(
            res_1b.is_err(),
            "Attack 1B ('safe/report.pdf<NBSP>') MUST be rejected by verify_kiosk_passport!"
        );
        let _ = fs::remove_file(&implant_1b);
    }
    assert!(verify_kiosk_passport(&export_dir, Some(&pub_bytes)).is_ok());

    // Attack 1C: Unlisted invisible NBSP subdirectory `safe/\u{00A0}/report.pdf`
    let nbsp_dir = export_dir.join("safe").join("\u{00A0}");
    if fs::create_dir_all(&nbsp_dir).is_ok() {
        let implant_1c = nbsp_dir.join("report.pdf");
        let _ = fs::write(&implant_1c, b"MZ\x90\x00_NBSP_SUBDIR_IMPLANT");
        let res_1c = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
        assert!(
            res_1c.is_err(),
            "Attack 1C ('safe/<NBSP>/report.pdf') MUST be rejected by verify_kiosk_passport!"
        );
        let _ = fs::remove_dir_all(&nbsp_dir);
    }
    assert!(verify_kiosk_passport(&export_dir, Some(&pub_bytes)).is_ok());

    // Attack 1D: Zero-width space homoglyph implant `safe/report\u{200B}.pdf`
    let implant_1d = export_dir.join("safe").join("report\u{200B}.pdf");
    if fs::write(&implant_1d, b"MZ\x90\x00_ZWSP_IMPLANT").is_ok() {
        let res_1d = verify_kiosk_passport(&export_dir, Some(&pub_bytes));
        assert!(
            res_1d.is_err(),
            "Attack 1D ('safe/report<ZWSP>.pdf') MUST be rejected by verify_kiosk_passport!"
        );
        let _ = fs::remove_file(&implant_1d);
    }
    assert!(verify_kiosk_passport(&export_dir, Some(&pub_bytes)).is_ok());
}

#[test]
fn cea_phase2_defect02_unified_ledger_mixed_shared_and_path_writers_stay_linearizable() {
    let tmp = tempdir().expect("tempdir");
    let unified_ledger_path = tmp.path().join("unified_audit_v2.jsonl");
    let shared_ledger =
        create_shared_audit_ledger(&unified_ledger_path).expect("create shared ledger");

    // 1. Append initial event via long-lived SharedAuditLedger (`seq = 1`)
    {
        let mut guard = shared_ledger.lock().expect("lock");
        guard
            .append_subsystem_event(
                AuditSubsystem::System,
                "BOOT_INIT",
                serde_json::json!({ "phase": 2 }),
            )
            .expect("append boot");
    }

    // 2. Interleave transient path-based writers (`KioskEnforcer::with_ledger_path` + `SecureShredder::shred_file_with_ledger`)
    let kiosk_session_dir = tmp.path().join("kiosk_sessions");
    let export_dir = tmp.path().join("kiosk_export");
    let mut path_kiosk = AirGappedKioskManager::new(KioskConfig::default(), kiosk_session_dir)
        .with_ledger_path(unified_ledger_path.clone());
    let (_sess_id, _sub) = path_kiosk
        .start_kiosk_session("USB-MIXED-01")
        .expect("start kiosk");
    path_kiosk
        .write_encrypted_session_file(Path::new("clean/doc.txt"), b"Kiosk payload")
        .expect("write session file");
    let _pass = path_kiosk
        .export_sanitized_batch_with_passport(
            &export_dir,
            "USB-MIXED-01",
            "POL-UNIFIED",
            3,
            &[(
                PathBuf::from("clean/doc.txt"),
                b"Sanitized doc".to_vec(),
                "CDR_CLEAN".to_string(),
            )],
        )
        .expect("export passport");
    path_kiosk.end_kiosk_session().expect("end kiosk");

    let scratch_shred = tmp.path().join("transient_malware.bin");
    fs::write(&scratch_shred, b"MALICIOUS_SAMPLE_TO_SHRED").expect("write sample");
    SecureShredder::shred_file_with_ledger(
        &scratch_shred,
        ShredMethod::NIST_CLEAR_THREE_PASS,
        &unified_ledger_path,
    )
    .expect("shred to unified path");

    // 3. Resume writing via the ORIGINAL long-lived `SharedAuditLedger` (`QuarantineVault` + `CrowdStrikeFalconBridge`)!
    // Previously this wrote duplicate `seq = 2` and corrupted the chain!
    let vault_dir = tmp.path().join("quarantine_vault");
    let vault = QuarantineVault::open(vault_dir)
        .expect("open vault")
        .with_shared_ledger(shared_ledger.clone());
    let sample_q = tmp.path().join("trojan.exe");
    fs::write(&sample_q, b"MZ\x90\x00_QUARANTINE_SAMPLE").expect("write trojan");
    let q_entry = vault
        .quarantine_file(&sample_q, "RULE-PHASE2-MASTER")
        .expect("quarantine");
    vault.purge(&q_entry.entry_id).expect("purge quarantine");

    let falcon =
        CrowdStrikeFalconBridge::with_spool_path("offline://siem", tmp.path().join("siem.spool"))
            .with_shared_ledger(shared_ledger.clone());
    falcon
        .emit_alert(&FalconTelemetryEvent {
            severity: 8,
            signature_id: "SIG-P2-MASTER".to_string(),
            name: "Cross-Component Test".to_string(),
            device_vendor_id: "0781".to_string(),
            device_product_id: "5581".to_string(),
            serial_number: "SN-MIXED-01".to_string(),
            file_sha256: None,
            action_taken: "QUARANTINED_AND_PURGED".to_string(),
            details: "Interleaved ledger verification".to_string(),
        })
        .expect("emit falcon alert");

    // 4. Multi-threaded race test: 4 threads mixing `SharedAuditLedger` and transient `AuditLedger::open_result`
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for tid in 0..4 {
        let b = barrier.clone();
        let sl = shared_ledger.clone();
        let lp = unified_ledger_path.clone();
        handles.push(thread::spawn(move || {
            b.wait();
            for iter in 0..3 {
                if (tid + iter) % 2 == 0 {
                    let mut g = sl.lock().expect("lock shared");
                    g.append_event("CONCURRENT_SHARED_EVENT", format!("tid={tid} iter={iter}"))
                        .expect("append shared");
                } else {
                    let mut transient = AuditLedger::open_result(&lp).expect("open transient");
                    transient
                        .append_event("CONCURRENT_PATH_EVENT", format!("tid={tid} iter={iter}"))
                        .expect("append transient");
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("join thread");
    }

    // 5. Emit WORM periodic checkpoint via `SharedAuditLedger` and verify entire hash chain & ECDSA `.head.sig`
    {
        let mut g = shared_ledger.lock().expect("lock shared");
        g.emit_worm_checkpoint().expect("emit worm checkpoint");
    }

    let verifier = AuditLedger::open_result(&unified_ledger_path).expect("open verifier");
    let count = verifier
        .verify_chain()
        .expect("Unified ledger chain MUST verify cleanly with zero sequence or hash breaks");
    assert!(
        count >= 20,
        "Expected at least 20 verified cross-component records, got {count}"
    );
}

#[test]
fn cea_phase2_defect03_vfs_teardown_locked_file_or_subdir_fails_closed() {
    let tmp = tempdir().expect("tempdir");
    let cache_root = tmp.path().join("shadow_cache_root");
    let raw_usb = tmp.path().join("raw_usb");
    let proj_mount = tmp.path().join("proj_mount");
    // Create directory structure on `raw_usb` so `ingest_volume_read_once` registers a live
    // `ShadowSessionState` even inside outer AppContainer sandboxes where child worker spawn is restricted.
    fs::create_dir_all(raw_usb.join("nested")).expect("create raw_usb/nested");

    let shared_ledger =
        create_shared_audit_ledger(tmp.path().join("vfs_ledger.jsonl")).expect("vfs ledger");
    let mgr = ShadowCacheManager::with_cache_root_and_quota(cache_root, 16 * 1024 * 1024)
        .with_shared_ledger(shared_ledger.clone());

    mgr.ingest_volume_read_once(&raw_usb, &proj_mount)
        .expect("ingest directory session");

    let hydrated_dir = proj_mount.join("nested");
    fs::create_dir_all(&hydrated_dir).expect("create hydrated nested dir");
    let hydrated = hydrated_dir.join("clean_note.txt");
    fs::write(
        &hydrated,
        b"Verified benign plaintext note for VFS teardown lock test.\n",
    )
    .expect("write hydrated clean_note.txt");

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Hold a handle without FILE_SHARE_DELETE (`share_mode(1)` = FILE_SHARE_READ only)
        // so `SecureShredder` / `remove_dir` cannot remove `hydrated` or `proj_mount/nested`.
        let locked_handle = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&hydrated)
            .expect("open exclusive read lock on hydrated file");

        let teardown_res = mgr.teardown_session(&proj_mount);
        assert!(
            teardown_res.is_err(),
            "teardown_session MUST fail closed (Err) when hydrated plaintext remains locked on disk!"
        );
        drop(locked_handle);

        let _ = sentinel_sys::normalize_file_attributes(&hydrated);
        SecureShredder::shred_file(&hydrated, ShredMethod::NIST_CLEAR_THREE_PASS)
            .expect("post-unlock shred");
        let _ = fs::remove_dir_all(&proj_mount);
    }

    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&hydrated_dir, fs::Permissions::from_mode(0o000));
        let teardown_res = mgr.teardown_session(&proj_mount);
        let _ = fs::set_permissions(&hydrated_dir, fs::Permissions::from_mode(0o700));
        assert!(
            teardown_res.is_err(),
            "teardown_session MUST fail closed (Err) when hydrated subdir is unreadable/unremovable!"
        );
        SecureShredder::shred_file(&hydrated, ShredMethod::NIST_CLEAR_THREE_PASS)
            .expect("post-unlock shred");
        let _ = fs::remove_dir_all(&proj_mount);
    }

    // Verify clean teardown also succeeds and removes `proj_mount2` completely when unlocked
    let raw_usb2 = tmp.path().join("raw_usb2");
    let proj_mount2 = tmp.path().join("proj_mount2");
    fs::create_dir_all(raw_usb2.join("sub")).expect("create raw_usb2");
    mgr.ingest_volume_read_once(&raw_usb2, &proj_mount2)
        .expect("ingest session 2");
    fs::create_dir_all(proj_mount2.join("sub")).expect("create proj2/sub");
    fs::write(proj_mount2.join("sub").join("ok.txt"), b"unlocked hydrated").expect("write ok.txt");
    mgr.teardown_session(&proj_mount2)
        .expect("unlocked teardown must succeed");
    assert!(
        !proj_mount2.exists(),
        "Clean teardown_session must remove projection_root completely"
    );

    let verified = shared_ledger
        .lock()
        .expect("lock")
        .verify_chain()
        .expect("verify vfs ledger chain");
    assert!(verified >= 2);
}

#[test]
fn cea_phase2_defect04_badusb_zero_expiry_bypass_unknown_fields_and_orphan_token_reaping() {
    let tmp = tempdir().expect("tempdir");
    let state_file = tmp.path().join("pending_device_confirmations.json");
    let mgr = PendingDeviceConfirmationManager::new(state_file.clone());

    let device_id = "USB\\VID_1D6B&PID_0104\\COMPOSITE_REENUM_01";

    // 1. Re-issuing a challenge for the same `device_id` MUST immediately wipe & delete the superseded `.token` file!
    let chal_1 = mgr
        .request_user_presence_challenge_extended(device_id)
        .expect("issue chal 1");
    let token_path_1 = tmp
        .path()
        .join(format!("pending_challenge_{}.token", chal_1.challenge_id));
    assert!(token_path_1.exists(), "First .token file must exist");

    let chal_2 = mgr
        .request_user_presence_challenge_extended(device_id)
        .expect("re-issue chal 2");
    let token_path_2 = tmp
        .path()
        .join(format!("pending_challenge_{}.token", chal_2.challenge_id));
    assert!(
        !token_path_1.exists(),
        "Superseded first .token secret file MUST be deleted immediately on challenge re-issuance!"
    );
    assert!(
        token_path_2.exists(),
        "Active second .token file must exist"
    );

    // 2. Attack A: `created_at_unix = now - 3600`, `expires_at_unix = 0` MUST fail closed and purge `.token`!
    let now = sentinel_sys::now_unix_secs();
    let mut state_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_file).expect("read state"))
            .expect("parse json");
    state_json[device_id]["created_at_unix"] = serde_json::json!(now - 3600);
    state_json[device_id]["expires_at_unix"] = serde_json::json!(0);
    fs::write(
        &state_file,
        serde_json::to_string_pretty(&state_json).expect("serialize"),
    )
    .expect("write zero expiry");

    let zero_exp_res = mgr.confirm_device_with_challenge(device_id, &chal_2.challenge_token);
    assert!(
        zero_exp_res.is_err(),
        "expires_at_unix = 0 MUST NOT bypass 300s TTL expiration!"
    );
    assert!(
        !token_path_2.exists(),
        "Expired/invalid challenge .token file must be purged!"
    );
    assert!(!mgr.is_confirmed(device_id));

    // 3. Attack B: `expires_at_unix` stretched beyond `created_at_unix + 300` MUST fail closed!
    let chal_3 = mgr
        .request_user_presence_challenge_extended(device_id)
        .expect("issue chal 3");
    let mut state_json_b: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_file).expect("read state"))
            .expect("parse json");
    state_json_b[device_id]["expires_at_unix"] = serde_json::json!(now + 86_400);
    fs::write(
        &state_file,
        serde_json::to_string_pretty(&state_json_b).expect("serialize"),
    )
    .expect("write stretched expiry");
    assert!(
        mgr.confirm_device_with_challenge(device_id, &chal_3.challenge_token)
            .is_err(),
        "Stretched >300s TTL window MUST fail closed!"
    );

    // 4. Attack C: Legacy `challenge_code` or unknown JSON field injection MUST be rejected by `#[serde(deny_unknown_fields)]`!
    let chal_4 = mgr
        .request_user_presence_challenge_extended(device_id)
        .expect("issue chal 4");
    let mut state_json_c: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_file).expect("read state"))
            .expect("parse json");
    state_json_c[device_id]["challenge_code"] = serde_json::json!("PLAINTEXT_BACKDOOR");
    fs::write(
        &state_file,
        serde_json::to_string_pretty(&state_json_c).expect("serialize"),
    )
    .expect("write unknown field");
    assert!(
        mgr.confirm_device_with_challenge(device_id, "PLAINTEXT_BACKDOOR")
            .is_err(),
        "Legacy challenge_code injection MUST fail closed!"
    );
    assert!(
        mgr.confirm_device_with_challenge(device_id, &chal_4.challenge_token)
            .is_err(),
        "Unknown field in state JSON MUST fail closed under #[serde(deny_unknown_fields)]!"
    );
}
