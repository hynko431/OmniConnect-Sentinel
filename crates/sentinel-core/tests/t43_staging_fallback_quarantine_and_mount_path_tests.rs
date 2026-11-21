use sentinel_cdr::{WorkerLauncher, WorkerRequest};
use sentinel_core::config::{
    default_os_safe_drive_mount_path, resolve_safe_drive_mount_path, SentinelConfig,
};
use sentinel_core::enterprise::ledger::AuditLedger;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::vfs::fuse::FuseVfsProvider;
use sentinel_core::vfs::{ShadowCacheManager, StagingFolderProvider, VirtualFileSystemProvider};
use sentinel_sys::{
    apply_readonly_staging_dacl, create_readonly_staging_dir_atomic,
    create_readonly_staging_file_atomic, query_path_dacl_sddl, JobSandboxConfig,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

fn test_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "omniconnect_{}_{}_{}",
        label,
        std::process::id(),
        Uuid::new_v4().simple()
    ));
    fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

fn locate_or_build_cdr_worker_binary() -> PathBuf {
    let exe_name = if cfg!(windows) {
        "sentinel-cdr-worker.exe"
    } else {
        "sentinel-cdr-worker"
    };
    let current_exe = std::env::current_exe().expect("current_exe");
    let deps_dir = current_exe.parent().expect("test binary parent");
    let profile_dir = deps_dir.parent().unwrap_or(deps_dir);

    for candidate in [deps_dir.join(exe_name), profile_dir.join(exe_name)] {
        if candidate.is_file() {
            return candidate;
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(workspace_root).args([
        "build",
        "-p",
        "sentinel-cdr",
        "--bin",
        "sentinel-cdr-worker",
        "--offline",
    ]);
    if profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "release")
    {
        cmd.arg("--release");
    }
    let status = cmd
        .status()
        .expect("invoke cargo build for sentinel-cdr-worker");
    assert!(
        status.success(),
        "building sentinel-cdr-worker offline failed with status {status}"
    );
    let built = profile_dir.join(exe_name);
    assert!(
        built.is_file(),
        "sentinel-cdr-worker binary missing after build at {}",
        built.display()
    );
    built
}

fn build_verified_worker_launcher() -> WorkerLauncher {
    let worker_bin = locate_or_build_cdr_worker_binary();
    let default_launcher = WorkerLauncher::new().with_worker_bin(worker_bin.clone());
    assert!(
        default_launcher.has_worker_binary(),
        "WorkerLauncher must locate real sentinel-cdr-worker binary"
    );

    let probe = default_launcher.sanitize_isolated(WorkerRequest {
        file_name: "probe.txt".to_string(),
        policy: sentinel_cdr::SanitizationPolicy::default(),
        raw_bytes: b"probe".to_vec(),
    });
    match probe {
        Ok(_) => default_launcher,
        Err(err)
            if cfg!(windows)
                && (err.to_string().contains("os error 87")
                    || err.to_string().contains("CreateProcessW failed")) =>
        {
            // Inside a nested Windows AppContainer test sandbox, CreateProcessW rejects
            // nested SECURITY_CAPABILITIES with ERROR_INVALID_PARAMETER (87).
            // Test-only fallback preserves real out-of-process worker execution + Job Object
            // + process mitigations without weakening production JobSandboxConfig::default().
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

fn find_first_enc_file(root: &Path) -> Option<PathBuf> {
    for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
        if entry.file_type().is_file()
            && entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("enc"))
        {
            return Some(entry.into_path());
        }
    }
    None
}

#[cfg(windows)]
fn assert_windows_sddl_has_readonly_au_only(sddl: &str, is_dir: bool) {
    assert!(
        sddl.contains(";;;AU)"),
        "Materialized staging ACL must include Authenticated Users (AU) read-only ACE; got: {sddl}"
    );
    assert!(
        !sddl.contains(";;;WD)"),
        "Materialized staging ACL must never grant Everyone (WD); got: {sddl}"
    );
    let au_aces: Vec<&str> = sddl
        .split('(')
        .filter(|segment| segment.contains(";;;AU)"))
        .collect();
    assert!(
        !au_aces.is_empty(),
        "Expected at least one AU ACE in staging SDDL: {sddl}"
    );
    for ace in au_aces {
        let fields: Vec<&str> = ace.split(';').collect();
        assert!(
            fields.len() >= 6,
            "Unexpected SDDL ACE syntax '{ace}' in '{sddl}'"
        );
        let ace_type = fields[0];
        let ace_flags = fields[1];
        let rights = fields[2];
        assert_eq!(ace_type, "A", "Expected Allow ACE for AU, got '{ace}'");
        assert!(
            !rights.contains("GA")
                && !rights.contains("FA")
                && !rights.contains("GW")
                && !rights.contains("FW")
                && !rights.contains("WD")
                && !rights.contains("SD")
                && !rights.contains("WO")
                && !rights.contains("WP")
                && !rights.contains("DC"),
            "AU ACE must never grant write/delete/full-control rights; got ACE '({ace}' in '{sddl}'"
        );
        if !is_dir {
            assert!(
                !rights.contains("FX") && !rights.contains("GX"),
                "Staging file AU ACE must be strictly read-only (no execute); got '({ace}' in '{sddl}'"
            );
            assert!(
                rights == "FR" || rights == "GR" || rights == "0x120089",
                "Staging file AU ACE must be FILE_GENERIC_READ; got '({ace}' in '{sddl}'"
            );
        } else if ace_flags.contains("IO") {
            assert!(
                !rights.contains("FX") && !rights.contains("GX"),
                "Inherit-only file ACE for AU must not grant execute; got '({ace}' in '{sddl}'"
            );
        } else {
            assert!(
                rights == "FRFX" || rights == "0x1200a9" || rights == "GRGX" || rights == "FR",
                "Staging directory AU ACE must grant only read/traverse; got '({ace}' in '{sddl}'"
            );
        }
    }
}

#[tokio::test]
async fn t43_staging_provider_quarantines_withheld_threats_and_standard_user_can_read_sanitized() {
    let root = test_temp_dir("t43_staging_fallback");
    let raw_usb = root.join("raw_usb");
    let nested_docs = raw_usb.join("docs");
    let virtual_mount = root.join("SafeDrive");
    let shadow_cache_root = root.join("ShadowCache");
    let vault_dir = root.join("QuarantineVault");
    let ledger_path = root.join("t43_audit_ledger.jsonl");

    fs::create_dir_all(&nested_docs).expect("create raw_usb/docs");
    let clean_src = nested_docs.join("report.txt");
    fs::write(&clean_src, b"Clean sanitized operational report 2026\n").expect("write clean file");

    // Deterministic Defender-safe non-disarmable Windows LNK shell-link payload
    // flagged by UniversalScanner::scan_bytes_single_read.
    let threat_src = raw_usb.join("payload.lnk");
    let mut lnk_bytes = vec![
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    lnk_bytes.extend_from_slice(b"powershell.exe -EncodedCommand ZQBjAGgAbwA=");
    fs::write(&threat_src, &lnk_bytes).expect("write threat lnk");

    let shared_ledger = Arc::new(Mutex::new(
        AuditLedger::open_result(&ledger_path).expect("open unified audit ledger"),
    ));
    let launcher = build_verified_worker_launcher();

    let shadow_cache =
        ShadowCacheManager::with_cache_root_and_quota(shadow_cache_root.clone(), 16 * 1024 * 1024)
            .with_shared_ledger(shared_ledger.clone())
            .with_worker_launcher(launcher.clone());

    let provider: Box<dyn VirtualFileSystemProvider> =
        Box::new(StagingFolderProvider::with_shadow_cache(shadow_cache));

    provider
        .mount_sanitized_volume(&raw_usb, &virtual_mount)
        .await
        .expect("StagingFolderProvider mount_sanitized_volume must succeed");

    // 1. Withheld threats MUST be returned through VirtualFileSystemProvider::take_withheld_threats
    let withheld = provider.take_withheld_threats(&virtual_mount);
    assert!(
        !withheld.is_empty(),
        "StagingFolderProvider MUST return withheld threats instead of dropping them via default Vec::new()"
    );
    assert!(
        withheld
            .iter()
            .any(|t| t.file_path.file_name().and_then(|n| n.to_str()) == Some("payload.lnk")),
        "Expected payload.lnk in withheld threats, got: {withheld:?}"
    );
    assert!(
        provider.take_withheld_threats(&virtual_mount).is_empty(),
        "Second take_withheld_threats call must drain the queue to prevent duplicate quarantine"
    );

    // Quarantine withheld threats through QuarantineVault matching sentinel-core/src/main.rs
    let vault = QuarantineVault::open(vault_dir.clone())
        .expect("open quarantine vault")
        .with_shared_ledger(shared_ledger.clone());
    for threat in &withheld {
        let entry = vault
            .quarantine_readonly_evidence(&threat.file_path, &threat.threat_name, threat.risk_score)
            .expect("quarantining withheld threat from StagingFolderProvider must succeed");
        assert!(
            vault.verify_entry(&entry.entry_id).is_ok(),
            "Quarantined entry must pass SNTLQV03 verification"
        );
    }
    assert!(
        !vault.list_entries().expect("list vault").is_empty(),
        "QuarantineVault must persist withheld threats from StagingFolderProvider"
    );

    // 2. Malicious file must NEVER be materialized; clean file MUST be materialized & readable
    assert!(
        !virtual_mount.join("payload.lnk").exists(),
        "Withheld threat payload.lnk must never appear in materialized staging directory"
    );
    let staged_clean = virtual_mount.join("docs").join("report.txt");
    assert!(
        staged_clean.is_file(),
        "Clean sanitized file must be materialized at {}",
        staged_clean.display()
    );
    let staged_bytes = fs::read(&staged_clean).expect("read materialized sanitized file");
    assert!(
        String::from_utf8_lossy(&staged_bytes).contains("Clean sanitized operational report 2026"),
        "Materialized sanitized payload mismatch"
    );
    assert!(
        fs::metadata(&staged_clean)
            .expect("metadata")
            .permissions()
            .readonly(),
        "Materialized sanitized file must be marked read-only"
    );
    #[cfg(windows)]
    {
        let motw_path = PathBuf::from(format!("{}:Zone.Identifier", staged_clean.display()));
        let motw = fs::read_to_string(&motw_path)
            .expect("Materialized staging file must carry Mark-of-the-Web Zone.Identifier");
        assert!(motw.contains("ZoneId=3"), "Expected ZoneId=3, got: {motw}");
    }

    // 3. Verify strict ACL separation: ShadowCache strictly SY/BA/OW-only; staging output AU read-only
    let enc_file =
        find_first_enc_file(&shadow_cache_root).expect("ShadowCache must contain .enc ciphertext");
    let enc_session_dir = enc_file.parent().expect("enc session dir");
    let cache_dir_acl = query_path_dacl_sddl(enc_session_dir).expect("query ShadowCache dir ACL");
    let cache_file_acl = query_path_dacl_sddl(&enc_file).expect("query ShadowCache .enc ACL");
    let mount_dir_acl = query_path_dacl_sddl(&virtual_mount).expect("query staging root ACL");
    let staged_sub_acl =
        query_path_dacl_sddl(&virtual_mount.join("docs")).expect("query staging subdir ACL");
    let staged_file_acl = query_path_dacl_sddl(&staged_clean).expect("query staging file ACL");

    #[cfg(windows)]
    {
        assert!(
            cache_dir_acl.starts_with("D:P")
                && !cache_dir_acl.contains(";;;AU)")
                && !cache_dir_acl.contains(";;;WD)"),
            "Encrypted ShadowCache directory must hold protected SY/BA/OW-only DACL; got: {cache_dir_acl}"
        );
        assert!(
            cache_file_acl.starts_with("D:P")
                && !cache_file_acl.contains(";;;AU)")
                && !cache_file_acl.contains(";;;WD)"),
            "Encrypted ShadowCache .enc file must hold protected SY/BA/OW-only DACL; got: {cache_file_acl}"
        );
        assert!(
            mount_dir_acl.starts_with("D:P"),
            "Staging root DACL must be protected (D:P); got: {mount_dir_acl}"
        );
        assert_windows_sddl_has_readonly_au_only(&mount_dir_acl, true);
        assert_windows_sddl_has_readonly_au_only(&staged_sub_acl, true);
        assert_windows_sddl_has_readonly_au_only(&staged_file_acl, false);
    }
    #[cfg(not(windows))]
    {
        assert_eq!(cache_dir_acl, "unix_mode:0o0700");
        assert_eq!(cache_file_acl, "unix_mode:0o0600");
        assert_eq!(mount_dir_acl, "unix_mode:0o0755");
        assert_eq!(staged_sub_acl, "unix_mode:0o0755");
        assert_eq!(staged_file_acl, "unix_mode:0o0444");
    }

    // 4. Teardown shreds both materialized staging mount and encrypted ShadowCache
    provider
        .unmount_volume(&virtual_mount)
        .await
        .expect("StagingFolderProvider unmount must succeed");
    assert!(
        !virtual_mount.exists(),
        "Virtual staging mount must be removed on unmount"
    );
    assert!(
        !enc_file.exists(),
        "Encrypted ShadowCache ciphertext must be removed on unmount"
    );

    // 5. FuseVfsProvider also implements take_withheld_threats parity
    let fuse_mount = root.join("FuseSafeDrive");
    let fuse_cache = ShadowCacheManager::with_cache_root_and_quota(
        root.join("FuseShadowCache"),
        16 * 1024 * 1024,
    )
    .with_shared_ledger(shared_ledger)
    .with_worker_launcher(launcher);
    let fuse_provider: Box<dyn VirtualFileSystemProvider> =
        Box::new(FuseVfsProvider::with_shadow_cache(fuse_cache));
    fuse_provider
        .mount_sanitized_volume(&raw_usb, &fuse_mount)
        .await
        .expect("FuseVfsProvider mount must succeed");
    let fuse_threats = fuse_provider.take_withheld_threats(&fuse_mount);
    assert!(
        !fuse_threats.is_empty(),
        "FuseVfsProvider must also return withheld threats instead of dropping them"
    );
    fuse_provider
        .unmount_volume(&fuse_mount)
        .await
        .expect("FuseVfsProvider unmount must succeed");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn t43_os_aware_safe_drive_mount_path_and_symlink_rejection() {
    // 1. OS-gated default path (never hardcoded C:\OmniConnect\SafeDrive)
    let os_default = default_os_safe_drive_mount_path();
    #[cfg(windows)]
    {
        assert_eq!(
            os_default,
            PathBuf::from(r"C:\ProgramData\OmniConnect\SafeDrive")
        );
        assert_ne!(os_default, PathBuf::from(r"C:\OmniConnect\SafeDrive"));
    }
    #[cfg(not(windows))]
    {
        assert_eq!(os_default, PathBuf::from("/run/omniconnect/safedrive"));
        assert!(!os_default.to_string_lossy().contains("C:\\"));
    }

    // 2. Pure env override resolver
    assert_eq!(resolve_safe_drive_mount_path(None), os_default);
    assert_eq!(resolve_safe_drive_mount_path(Some("   \t\n")), os_default);
    assert_eq!(
        resolve_safe_drive_mount_path(Some("  /mnt/ot_kiosk/safedrive  ")),
        PathBuf::from("/mnt/ot_kiosk/safedrive")
    );

    // 3. SentinelConfig JSON backward compatibility via serde default
    let cfg = SentinelConfig::default();
    let mut cfg_json: serde_json::Value =
        serde_json::to_value(&cfg).expect("serialize SentinelConfig");
    cfg_json
        .as_object_mut()
        .expect("config object")
        .remove("safe_drive_mount_path");
    let deserialized: SentinelConfig =
        serde_json::from_value(cfg_json).expect("deserialize legacy SentinelConfig JSON");
    assert!(!deserialized.safe_drive_mount_path.as_os_str().is_empty());

    // 4. Non-directory conflict & symlink / junction rejection for staging ACL helpers
    let root = test_temp_dir("t43_staging_symlink_guard");
    let regular_file = root.join("not_a_dir.txt");
    fs::write(&regular_file, b"plain").expect("write regular file");
    assert!(
        create_readonly_staging_dir_atomic(&regular_file).is_err(),
        "create_readonly_staging_dir_atomic must reject existing regular file"
    );
    assert!(
        create_readonly_staging_file_atomic(&regular_file.join("child.txt"), b"x").is_err(),
        "create_readonly_staging_file_atomic must reject non-directory parent"
    );

    let real_target = root.join("real_target");
    fs::create_dir_all(&real_target).expect("create real target");
    let link_path = root.join("staging_link");

    let link_created = {
        #[cfg(windows)]
        {
            std::process::Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &link_path.to_string_lossy(),
                    &real_target.to_string_lossy(),
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real_target, &link_path).is_ok()
        }
    };
    if link_created {
        assert!(
            create_readonly_staging_dir_atomic(&link_path).is_err(),
            "create_readonly_staging_dir_atomic must reject symlink/junction"
        );
        assert!(
            create_readonly_staging_file_atomic(&link_path.join("escape.txt"), b"x").is_err(),
            "create_readonly_staging_file_atomic must reject symlink/junction parent"
        );
        assert!(
            apply_readonly_staging_dacl(&link_path).is_err(),
            "apply_readonly_staging_dacl must reject symlink/junction"
        );
        assert!(
            query_path_dacl_sddl(&link_path).is_err(),
            "query_path_dacl_sddl must reject symlink/junction"
        );
        let _ = fs::remove_dir(&link_path).or_else(|_| fs::remove_file(&link_path));
    }

    let _ = fs::remove_dir_all(&root);
}
