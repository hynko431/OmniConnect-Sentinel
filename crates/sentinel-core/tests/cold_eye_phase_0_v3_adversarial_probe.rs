use sentinel_cdr::{WorkerLauncher, WorkerRequest};
use sentinel_core::config::{default_os_safe_drive_mount_path, resolve_safe_drive_mount_path};
use sentinel_core::enterprise::kiosk::{
    compute_current_binary_provenance, extract_dep_v0_section_sha256, verify_kiosk_passport,
    AirGappedKioskManager, KioskConfig, KioskSanitizationPassport, PASSPORT_MANIFEST_FILENAME,
    PASSPORT_PUBKEY_FILENAME,
};
use sentinel_core::enterprise::ledger::AuditLedger;
use sentinel_core::scanner::quarantine::{
    QuarantineVault, ENVELOPE_MAGIC_V2_FULL, ENVELOPE_MAGIC_V3_FULL, ENVELOPE_VERSION_V3,
};
use sentinel_core::scanner::secure_shredder::{
    validate_shred_receipt_fail_closed, write_non_repeating_csprng_chunks, Nist80088Rev2Category,
    SecureShredder, ShredLedgerSink, ShredReceipt,
};
use sentinel_core::vfs::{ShadowCacheManager, StagingFolderProvider, VirtualFileSystemProvider};
use sentinel_sys::{generate_hybrid_soc_keypair_with_bits, query_path_dacl_sddl, JobSandboxConfig};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

fn test_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "omniconnect_p0_probe_{}_{}_{}",
        label,
        std::process::id(),
        Uuid::new_v4().simple()
    ));
    fs::create_dir_all(&dir).expect("create probe dir");
    dir
}

fn locate_or_build_cdr_worker_binary() -> PathBuf {
    let exe_name = if cfg!(windows) {
        "sentinel-cdr-worker.exe"
    } else {
        "sentinel-cdr-worker"
    };
    let current_exe = std::env::current_exe().expect("current_exe");
    let deps_dir = current_exe.parent().expect("deps dir");
    let profile_dir = current_exe
        .ancestors()
        .skip(1)
        .find(|a| {
            matches!(
                a.file_name().and_then(|n| n.to_str()),
                Some("debug" | "release")
            )
        })
        .unwrap_or_else(|| deps_dir.parent().unwrap_or(deps_dir));
    for candidate in [deps_dir.join(exe_name), profile_dir.join(exe_name)] {
        if candidate.is_file() {
            return candidate;
        }
    }
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
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
    assert!(
        cmd.status().expect("build sentinel-cdr-worker").success(),
        "building sentinel-cdr-worker failed"
    );
    let built = profile_dir.join(exe_name);
    assert!(built.is_file(), "worker missing at {}", built.display());
    built
}

fn build_verified_worker_launcher() -> WorkerLauncher {
    let worker_bin = locate_or_build_cdr_worker_binary();
    let default_launcher = WorkerLauncher::new().with_worker_bin(worker_bin.clone());
    match default_launcher.sanitize_isolated(WorkerRequest {
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

struct FailingDiskWriter {
    chunks: Vec<Vec<u8>>,
    fail_after: usize,
    error_kind: io::ErrorKind,
}

impl Write for FailingDiskWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.chunks.len() >= self.fail_after {
            return Err(io::Error::new(self.error_kind, "injected write error"));
        }
        self.chunks.push(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn phase0_cse15_shredder_fail_closed_and_honest_purge_adversarial() {
    let root = test_temp_dir("cse15");
    let ledger_path = root.join("cse15_ledger.jsonl");
    let shared_ledger = Arc::new(Mutex::new(
        AuditLedger::open_result(&ledger_path).expect("open ledger"),
    ));

    // 1. Receipt validation MUST fail closed on unverified or unflushed receipts
    let bad_verify_receipt = ShredReceipt {
        original_path: "adversarial_target.xlsx".to_string(),
        file_size_bytes: 4096,
        sector_alignment_bytes: 4096,
        passes_completed: 3,
        final_pass_sha256: "a".repeat(64),
        hardware_buffers_flushed: true,
        flush_succeeded: true,
        mft_filename_scrambled: true,
        actual_scramble_cycles: 3,
        rename_cycles_completed: 3,
        media_type: "SsdOrFlash".to_string(),
        sanitization_level: "NIST SP 800-88 Rev. 2 — Clear".to_string(),
        nist_standard: "NIST SP 800-88 Rev. 2".to_string(),
        rev2_category: Nist80088Rev2Category::Clear,
        inception_encrypted_dek_destroyed: false,
        verification_passed: false,
        verify_read_ok: false,
    };
    assert!(validate_shred_receipt_fail_closed(&bad_verify_receipt).is_err());
    let finalize_err = SecureShredder::finalize_and_record_shred_receipt(
        ShredLedgerSink::Shared(&shared_ledger),
        "SHRED_RECEIPT",
        bad_verify_receipt.clone(),
    );
    assert!(
        finalize_err
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("SHRED_VERIFICATION_FAILED")),
        "finalize_and_record_shred_receipt must fail closed with SHRED_VERIFICATION_FAILED"
    );

    let mut bad_flush_receipt = bad_verify_receipt;
    bad_flush_receipt.verification_passed = true;
    bad_flush_receipt.verify_read_ok = true;
    bad_flush_receipt.flush_succeeded = false;
    assert!(validate_shred_receipt_fail_closed(&bad_flush_receipt).is_err());

    let ledger_text = fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(
        ledger_text.contains("SHRED_VERIFICATION_FAILED"),
        "Failed shred receipt must remain tamper-evidently logged in AuditLedger"
    );

    // 2. Non-repeating CSPRNG chunks: stop cleanly ONLY on StorageFull, fail closed on PermissionDenied
    let mut chunk_buf = vec![0u8; 65536];
    let mut full_writer = FailingDiskWriter {
        chunks: Vec::new(),
        fail_after: 4,
        error_kind: io::ErrorKind::StorageFull,
    };
    let written = write_non_repeating_csprng_chunks(&mut full_writer, 6 * 65536, &mut chunk_buf)
        .expect("StorageFull must terminate free-space fill cleanly");
    assert_eq!(written, 4 * 65536);
    assert_eq!(full_writer.chunks.len(), 4);
    for pair in full_writer.chunks.windows(2) {
        assert_ne!(
            pair[0], pair[1],
            "Consecutive free-space fill chunks must have fresh CSPRNG entropy"
        );
    }

    let mut denied_writer = FailingDiskWriter {
        chunks: Vec::new(),
        fail_after: 1,
        error_kind: io::ErrorKind::PermissionDenied,
    };
    assert!(
        write_non_repeating_csprng_chunks(&mut denied_writer, 4 * 65536, &mut chunk_buf).is_err(),
        "Non-StorageFull write errors must propagate instead of pretending fill succeeded"
    );

    // 3. QuarantineVault::purge() must log honest NIST SP 800-88 Rev. 2 Clear (never Purge)
    let vault_dir = root.join("vault");
    let vault = QuarantineVault::open(vault_dir)
        .expect("open vault")
        .with_shared_ledger(shared_ledger);
    let sample = root.join("threat.bin");
    fs::write(&sample, b"MZ_TEST_PURGE_HONESTY").expect("write sample");
    let entry = vault
        .quarantine_file_with_score(&sample, "TEST_THREAT", 95)
        .expect("quarantine");
    vault.purge(&entry.entry_id).expect("purge");

    let full_ledger = fs::read_to_string(&ledger_path).expect("read ledger after purge");
    assert!(
        !full_ledger.contains("CryptographicErasePurge"),
        "QuarantineVault::purge() must never emit CryptographicErasePurge while KEK stays active"
    );
    let mut clear_receipt_count = 0usize;
    for line in full_ledger.lines() {
        if let Ok(rec) = serde_json::from_str::<serde_json::Value>(line) {
            if rec.get("event").and_then(|v| v.as_str()) == Some("SHRED_RECEIPT") {
                if let Some(data_str) = rec.get("data").and_then(|v| v.as_str()) {
                    if let Ok(outer) = serde_json::from_str::<serde_json::Value>(data_str) {
                        if let Some(payload) = outer.get("payload") {
                            let cat = payload.get("rev2_category").and_then(|v| v.as_str());
                            assert_ne!(
                                cat,
                                Some("CryptographicErasePurge"),
                                "QuarantineVault::purge() must not claim CryptographicErasePurge while KEK stays active"
                            );
                            assert_eq!(
                                cat,
                                Some("Clear"),
                                "Every SHRED_RECEIPT from quarantine & purge must honestly report Clear"
                            );
                            clear_receipt_count += 1;
                        }
                    }
                }
            }
        }
    }
    // 1 source shred during quarantine_file_with_score + 2 shreds (.dek + .quar) during purge()
    assert!(
        clear_receipt_count >= 3,
        "Expected >= 3 honest Clear SHRED_RECEIPT records (source + .dek + .quar), got {clear_receipt_count}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn phase0_cse16_zero_pii_v3_envelope_tamper_and_hybrid_escrow_recovery() {
    let root = test_temp_dir("cse16");
    let vault_dir = root.join("vault");
    let ledger_path = root.join("cse16_ledger.jsonl");
    let shared_ledger = Arc::new(Mutex::new(
        AuditLedger::open_result(&ledger_path).expect("open ledger"),
    ));

    let (pub_bundle, priv_bundle) = generate_hybrid_soc_keypair_with_bits(3072)
        .expect("generate hybrid ML-KEM-768 + RSA SOC keypair");
    let vault = QuarantineVault::open(vault_dir.clone())
        .expect("open vault")
        .with_shared_ledger(shared_ledger.clone());
    vault
        .provision_hybrid_soc_escrow_v3(&pub_bundle)
        .expect("provision hybrid escrow v3");

    let pii_dir = root.join("patients_ssn_987_65_4321");
    fs::create_dir_all(&pii_dir).expect("create pii dir");
    let pii_file = pii_dir.join("john_doe_confidential_record.txt");
    let original_payload = b"CONFIDENTIAL_MEDICAL_PAYLOAD_PHASE0_VERIFY";
    fs::write(&pii_file, original_payload).expect("write pii file");

    let entry = vault
        .quarantine_readonly_evidence(&pii_file, "PII_PROBE_THREAT", 88)
        .expect("quarantine_readonly_evidence");

    // 1. Raw .quar envelope MUST parse as SNTLQV03 v3 and contain ZERO plaintext path/filename PII
    let quar_path = PathBuf::from(&entry.vault_file_path);
    let raw_quar = fs::read(&quar_path).expect("read .quar bytes");
    let (header, _header_json, ciphertext) =
        QuarantineVault::parse_envelope(&raw_quar).expect("parse SNTLQV03 envelope");
    assert_eq!(&header.magic, ENVELOPE_MAGIC_V3_FULL);
    assert_eq!(header.version, ENVELOPE_VERSION_V3);
    assert!(
        header.original_path.len() == 64
            && header.original_path.chars().all(|c| c.is_ascii_hexdigit()),
        "On-disk header.original_path must be a 64-hex HMAC token"
    );
    let raw_quar_lossy = String::from_utf8_lossy(&raw_quar);
    assert!(
        !raw_quar_lossy.contains("patients_ssn_987_65_4321")
            && !raw_quar_lossy.contains("john_doe_confidential_record"),
        "SNTLQV03 raw .quar header must not leak plaintext path/filename PII"
    );

    // 2. Mismatched magic/version tampering MUST fail closed
    let mut bad_header = header;
    bad_header.magic = *ENVELOPE_MAGIC_V2_FULL; // SNTLQV02 magic with version: 3 JSON header
    let bad_json = serde_json::to_vec(&bad_header).expect("serialize mismatched header");
    let mut bad_magic = Vec::with_capacity(4 + bad_json.len() + ciphertext.len());
    bad_magic.extend_from_slice(&(bad_json.len() as u32).to_le_bytes());
    bad_magic.extend_from_slice(&bad_json);
    bad_magic.extend_from_slice(ciphertext);
    assert!(
        QuarantineVault::parse_envelope(&bad_magic).is_err(),
        "Mismatched SNTLQV02 magic with v3 header must fail parse_envelope closed"
    );
    fs::write(&quar_path, &bad_magic).expect("write tampered magic");
    assert!(
        vault.verify_entry(&entry.entry_id).is_err(),
        "Mismatched SNTLQV02 magic with v3 header must fail verify_entry closed"
    );
    fs::write(&quar_path, &raw_quar).expect("restore valid .quar");
    vault
        .verify_entry(&entry.entry_id)
        .expect("valid .quar verifies");

    // 3. Corrupt vault_kek.sealed -> fail closed -> recover via hybrid v3 escrow -> restore exact bytes
    let sealed_kek_path = vault_dir.join("vault_kek.sealed");
    fs::write(&sealed_kek_path, b"CORRUPTED_HOST_TPM_SEALED_KEK").expect("corrupt sealed KEK");
    assert!(
        QuarantineVault::open(vault_dir.clone()).is_err(),
        "Corrupted vault_kek.sealed must fail closed before escrow recovery"
    );

    let recovered_vault = QuarantineVault::recover_from_hybrid_soc_escrow_v3_with_shared_ledger(
        vault_dir,
        &priv_bundle,
        Some(shared_ledger),
    )
    .expect("hybrid v3 SOC escrow recovery must succeed");

    let listed = recovered_vault
        .list_entries()
        .expect("list recovered entries");
    let found = listed
        .iter()
        .find(|e| e.entry_id == entry.entry_id)
        .expect("recovered entry must be listed");
    assert!(
        found
            .original_path
            .contains("john_doe_confidential_record.txt"),
        "Unlocked v3 vault must decrypt original_path cleanly; got: {}",
        found.original_path
    );

    let restored_path = root.join("restored_record.txt");
    recovered_vault
        .restore_file(&entry.entry_id, &restored_path)
        .expect("restore_file after escrow recovery");
    assert_eq!(
        fs::read(&restored_path).expect("read restored"),
        original_payload
    );

    let ledger_text = fs::read_to_string(&ledger_path).expect("read cse16 ledger");
    assert!(
        ledger_text.contains("VAULT_HYBRID_PQC_ESCROW_V3_RECOVERED"),
        "Hybrid escrow recovery must emit VAULT_HYBRID_PQC_ESCROW_V3_RECOVERED"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn phase0_cse17_dep_v0_parser_fuzz_bounds_and_passport_tamper_rejection() {
    // 1. Adversarial malformed PE/ELF slices must NEVER panic and must return None
    let malformed_inputs: Vec<Vec<u8>> = vec![
        vec![],
        b"MZ".to_vec(),
        vec![0x4D, 0x5A, 0x90, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
        b"\x7fELF".to_vec(),
        vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        {
            // PE with e_lfanew pointing past EOF
            let mut pe = vec![0u8; 64];
            pe[0] = b'M';
            pe[1] = b'Z';
            pe[60..64].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
            pe
        },
        {
            // ELF64 with overflowing e_shoff
            let mut elf = vec![0u8; 64];
            elf[0..4].copy_from_slice(b"\x7fELF");
            elf[4] = 2;
            elf[5] = 1;
            elf[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
            elf[58..60].copy_from_slice(&64u16.to_le_bytes());
            elf[60..62].copy_from_slice(&4u16.to_le_bytes());
            elf[62..64].copy_from_slice(&1u16.to_le_bytes());
            elf
        },
    ];
    for blob in &malformed_inputs {
        assert_eq!(
            extract_dep_v0_section_sha256(blob),
            None,
            "Malformed binary must return None without panicking"
        );
    }

    // 2. Provenance split must never spoof binary_exe_sha256 into binary_dep_v0_sha256
    let (exe_sha, dep_v0_sha) = compute_current_binary_provenance();
    assert_eq!(exe_sha.len(), 64);
    assert_ne!(
        dep_v0_sha.as_deref(),
        Some(exe_sha.as_str()),
        "binary_dep_v0_sha256 must never spoof binary_exe_sha256"
    );

    // 3. Passport tamper on binary_exe_sha256 OR binary_dep_v0_sha256 MUST fail signature check
    let root = test_temp_dir("cse17");
    let kiosk = AirGappedKioskManager::new(KioskConfig::default(), root.join("kiosk_state"));
    let export_dir = root.join("export");
    let clean_bytes = b"Phase 0 verified kiosk output\n".to_vec();
    let batch = vec![(
        PathBuf::from("clean.txt"),
        clean_bytes,
        "DEEP_CDR_RECONSTRUCTED:Text".to_string(),
    )];
    let passport = kiosk
        .export_sanitized_batch_with_passport(&export_dir, "USB-P0-PROBE", "POL-P0", 1, &batch)
        .expect("export passport");
    assert_eq!(passport.binary_exe_sha256, exe_sha);
    assert_eq!(passport.binary_dep_v0_sha256, dep_v0_sha);

    let pub_bytes = fs::read(export_dir.join(PASSPORT_PUBKEY_FILENAME)).expect("read pubkey");
    let valid =
        verify_kiosk_passport(&export_dir, Some(&pub_bytes)).expect("verify clean passport");
    assert_eq!(valid.binary_exe_sha256, exe_sha);

    let passport_path = export_dir.join(PASSPORT_MANIFEST_FILENAME);
    let orig_bytes = fs::read(&passport_path).expect("read passport");

    // Tamper binary_exe_sha256
    let mut tampered_exe: KioskSanitizationPassport =
        serde_json::from_slice(&orig_bytes).expect("parse passport");
    tampered_exe.binary_exe_sha256 = "0".repeat(64);
    fs::write(
        &passport_path,
        serde_json::to_vec_pretty(&tampered_exe).expect("serialize"),
    )
    .expect("write tampered exe sha");
    let exe_err = verify_kiosk_passport(&export_dir, Some(&pub_bytes))
        .expect_err("Tampered binary_exe_sha256 must fail signature verification");
    assert!(exe_err.contains("PASSPORT_SIGNATURE_INVALID"));

    // Tamper binary_dep_v0_sha256
    let mut tampered_dep: KioskSanitizationPassport =
        serde_json::from_slice(&orig_bytes).expect("parse passport");
    tampered_dep.binary_dep_v0_sha256 = Some("f".repeat(64));
    fs::write(
        &passport_path,
        serde_json::to_vec_pretty(&tampered_dep).expect("serialize"),
    )
    .expect("write tampered dep_v0");
    let dep_err = verify_kiosk_passport(&export_dir, Some(&pub_bytes))
        .expect_err("Tampered binary_dep_v0_sha256 must fail signature verification");
    assert!(dep_err.contains("PASSPORT_SIGNATURE_INVALID"));

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn phase0_cse18_staging_threat_quarantine_acl_separation_and_mount_defaults() {
    // 1. OS-aware mount path defaults & override
    let os_default = default_os_safe_drive_mount_path();
    assert_ne!(os_default, PathBuf::from(r"C:\OmniConnect\SafeDrive"));
    assert_eq!(
        resolve_safe_drive_mount_path(Some("/srv/sentinel/safedrive")),
        PathBuf::from("/srv/sentinel/safedrive")
    );
    assert_eq!(resolve_safe_drive_mount_path(Some("   ")), os_default);

    // 2. End-to-end StagingFolderProvider withheld threat quarantine + ACL separation
    let root = test_temp_dir("cse18");
    let raw_usb = root.join("usb");
    let mount_root = root.join("SafeDrive");
    let cache_root = root.join("ShadowCache");
    let vault_dir = root.join("Vault");
    let ledger_path = root.join("cse18_ledger.jsonl");

    fs::create_dir_all(&raw_usb).expect("create usb dir");
    fs::write(raw_usb.join("memo.txt"), b"Clean memo for Phase 0 probe\n").expect("write memo");
    let mut lnk = vec![
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    lnk.extend_from_slice(b"cmd.exe /c whoami");
    fs::write(raw_usb.join("shortcut.lnk"), &lnk).expect("write threat lnk");

    let shared_ledger = Arc::new(Mutex::new(
        AuditLedger::open_result(&ledger_path).expect("open ledger"),
    ));
    let launcher = build_verified_worker_launcher();
    let shadow_cache =
        ShadowCacheManager::with_cache_root_and_quota(cache_root.clone(), 16 * 1024 * 1024)
            .with_shared_ledger(shared_ledger.clone())
            .with_worker_launcher(launcher);
    let provider: Box<dyn VirtualFileSystemProvider> =
        Box::new(StagingFolderProvider::with_shadow_cache(shadow_cache));

    provider
        .mount_sanitized_volume(&raw_usb, &mount_root)
        .await
        .expect("mount via StagingFolderProvider");

    let threats = provider.take_withheld_threats(&mount_root);
    assert!(!threats.is_empty(), "Withheld threats must not be dropped");
    assert!(!mount_root.join("shortcut.lnk").exists());
    assert!(mount_root.join("memo.txt").is_file());

    let vault = QuarantineVault::open(vault_dir)
        .expect("open vault")
        .with_shared_ledger(shared_ledger);
    for t in &threats {
        vault
            .quarantine_readonly_evidence(&t.file_path, &t.threat_name, t.risk_score)
            .expect("quarantine withheld threat");
    }
    assert!(!vault.list_entries().expect("list vault").is_empty());

    // Verify BOTH halves of ACL separation: ShadowCache strictly {SY, BA, OW} vs staging AU read-only
    let enc_file = walkdir::WalkDir::new(&cache_root)
        .into_iter()
        .flatten()
        .find(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("enc"))
        })
        .map(|e| e.into_path())
        .expect("ShadowCache must hold encrypted .enc ciphertext");
    let enc_session_dir = enc_file.parent().expect("ShadowCache session dir");
    let cache_dir_acl = query_path_dacl_sddl(enc_session_dir).expect("ShadowCache dir ACL");
    let cache_file_acl = query_path_dacl_sddl(&enc_file).expect("ShadowCache .enc ACL");
    let staged_root_acl = query_path_dacl_sddl(&mount_root).expect("staged mount root ACL");
    let staged_acl = query_path_dacl_sddl(&mount_root.join("memo.txt")).expect("staged file ACL");
    #[cfg(windows)]
    {
        for (label, sddl) in [
            ("ShadowCache dir", cache_dir_acl.as_str()),
            ("ShadowCache .enc", cache_file_acl.as_str()),
        ] {
            assert!(
                sddl.starts_with("D:P"),
                "{label} must hold protected DACL (D:P): {sddl}"
            );
            let mut trustees = std::collections::BTreeSet::new();
            for seg in sddl.split('(').skip(1) {
                if let Some(inner) = seg.strip_suffix(')') {
                    let fields: Vec<&str> = inner.split(';').collect();
                    assert_eq!(fields.len(), 6, "Unexpected ACE syntax in {label}: {sddl}");
                    assert!(
                        matches!(fields[5], "SY" | "BA" | "OW"),
                        "{label} must strictly limit trustees to {{SY, BA, OW}}, found '{}' in {sddl}",
                        fields[5]
                    );
                    trustees.insert(fields[5]);
                }
            }
            assert!(
                trustees.contains("SY") && trustees.contains("BA") && trustees.contains("OW"),
                "{label} must include SY, BA, OW trustees; got {trustees:?}"
            );
        }
        assert!(
            staged_root_acl.starts_with("D:P")
                && staged_root_acl.contains(";;;AU)")
                && !staged_root_acl.contains(";;;WD)"),
            "Unexpected staged mount root DACL: {staged_root_acl}"
        );
        assert!(
            staged_acl.starts_with("D:P")
                && staged_acl.contains("(A;;FR;;;AU)")
                && !staged_acl.contains(";;;WD)"),
            "Unexpected staged file DACL: {staged_acl}"
        );
    }
    #[cfg(not(windows))]
    {
        assert_eq!(cache_dir_acl, "unix_mode:0o0700");
        assert_eq!(cache_file_acl, "unix_mode:0o0600");
        assert_eq!(staged_root_acl, "unix_mode:0o0755");
        assert_eq!(staged_acl, "unix_mode:0o0444");
    }

    provider
        .unmount_volume(&mount_root)
        .await
        .expect("unmount StagingFolderProvider");
    assert!(!mount_root.exists());

    let _ = fs::remove_dir_all(&root);
}
