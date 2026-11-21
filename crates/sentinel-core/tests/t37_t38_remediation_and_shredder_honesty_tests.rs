//! Behavioral & Adversarial Verification Suite for Master Security Hardening Plan v3
//! Sub-Phase 0.1 (`CSE-15`, `F-13`): `T37` and `T38`.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use sentinel_core::enterprise::ledger::AuditLedger;
use sentinel_core::scanner::quarantine::QuarantineVault;
use sentinel_core::scanner::secure_shredder::{
    generate_equal_length_hex_scramble_name, validate_shred_receipt_fail_closed,
    write_non_repeating_csprng_chunks, Nist80088Rev2Category, SecureShredder, ShredLedgerSink,
    ShredMethod, ShredReceipt,
};
use tempfile::tempdir;

#[test]
fn t37_shredder_fail_closed_receipt_validation_and_equal_length_hex_scramble() {
    // 1. Verify `validate_shred_receipt_fail_closed` rejects unverified or unflushed receipts
    let mut receipt = ShredReceipt {
        original_path: "secret_payroll_2026.xlsx".to_string(),
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
        verification_passed: true,
        verify_read_ok: true,
    };
    assert!(validate_shred_receipt_fail_closed(&receipt).is_ok());

    receipt.verification_passed = false;
    let err_verify = validate_shred_receipt_fail_closed(&receipt);
    assert!(
        err_verify.is_err(),
        "verification_passed == false must fail closed (I6)"
    );

    receipt.verification_passed = true;
    receipt.flush_succeeded = false;
    let err_flush = validate_shred_receipt_fail_closed(&receipt);
    assert!(
        err_flush.is_err(),
        "flush_succeeded == false must fail closed (I6)"
    );

    // 2. Verify equal-length pure-hex filename scrambling (`README.md §9 #5`, `CSE-15`)
    for orig in [
        "a",
        "CON.txt",
        "secret_customer_payroll_2026.xlsx",
        &"x".repeat(300),
    ] {
        let scrambled = generate_equal_length_hex_scramble_name(orig);
        let expected_len = orig.chars().count().clamp(1, 240);
        assert_eq!(
            scrambled.len(),
            expected_len,
            "Scrambled name must match original length (clamped to 1..=240)"
        );
        assert!(
            scrambled
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "Scrambled filename must be pure lowercase hex [0-9a-f]"
        );
    }

    // 3. End-to-end shred verifies scramble cycles, verification_passed, flush_succeeded, and ledger chain
    let tmp = tempdir().expect("tempdir");
    let ledger_path = tmp.path().join("t37_shred_ledger.jsonl");
    let target = tmp.path().join("confidential_merger_terms_2026.pdf");
    fs::write(&target, vec![0x5Au8; 8192]).expect("write target");

    let live_receipt = SecureShredder::shred_file_with_ledger(
        &target,
        ShredMethod::NIST_CLEAR_THREE_PASS,
        &ledger_path,
    )
    .expect("live shred must pass verification and flush");
    assert!(!target.exists());
    assert!(live_receipt.verification_passed);
    assert!(live_receipt.flush_succeeded);
    assert_eq!(live_receipt.actual_scramble_cycles, 3);
    assert_eq!(live_receipt.rev2_category, Nist80088Rev2Category::Clear);

    let ledger = AuditLedger::open_result(&ledger_path).expect("open ledger");
    assert_eq!(ledger.verify_chain().expect("verify ledger"), 1);

    // 4. Verify failed verification/flush logs `SHRED_VERIFICATION_FAILED` to the ledger AND fails closed (`CSE-15`)
    let fail_ledger_path = tmp.path().join("t37_fail_ledger.jsonl");
    let mut failed_receipt = live_receipt.clone();
    failed_receipt.verification_passed = false;
    failed_receipt.verify_read_ok = false;
    let fail_res = SecureShredder::finalize_and_record_shred_receipt(
        ShredLedgerSink::Path(&fail_ledger_path),
        "SHRED_RECEIPT",
        failed_receipt,
    );
    assert!(
        fail_res
            .as_ref()
            .err()
            .is_some_and(|e| e.starts_with("SHRED_VERIFICATION_FAILED")),
        "Failed verification receipt must return SHRED_VERIFICATION_FAILED error"
    );
    let fail_ledger_text = fs::read_to_string(&fail_ledger_path).expect("read fail ledger");
    assert!(
        fail_ledger_text.contains("SHRED_VERIFICATION_FAILED"),
        "Audit ledger must tag failed shred verification with SHRED_VERIFICATION_FAILED"
    );
    assert!(
        !fail_ledger_text.contains("\"SHRED_RECEIPT\""),
        "Failed shred must NOT be tagged as SHRED_RECEIPT"
    );
    let fail_ledger = AuditLedger::open_result(&fail_ledger_path).expect("open fail ledger");
    assert_eq!(fail_ledger.verify_chain().expect("verify fail ledger"), 1);

    // 5. On Windows NTFS, verify `shred_ntfs_stream_with_ledger` removes ADS cleanly while preserving host file
    #[cfg(windows)]
    {
        let ads_host = tmp.path().join("t37_ads_host.txt");
        fs::write(&ads_host, b"HOST_STREAM_INTACT").expect("write host");
        let ads_path = format!("{}:t37_hidden", ads_host.display());
        if fs::write(&ads_path, b"SECRET_ADS_PAYLOAD").is_ok() {
            let ads_ledger = tmp.path().join("t37_ads_ledger.jsonl");
            let ads_receipt =
                SecureShredder::shred_ntfs_stream_with_ledger(&ads_host, "t37_hidden", &ads_ledger)
                    .expect("ADS shred must succeed");
            assert!(ads_receipt.verification_passed && ads_receipt.flush_succeeded);
            assert_eq!(
                fs::read(&ads_host).expect("read host"),
                b"HOST_STREAM_INTACT"
            );
            assert!(fs::metadata(&ads_path).is_err(), "ADS must be removed");
            let ads_log = fs::read_to_string(&ads_ledger).expect("read ads ledger");
            assert!(ads_log.contains("SHRED_ADS_RECEIPT"));
        }
    }
}

#[test]
fn t38_fill_free_space_non_repeating_csprng_and_purge_honest_clear_classification() {
    // 1. Verify `write_non_repeating_csprng_chunks` generates distinct CSPRNG chunks on every iteration
    let mut sink = Vec::new();
    let mut chunk_buf = vec![0u8; 65536];
    let written = write_non_repeating_csprng_chunks(&mut sink, 65536 * 4, &mut chunk_buf)
        .expect("csprng chunk write must succeed");
    assert_eq!(written, 65536 * 4);
    assert_eq!(sink.len(), 65536 * 4);

    // Verify non-disk-full write errors propagate cleanly instead of silently succeeding
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "simulated non-ENOSPC I/O error",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut failing = FailingWriter;
    assert!(
        write_non_repeating_csprng_chunks(&mut failing, 65536, &mut chunk_buf).is_err(),
        "Non-disk-full I/O errors must propagate"
    );

    // Verify out-of-space (`StorageFull` and raw OS `112`/`28`) stops cleanly with `Ok(partial_written)`
    struct DiskFullWriter {
        chunks_allowed: usize,
        os_code: Option<i32>,
    }
    impl std::io::Write for DiskFullWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.chunks_allowed == 0 {
                return match self.os_code {
                    Some(code) => Err(std::io::Error::from_raw_os_error(code)),
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::StorageFull,
                        "simulated StorageFull",
                    )),
                };
            }
            self.chunks_allowed -= 1;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut storage_full = DiskFullWriter {
        chunks_allowed: 1,
        os_code: None,
    };
    assert_eq!(
        write_non_repeating_csprng_chunks(&mut storage_full, 65536 * 4, &mut chunk_buf)
            .expect("StorageFull must stop cleanly"),
        65536
    );
    let mut win_disk_full = DiskFullWriter {
        chunks_allowed: 2,
        os_code: Some(112), // ERROR_DISK_FULL
    };
    assert_eq!(
        write_non_repeating_csprng_chunks(&mut win_disk_full, 65536 * 4, &mut chunk_buf)
            .expect("ERROR_DISK_FULL (112) must stop cleanly"),
        65536 * 2
    );
    let mut posix_enospc = DiskFullWriter {
        chunks_allowed: 1,
        os_code: Some(28), // ENOSPC
    };
    assert_eq!(
        write_non_repeating_csprng_chunks(&mut posix_enospc, 65536 * 4, &mut chunk_buf)
            .expect("ENOSPC (28) must stop cleanly"),
        65536
    );

    let mut unique_chunks: HashSet<&[u8]> = HashSet::new();
    for idx in 0..4 {
        let slice = &sink[idx * 65536..(idx + 1) * 65536];
        assert!(
            unique_chunks.insert(slice),
            "Chunk {idx} repeated an earlier free-space fill block (vulnerable to SSD deduplication)"
        );
    }

    // Verify bounded on-disk `fill_free_space` cleans up its balloon artifact cleanly
    let tmp = tempdir().expect("tempdir");
    let fill_dir = tmp.path().join("free_space_target");
    fs::create_dir_all(&fill_dir).expect("create fill dir");
    let filled = SecureShredder::fill_free_space(&fill_dir, 131_072).expect("fill_free_space");
    assert_eq!(filled, 131_072);
    let leftover = fs::read_dir(&fill_dir).expect("read_dir").count();
    assert_eq!(leftover, 0, "fill_free_space must unlink its balloon file");

    // 2. Verify `QuarantineVault::purge()` records honest NIST 800-88 Rev. 2 Clear (NEVER CryptographicErasePurge)
    let ledger_path = tmp.path().join("t38_purge_ledger.jsonl");
    let shared_ledger = Arc::new(Mutex::new(
        AuditLedger::open_result(&ledger_path).expect("open shared ledger"),
    ));
    let vault_dir = tmp.path().join("vault");
    let vault = QuarantineVault::open(vault_dir.clone())
        .expect("open vault")
        .with_shared_ledger(shared_ledger.clone());

    let sample = tmp.path().join("malicious_dropper.bin");
    fs::write(&sample, b"MZ_TEST_DROPPER_FOR_T38_PURGE_HONESTY").expect("write sample");
    let entry = vault
        .quarantine_file(&sample, "T38.Test.Dropper")
        .expect("quarantine sample");
    assert!(!sample.exists());
    assert!(Path::new(&entry.vault_file_path).exists());

    vault.purge(&entry.entry_id).expect("purge entry");
    assert!(!Path::new(&entry.vault_file_path).exists());
    assert!(!vault_dir.join(format!("{}.dek", entry.entry_id)).exists());

    // Inspect every JSONL ledger entry written during `purge()` and confirm every `SHRED_RECEIPT`
    // has `rev2_category == "Clear"` (ZERO `CryptographicErasePurge` claims)
    let ledger_text = fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(
        !ledger_text.contains("CryptographicErasePurge"),
        "QuarantineVault::purge() MUST NOT claim CryptographicErasePurge while vault KEK/escrow remain live (CSE-15 / F-13)"
    );
    let mut clear_receipt_count = 0usize;
    let mut saw_quarantine_purged = false;
    for line in ledger_text.lines().filter(|l| !l.trim().is_empty()) {
        let rec: serde_json::Value = serde_json::from_str(line).expect("valid ledger JSONL");
        if rec["event"].as_str() == Some("SHRED_RECEIPT") {
            let data_str = rec["data"].as_str().expect("receipt data string");
            let receipt_json: serde_json::Value =
                serde_json::from_str(data_str).expect("valid embedded ShredReceipt JSON");
            let inner = receipt_json.get("payload").unwrap_or(&receipt_json);
            assert_eq!(
                inner["rev2_category"].as_str(),
                Some("Clear"),
                "Every purge shred receipt must report rev2_category == Clear (got {receipt_json})"
            );
            assert_eq!(
                inner["inception_encrypted_dek_destroyed"].as_bool(),
                Some(false)
            );
            clear_receipt_count += 1;
        } else if rec["event"].as_str() == Some("QUARANTINE_PURGED") {
            let data_str = rec["data"].as_str().unwrap_or("");
            assert!(data_str.contains("NIST SP 800-88 Rev. 2 Clear"));
            saw_quarantine_purged = true;
        }
    }
    assert!(
        clear_receipt_count >= 2,
        "Expected >= 2 Clear SHRED_RECEIPT entries (source shred + DEK + .quar), got {clear_receipt_count}"
    );
    assert!(
        saw_quarantine_purged,
        "Ledger must record QUARANTINE_PURGED event with honest Clear label"
    );
    let ledger = AuditLedger::open_result(&ledger_path).expect("reopen ledger");
    assert!(ledger.verify_chain().expect("verify chain") >= 3);
}
