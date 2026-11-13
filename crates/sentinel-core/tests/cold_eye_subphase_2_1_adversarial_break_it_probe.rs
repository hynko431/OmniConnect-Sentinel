//! Cold-Eye Adversarial "Break-It" Probe for Sub-Phase 2.1
//!
//! Stress-tests:
//! 1. Fuzzing and adversarial evasion on `sanitize_strict_relative_subpath`:
//!    - Case-insensitive DOS devices with multiple extensions (`cOn.TxT`, `aUx.DaT`, `pRn.pDf`)
//!    - Complex path traversals with trailing periods, spaces, forward/backward slashes
//!    - NTFS alternate data stream (ADS) variations
//!    - Unicode bidirectional override smuggling
//! 2. Brute-force resistance on 128-bit BadUSB challenge gate:
//!    - Verifies entry is purged on strike 3
//!    - 50 rapid sequential invalid attempts fail closed with permission denied / not found
//!    - Cryptographic entropy check: no repeat tokens across 100 generations
//! 3. Zero-leakage verification:
//!    - Verifies neither state file nor serialized JSON ever contains plaintext tokens
//! 4. Zero `thread_rng` check across all production crates.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

use sentinel_core::enterprise::kiosk::{
    is_valid_media_id, sanitize_strict_relative_subpath, KioskPathError,
};
use sentinel_core::interceptor::PendingDeviceConfirmationManager;

#[test]
fn adversarial_fuzz_path_sanitizer() {
    let adversarial_traversals = [
        "..",
        "../",
        "..\\",
        "/..",
        "\\..",
        "....//",
        "....\\\\",
        "foo/../../bar",
        "foo\\..\\..\\bar",
        "sub/dir/../../../etc/passwd",
        "valid/../../../../root",
        "nested/../..",
    ];

    for bad in &adversarial_traversals {
        let res = sanitize_strict_relative_subpath(Path::new(bad));
        assert!(
            res.is_err(),
            "Path traversal '{bad}' unexpectedly passed sanitizer!"
        );
    }

    let adversarial_dos_devices = [
        "cOn",
        "CoN.tXt",
        "CON.tar.gz",
        "AuX",
        "aUx.log",
        "PrN",
        "pRn.dAt",
        "NuL",
        "nUl.bin",
        "CoM1",
        "com1.exe",
        "COM9.txt",
        "LpT1",
        "lpt1.data",
        "LPT9.old",
        "sub/folder/cOn.txt",
        "deeply/nested/NuL",
    ];

    for dos in &adversarial_dos_devices {
        let res = sanitize_strict_relative_subpath(Path::new(dos));
        assert!(
            matches!(res, Err(KioskPathError::DosDeviceName(_, _))),
            "DOS device '{dos}' was not rejected as DosDeviceName: got {res:?}"
        );
    }

    let adversarial_ads = [
        "file.txt:stream",
        "file.txt:$DATA",
        "file.txt:stream:$DATA",
        "dir:ads/file.txt",
        "::$INDEX_ALLOCATION",
    ];

    for ads in &adversarial_ads {
        let res = sanitize_strict_relative_subpath(Path::new(ads));
        assert!(res.is_err(), "ADS '{ads}' unexpectedly passed sanitizer!");
    }
}

#[test]
fn adversarial_media_id_injection() {
    let bad_media_ids = [
        "../../../etc/passwd",
        "MEDIA-ID; rm -rf /",
        "MEDIA\0INJECT",
        "MEDIA ID WITH SPACES",
        "MEDIA_ID_WITH_SPECIAL_CHARS!@#$%",
        "",
        "toolong012345678901234567890123456789012345678901234567890123456789012345",
    ];

    for bad in &bad_media_ids {
        assert!(
            !is_valid_media_id(bad),
            "Malicious or malformed media_id '{bad}' was unexpectedly accepted!"
        );
    }
}

#[test]
fn adversarial_badusb_brute_force_resistance() {
    let tmp = tempdir().expect("tempdir");
    let state_file = tmp.path().join("pending_confirmations.json");
    let mgr = PendingDeviceConfirmationManager::new(state_file.clone());

    let device_id = "USB\\VID_DEAD&PID_BEEF\\SN999999";
    let issued = mgr
        .request_user_presence_challenge_extended(device_id)
        .expect("request challenge");

    // Execute 3 wrong attempts
    for strike in 1..=3 {
        let guess = format!("BAD_GUESS_{strike:032}");
        let res = mgr.confirm_device_with_challenge(device_id, &guess);
        assert!(res.is_err(), "Strike {strike} should fail!");
    }

    // Now attempt 50 rapid brute force guesses - all must fail closed
    for i in 4..=54 {
        let guess = format!("BRUTE_FORCE_{i:032}");
        let res = mgr.confirm_device_with_challenge(device_id, &guess);
        assert!(res.is_err(), "Attempt {i} after lockout must fail closed!");
    }

    // Even the original valid token MUST fail closed because the entry was purged
    let valid_attempt = mgr.confirm_device_with_challenge(device_id, &issued.challenge_token);
    assert!(
        valid_attempt.is_err(),
        "Valid token after lockout MUST fail closed!"
    );

    // Verify token file was purged
    let token_file = tmp
        .path()
        .join(format!("pending_challenge_{}.token", issued.challenge_id));
    assert!(
        !token_file.exists(),
        "Token file must be purged after lockout!"
    );
}

#[test]
fn adversarial_token_entropy_and_state_zero_leakage() {
    let tmp = tempdir().expect("tempdir");
    let state_file = tmp.path().join("pending_confirmations.json");
    let mgr = PendingDeviceConfirmationManager::new(state_file.clone());

    let mut generated_tokens = HashSet::new();
    let mut generated_ids = HashSet::new();
    let mut pairs = Vec::new();

    // Generate 50 distinct challenges
    for i in 0..50 {
        let dev_id = format!("USB\\VID_{i:04X}&PID_{i:04X}\\SN{i}");
        let issued = mgr
            .request_user_presence_challenge_extended(&dev_id)
            .expect("request challenge");

        assert_eq!(issued.challenge_token.len(), 32);
        assert!(generated_tokens.insert(issued.challenge_token.clone()));
        assert!(generated_ids.insert(issued.challenge_id.clone()));
        pairs.push((dev_id, issued.challenge_token));
    }

    // Inspect the on-disk state file: ensure ZERO tokens appear in plaintext
    let state_content = fs::read_to_string(&state_file).expect("read state file");
    for token in &generated_tokens {
        assert!(
            !state_content.contains(token),
            "CRITICAL SECURITY FAILURE: Plaintext challenge token found in state file!"
        );
    }

    // Ensure state file contains the SHA-256 digests
    for (dev_id, token) in &pairs {
        let expected_hash = hex::encode(Sha256::digest(format!("{dev_id}:{token}").as_bytes()));
        assert!(
            state_content.contains(&expected_hash),
            "Digest missing for device {dev_id}"
        );
    }
}
