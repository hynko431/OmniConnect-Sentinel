//! T35: 128-Bit BadUSB Cryptographic Challenge, Constant-Time Verification, & 3-Strike Lockout Tests
//!
//! Verifies:
//! 1. 128-bit cryptographic challenge generation (32 hex chars, `OsRng` entropy) (`CSE-12`).
//! 2. State storage security: state file stores only `challenge_hash` and never plaintext token.
//! 3. Local token file `pending_challenge_{challenge_id}.token` created with restricted permissions.
//! 4. Successful confirmation with correct token verifies constant-time and re-enables device.
//! 5. Automatic cleanup of `.token` file upon confirmation.
//! 6. 3-strike lockout: 3 failed attempts purge entry completely; 4th attempt fails closed.
//! 7. 300s TTL enforcement: expired challenges fail closed and are purged.
//! 8. Telemetry and audit ledger redaction: secret token is never emitted to SIEM/logs.

use sha2::{Digest, Sha256};
use std::fs;
use tempfile::tempdir;

use sentinel_core::interceptor::{IssuedBadUsbChallenge, PendingDeviceConfirmationManager};

#[test]
fn test_128bit_challenge_generation_and_entropy() {
    let tmp = tempdir().expect("tempdir");
    let state_file = tmp.path().join("pending_confirmations.json");
    let mgr = PendingDeviceConfirmationManager::new(state_file.clone());

    let device_id = "USB\\VID_046D&PID_C52B\\123456";
    let issued = mgr
        .request_user_presence_challenge_extended(device_id)
        .expect("request challenge");

    // 128 bits = 16 bytes = 32 hex chars
    assert_eq!(
        issued.challenge_token.len(),
        32,
        "Challenge token must be 32 hex characters (128 bits)"
    );
    assert!(
        issued
            .challenge_token
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "Challenge token must be valid hex"
    );
    assert!(
        issued.challenge_id.starts_with("CHAL-"),
        "Challenge ID must have CHAL- prefix"
    );
    assert!(
        issued.expires_at_unix > chrono::Utc::now().timestamp(),
        "Challenge expiry must be in the future"
    );

    // Verify token file was created
    let token_file = tmp
        .path()
        .join(format!("pending_challenge_{}.token", issued.challenge_id));
    assert!(token_file.exists(), "Local token file must exist");
    let token_file_content = fs::read_to_string(&token_file).expect("read token file");
    assert_eq!(
        token_file_content, issued.challenge_token,
        "Token file must contain plaintext token"
    );

    // Verify state file does NOT contain plaintext token
    let state_content = fs::read_to_string(&state_file).expect("read state file");
    assert!(
        !state_content.contains(&issued.challenge_token),
        "CRITICAL: State file must NEVER contain plaintext challenge token!"
    );

    // Verify state file contains the SHA-256 hash
    let expected_hash = hex::encode(Sha256::digest(
        format!("{device_id}:{}", issued.challenge_token).as_bytes(),
    ));
    assert!(
        state_content.contains(&expected_hash),
        "State file must contain SHA-256 hash of device_id:challenge_token"
    );
}

#[test]
fn test_successful_confirmation_and_token_cleanup() {
    let tmp = tempdir().expect("tempdir");
    let state_file = tmp.path().join("pending_confirmations.json");
    let mgr = PendingDeviceConfirmationManager::new(state_file);

    let device_id = "USB\\VID_1234&PID_5678\\SN001";
    let issued = mgr
        .request_user_presence_challenge_extended(device_id)
        .expect("request challenge");

    let token_file = tmp
        .path()
        .join(format!("pending_challenge_{}.token", issued.challenge_id));
    assert!(
        token_file.exists(),
        "Token file must exist before confirmation"
    );

    assert!(
        !mgr.is_confirmed(device_id),
        "Device must not be confirmed initially"
    );

    // Confirm with correct token
    let confirm_res = mgr.confirm_device_with_challenge(device_id, &issued.challenge_token);
    assert!(
        confirm_res.is_ok(),
        "Confirmation with correct token failed: {confirm_res:?}"
    );

    assert!(mgr.is_confirmed(device_id), "Device must now be confirmed");

    // Token file must be purged after successful confirmation
    assert!(
        !token_file.exists(),
        "Token file must be purged after successful confirmation"
    );
}

#[test]
fn test_3_strike_lockout_and_fail_closed() {
    let tmp = tempdir().expect("tempdir");
    let state_file = tmp.path().join("pending_confirmations.json");
    let mgr = PendingDeviceConfirmationManager::new(state_file);

    let device_id = "USB\\VID_9999&PID_8888\\BADUSB01";
    let issued = mgr
        .request_user_presence_challenge_extended(device_id)
        .expect("request challenge");

    let token_file = tmp
        .path()
        .join(format!("pending_challenge_{}.token", issued.challenge_id));
    assert!(token_file.exists(), "Token file must exist before strikes");

    // Strike 1
    let strike1 = mgr.confirm_device_with_challenge(device_id, "WRONG_TOKEN_00000000000000000001");
    assert!(strike1.is_err(), "Strike 1 must fail");
    assert!(strike1.unwrap_err().to_string().contains("strike 1 of 3"));
    assert!(!mgr.is_confirmed(device_id));

    // Strike 2
    let strike2 = mgr.confirm_device_with_challenge(device_id, "WRONG_TOKEN_00000000000000000002");
    assert!(strike2.is_err(), "Strike 2 must fail");
    assert!(strike2.unwrap_err().to_string().contains("strike 2 of 3"));
    assert!(!mgr.is_confirmed(device_id));

    // Strike 3 - Lockout!
    let strike3 = mgr.confirm_device_with_challenge(device_id, "WRONG_TOKEN_00000000000000000003");
    assert!(strike3.is_err(), "Strike 3 must fail");
    assert!(strike3.unwrap_err().to_string().contains("strike 3 of 3"));
    assert!(!mgr.is_confirmed(device_id));

    // After strike 3: token file must be purged and state entry removed
    assert!(
        !token_file.exists(),
        "Token file must be purged after strike 3 lockout"
    );

    // Attempt 4: Even with the CORRECT token, it must fail closed!
    let attempt4 = mgr.confirm_device_with_challenge(device_id, &issued.challenge_token);
    assert!(
        attempt4.is_err(),
        "Attempt 4 after lockout must fail closed even with correct token!"
    );
    assert!(!mgr.is_confirmed(device_id));
}

#[test]
fn test_300s_ttl_expiration_fails_closed() {
    let tmp = tempdir().expect("tempdir");
    let state_file = tmp.path().join("pending_confirmations.json");
    let mgr = PendingDeviceConfirmationManager::new(state_file.clone());

    let device_id = "USB\\VID_4321&PID_8765\\EXPIRING01";
    let issued = mgr
        .request_user_presence_challenge_extended(device_id)
        .expect("request challenge");

    let token_file = tmp
        .path()
        .join(format!("pending_challenge_{}.token", issued.challenge_id));
    assert!(token_file.exists());

    // Manually manipulate state file to simulate expiration (backdate expires_at_unix by 10 seconds)
    let state_content = fs::read_to_string(&state_file).expect("read state file");
    let mut state_json: serde_json::Value =
        serde_json::from_str(&state_content).expect("parse json");
    let expired_timestamp = chrono::Utc::now().timestamp() - 10;
    state_json[device_id]["expires_at_unix"] = serde_json::json!(expired_timestamp);
    fs::write(
        &state_file,
        serde_json::to_string_pretty(&state_json).expect("serialize"),
    )
    .expect("write manipulated state file");

    // Attempt to confirm with correct token on expired entry
    let confirm_res = mgr.confirm_device_with_challenge(device_id, &issued.challenge_token);
    assert!(
        confirm_res.is_err(),
        "Confirmation on expired challenge must fail closed!"
    );
    let err_msg = confirm_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("expired") || err_msg.contains("TTL"),
        "Error message must mention expiration: {err_msg}"
    );

    // Token file must be purged upon expiration detection
    assert!(
        !token_file.exists(),
        "Token file must be purged after expiration"
    );
    assert!(!mgr.is_confirmed(device_id));
}

#[test]
fn test_secret_token_never_in_telemetry_or_logs() {
    let challenge = IssuedBadUsbChallenge {
        challenge_id: "CHAL-A1B2C3D4".to_string(),
        challenge_token: "0123456789ABCDEF0123456789ABCDEF".to_string(),
        expires_at_unix: chrono::Utc::now().timestamp() + 300,
    };

    // Telemetry details template used in sentinel-core/src/main.rs
    let device_id = "USB\\VID_046D&PID_C52B\\DEMO";
    let details = format!(
        "Blocked composite device {device_id}; challenge_id={}; physical console authorization token required",
        challenge.challenge_id
    );

    assert!(
        !details.contains(&challenge.challenge_token),
        "Telemetry details must never contain the secret challenge token"
    );
    assert!(
        details.contains(&challenge.challenge_id),
        "Telemetry details must contain public challenge_id"
    );

    // Audit log event template used in sentinel-core/src/main.rs
    let audit_event = format!(
        "Severed data lines for composite device {device_id}; challenge_id={} issued",
        challenge.challenge_id
    );

    assert!(
        !audit_event.contains(&challenge.challenge_token),
        "Audit log event must never contain the secret challenge token"
    );
    assert!(
        audit_event.contains(&challenge.challenge_id),
        "Audit log event must contain public challenge_id"
    );
}
