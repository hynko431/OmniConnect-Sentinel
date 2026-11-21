use sentinel_sys::crypto_seal::{
    generate_ecdsa_p256_keypair_software, sign_ecdsa_p256_digest_software,
    unix_authenticated_seal_with_secret, unix_authenticated_unseal_with_secret,
    verify_ecdsa_p256_digest, verify_ecdsa_p256_digest_software,
};
use sha2::{Digest, Sha256};

/// Adversarial Probe 1: Mathematical ECDSA P-256 forgery and corruption resilience.
/// Verifies that no adversary with public-key-only access can forge valid signatures,
/// that tampered signatures and digests fail, and that malformed inputs never panic.
#[test]
fn probe_adversarial_ecdsa_p256_forgery_and_corruption() {
    let (pub_blob, priv_blob) =
        generate_ecdsa_p256_keypair_software().expect("Valid keypair generation");

    assert_eq!(pub_blob.len(), 72);
    assert_eq!(&pub_blob[0..4], b"ECS1");
    assert_eq!(priv_blob.len(), 104);
    assert_eq!(&priv_blob[0..4], b"ECS2");

    let message = b"CRITICAL_SECURITY_EVENT: Sentinel Quarantine Vault Policy Revocation";
    let digest: [u8; 32] = Sha256::digest(message).into();

    let valid_sig = sign_ecdsa_p256_digest_software(&priv_blob, &digest)
        .expect("Signing with private key must succeed");
    assert_eq!(valid_sig.len(), 64);

    // Verify valid signature passes
    assert!(
        verify_ecdsa_p256_digest(&pub_blob, &digest, &valid_sig)
            .expect("Verification must not error"),
        "Legitimate signature must verify successfully"
    );

    // Adversarial Scenario A: Attacker attempts forgery using all-zeros signature
    let zero_sig = [0u8; 64];
    assert!(
        !verify_ecdsa_p256_digest(&pub_blob, &digest, &zero_sig).unwrap_or(false),
        "Adversary forging with all-zeros signature must be rejected"
    );

    // Adversarial Scenario B: Attacker attempts forgery using all-0xFF signature
    let ff_sig = [0xFFu8; 64];
    assert!(
        !verify_ecdsa_p256_digest(&pub_blob, &digest, &ff_sig).unwrap_or(false),
        "Adversary forging with all-0xFF signature must be rejected"
    );

    // Adversarial Scenario C: Attacker attempts CSE-01 SHA256 shortcut forgery
    let pub_x = &pub_blob[8..40];
    let mut fake_hasher = Sha256::new();
    fake_hasher.update(b"ECDSA-P256-UNIX-SIG:");
    fake_hasher.update(pub_x);
    fake_hasher.update(digest);
    let fake_digest = fake_hasher.finalize();
    let mut forged_fake_sig = [0u8; 64];
    forged_fake_sig[..32].copy_from_slice(&fake_digest);
    forged_fake_sig[32..].copy_from_slice(&fake_digest);
    assert!(
        !verify_ecdsa_p256_digest(&pub_blob, &digest, &forged_fake_sig).unwrap_or(false),
        "CSE-01 SHA256 shortcut forgery MUST fail verification against genuine P-256 verifier"
    );

    // Adversarial Scenario D: Attacker alters digest bytes (1-bit mutation across all 32 bytes)
    for byte_idx in 0..32 {
        let mut tampered_digest = digest;
        tampered_digest[byte_idx] ^= 0x80;
        assert!(
            !verify_ecdsa_p256_digest(&pub_blob, &tampered_digest, &valid_sig).unwrap_or(false),
            "Digest tampered at byte {byte_idx} must fail signature verification"
        );
    }

    // Adversarial Scenario E: Attacker alters signature bytes (1-bit mutation across all 64 bytes)
    for byte_idx in 0..64 {
        let mut tampered_sig = valid_sig.clone();
        tampered_sig[byte_idx] ^= 0x01;
        assert!(
            !verify_ecdsa_p256_digest(&pub_blob, &digest, &tampered_sig).unwrap_or(false),
            "Signature tampered at byte {byte_idx} must fail verification"
        );
    }

    // Adversarial Scenario F: Signature length tampering (truncated or oversized)
    for bad_len in [0, 1, 31, 32, 48, 63, 65, 72, 128] {
        let bad_sig = vec![0x42u8; bad_len];
        assert!(
            !verify_ecdsa_p256_digest(&pub_blob, &digest, &bad_sig).unwrap_or(false),
            "Signature of invalid length {bad_len} must be rejected"
        );
    }

    // Adversarial Scenario G: Public key blob corruptions
    // G.1: Truncated public key
    for bad_pub_len in [0, 1, 32, 64, 71] {
        let bad_pub = vec![0x00u8; bad_pub_len];
        assert!(
            !verify_ecdsa_p256_digest(&bad_pub, &digest, &valid_sig).unwrap_or(false),
            "Truncated public key of length {bad_pub_len} must fail safely"
        );
    }
    // G.2: Wrong magic in ECS1 header
    let mut bad_magic_pub = pub_blob.clone();
    bad_magic_pub[0..4].copy_from_slice(b"ECS0");
    assert!(
        !verify_ecdsa_p256_digest(&bad_magic_pub, &digest, &valid_sig).unwrap_or(false),
        "Public key with invalid magic 'ECS0' must be rejected"
    );
    // G.3: Invalid curve point coordinates (X = 0, Y = 0 is not on P-256 curve)
    let mut zero_point_pub = pub_blob.clone();
    zero_point_pub[8..72].fill(0);
    assert!(
        !verify_ecdsa_p256_digest(&zero_point_pub, &digest, &valid_sig).unwrap_or(false),
        "Degenerate curve point (0,0) must fail verification safely"
    );

    // Adversarial Scenario H: Cross-verification with standard SEC1 65-byte uncompressed format
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&pub_blob[8..40]);
    sec1[33..65].copy_from_slice(&pub_blob[40..72]);
    assert!(
        verify_ecdsa_p256_digest(&sec1, &digest, &valid_sig).expect("SEC1 verification"),
        "Standard SEC1 uncompressed public key must verify legitimate signature"
    );

    // Adversarial Scenario I: SEC1 compressed format (0x02 / 0x03 prefix) must be rejected safely
    let mut comp_sec1 = vec![0x02u8];
    comp_sec1.extend_from_slice(&pub_blob[8..40]);
    assert!(
        !verify_ecdsa_p256_digest(&comp_sec1, &digest, &valid_sig).unwrap_or(false),
        "Compressed SEC1 point must be rejected without panicking"
    );
}

/// Adversarial Probe 2: AEAD Authenticated Encryption Tamper & Injection Resistance.
/// Probes AES-256-GCM + HKDF-SHA256 sealing envelope against bitflips, truncated ciphertexts,
/// forged tags, mismatched AAD, wrong salt, and key derivation attacks.
#[test]
fn probe_adversarial_ocsl2_aead_tamper_resistance() {
    let master_secret = [0x33u8; 32];
    let payload_key = [0x77u8; 32];
    let entropy = b"EntropyTag-NonceBinding-Audit-2026";
    let kek_id = "master-kek-vault-primary";

    let sealed = unix_authenticated_seal_with_secret(&payload_key, &master_secret, entropy, kek_id)
        .expect("Legitimate seal must succeed");

    // Envelope validation: 5 (magic) + 16 (salt) + 12 (nonce) + 32 (payload) + 16 (GCM tag) = 81 bytes
    assert_eq!(&sealed[0..5], b"OCSL2");
    assert_eq!(sealed.len(), 5 + 16 + 12 + 32 + 16);

    // Legitimate unseal round-trip
    let recovered = unix_authenticated_unseal_with_secret(&sealed, &master_secret, entropy, kek_id)
        .expect("Legitimate unseal must succeed");
    assert_eq!(recovered, payload_key);

    // Adversarial Scenario A: Single-bit flips across every single byte of the sealed envelope
    // Bytes 0..5 (Magic)
    // Bytes 5..21 (Salt)
    // Bytes 21..33 (Nonce)
    // Bytes 33..65 (Ciphertext payload)
    // Bytes 65..81 (AEAD authentication tag)
    for byte_pos in 0..sealed.len() {
        for bit_mask in [0x01u8, 0x02, 0x10, 0x80] {
            let mut corrupted = sealed.clone();
            corrupted[byte_pos] ^= bit_mask;
            let result =
                unix_authenticated_unseal_with_secret(&corrupted, &master_secret, entropy, kek_id);
            assert!(
                result.is_err(),
                "Corrupted envelope at byte {byte_pos} with bitmask 0x{bit_mask:02X} MUST fail authentication"
            );
        }
    }

    // Adversarial Scenario B: Truncated envelopes
    for trunc_len in [0, 1, 4, 5, 10, 20, 32, 33, 48, 64, 80] {
        let truncated = &sealed[..trunc_len];
        let result =
            unix_authenticated_unseal_with_secret(truncated, &master_secret, entropy, kek_id);
        assert!(
            result.is_err(),
            "Truncated envelope of length {trunc_len} MUST fail authentication safely"
        );
    }

    // Adversarial Scenario C: Trailing garbage injection
    let mut extended = sealed.clone();
    extended.push(0x00);
    assert!(
        unix_authenticated_unseal_with_secret(&extended, &master_secret, entropy, kek_id).is_err(),
        "Envelope with trailing byte injection MUST fail AEAD tag check"
    );

    // Adversarial Scenario D: AAD Tampering Attacks
    // D.1: Mismatched entropy tag
    assert!(
        unix_authenticated_unseal_with_secret(&sealed, &master_secret, b"ForgedEntropyTag", kek_id)
            .is_err(),
        "Tampered entropy tag in AAD MUST cause AEAD authentication failure"
    );
    // D.2: Empty entropy tag
    assert!(
        unix_authenticated_unseal_with_secret(&sealed, &master_secret, b"", kek_id).is_err(),
        "Empty entropy tag in AAD MUST cause AEAD authentication failure"
    );
    // D.3: Mismatched KEK ID (e.g. cross-kek injection)
    assert!(
        unix_authenticated_unseal_with_secret(
            &sealed,
            &master_secret,
            entropy,
            "master-kek-vault-secondary"
        )
        .is_err(),
        "Cross-KEK AAD substitution MUST cause AEAD authentication failure"
    );
    // D.4: Prefix / Suffix mutation of KEK ID
    assert!(
        unix_authenticated_unseal_with_secret(
            &sealed,
            &master_secret,
            entropy,
            "master-kek-vault-primary-suffix"
        )
        .is_err(),
        "Modified KEK ID MUST cause AEAD authentication failure"
    );

    // Adversarial Scenario E: Master secret substitution
    let wrong_master_secret = [0x34u8; 32];
    assert!(
        unix_authenticated_unseal_with_secret(&sealed, &wrong_master_secret, entropy, kek_id)
            .is_err(),
        "Decryption with incorrect master secret MUST fail AEAD authentication"
    );

    // Adversarial Scenario F: Magic substitution ("OCSL1" legacy or "XCSL2" invalid)
    let mut bad_magic = sealed.clone();
    bad_magic[0..5].copy_from_slice(b"OCSL1");
    assert!(
        unix_authenticated_unseal_with_secret(&bad_magic, &master_secret, entropy, kek_id).is_err(),
        "Legacy or invalid envelope magic MUST fail validation"
    );
}

/// Adversarial Probe 3: Constant-time software signature verification safety against invalid inputs.
#[test]
fn probe_adversarial_constant_time_software_verifier_edge_cases() {
    let (pub_blob, priv_blob) =
        generate_ecdsa_p256_keypair_software().expect("Valid keypair generation");
    let digest = [0xAAu8; 32];
    let valid_sig = sign_ecdsa_p256_digest_software(&priv_blob, &digest).expect("Valid sign");

    // Probe verify_ecdsa_p256_digest_software directly
    assert!(
        verify_ecdsa_p256_digest_software(&pub_blob, &digest, &valid_sig)
            .expect("Verification must succeed"),
        "Genuine signature verified via software engine"
    );

    // Corrupted digest
    let wrong_digest = [0xBBu8; 32];
    assert!(
        !verify_ecdsa_p256_digest_software(&pub_blob, &wrong_digest, &valid_sig)
            .expect("Verification returns false"),
        "Wrong digest must return Ok(false) without error"
    );

    // Truncated signature to software engine
    assert!(
        !verify_ecdsa_p256_digest_software(&pub_blob, &digest, &valid_sig[..32])
            .expect("Truncated sig returns false"),
        "Truncated signature must return Ok(false) without panic"
    );

    // Corrupted curve point in SEC1 point format
    let mut invalid_point = vec![0x04u8];
    invalid_point.extend_from_slice(&[0xFFu8; 64]); // Point (2^256-1, 2^256-1) not on curve
    assert!(
        !verify_ecdsa_p256_digest_software(&invalid_point, &digest, &valid_sig)
            .expect("Invalid point returns false"),
        "Invalid curve point must return Ok(false) safely"
    );
}
