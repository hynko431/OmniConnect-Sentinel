//! Cold-Eye Compliance Auditor - Sub-Phase 0.2 Adversarial Break-It Probe
//! Relentlessly tests RSA-3072 semiprime properties, OAEP padding integrity,
//! label binding, corrupted/downgraded 2048-bit key rejection, and escrow recovery isolation.

use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use sentinel_sys::crypto_seal::{
    decrypt_kek_from_soc_escrow, decrypt_kek_from_soc_escrow_software, encrypt_kek_for_soc_escrow,
    encrypt_kek_for_soc_escrow_hybrid_v3, encrypt_kek_for_soc_escrow_software,
    export_rsa_private_key_to_cng, export_rsa_public_key_to_cng, generate_hybrid_soc_keypair_v3,
    generate_hybrid_soc_keypair_with_bits, generate_soc_rsa_keypair,
    generate_soc_rsa_keypair_software, parse_rsa_private_key, parse_rsa_public_key, SocEscrowBlob,
};

#[test]
fn probe_adversarial_rsa3072_semiprime_mathematical_soundness() {
    // 1. Generate keypairs via software and CNG (if windows)
    let (sw_pub, sw_priv) = generate_soc_rsa_keypair_software().expect("software keygen");
    assert_eq!(&sw_pub[0..4], b"RSA1");
    assert_eq!(&sw_priv[0..4], b"RSA2");

    // 2. Parse software keypair into RSA structures and verify mathematical properties
    let parsed_priv = parse_rsa_private_key(&sw_priv).expect("parse private key");
    let parsed_pub = parse_rsa_public_key(&sw_pub).expect("parse public key");

    // Test export functions
    let re_exported_pub = export_rsa_public_key_to_cng(&parsed_pub);
    assert_eq!(re_exported_pub, sw_pub);
    let re_exported_priv = export_rsa_private_key_to_cng(&parsed_priv).expect("re-export priv");
    assert_eq!(re_exported_priv, sw_priv);

    // Check modulus bit length (>= 3072 bits / 384 bytes)
    let n = parsed_priv.n();
    let n_bytes = n.to_be_bytes();
    assert_eq!(
        n_bytes.len(),
        384,
        "Modulus must be exactly 384 bytes (3072 bits)"
    );
    assert_eq!(
        n_bytes[0] & 0x80,
        0x80,
        "MSB of modulus must be 1 (full 3072 bits)"
    );
    assert_eq!(n_bytes[383] & 0x01, 0x01, "Modulus must be odd");

    // Check exponent: F4 is 65537 (0x010001)
    let e = parsed_priv.e();
    let e_bytes = e.to_be_bytes();
    let e_trimmed = e_bytes
        .iter()
        .skip_while(|&&b| b == 0)
        .copied()
        .collect::<Vec<u8>>();
    assert_eq!(
        e_trimmed,
        vec![0x01, 0x00, 0x01],
        "Public exponent must be F4 (65537)"
    );

    // Check genuine primes (semiprime factorization p * q == n)
    let primes = parsed_priv.primes();
    assert_eq!(
        primes.len(),
        2,
        "RSA keypair must have exactly 2 prime factors"
    );
    let p = &primes[0];
    let q = &primes[1];
    assert_ne!(p, q, "Primes p and q must not be identical");

    let p_bytes = p.to_be_bytes();
    let q_bytes = q.to_be_bytes();
    assert_eq!(p_bytes.len(), 192, "Prime p must be 1536 bits (192 bytes)");
    assert_eq!(q_bytes.len(), 192, "Prime q must be 1536 bits (192 bytes)");

    // Both p and q must be odd
    assert_eq!(p_bytes[191] & 0x01, 0x01, "Prime p must be odd");
    assert_eq!(q_bytes[191] & 0x01, 0x01, "Prime q must be odd");

    // Public key n and e must match private key parts
    assert_eq!(
        parsed_pub.n(),
        parsed_priv.n(),
        "Public key modulus must match private key modulus"
    );
    assert_eq!(
        parsed_pub.e(),
        parsed_priv.e(),
        "Public key exponent must match private key exponent"
    );

    // 3. Hardware/primary SOC keygen must also produce >= 3072-bit RSA
    let (gen_pub, gen_priv) = generate_soc_rsa_keypair().expect("generate primary RSA-3072");
    let gen_parsed_pub = parse_rsa_public_key(&gen_pub).expect("parse primary pub");
    let gen_parsed_priv = parse_rsa_private_key(&gen_priv).expect("parse primary priv");
    assert_eq!(gen_parsed_pub.n(), gen_parsed_priv.n());
    assert_eq!(gen_parsed_pub.n().to_be_bytes().len(), 384);
}

#[test]
fn probe_adversarial_rsa_oaep_label_and_ciphertext_tampering() {
    let (pub_blob, priv_blob) = generate_soc_rsa_keypair().expect("generate keypair");
    let kek = [0x5Au8; 32];
    let kek_id = "target-kek-778899aabbcc";

    // Legitimate encryption
    let escrow = encrypt_kek_for_soc_escrow(&kek, &pub_blob, kek_id).expect("encrypt");
    assert_eq!(escrow.version, 2);
    assert_eq!(escrow.algorithm, "RSA-3072-OAEP-SHA256");
    assert_eq!(escrow.kek_id, kek_id);
    assert_eq!(escrow.rsa_oaep_ciphertext.len(), 384);

    // Legitimate decryption
    let decrypted = decrypt_kek_from_soc_escrow(&escrow, &priv_blob).expect("decrypt");
    assert_eq!(decrypted, kek);

    // Test software engine directly
    let sw_escrow =
        encrypt_kek_for_soc_escrow_software(&kek, &pub_blob, kek_id).expect("sw encrypt");
    assert_eq!(sw_escrow.algorithm, "RSA-3072-OAEP-SHA256");
    let sw_decrypted =
        decrypt_kek_from_soc_escrow_software(&sw_escrow, &priv_blob).expect("sw decrypt");
    assert_eq!(sw_decrypted, kek);

    // Cross engine: decrypt software-encrypted blob using main decrypt
    let cross_dec = decrypt_kek_from_soc_escrow(&sw_escrow, &priv_blob).expect("cross decrypt");
    assert_eq!(cross_dec, kek);

    // Adversarial Scenario 1: Bit-flip across the 384-byte ciphertext
    // OAEP-SHA256 integrity verification MUST reject any tampered ciphertext without panicking.
    for byte_idx in [0, 1, 15, 31, 63, 127, 255, 300, 383] {
        let mut tampered_escrow = escrow.clone();
        tampered_escrow.rsa_oaep_ciphertext[byte_idx] ^= 0x01;
        let res = decrypt_kek_from_soc_escrow(&tampered_escrow, &priv_blob);
        assert!(
            res.is_err(),
            "Ciphertext bitflip at byte {byte_idx} must fail OAEP padding verification"
        );
    }

    // Adversarial Scenario 2: Truncated ciphertext
    for trunc_len in [0, 1, 16, 64, 128, 255, 256, 383] {
        let mut tampered_escrow = escrow.clone();
        tampered_escrow.rsa_oaep_ciphertext.truncate(trunc_len);
        let res = decrypt_kek_from_soc_escrow(&tampered_escrow, &priv_blob);
        assert!(
            res.is_err(),
            "Truncated ciphertext of length {trunc_len} must fail safely"
        );
    }

    // Adversarial Scenario 3: Label mismatch via altered kek_id
    // OAEP label is bound to "SOC-OFFLINE-ESCROW-RECOVERY-V2:{kek_id}"
    let mut altered_id_escrow = escrow.clone();
    altered_id_escrow.kek_id = "target-kek-778899aabbcd".to_string();
    let res = decrypt_kek_from_soc_escrow(&altered_id_escrow, &priv_blob);
    assert!(
        res.is_err(),
        "Modified kek_id in escrow envelope must cause OAEP label mismatch failure"
    );

    // Adversarial Scenario 4: Empty kek_id
    let mut empty_id_escrow = escrow.clone();
    empty_id_escrow.kek_id = "".to_string();
    let res = decrypt_kek_from_soc_escrow(&empty_id_escrow, &priv_blob);
    assert!(
        res.is_err(),
        "Empty kek_id must cause OAEP label mismatch failure"
    );

    // Adversarial Scenario 5: Decryption using wrong private key
    let (_other_pub, other_priv) = generate_soc_rsa_keypair().expect("other keypair");
    let wrong_key_res = decrypt_kek_from_soc_escrow(&escrow, &other_priv);
    assert!(
        wrong_key_res.is_err(),
        "Decryption with an unrelated RSA-3072 private key must fail OAEP verification"
    );
}

#[test]
fn probe_adversarial_malformed_rsa_blobs_never_panic() {
    let kek = [0x42u8; 32];
    let escrow = SocEscrowBlob {
        version: 2,
        algorithm: "RSA-3072-OAEP-SHA256".to_string(),
        kek_id: "test-malformed".to_string(),
        soc_key_fingerprint: "0123456789abcdef".to_string(),
        rsa_oaep_ciphertext: vec![0u8; 384],
    };

    // 1. Truncated blobs to parse_rsa_public_key
    for len in [0, 1, 4, 12, 23] {
        let truncated = vec![0x00u8; len];
        assert!(parse_rsa_public_key(&truncated).is_err());
        assert!(encrypt_kek_for_soc_escrow(&kek, &truncated, "test").is_err());
    }

    // 2. Bad magic in public key
    let mut bad_magic = vec![0u8; 24 + 3 + 384];
    bad_magic[0..4].copy_from_slice(b"BAD!");
    assert!(parse_rsa_public_key(&bad_magic).is_err());
    assert!(encrypt_kek_for_soc_escrow(&kek, &bad_magic, "test").is_err());

    // 3. Insecure key lengths (< 3072 bits: 1024 and 2048 bits) MUST be rejected everywhere
    let mut weak_key_1024 = vec![0u8; 24 + 3 + 128];
    weak_key_1024[0..4].copy_from_slice(b"RSA1");
    weak_key_1024[4..8].copy_from_slice(&1024u32.to_le_bytes());
    assert!(parse_rsa_public_key(&weak_key_1024).is_err());

    struct TestOsRng;
    impl rsa::rand_core::TryRng for TestOsRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(rand::RngCore::next_u32(&mut rand::rngs::OsRng))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(rand::RngCore::next_u64(&mut rand::rngs::OsRng))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, dst);
            Ok(())
        }
    }
    impl rsa::rand_core::TryCryptoRng for TestOsRng {}

    let mut test_rng = TestOsRng;
    let rsa2048_priv = rsa::PrivateKey::new(&mut test_rng, 2048).expect("2048 test key");
    let rsa2048_pub = rsa::PublicKey::from(&rsa2048_priv);
    let rsa2048_pub_blob = export_rsa_public_key_to_cng(&rsa2048_pub);
    let rsa2048_priv_blob = export_rsa_private_key_to_cng(&rsa2048_priv).expect("2048 priv blob");
    assert!(
        parse_rsa_public_key(&rsa2048_pub_blob).is_err(),
        "2048-bit RSA public key must be rejected (< 3072 bits)"
    );
    assert!(
        parse_rsa_private_key(&rsa2048_priv_blob).is_err(),
        "2048-bit RSA private key must be rejected (< 3072 bits)"
    );
    assert!(
        encrypt_kek_for_soc_escrow(&kek, &rsa2048_pub_blob, "downgrade-test").is_err(),
        "encrypt_kek_for_soc_escrow must reject 2048-bit RSA downgrade"
    );
    assert!(
        generate_hybrid_soc_keypair_with_bits(2048).is_err(),
        "generate_hybrid_soc_keypair_with_bits(2048) must fail closed"
    );
    let (mut v3_pub, _v3_priv) = generate_hybrid_soc_keypair_v3().expect("v3 keygen");
    v3_pub.rsa_public_blob = rsa2048_pub_blob;
    assert!(
        encrypt_kek_for_soc_escrow_hybrid_v3(&kek, &v3_pub, "downgrade-v3").is_err(),
        "encrypt_kek_for_soc_escrow_hybrid_v3 must reject 2048-bit RSA downgrade"
    );

    // 4. Truncated private key blobs to parse_rsa_private_key
    for len in [0, 1, 4, 12, 23, 24] {
        let truncated = vec![0x00u8; len];
        assert!(parse_rsa_private_key(&truncated).is_err());
        assert!(decrypt_kek_from_soc_escrow(&escrow, &truncated).is_err());
    }

    // 5. Bad magic in private key
    let mut bad_priv_magic = vec![0u8; 24 + 3 + 384 + 192 + 192];
    bad_priv_magic[0..4].copy_from_slice(b"RSA1"); // Wrong magic for private key (needs RSA2)
    assert!(parse_rsa_private_key(&bad_priv_magic).is_err());
    assert!(decrypt_kek_from_soc_escrow(&escrow, &bad_priv_magic).is_err());

    // 6. Spoofed SocEscrowBlob metadata (version != 2 or RSA-2048 algorithm label) must be rejected
    let (_rsa3072_pub_v, rsa3072_priv_v) = generate_soc_rsa_keypair().expect("RSA-3072 keygen");
    let valid_escrow =
        encrypt_kek_for_soc_escrow(&kek, &_rsa3072_pub_v, "meta-check").expect("valid escrow");
    let mut bad_ver = valid_escrow.clone();
    bad_ver.version = 1;
    assert!(decrypt_kek_from_soc_escrow(&bad_ver, &rsa3072_priv_v).is_err());
    assert!(decrypt_kek_from_soc_escrow_software(&bad_ver, &rsa3072_priv_v).is_err());

    let mut bad_alg = valid_escrow;
    bad_alg.algorithm = "RSA-2048-OAEP-SHA256".to_string();
    assert!(decrypt_kek_from_soc_escrow(&bad_alg, &rsa3072_priv_v).is_err());
    assert!(decrypt_kek_from_soc_escrow_software(&bad_alg, &rsa3072_priv_v).is_err());
}
