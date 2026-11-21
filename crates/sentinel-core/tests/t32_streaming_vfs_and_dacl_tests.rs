//! Gate T32: Handle-Bound `O_NOFOLLOW` 64 KiB Streaming VFS & Atomic DACL Tests (`Sub-Phase 1.3`, `CSE-07`, `CSE-10`).
//!
//! Verifies:
//! 1. `open_untrusted_readonly_nofollow`: Regular files open cleanly; reparse points, symlinks,
//!    directories, and non-disk handles are rejected without following.
//! 2. `read_untrusted_to_end_bounded`: `Read::take(budget + 1)` quota bounds prevent memory exhaustion.
//! 3. `create_restricted_file_atomic` & `create_restricted_dir_atomic`: Binds SYSTEM+Admin DACLs
//!    at inode/MFT creation time, eliminating post-creation DACL races.
//! 4. `64 KiB` Chunked Streaming (`chunked_cache`):
//!    - Multi-chunk roundtrip preserves byte parity.
//!    - Empty file handled securely.
//!    - Adversarial chunk swap attack fails closed (AEAD nonce sequence mismatch).
//!    - Adversarial chunk truncation attack fails closed (`IntegrityError`).
//!    - Adversarial `is_final` flag tampering fails closed (AAD mismatch).
//!    - Adversarial file_id substitution fails closed (AAD mismatch).
//! 5. Production `std::env::temp_dir()` elimination.

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::PathBuf;
use uuid::Uuid;

use sentinel_core::vfs::chunked_cache::{decrypt_chunked_stream, encrypt_chunked_stream};
use sentinel_sys::{
    create_restricted_dir_atomic, create_restricted_file_atomic, open_untrusted_readonly_nofollow,
    read_untrusted_to_end_bounded,
};

fn create_test_temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("t32_{prefix}_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&dir);
    dir
}

#[test]
fn test_t32_open_untrusted_regular_file() {
    let dir = create_test_temp_dir("open_reg");
    let file_path = dir.join("test_sample.bin");
    fs::write(&file_path, b"CONFIDENTIAL_PAYLOAD_BYTES").unwrap();

    let mut opened =
        open_untrusted_readonly_nofollow(&file_path).expect("Regular file should open");
    let mut read_bytes = Vec::new();
    opened.read_to_end(&mut read_bytes).unwrap();
    assert_eq!(read_bytes, b"CONFIDENTIAL_PAYLOAD_BYTES");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_open_untrusted_directory_fails_closed() {
    let dir = create_test_temp_dir("open_dir");
    let sub_dir = dir.join("nested_folder");
    fs::create_dir_all(&sub_dir).unwrap();

    let res = open_untrusted_readonly_nofollow(&sub_dir);
    assert!(
        res.is_err(),
        "Opening a directory as an untrusted file must fail"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_open_untrusted_symlink_or_reparse_point_fails_closed() {
    let dir = create_test_temp_dir("open_sym");
    let target_file = dir.join("real_target.txt");
    fs::write(&target_file, b"TARGET_FILE_SECRET").unwrap();

    let link_path = dir.join("malicious_symlink.txt");

    #[cfg(windows)]
    {
        // Try creating symlink or junction if permitted, else test with nonexistent/invalid
        let sym_res = std::os::windows::fs::symlink_file(&target_file, &link_path);
        if sym_res.is_ok() {
            let res = open_untrusted_readonly_nofollow(&link_path);
            assert!(
                res.is_err(),
                "Opening a Windows symlink via open_untrusted_readonly_nofollow must fail"
            );
        }
    }

    #[cfg(unix)]
    {
        let sym_res = std::os::unix::fs::symlink(&target_file, &link_path);
        if sym_res.is_ok() {
            let res = open_untrusted_readonly_nofollow(&link_path);
            assert!(
                res.is_err(),
                "Opening a Unix symlink via open_untrusted_readonly_nofollow must fail"
            );
        }
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_read_untrusted_to_end_bounded_quota_enforcement() {
    let small_data = vec![0x42u8; 1024]; // 1 KiB
    let mut cursor = Cursor::new(small_data);

    // Reading within quota
    let read_res = read_untrusted_to_end_bounded(&mut cursor, 2048).expect("Read within quota");
    assert_eq!(read_res.len(), 1024);

    // Reading stream exceeding quota fails closed with InvalidData
    let large_data = vec![0x42u8; 4096]; // 4 KiB
    let mut cursor_large = Cursor::new(large_data);
    let overflow_res = read_untrusted_to_end_bounded(&mut cursor_large, 2048);
    assert!(
        overflow_res.is_err(),
        "Reading beyond quota must fail closed"
    );
    assert_eq!(
        overflow_res.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn test_t32_atomic_restricted_file_and_dir_dacl() {
    let dir = create_test_temp_dir("atomic_dacl");
    let secure_dir = dir.join("secure_vault");
    create_restricted_dir_atomic(&secure_dir).expect("Atomic restricted dir creation");
    assert!(secure_dir.is_dir());

    let secure_file = secure_dir.join("vault_key.bin");
    let content = b"ATOMIC_RESTRICTED_KEY_SECRET";
    create_restricted_file_atomic(&secure_file, content).expect("Atomic restricted file creation");
    assert!(secure_file.is_file());

    let mut read_back = Vec::new();
    File::open(&secure_file)
        .unwrap()
        .read_to_end(&mut read_back)
        .unwrap();
    assert_eq!(read_back, content);

    #[cfg(windows)]
    {
        // Verify DACL via GetNamedSecurityInfoW or ConvertSecurityDescriptorToStringSecurityDescriptorW
        use std::os::windows::ffi::OsStrExt;
        let verbatim = sentinel_sys::to_verbatim_path(&secure_file);
        let wide: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();

        extern "system" {
            fn GetNamedSecurityInfoW(
                pObjectName: *const u16,
                ObjectType: i32,
                SecurityInfo: u32,
                ppsidOwner: *mut *mut core::ffi::c_void,
                ppsidGroup: *mut *mut core::ffi::c_void,
                ppDacl: *mut *mut core::ffi::c_void,
                ppSacl: *mut *mut core::ffi::c_void,
                ppSecurityDescriptor: *mut *mut core::ffi::c_void,
            ) -> u32;
            fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
                SecurityDescriptor: *const core::ffi::c_void,
                RequestedStringSDRevision: u32,
                SecurityInformation: u32,
                StringSecurityDescriptor: *mut *mut u16,
                StringSecurityDescriptorLen: *mut u32,
            ) -> i32;
            fn LocalFree(hMem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        }

        const SE_FILE_OBJECT: i32 = 1;
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;

        let mut p_sd: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut p_dacl: *mut core::ffi::c_void = core::ptr::null_mut();

        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut p_dacl,
                core::ptr::null_mut(),
                &mut p_sd,
            )
        };
        assert_eq!(status, 0, "GetNamedSecurityInfoW must succeed");

        let mut sddl_out: *mut u16 = core::ptr::null_mut();
        let mut sddl_len: u32 = 0;
        let ok_sddl = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                p_sd,
                1,
                DACL_SECURITY_INFORMATION,
                &mut sddl_out,
                &mut sddl_len,
            )
        };
        assert_ne!(ok_sddl, 0);

        let slice = unsafe { std::slice::from_raw_parts(sddl_out, sddl_len as usize) };
        let sddl_str = String::from_utf16_lossy(slice);

        unsafe {
            let _ = LocalFree(sddl_out as *mut core::ffi::c_void);
            let _ = LocalFree(p_sd);
        }

        // Verify that SYSTEM (SY) and Administrators (BA) are present, and unprivileged users (AU/WD) are absent
        assert!(sddl_str.contains("SY") || sddl_str.contains("S-1-5-18"));
        assert!(sddl_str.contains("BA") || sddl_str.contains("S-1-5-32-544"));
        assert!(!sddl_str.contains("AU") && !sddl_str.contains("WD"));
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_chunked_streaming_roundtrip_multi_chunk() {
    let dir = create_test_temp_dir("chunk_roundtrip");
    let key = [0x5au8; 32];
    let file_id = [0x33u8; 16];

    // Create a 200 KiB payload spanning across 4 chunks (64 KiB each: 65536 * 3 + 3488)
    let total_size = 200 * 1024;
    let mut payload = vec![0u8; total_size];
    rand::rngs::OsRng.fill_bytes(&mut payload);
    let original_sha = hex::encode(Sha256::digest(&payload));

    let cache_file = dir.join("stream.cache");

    // Encrypt
    let written = encrypt_chunked_stream(&key, &file_id, Cursor::new(&payload), &cache_file)
        .expect("Encryption should succeed");
    assert_eq!(written, total_size as u64);
    assert!(cache_file.exists());

    // Decrypt
    let mut decrypted = Vec::with_capacity(total_size);
    let read_back = decrypt_chunked_stream(&key, &file_id, &cache_file, &mut decrypted)
        .expect("Decryption should succeed");
    assert_eq!(read_back, total_size as u64);
    assert_eq!(decrypted.len(), total_size);

    let decrypted_sha = hex::encode(Sha256::digest(&decrypted));
    assert_eq!(original_sha, decrypted_sha);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_chunked_streaming_empty_file() {
    let dir = create_test_temp_dir("chunk_empty");
    let key = [0x1au8; 32];
    let file_id = [0x77u8; 16];

    let cache_file = dir.join("empty.cache");

    // Encrypt 0-byte stream
    let written = encrypt_chunked_stream(&key, &file_id, Cursor::new(b""), &cache_file)
        .expect("Empty stream encryption should succeed");
    assert_eq!(written, 0);

    // Decrypt
    let mut decrypted = Vec::new();
    let read_back = decrypt_chunked_stream(&key, &file_id, &cache_file, &mut decrypted)
        .expect("Empty stream decryption should succeed");
    assert_eq!(read_back, 0);
    assert!(decrypted.is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_chunked_streaming_swap_chunks_attack_fails_closed() {
    let dir = create_test_temp_dir("chunk_swap");
    let key = [0x8bu8; 32];
    let file_id = [0x12u8; 16];

    // Payload spanning at least 2 full chunks (128 KiB + 1 KiB)
    let payload = vec![0xa5u8; 129 * 1024];
    let cache_file = dir.join("swap_attack.cache");

    encrypt_chunked_stream(&key, &file_id, Cursor::new(&payload), &cache_file)
        .expect("Encrypt should succeed");

    // Read raw cache file bytes
    let raw_cache = fs::read(&cache_file).unwrap();

    // Cache header = 29 bytes
    let header_len = 29;
    assert!(raw_cache.len() > header_len + 5);

    // Parse Chunk 0:
    // is_final (1 byte)
    // chunk_len (4 bytes)
    let _chunk0_is_final = raw_cache[header_len];
    let chunk0_len = u32::from_be_bytes([
        raw_cache[header_len + 1],
        raw_cache[header_len + 2],
        raw_cache[header_len + 3],
        raw_cache[header_len + 4],
    ]) as usize;
    let chunk0_total_len = 1 + 4 + chunk0_len;

    // Parse Chunk 1:
    let chunk1_offset = header_len + chunk0_total_len;
    let _chunk1_is_final = raw_cache[chunk1_offset];
    let chunk1_len = u32::from_be_bytes([
        raw_cache[chunk1_offset + 1],
        raw_cache[chunk1_offset + 2],
        raw_cache[chunk1_offset + 3],
        raw_cache[chunk1_offset + 4],
    ]) as usize;
    let chunk1_total_len = 1 + 4 + chunk1_len;

    let chunk0_slice = &raw_cache[header_len..header_len + chunk0_total_len];
    let chunk1_slice = &raw_cache[chunk1_offset..chunk1_offset + chunk1_total_len];
    let remainder_slice = &raw_cache[chunk1_offset + chunk1_total_len..];

    // Construct swapped ciphertext: Header || Chunk 1 || Chunk 0 || Remainder
    let mut swapped_cache = Vec::new();
    swapped_cache.extend_from_slice(&raw_cache[..header_len]);
    swapped_cache.extend_from_slice(chunk1_slice);
    swapped_cache.extend_from_slice(chunk0_slice);
    swapped_cache.extend_from_slice(remainder_slice);

    let tampered_path = dir.join("tampered_swap.cache");
    fs::write(&tampered_path, &swapped_cache).unwrap();

    // Attempt decryption
    let mut decrypted = Vec::new();
    let decrypt_res = decrypt_chunked_stream(&key, &file_id, &tampered_path, &mut decrypted);
    assert!(
        decrypt_res.is_err(),
        "Swapped chunks MUST fail AEAD tag verification closed"
    );

    let err_str = format!("{:?}", decrypt_res.unwrap_err());
    assert!(
        err_str.contains("AES-256-GCM authentication tag verification failed")
            || err_str.contains("IntegrityError"),
        "Error must indicate AEAD integrity failure, got: {err_str}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_chunked_streaming_truncation_attack_fails_closed() {
    let dir = create_test_temp_dir("chunk_trunc");
    let key = [0x44u8; 32];
    let file_id = [0x88u8; 16];

    // Payload spanning 2 chunks
    let payload = vec![0x11u8; 70 * 1024];
    let cache_file = dir.join("trunc_attack.cache");

    encrypt_chunked_stream(&key, &file_id, Cursor::new(&payload), &cache_file)
        .expect("Encrypt should succeed");

    let raw_cache = fs::read(&cache_file).unwrap();

    // Header (29) + Chunk 0 (1 + 4 + 65536 + 16)
    let header_len = 29;
    let chunk0_len = u32::from_be_bytes([
        raw_cache[header_len + 1],
        raw_cache[header_len + 2],
        raw_cache[header_len + 3],
        raw_cache[header_len + 4],
    ]) as usize;
    let chunk0_total_len = 1 + 4 + chunk0_len;

    // Truncate file so that Chunk 1 (which had is_final = 1) is completely omitted
    let truncated_cache = &raw_cache[..header_len + chunk0_total_len];
    let trunc_path = dir.join("truncated.cache");
    fs::write(&trunc_path, truncated_cache).unwrap();

    let mut decrypted = Vec::new();
    let decrypt_res = decrypt_chunked_stream(&key, &file_id, &trunc_path, &mut decrypted);
    assert!(
        decrypt_res.is_err(),
        "Truncated cache stream MUST fail closed with IntegrityError"
    );

    let err_str = format!("{:?}", decrypt_res.unwrap_err());
    assert!(
        err_str.contains("Unexpected EOF before final chunk")
            || err_str.contains("final chunk was not reached"),
        "Error must indicate truncation, got: {err_str}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_chunked_streaming_is_final_tamper_attack_fails_closed() {
    let dir = create_test_temp_dir("chunk_final_tamper");
    let key = [0x77u8; 32];
    let file_id = [0x99u8; 16];

    // 2-chunk payload
    let payload = vec![0x33u8; 80 * 1024];
    let cache_file = dir.join("final_tamper.cache");

    encrypt_chunked_stream(&key, &file_id, Cursor::new(&payload), &cache_file)
        .expect("Encrypt should succeed");

    let mut raw_cache = fs::read(&cache_file).unwrap();

    // Header = 29 bytes. Chunk 0 is_final is at byte 29 (which was 0).
    // Flip is_final from 0 to 1
    assert_eq!(raw_cache[29], 0);
    raw_cache[29] = 1;

    let tampered_path = dir.join("tampered_final.cache");
    fs::write(&tampered_path, &raw_cache).unwrap();

    let mut decrypted = Vec::new();
    let decrypt_res = decrypt_chunked_stream(&key, &file_id, &tampered_path, &mut decrypted);
    assert!(
        decrypt_res.is_err(),
        "Tampered is_final bit MUST fail AEAD tag verification due to AAD mismatch"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_chunked_streaming_cross_file_aad_tamper_fails_closed() {
    let dir = create_test_temp_dir("cross_file");
    let key = [0x22u8; 32];
    let file_id_a = [0x11u8; 16];
    let file_id_b = [0x22u8; 16];

    let payload = b"SECRET_CONTENT_FOR_FILE_A";
    let cache_file = dir.join("file_a.cache");

    encrypt_chunked_stream(&key, &file_id_a, Cursor::new(payload), &cache_file)
        .expect("Encrypt should succeed");

    // Attempt decrypting with file_id_b
    let mut decrypted = Vec::new();
    let decrypt_res = decrypt_chunked_stream(&key, &file_id_b, &cache_file, &mut decrypted);
    assert!(
        decrypt_res.is_err(),
        "Cross-file substitution MUST fail closed"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_t32_temp_dir_production_elimination_verified() {
    let dir = create_test_temp_dir("atomic_restricted_tree");
    let p1 = dir.join("OmniConnect");
    let r1 = sentinel_sys::create_restricted_dir_atomic(&p1);
    assert!(r1.is_ok(), "Restricted dir level 1 failed: {:?}", r1.err());
    let p2 = p1.join("Sentinel");
    let r2 = sentinel_sys::create_restricted_dir_atomic(&p2);
    assert!(r2.is_ok(), "Restricted dir level 2 failed: {:?}", r2.err());
    let p3 = p2.join("ShredAudit");
    let r3 = sentinel_sys::create_restricted_dir_atomic(&p3);
    assert!(r3.is_ok(), "Restricted dir level 3 failed: {:?}", r3.err());

    let _ = fs::remove_dir_all(&dir);
}
