//! 64 KiB framed chunked streaming AES-256-GCM cipher for ShadowCache (`CSE-07`, `CSE-10`).
//!
//! Format Specification:
//! - File Header (29 bytes):
//!   - `magic`: `[u8; 4]` = `*b"SC64"`
//!   - `version`: `u8` = 1
//!   - `salt`: `[u8; 8]`
//!   - `file_id`: `[u8; 16]`
//! - Per-Chunk Record:
//!   - `is_final`: `u8` (0 = intermediate chunk, 1 = final chunk)
//!   - `ciphertext_len`: `u32` (big-endian, = plaintext_len + 16 bytes AEAD tag)
//!   - `ciphertext`: `[u8; ciphertext_len]` (AES-256-GCM ciphertext + 16 bytes authentication tag)
//!
//! Cryptographic Invariants:
//! - Nonce (12 bytes): `salt[0..8] || seq_u32_be`
//! - AAD (17 bytes): `file_id[0..16] || is_final_u8`
//! - Bound: each plaintext chunk is strictly <= 64 KiB (`65536` bytes).
//! - Security Guarantees:
//!   - Swap Chunk 0 and Chunk 1: Sequence number in nonce mismatch triggers AEAD tag authentication error.
//!   - Swap chunks across different files: File ID in AAD triggers AEAD tag authentication error.
//!   - Truncate final chunk: Reader encounters EOF before `is_final == 1`, failing closed with `IntegrityError`.
//!   - Premature `is_final` bit flip: AAD mismatch triggers AEAD tag authentication error.
//!   - Memory complexity: Strict O(1), memory bounded by 64 KiB buffer during both encryption and decryption.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

pub const CACHE_MAGIC: &[u8; 4] = b"SC64";
pub const CACHE_VERSION: u8 = 1;
pub const CHUNK_PLAINTEXT_CAPACITY: usize = 65536; // 64 KiB
pub const AEAD_TAG_LEN: usize = 16;
pub const MAX_CIPHERTEXT_CHUNK_LEN: usize = CHUNK_PLAINTEXT_CAPACITY + AEAD_TAG_LEN;

#[derive(Debug, thiserror::Error)]
pub enum ChunkedCacheError {
    #[error("I/O error during chunked cache operation: {0}")]
    Io(#[from] io::Error),
    #[error("IntegrityError: {0}")]
    Integrity(String),
}

/// Encrypts input plaintext in 64 KiB chunks and writes to `dest_path` atomically with restricted DACL.
pub fn encrypt_chunked_stream(
    key_bytes: &[u8],
    file_id: &[u8; 16],
    mut reader: impl Read,
    dest_path: &Path,
) -> Result<u64, ChunkedCacheError> {
    if key_bytes.len() != 32 {
        return Err(ChunkedCacheError::Integrity(
            "Invalid key length (must be 32 bytes)".to_string(),
        ));
    }
    let mut out_file = sentinel_sys::create_restricted_file_handle_atomic(dest_path)
        .map_err(ChunkedCacheError::Io)?;

    let mut salt = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    // Write file header: magic (4) + version (1) + salt (8) + file_id (16) = 29 bytes
    out_file.write_all(CACHE_MAGIC)?;
    out_file.write_all(&[CACHE_VERSION])?;
    out_file.write_all(&salt)?;
    out_file.write_all(file_id)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let mut seq: u32 = 0;
    let mut total_plaintext_bytes: u64 = 0;

    let mut chunk_buf = vec![0u8; CHUNK_PLAINTEXT_CAPACITY];
    let mut next_buf = vec![0u8; CHUNK_PLAINTEXT_CAPACITY];

    // Read the first chunk
    let mut n_curr = read_full_or_eof(&mut reader, &mut chunk_buf)?;

    if n_curr == 0 {
        // Empty file: write 1 final chunk with 0 bytes
        let is_final = 1u8;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&salt);
        nonce_bytes[8..12].copy_from_slice(&seq.to_be_bytes());

        let mut aad = [0u8; 17];
        aad[..16].copy_from_slice(file_id);
        aad[16] = is_final;

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &[],
                    aad: &aad,
                },
            )
            .map_err(|e| ChunkedCacheError::Integrity(format!("Encryption failed: {e}")))?;

        out_file.write_all(&[is_final])?;
        out_file.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        out_file.write_all(&ciphertext)?;
        out_file.sync_all()?;
        return Ok(0);
    }

    loop {
        // Try reading next chunk to determine if current chunk is final
        let n_next = read_full_or_eof(&mut reader, &mut next_buf)?;
        let is_final = if n_next == 0 { 1u8 } else { 0u8 };

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&salt);
        nonce_bytes[8..12].copy_from_slice(&seq.to_be_bytes());

        let mut aad = [0u8; 17];
        aad[..16].copy_from_slice(file_id);
        aad[16] = is_final;

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &chunk_buf[..n_curr],
                    aad: &aad,
                },
            )
            .map_err(|e| ChunkedCacheError::Integrity(format!("Encryption failed: {e}")))?;

        out_file.write_all(&[is_final])?;
        out_file.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        out_file.write_all(&ciphertext)?;

        total_plaintext_bytes = total_plaintext_bytes.saturating_add(n_curr as u64);
        seq = seq.checked_add(1).ok_or_else(|| {
            ChunkedCacheError::Integrity("Chunk sequence number overflow".to_string())
        })?;

        if is_final == 1 {
            break;
        }

        // Swap buffers for next iteration
        std::mem::swap(&mut chunk_buf, &mut next_buf);
        n_curr = n_next;
    }

    out_file.sync_all()?;
    Ok(total_plaintext_bytes)
}

/// Decrypts a 64 KiB chunked stream from `src_path`, verifying each chunk's AEAD tag, sequence number,
/// and `is_final` flag, writing plaintext to `writer`.
pub fn decrypt_chunked_stream(
    key_bytes: &[u8],
    file_id: &[u8; 16],
    src_path: &Path,
    mut writer: impl Write,
) -> Result<u64, ChunkedCacheError> {
    if key_bytes.len() != 32 {
        return Err(ChunkedCacheError::Integrity(
            "Invalid key length (must be 32 bytes)".to_string(),
        ));
    }
    let mut in_file = File::open(src_path).map_err(ChunkedCacheError::Io)?;

    // Read header: 29 bytes
    let mut header = [0u8; 29];
    in_file
        .read_exact(&mut header)
        .map_err(|e| ChunkedCacheError::Integrity(format!("Failed reading cache header: {e}")))?;

    if &header[0..4] != CACHE_MAGIC {
        return Err(ChunkedCacheError::Integrity(
            "Invalid cache magic header (not SC64)".to_string(),
        ));
    }
    if header[4] != CACHE_VERSION {
        return Err(ChunkedCacheError::Integrity(format!(
            "Unsupported cache version: {}",
            header[4]
        )));
    }

    let mut salt = [0u8; 8];
    salt.copy_from_slice(&header[5..13]);

    let mut recorded_file_id = [0u8; 16];
    recorded_file_id.copy_from_slice(&header[13..29]);

    if &recorded_file_id != file_id {
        return Err(ChunkedCacheError::Integrity(
            "File ID mismatch in cache header".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let mut seq: u32 = 0;
    let mut total_decrypted_bytes: u64 = 0;
    let mut seen_final = false;

    let mut cipher_buf = vec![0u8; MAX_CIPHERTEXT_CHUNK_LEN];

    loop {
        let mut is_final_buf = [0u8; 1];
        match in_file.read_exact(&mut is_final_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                if !seen_final {
                    return Err(ChunkedCacheError::Integrity(
                        "Unexpected EOF before final chunk flag (truncation detected)".to_string(),
                    ));
                }
                break;
            }
            Err(e) => return Err(ChunkedCacheError::Io(e)),
        }

        let is_final = is_final_buf[0];
        if is_final > 1 {
            return Err(ChunkedCacheError::Integrity(format!(
                "Invalid is_final byte value: {is_final}"
            )));
        }

        let mut len_buf = [0u8; 4];
        in_file.read_exact(&mut len_buf).map_err(|e| {
            ChunkedCacheError::Integrity(format!("Unexpected EOF reading chunk length: {e}"))
        })?;
        let chunk_len = u32::from_be_bytes(len_buf) as usize;

        if !(AEAD_TAG_LEN..=MAX_CIPHERTEXT_CHUNK_LEN).contains(&chunk_len) {
            return Err(ChunkedCacheError::Integrity(format!(
                "Invalid chunk length {chunk_len} (bounds {AEAD_TAG_LEN}..={MAX_CIPHERTEXT_CHUNK_LEN})"
            )));
        }

        in_file
            .read_exact(&mut cipher_buf[..chunk_len])
            .map_err(|e| {
                ChunkedCacheError::Integrity(format!(
                    "Unexpected EOF reading chunk ciphertext: {e}"
                ))
            })?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&salt);
        nonce_bytes[8..12].copy_from_slice(&seq.to_be_bytes());

        let mut aad = [0u8; 17];
        aad[..16].copy_from_slice(file_id);
        aad[16] = is_final;

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &cipher_buf[..chunk_len],
                    aad: &aad,
                },
            )
            .map_err(|_| {
                ChunkedCacheError::Integrity(format!(
                    "AES-256-GCM authentication tag verification failed on chunk seq={seq}"
                ))
            })?;

        writer.write_all(&plaintext)?;
        total_decrypted_bytes = total_decrypted_bytes.saturating_add(plaintext.len() as u64);

        seq = seq.checked_add(1).ok_or_else(|| {
            ChunkedCacheError::Integrity("Chunk sequence number overflow".to_string())
        })?;

        if is_final == 1 {
            seen_final = true;
            // Verify no trailing garbage bytes after final chunk
            let mut trailing = [0u8; 1];
            if in_file.read(&mut trailing)? > 0 {
                return Err(ChunkedCacheError::Integrity(
                    "Extraneous trailing data detected after final chunk".to_string(),
                ));
            }
            break;
        }
    }

    if !seen_final {
        return Err(ChunkedCacheError::Integrity(
            "Incomplete chunk stream: final chunk was not reached".to_string(),
        ));
    }

    Ok(total_decrypted_bytes)
}

fn read_full_or_eof(mut reader: impl Read, mut buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                buf = &mut buf[n..];
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}
