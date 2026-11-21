use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::{info, warn};
use uuid::Uuid;

use sentinel_sys::{
    ensure_not_symlink_or_reparse_point, flush_hardware_buffers, is_reparse_point_or_symlink,
    issue_file_level_trim, normalize_file_attributes, open_no_buffering_write_through,
    open_write_through, query_media_type, query_sector_alignment, query_sector_alignment_for_path,
    to_verbatim_path, AlignedSectorBuffer, MediaType,
};

use crate::enterprise::ledger::{AuditLedger, AuditSubsystem, SharedAuditLedger};

/// NIST SP 800-88 Rev. 2 sanitization outcome classification (`Sub-Phase 2.2`, `CSE-14`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Nist80088Rev2Category {
    /// Logical overwrite + TRIM (`NIST SP 800-88 Rev. 2` Clear; never claims physical flash Purge on wear-leveled media).
    #[default]
    Clear,
    /// Cryptographic Erase (`NIST SP 800-88 Rev. 2` Purge), reserved strictly for artifacts encrypted from inception
    /// under a strong CSPRNG DEK (`ShadowCache` / `.quar`) whose DEK has been cryptographically destroyed.
    CryptographicErasePurge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShredMethod {
    ClearMultiPass { passes: u8 },
    CryptoErase,
}

impl ShredMethod {
    pub const NIST_CLEAR_THREE_PASS: Self = Self::ClearMultiPass { passes: 3 };

    pub const fn default_clear() -> Self {
        Self::ClearMultiPass { passes: 3 }
    }
}

fn default_nist_standard_rev2() -> String {
    "NIST SP 800-88 Rev. 2".to_string()
}

/// Computes the authoritative `NIST SP 800-88 Rev. 2` sanitization classification and human-auditable
/// media-honesty label (`Sub-Phase 2.2`, `CSE-14`).
pub fn classify_nist_sp800_88_rev2(
    method: ShredMethod,
    media: MediaType,
) -> (Nist80088Rev2Category, bool, String) {
    match method {
        ShredMethod::ClearMultiPass { .. } => match media {
            MediaType::UsbFlash | MediaType::SsdOrFlash => (
                Nist80088Rev2Category::Clear,
                false,
                "NIST SP 800-88 Rev. 2 — Clear (NIST 800-88 Clear (logical) Overwrite + TRIM; Flash Wear-Leveling Caveat: Purge is not guaranteed on flash/SSD wear-leveling media without hardware Secure Erase or inception-encrypted DEK Cryptographic Erase)".to_string(),
            ),
            MediaType::Hdd | MediaType::UnknownOrVirtual => (
                Nist80088Rev2Category::Clear,
                false,
                "NIST SP 800-88 Rev. 2 — Clear (NIST 800-88 Clear (logical) Multi-Pass Overwrite + Flush — Note: NIST 800-88 Purge is not guaranteed on flash/SSD wear-leveling media without hardware Secure Erase or crypto-erase)".to_string(),
            ),
        },
        ShredMethod::CryptoErase => (
            Nist80088Rev2Category::CryptographicErasePurge,
            true,
            "NIST SP 800-88 Rev. 2 — Cryptographic Erase (Purge) (Inception-Encrypted Payload DEK Destroyed + Ciphertext Overwritten)".to_string(),
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShredReceipt {
    pub original_path: String,
    pub file_size_bytes: u64,
    pub sector_alignment_bytes: u32,
    pub passes_completed: u8,
    pub final_pass_sha256: String,
    pub hardware_buffers_flushed: bool,
    pub flush_succeeded: bool,
    pub mft_filename_scrambled: bool,
    pub actual_scramble_cycles: u8,
    pub rename_cycles_completed: u8,
    pub media_type: String,
    pub sanitization_level: String,
    #[serde(default = "default_nist_standard_rev2")]
    pub nist_standard: String,
    #[serde(default)]
    pub rev2_category: Nist80088Rev2Category,
    #[serde(default)]
    pub inception_encrypted_dek_destroyed: bool,
    pub verification_passed: bool,
    pub verify_read_ok: bool,
}

/// Cryptographic & Multi-Pass File Sanitizer (`BUG-CORE-06`, `Sub-Phase 2.2`, `CSE-14`)
///
/// Implements **NIST SP 800-88 Rev. 2** `Clear` (logical multi-pass overwrite with
/// sector-aligned `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH`,
/// `FSCTL_FILE_LEVEL_TRIM`, and `FlushFileBuffers`) and `Cryptographic Erase (Purge)`
/// (reserved strictly for destroying DEKs of inception-encrypted payloads such as
/// `ShadowCache` and `.quar`), with verbatim `\\?\` path support for reserved DOS device
/// names (`CON.txt`, `NUL.doc`, etc.) and strict refusal to follow symlinks or NTFS reparse points.
/// Destination ledger sink for `SecureShredder` sanitization receipts (`Sub-Phase 2.2`).
pub enum ShredLedgerSink<'a> {
    Shared(&'a SharedAuditLedger),
    Path(&'a Path),
    DefaultUnified,
}

/// Generates a cryptographically random lowercase hexadecimal filename of equal character length
/// to `original_name` (clamped to `1..=240`) to scrub residual NTFS `$MFT` / FAT directory entry
/// characters (`CSE-15`, `README.md §9 #5`). Pure hex `[0-9a-f]` never matches Windows DOS device names.
pub fn generate_equal_length_hex_scramble_name(original_name: &str) -> String {
    let target_len = original_name.chars().count().clamp(1, 240);
    let byte_len = target_len.div_ceil(2);
    let mut raw = vec![0u8; byte_len];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let mut out = hex::encode(raw);
    out.truncate(target_len);
    out
}

/// Validates that a `ShredReceipt` passed both cryptographic read-back verification and hardware
/// buffer flushing (`CSE-15`, Invariant `I6`). Returns `Err` if either gate failed.
pub fn validate_shred_receipt_fail_closed(receipt: &ShredReceipt) -> Result<(), String> {
    if !receipt.verification_passed || !receipt.flush_succeeded {
        return Err(format!(
            "SHRED_VERIFICATION_FAILED: verification_passed={}, flush_succeeded={} for '{}'",
            receipt.verification_passed, receipt.flush_succeeded, receipt.original_path
        ));
    }
    Ok(())
}

/// Streams fresh per-chunk `OsRng` CSPRNG bytes into `writer` up to `target_limit`, refreshing
/// `chunk_buf` on every write iteration so hardware-compressing SSD controllers cannot deduplicate
/// identical fill blocks (`CSE-15`). Stops cleanly with `Ok(written)` when the destination volume
/// reports out-of-space (`StorageFull` / `ENOSPC` / `ERROR_DISK_FULL`), and propagates any other I/O error.
pub fn write_non_repeating_csprng_chunks<W: Write>(
    writer: &mut W,
    target_limit: u64,
    chunk_buf: &mut [u8],
) -> Result<u64, std::io::Error> {
    if chunk_buf.is_empty() {
        return Ok(0);
    }
    let mut written: u64 = 0;
    while written < target_limit {
        let to_write = std::cmp::min(target_limit - written, chunk_buf.len() as u64) as usize;
        rand::rngs::OsRng.fill_bytes(&mut chunk_buf[..to_write]);
        match writer.write_all(&chunk_buf[..to_write]) {
            Ok(()) => {
                written += to_write as u64;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::StorageFull
                    || matches!(e.raw_os_error(), Some(28) | Some(112)) =>
            {
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(written)
}

pub struct SecureShredder;

impl SecureShredder {
    pub fn shred_file_with_shared_ledger(
        path: &Path,
        method: ShredMethod,
        shared_ledger: Option<&SharedAuditLedger>,
    ) -> Result<ShredReceipt, String> {
        Self::shred_file_with_media_hint(path, method, None, shared_ledger)
    }

    pub fn shred_file_with_media_hint(
        path: &Path,
        method: ShredMethod,
        media_override: Option<MediaType>,
        shared_ledger: Option<&SharedAuditLedger>,
    ) -> Result<ShredReceipt, String> {
        let sink = match shared_ledger {
            Some(sl) => ShredLedgerSink::Shared(sl),
            None => ShredLedgerSink::DefaultUnified,
        };
        Self::shred_file_to_sink(path, method, media_override, sink)
    }

    pub fn shred_file_to_sink(
        path: &Path,
        method: ShredMethod,
        media_override: Option<MediaType>,
        sink: ShredLedgerSink<'_>,
    ) -> Result<ShredReceipt, String> {
        // Refuse symlinks and NTFS reparse points before touching attributes or opening handles (`Critical #1`, Row 67)
        ensure_not_symlink_or_reparse_point(path).map_err(|e| {
            format!(
                "Refusing to shred symlink or reparse point '{}': {}",
                path.display(),
                e
            )
        })?;

        let verbatim_path = to_verbatim_path(path);
        let verbatim_exists = fs::symlink_metadata(&verbatim_path).is_ok();
        let raw_exists = fs::symlink_metadata(path).is_ok();
        if !verbatim_exists && !raw_exists {
            return Err(format!("Target file does not exist: {}", path.display()));
        }

        let target_path = if verbatim_exists {
            verbatim_path
        } else {
            path.to_path_buf()
        };

        let sym_meta = fs::symlink_metadata(&target_path)
            .map_err(|e| format!("Failed reading symlink_metadata: {e}"))?;
        if is_reparse_point_or_symlink(&sym_meta) {
            return Err(format!(
                "Refusing to shred symlink or NTFS reparse point: {}",
                path.display()
            ));
        }

        let original_path_str = path.to_string_lossy().to_string();

        // 1. Clear READONLY / HIDDEN / SYSTEM attributes via safe FFI wrapper
        normalize_file_attributes(&target_path)
            .map_err(|e| format!("Failed normalizing file attributes: {e}"))?;

        let metadata = fs::symlink_metadata(&target_path)
            .map_err(|e| format!("Failed reading file metadata: {e}"))?;
        let file_size = metadata.len();
        let detected_media = media_override.unwrap_or_else(|| query_media_type(&target_path));
        let sector_alignment = query_sector_alignment_for_path(&target_path, None).max(512);

        let effective_passes = match method {
            ShredMethod::ClearMultiPass { passes } => passes.max(3),
            ShredMethod::CryptoErase => 1,
        };

        let mut all_flushes_ok = true;
        let mut final_pass_sha256 = String::new();
        let mut verification_passed = true;

        let mut aligned_buf = Box::new(AlignedSectorBuffer::new());
        let chunk_capacity = aligned_buf.data.len(); // 65536 (16 * 4096)

        // Try sector-aligned `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH` first (`Row 55`),
        // padding the final partial sector to `sector_alignment`. Fall back to `open_write_through`
        // if the filesystem rejects unbuffered I/O (e.g. MFT-resident small files on NTFS).
        let sector_u64 = sector_alignment as u64;
        let padded_size = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(sector_u64) * sector_u64
        };

        let mut unbuffered_completed = false;
        if padded_size > 0 {
            if let Ok(mut nb_file) = open_no_buffering_write_through(&target_path) {
                let actual_sector = query_sector_alignment(&nb_file).max(sector_alignment) as u64;
                let nb_padded_size = file_size.div_ceil(actual_sector) * actual_sector;
                let mut nb_ok = true;

                for pass in 1..=effective_passes {
                    if nb_file.seek(SeekFrom::Start(0)).is_err() {
                        nb_ok = false;
                        break;
                    }
                    let mut remaining = nb_padded_size;
                    let mut pass_hasher = Sha256::new();

                    while remaining > 0 {
                        let to_write = std::cmp::min(remaining, chunk_capacity as u64) as usize;
                        if pass == effective_passes {
                            rand::rngs::OsRng.fill_bytes(&mut aligned_buf.data[..to_write]);
                        } else if pass % 2 == 1 {
                            aligned_buf.data[..to_write].fill(0x00);
                        } else {
                            aligned_buf.data[..to_write].fill(0xFF);
                        }

                        if nb_file.write_all(&aligned_buf.data[..to_write]).is_err() {
                            nb_ok = false;
                            break;
                        }
                        if pass == effective_passes {
                            pass_hasher.update(&aligned_buf.data[..to_write]);
                        }
                        remaining -= to_write as u64;
                    }

                    if !nb_ok {
                        break;
                    }

                    let flushed = flush_hardware_buffers(&nb_file);
                    all_flushes_ok = all_flushes_ok && flushed;

                    if pass == effective_passes {
                        final_pass_sha256 = hex::encode(pass_hasher.finalize());
                    }
                }

                if nb_ok {
                    if nb_file.seek(SeekFrom::Start(0)).is_ok() {
                        let mut verify_hasher = Sha256::new();
                        let mut verify_remaining = nb_padded_size;
                        while verify_remaining > 0 {
                            let to_read =
                                std::cmp::min(verify_remaining, chunk_capacity as u64) as usize;
                            match nb_file.read_exact(&mut aligned_buf.data[..to_read]) {
                                Ok(()) => {
                                    verify_hasher.update(&aligned_buf.data[..to_read]);
                                    verify_remaining -= to_read as u64;
                                }
                                Err(_) => {
                                    verification_passed = false;
                                    break;
                                }
                            }
                        }
                        if verification_passed {
                            let verify_hex = hex::encode(verify_hasher.finalize());
                            verification_passed = verify_hex == final_pass_sha256;
                        }
                    } else {
                        verification_passed = false;
                    }

                    let _ = issue_file_level_trim(&nb_file, nb_padded_size);
                    unbuffered_completed = true;
                }
            }
        }

        if !unbuffered_completed {
            all_flushes_ok = true;
            verification_passed = true;
            let mut file = open_write_through(&target_path).map_err(|e| {
                format!("Failed opening file with write-through flags for shredding: {e}")
            })?;

            for pass in 1..=effective_passes {
                file.seek(SeekFrom::Start(0))
                    .map_err(|e| format!("Seek failed on pass {pass}: {e}"))?;

                let mut remaining = file_size;
                let mut pass_hasher = Sha256::new();

                while remaining > 0 {
                    let to_write = std::cmp::min(remaining, chunk_capacity as u64) as usize;

                    if pass == effective_passes {
                        rand::rngs::OsRng.fill_bytes(&mut aligned_buf.data[..to_write]);
                    } else if pass % 2 == 1 {
                        aligned_buf.data[..to_write].fill(0x00);
                    } else {
                        aligned_buf.data[..to_write].fill(0xFF);
                    }

                    file.write_all(&aligned_buf.data[..to_write])
                        .map_err(|e| format!("Write failed on pass {pass}: {e}"))?;

                    if pass == effective_passes {
                        pass_hasher.update(&aligned_buf.data[..to_write]);
                    }

                    remaining -= to_write as u64;
                }

                let flushed = flush_hardware_buffers(&file);
                all_flushes_ok = all_flushes_ok && flushed;

                if pass == effective_passes {
                    final_pass_sha256 = hex::encode(pass_hasher.finalize());
                }
            }

            if file_size > 0 {
                file.seek(SeekFrom::Start(0))
                    .map_err(|e| format!("Verification seek failed: {e}"))?;
                let mut verify_hasher = Sha256::new();
                let mut verify_remaining = file_size;
                while verify_remaining > 0 {
                    let to_read = std::cmp::min(verify_remaining, chunk_capacity as u64) as usize;
                    match file.read_exact(&mut aligned_buf.data[..to_read]) {
                        Ok(()) => {
                            verify_hasher.update(&aligned_buf.data[..to_read]);
                            verify_remaining -= to_read as u64;
                        }
                        Err(_) => {
                            verification_passed = false;
                            break;
                        }
                    }
                }
                if verification_passed {
                    let verify_hex = hex::encode(verify_hasher.finalize());
                    verification_passed = verify_hex == final_pass_sha256;
                }
            } else {
                let empty_hash = Sha256::digest([]);
                final_pass_sha256 = hex::encode(empty_hash);
            }

            let _ = issue_file_level_trim(&file, file_size);
        }

        // MFT / Directory Entry Filename Scrambling BEFORE truncation & unlink (`BUG-CORE-06` #4, `CSE-15`).
        // Uses random hex filenames of equal length to scrub residual filename characters in `$MFT` / FAT slots.
        let mut current_path = target_path.clone();
        let mut actual_scramble_cycles = 0u8;
        let orig_file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "000000000000".to_string());

        if let Some(parent) = target_path.parent() {
            for cycle in 0..3u8 {
                let mut renamed = false;
                for attempt in 0..16u8 {
                    let random_name = if attempt < 12 {
                        generate_equal_length_hex_scramble_name(&orig_file_name)
                    } else {
                        // Fallback widening only if an extremely short name collided repeatedly
                        format!("{}{}", &Uuid::new_v4().simple().to_string()[..12], cycle)
                    };
                    let next_path = parent.join(random_name);
                    if next_path == current_path || fs::symlink_metadata(&next_path).is_ok() {
                        continue;
                    }
                    if fs::rename(&current_path, &next_path).is_ok() {
                        current_path = next_path;
                        actual_scramble_cycles += 1;
                        renamed = true;
                        break;
                    }
                }
                if !renamed {
                    warn!(
                        "MFT filename scramble rename failed on cycle {} for {}",
                        cycle, original_path_str
                    );
                    break;
                }
            }
        }

        // Truncate cluster allocation to 0 bytes after hash verification and filename scrambling (`Row 61`, `CSE-15`)
        {
            let trunc_file = open_write_through(&current_path).map_err(|e| {
                format!("Failed reopening '{original_path_str}' for zero-length truncation: {e}")
            })?;
            trunc_file
                .set_len(0)
                .map_err(|e| format!("Failed truncating '{original_path_str}' to 0 bytes: {e}"))?;
            let flushed_after_trunc = flush_hardware_buffers(&trunc_file);
            all_flushes_ok = all_flushes_ok && flushed_after_trunc;
        }

        // Unlink the final scrambled path
        fs::remove_file(&current_path).map_err(|e| {
            format!(
                "Failed unlinking shredded file {}: {}",
                current_path.display(),
                e
            )
        })?;

        let (rev2_category, inception_encrypted_dek_destroyed, sanitization_level) =
            classify_nist_sp800_88_rev2(method, detected_media);

        let media_type_label = format!("{:?} — {}", detected_media, detected_media.label());

        info!(
            "Shred complete for '{}' ({} bytes, {} passes, sector: {}B, media: {}, level: {})",
            original_path_str,
            file_size,
            effective_passes,
            sector_alignment,
            media_type_label,
            sanitization_level
        );

        let receipt = ShredReceipt {
            original_path: original_path_str,
            file_size_bytes: file_size,
            sector_alignment_bytes: sector_alignment,
            passes_completed: effective_passes,
            final_pass_sha256,
            hardware_buffers_flushed: all_flushes_ok,
            flush_succeeded: all_flushes_ok,
            mft_filename_scrambled: actual_scramble_cycles > 0,
            actual_scramble_cycles,
            rename_cycles_completed: actual_scramble_cycles,
            media_type: media_type_label,
            sanitization_level,
            nist_standard: default_nist_standard_rev2(),
            rev2_category,
            inception_encrypted_dek_destroyed,
            verification_passed,
            verify_read_ok: verification_passed,
        };

        Self::finalize_and_record_shred_receipt(sink, "SHRED_RECEIPT", receipt)
    }

    /// Persists a `ShredReceipt` to `sink` (tagging failed verification/flush as
    /// `"SHRED_VERIFICATION_FAILED"`) and fails closed via `validate_shred_receipt_fail_closed` (`CSE-15`, `I6`).
    pub fn finalize_and_record_shred_receipt(
        sink: ShredLedgerSink<'_>,
        success_event: &str,
        receipt: ShredReceipt,
    ) -> Result<ShredReceipt, String> {
        let ledger_event_type = if receipt.verification_passed && receipt.flush_succeeded {
            success_event
        } else {
            "SHRED_VERIFICATION_FAILED"
        };

        match sink {
            ShredLedgerSink::Shared(sl) => {
                Self::record_shred_receipt_to_shared_ledger(sl, ledger_event_type, &receipt)?;
            }
            ShredLedgerSink::Path(lp) => {
                Self::record_shred_receipt_to_ledger(lp, ledger_event_type, &receipt)?;
            }
            ShredLedgerSink::DefaultUnified => {
                Self::record_shred_receipt_to_ledger(
                    &default_shred_ledger_path(),
                    ledger_event_type,
                    &receipt,
                )?;
            }
        }
        validate_shred_receipt_fail_closed(&receipt)?;
        Ok(receipt)
    }

    pub fn shred_file(path: &Path, method: ShredMethod) -> Result<ShredReceipt, String> {
        Self::shred_file_to_sink(path, method, None, ShredLedgerSink::DefaultUnified)
    }

    pub fn shred_file_with_ledger(
        path: &Path,
        method: ShredMethod,
        ledger_path: &Path,
    ) -> Result<ShredReceipt, String> {
        Self::shred_file_to_sink(path, method, None, ShredLedgerSink::Path(ledger_path))
    }

    /// Produces a privacy-redacted JSON payload for `AuditLedger` where raw user/device
    /// `original_path` PII is replaced by an HMAC-SHA256 `path_token` keyed by the ledger's
    /// OS-sealed privacy key (`CEA-DEFECT-06`, GDPR/DPDP compliance).
    pub fn redacted_receipt_json(
        ledger: &AuditLedger,
        receipt: &ShredReceipt,
    ) -> Result<serde_json::Value, String> {
        let path_token = ledger.tokenize_path(Path::new(&receipt.original_path))?;
        let mut payload = serde_json::to_value(receipt)
            .map_err(|e| format!("Failed serializing ShredReceipt for AuditLedger: {e}"))?;
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("original_path");
            obj.insert(
                "path_token".to_string(),
                serde_json::Value::String(path_token),
            );
        }
        Ok(payload)
    }

    pub fn record_shred_receipt_to_shared_ledger(
        shared_ledger: &SharedAuditLedger,
        event_type: &str,
        receipt: &ShredReceipt,
    ) -> Result<(), String> {
        let mut guard = shared_ledger
            .lock()
            .map_err(|e| format!("SharedAuditLedger lock poisoned: {e}"))?;
        let payload = Self::redacted_receipt_json(&guard, receipt)?;
        guard.append_subsystem_event(AuditSubsystem::SecureShredder, event_type, payload)?;
        Ok(())
    }

    fn record_shred_receipt_to_ledger(
        ledger_path: &Path,
        event_type: &str,
        receipt: &ShredReceipt,
    ) -> Result<(), String> {
        static SHRED_LEDGER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = SHRED_LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut ledger = AuditLedger::open_result(ledger_path)?;
        let payload = Self::redacted_receipt_json(&ledger, receipt)?;
        ledger.append_subsystem_event(AuditSubsystem::SecureShredder, event_type, payload)?;
        Ok(())
    }

    pub fn shred_file_with_passes(path: &Path, passes: u8) -> Result<ShredReceipt, String> {
        Self::shred_file(path, ShredMethod::ClearMultiPass { passes })
    }

    pub fn shred_file_with_method(
        path: &Path,
        method: ShredMethod,
    ) -> Result<ShredReceipt, String> {
        Self::shred_file(path, method)
    }

    /// Surgically overwrites and unlinks an NTFS Alternate Data Stream (`host_path:stream_name`)
    /// without harming the primary `$DATA` stream of `host_path` (`BUG-CORE-06` #7).
    pub fn shred_ntfs_stream_with_shared_ledger(
        host_path: &Path,
        stream_name: &str,
        shared_ledger: Option<&SharedAuditLedger>,
    ) -> Result<ShredReceipt, String> {
        let sink = match shared_ledger {
            Some(sl) => ShredLedgerSink::Shared(sl),
            None => ShredLedgerSink::DefaultUnified,
        };
        Self::shred_ntfs_stream_to_sink(host_path, stream_name, sink)
    }

    pub fn shred_ntfs_stream_with_ledger(
        host_path: &Path,
        stream_name: &str,
        ledger_path: &Path,
    ) -> Result<ShredReceipt, String> {
        Self::shred_ntfs_stream_to_sink(host_path, stream_name, ShredLedgerSink::Path(ledger_path))
    }

    pub fn shred_ntfs_stream_to_sink(
        host_path: &Path,
        stream_name: &str,
        sink: ShredLedgerSink<'_>,
    ) -> Result<ShredReceipt, String> {
        ensure_not_symlink_or_reparse_point(host_path).map_err(|e| {
            format!(
                "Refusing NTFS ADS shred on symlink or reparse point '{}': {}",
                host_path.display(),
                e
            )
        })?;

        let clean_stream = stream_name
            .trim_start_matches(':')
            .trim_end_matches(":$DATA");
        if clean_stream.is_empty() {
            return Err("Empty NTFS Alternate Data Stream name".to_string());
        }

        let verbatim_host = to_verbatim_path(host_path);
        let base_host = if fs::symlink_metadata(&verbatim_host).is_ok() {
            verbatim_host
        } else {
            host_path.to_path_buf()
        };

        let ads_path_str = format!("{}:{}", base_host.display(), clean_stream);
        let ads_path = Path::new(&ads_path_str);
        let display_ads = format!("{}:{}", host_path.display(), clean_stream);

        let metadata = fs::metadata(ads_path)
            .map_err(|e| format!("Failed querying NTFS ADS '{display_ads}': {e}"))?;
        let stream_size = metadata.len();
        let detected_media = query_media_type(&base_host);
        let sector_alignment = query_sector_alignment_for_path(&base_host, None).max(512);

        let passes = 3u8;
        let mut all_flushes_ok = true;
        let mut final_pass_sha256 = String::new();
        let mut verification_passed = true;

        {
            let mut stream_file = open_write_through(ads_path).map_err(|e| {
                format!("Failed opening NTFS ADS '{display_ads}' for write-through shredding: {e}")
            })?;

            let mut aligned_buf = Box::new(AlignedSectorBuffer::new());
            let chunk_size = aligned_buf.data.len();

            for pass in 1..=passes {
                stream_file
                    .seek(SeekFrom::Start(0))
                    .map_err(|e| format!("ADS seek error on pass {pass}: {e}"))?;

                let mut remaining = stream_size;
                let mut hasher = Sha256::new();

                while remaining > 0 {
                    let to_write = std::cmp::min(remaining, chunk_size as u64) as usize;
                    match pass {
                        1 => aligned_buf.data[..to_write].fill(0x00),
                        2 => aligned_buf.data[..to_write].fill(0xFF),
                        _ => rand::rngs::OsRng.fill_bytes(&mut aligned_buf.data[..to_write]),
                    }
                    stream_file
                        .write_all(&aligned_buf.data[..to_write])
                        .map_err(|e| format!("ADS write error on pass {pass}: {e}"))?;
                    if pass == passes {
                        hasher.update(&aligned_buf.data[..to_write]);
                    }
                    remaining -= to_write as u64;
                }

                let flushed = flush_hardware_buffers(&stream_file);
                all_flushes_ok = all_flushes_ok && flushed;

                if pass == passes {
                    final_pass_sha256 = hex::encode(hasher.finalize());
                }
            }

            if stream_size > 0 {
                stream_file
                    .seek(SeekFrom::Start(0))
                    .map_err(|e| format!("ADS verification seek failed: {e}"))?;
                let mut verify_hasher = Sha256::new();
                let mut rem = stream_size;
                while rem > 0 {
                    let to_read = std::cmp::min(rem, chunk_size as u64) as usize;
                    if stream_file
                        .read_exact(&mut aligned_buf.data[..to_read])
                        .is_ok()
                    {
                        verify_hasher.update(&aligned_buf.data[..to_read]);
                        rem -= to_read as u64;
                    } else {
                        verification_passed = false;
                        break;
                    }
                }
                if verification_passed {
                    verification_passed =
                        hex::encode(verify_hasher.finalize()) == final_pass_sha256;
                }
            } else {
                final_pass_sha256 = hex::encode(Sha256::digest([]));
            }

            stream_file.set_len(0).map_err(|e| {
                format!("Failed truncating NTFS ADS '{display_ads}' to 0 bytes: {e}")
            })?;
            all_flushes_ok = all_flushes_ok && flush_hardware_buffers(&stream_file);
        }

        // Unlink only the Alternate Data Stream; host file remains untouched
        fs::remove_file(ads_path)
            .map_err(|e| format!("Failed unlinking NTFS ADS '{display_ads}': {e}"))?;

        let media_type_label = format!("{:?} — {}", detected_media, detected_media.label());

        info!(
            "Surgically shredded NTFS ADS '{}' ({} bytes)",
            display_ads, stream_size
        );

        let receipt = ShredReceipt {
            original_path: display_ads,
            file_size_bytes: stream_size,
            sector_alignment_bytes: sector_alignment,
            passes_completed: passes,
            final_pass_sha256,
            hardware_buffers_flushed: all_flushes_ok,
            flush_succeeded: all_flushes_ok,
            mft_filename_scrambled: false,
            actual_scramble_cycles: 0,
            rename_cycles_completed: 0,
            media_type: media_type_label,
            sanitization_level: "NIST SP 800-88 Rev. 2 — Clear (NIST 800-88 Clear (logical ADS)) — Note: Purge is not guaranteed on flash/SSD wear-leveling media".to_string(),
            nist_standard: default_nist_standard_rev2(),
            rev2_category: Nist80088Rev2Category::Clear,
            inception_encrypted_dek_destroyed: false,
            verification_passed,
            verify_read_ok: verification_passed,
        };

        Self::finalize_and_record_shred_receipt(sink, "SHRED_ADS_RECEIPT", receipt)
    }

    pub fn shred_ntfs_stream(host_path: &Path, stream_name: &str) -> Result<ShredReceipt, String> {
        Self::shred_ntfs_stream_with_shared_ledger(host_path, stream_name, None)
    }

    /// Best-effort unallocated free-space fill (`--fill-free-space`, Master Plan v2 §1.2, `CSE-15`).
    /// Generates fresh per-chunk `OsRng` CSPRNG data on every write iteration to defeat SSD controller
    /// block deduplication/compression. Note: On flash media, wear-leveling controllers remap blocks,
    /// so this does not reach controller spare blocks (Honest Limit L2).
    pub fn fill_free_space(target_dir: &Path, max_fill_bytes: u64) -> Result<u64, String> {
        ensure_not_symlink_or_reparse_point(target_dir).map_err(|e| {
            format!(
                "Refusing free-space fill on symlink or reparse point '{}': {}",
                target_dir.display(),
                e
            )
        })?;
        let balloon_path = target_dir.join(format!(
            ".sentinel_freespace_{}.balloon",
            Uuid::new_v4().simple()
        ));
        let target_limit = if max_fill_bytes == 0 {
            u64::MAX
        } else {
            max_fill_bytes
        };
        let mut opts = fs::OpenOptions::new();
        opts.create_new(true).read(true).write(true);
        let mut file = opts
            .open(to_verbatim_path(&balloon_path))
            .map_err(|e| format!("Failed creating free-space balloon file: {e}"))?;

        let mut aligned_chunk = Box::new(AlignedSectorBuffer::new());
        let write_res =
            write_non_repeating_csprng_chunks(&mut file, target_limit, &mut aligned_chunk.data);
        let flush_ok = flush_hardware_buffers(&file);
        drop(file);
        let remove_res = fs::remove_file(to_verbatim_path(&balloon_path))
            .or_else(|_| fs::remove_file(&balloon_path));
        let written = write_res.map_err(|e| format!("Free-space fill write failed: {e}"))?;
        remove_res.map_err(|e| format!("Failed removing free-space balloon file: {e}"))?;
        if !flush_ok {
            return Err(
                "SHRED_VERIFICATION_FAILED: Hardware buffer flush failed after free-space fill"
                    .to_string(),
            );
        }
        Ok(written)
    }
}

fn default_shred_ledger_path() -> std::path::PathBuf {
    if let Ok(custom) = std::env::var("SENTINEL_SHRED_LEDGER_PATH") {
        let pb = std::path::PathBuf::from(custom);
        if let Some(parent) = pb.parent() {
            let _ = sentinel_sys::create_restricted_dir_atomic(parent);
        }
        return pb;
    }

    crate::enterprise::ledger::default_unified_ledger_path()
}
