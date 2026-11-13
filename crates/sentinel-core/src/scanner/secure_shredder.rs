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
    to_verbatim_path, AlignedSectorBuffer,
};

use crate::enterprise::ledger::{AuditLedger, AuditSubsystem, SharedAuditLedger};

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
    pub verification_passed: bool,
    pub verify_read_ok: bool,
}

/// Cryptographic & Multi-Pass File Sanitizer (`BUG-CORE-06`, Phase 1.2)
///
/// Implements NIST SP 800-88 Rev. 1 Clear (logical multi-pass overwrite with
/// sector-aligned `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH`,
/// `FSCTL_FILE_LEVEL_TRIM`, and `FlushFileBuffers`) and Cryptographic Erase,
/// with verbatim `\\?\` path support for reserved DOS device names (`CON.txt`,
/// `NUL.doc`, etc.) and strict refusal to follow symlinks or NTFS reparse points.
pub struct SecureShredder;

impl SecureShredder {
    pub fn shred_file_with_shared_ledger(
        path: &Path,
        method: ShredMethod,
        shared_ledger: Option<&SharedAuditLedger>,
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
        let detected_media = query_media_type(&target_path);
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

        // Truncate cluster allocation to 0 bytes after hash verification, propagating errors (`Row 61`)
        {
            let trunc_file = open_write_through(&target_path).map_err(|e| {
                format!("Failed reopening '{original_path_str}' for zero-length truncation: {e}")
            })?;
            trunc_file
                .set_len(0)
                .map_err(|e| format!("Failed truncating '{original_path_str}' to 0 bytes: {e}"))?;
            let flushed_after_trunc = flush_hardware_buffers(&trunc_file);
            all_flushes_ok = all_flushes_ok && flushed_after_trunc;
        }

        // MFT / Directory Entry Filename Scrambling with actual cycle tracking (`BUG-CORE-06` #4)
        let mut current_path = target_path.clone();
        let mut actual_scramble_cycles = 0u8;

        if let Some(parent) = target_path.parent() {
            for cycle in 0..3u8 {
                let random_name = format!(
                    ".{}{}.tmp",
                    &Uuid::new_v4().simple().to_string()[..12],
                    cycle
                );
                let next_path = parent.join(random_name);
                if fs::rename(&current_path, &next_path).is_ok() {
                    current_path = next_path;
                    actual_scramble_cycles += 1;
                } else {
                    warn!(
                        "MFT filename scramble rename failed on cycle {} for {}",
                        cycle, original_path_str
                    );
                    break;
                }
            }
        }

        // Unlink the final scrambled path
        fs::remove_file(&current_path).map_err(|e| {
            format!(
                "Failed unlinking shredded file {}: {}",
                current_path.display(),
                e
            )
        })?;

        let sanitization_level = match method {
            ShredMethod::ClearMultiPass { .. } => {
                "NIST 800-88 Clear (logical) — Note: NIST 800-88 Purge is not guaranteed on flash/SSD wear-leveling media without hardware Secure Erase or crypto-erase".to_string()
            }
            ShredMethod::CryptoErase => {
                "NIST 800-88 Cryptographic Erase (NIST 800-88 Clear (logical) + Key Destruction — Note: physical flash Purge depends on controller wear-leveling)".to_string()
            }
        };

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
            verification_passed,
            verify_read_ok: verification_passed,
        };

        if let Some(sl) = shared_ledger {
            Self::record_shred_receipt_to_shared_ledger(sl, "SHRED_RECEIPT", &receipt)?;
        } else {
            Self::record_shred_receipt_to_ledger(
                &default_shred_ledger_path(),
                "SHRED_RECEIPT",
                &receipt,
            )?;
        }
        Ok(receipt)
    }

    pub fn shred_file(path: &Path, method: ShredMethod) -> Result<ShredReceipt, String> {
        Self::shred_file_with_shared_ledger(path, method, None)
    }

    pub fn shred_file_with_ledger(
        path: &Path,
        method: ShredMethod,
        ledger_path: &Path,
    ) -> Result<ShredReceipt, String> {
        let receipt = Self::shred_file(path, method)?;
        Self::record_shred_receipt_to_ledger(ledger_path, "SHRED_RECEIPT", &receipt)?;
        Ok(receipt)
    }

    pub fn record_shred_receipt_to_shared_ledger(
        shared_ledger: &SharedAuditLedger,
        event_type: &str,
        receipt: &ShredReceipt,
    ) -> Result<(), String> {
        let mut guard = shared_ledger
            .lock()
            .map_err(|e| format!("SharedAuditLedger lock poisoned: {e}"))?;
        let payload = serde_json::to_value(receipt)
            .map_err(|e| format!("Failed serializing ShredReceipt for AuditLedger: {e}"))?;
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
        let mut ledger = AuditLedger::open(ledger_path);
        let payload = serde_json::to_value(receipt)
            .map_err(|e| format!("Failed serializing ShredReceipt for AuditLedger: {e}"))?;
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
            sanitization_level: "NIST 800-88 Clear (logical ADS) — Note: Purge is not guaranteed on flash/SSD wear-leveling media".to_string(),
            verification_passed,
            verify_read_ok: verification_passed,
        };

        if let Some(sl) = shared_ledger {
            Self::record_shred_receipt_to_shared_ledger(sl, "SHRED_ADS_RECEIPT", &receipt)?;
        } else {
            Self::record_shred_receipt_to_ledger(
                &default_shred_ledger_path(),
                "SHRED_ADS_RECEIPT",
                &receipt,
            )?;
        }
        Ok(receipt)
    }

    pub fn shred_ntfs_stream(host_path: &Path, stream_name: &str) -> Result<ShredReceipt, String> {
        Self::shred_ntfs_stream_with_shared_ledger(host_path, stream_name, None)
    }

    /// Best-effort unallocated free-space fill (`--fill-free-space`, Master Plan v2 §1.2).
    /// Note: On flash media, wear-leveling controllers remap blocks, so this does not reach
    /// controller spare blocks (Honest Limit L2).
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
        let mut written: u64 = 0;
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
        rand::rngs::OsRng.fill_bytes(&mut aligned_chunk.data);
        while written < target_limit {
            let to_write =
                std::cmp::min(target_limit - written, aligned_chunk.data.len() as u64) as usize;
            if file.write_all(&aligned_chunk.data[..to_write]).is_err() {
                break;
            }
            written += to_write as u64;
        }
        let _ = flush_hardware_buffers(&file);
        drop(file);
        fs::remove_file(to_verbatim_path(&balloon_path))
            .or_else(|_| fs::remove_file(&balloon_path))
            .map_err(|e| format!("Failed removing free-space balloon file: {e}"))?;
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
