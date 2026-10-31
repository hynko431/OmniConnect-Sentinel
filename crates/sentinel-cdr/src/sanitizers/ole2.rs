use std::collections::HashSet;

use crate::error::{CdrError, Result};
use crate::policy::{ResourceBudget, SanitizationPolicy};
use crate::sanitizers::DisarmReportItem;

pub const OLE2_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const FREESECT: u32 = 0xFFFF_FFFF;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FATSECT: u32 = 0xFFFF_FFFD;
const DIFSECT: u32 = 0xFFFF_FFFC;

pub struct Ole2Sanitizer;

impl Ole2Sanitizer {
    /// Inspects and disarms legacy OLE2 Compound File Binary (`.doc`, `.xls`, `.ppt`) containers (Phase 2.6, Row 134).
    ///
    /// Parses the MS-CFB header, DIFAT, FAT, MiniFAT, and 128-byte Directory Entries.
    /// When `policy.strip_office_macros` or `policy.strip_office_ole_objects` is enabled,
    /// walks the FAT / MiniFAT sector chain of every macro/OLE stream (`Macros`, `VBA`, `_VBA_PROJECT`,
    /// `dir`, `ObjPool`, `Package`, `Ole10Native`, `CONTENTS`), zeroes out all data sectors belonging
    /// to that stream, frees its FAT/MiniFAT chain entries (`0xFFFFFFFF`), and zeroes the 128-byte directory entry.
    pub fn sanitize(
        input: &[u8],
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        let mut budget = ResourceBudget::from_policy(policy);
        Self::sanitize_with_budget(input, policy, &mut budget)
    }

    pub fn sanitize_with_budget(
        input: &[u8],
        policy: &SanitizationPolicy,
        budget: &mut ResourceBudget,
    ) -> Result<(Vec<u8>, Vec<DisarmReportItem>)> {
        if input.len() < 512 || input[..8] != OLE2_MAGIC {
            return Err(CdrError::ParserCorruption(
                "Invalid OLE2 Compound File Binary header".to_string(),
            ));
        }
        if input.len() as u64 > policy.max_decompressed_bytes {
            return Err(CdrError::ResourceLimitExceeded(
                "OLE2 container exceeds max_decompressed_bytes".to_string(),
            ));
        }
        budget.check_deadline()?;
        budget.charge_bytes(input.len() as u64)?;

        let sector_shift = u16::from_le_bytes([input[30], input[31]]) as usize;
        if sector_shift != 9 && sector_shift != 12 {
            return Err(CdrError::ParserCorruption(format!(
                "Unsupported OLE2 sector shift: {}",
                sector_shift
            )));
        }
        let sector_size = 1usize << sector_shift;
        let mini_sector_shift = u16::from_le_bytes([input[32], input[33]]) as usize;
        let mini_sector_size = if (4..=12).contains(&mini_sector_shift) {
            1usize << mini_sector_shift
        } else {
            64usize
        };
        let mini_stream_cutoff =
            u32::from_le_bytes([input[56], input[57], input[58], input[59]]) as u64;
        let first_minifat_sec =
            u32::from_le_bytes([input[60], input[61], input[62], input[63]]);
        let first_difat_sec =
            u32::from_le_bytes([input[68], input[69], input[70], input[71]]);
        let num_difat_secs =
            u32::from_le_bytes([input[72], input[73], input[74], input[75]]) as usize;

        let mut output = input.to_vec();
        let mut reports = Vec::new();

        // 1. Collect FAT sector IDs from header DIFAT[0..109] and any chained DIFAT sectors
        let fat_sector_ids = Self::collect_fat_sectors(&output, sector_size, first_difat_sec, num_difat_secs);

        // 2. Locate Root Entry (obj_type == 5) to resolve MiniStream sectors if needed
        let mut root_start_sec = ENDOFCHAIN;
        for chunk_offset in (512..output.len()).step_by(128) {
            if chunk_offset + 128 > output.len() {
                break;
            }
            let entry = &output[chunk_offset..chunk_offset + 128];
            if entry[66] == 5 {
                root_start_sec =
                    u32::from_le_bytes([entry[116], entry[117], entry[118], entry[119]]);
                break;
            }
        }
        let root_ministream_sectors = if root_start_sec < DIFSECT {
            Self::follow_chain(&output, &fat_sector_ids, sector_size, root_start_sec)
        } else {
            Vec::new()
        };
        let minifat_sector_ids = if first_minifat_sec < DIFSECT {
            Self::follow_chain(&output, &fat_sector_ids, sector_size, first_minifat_sec)
        } else {
            Vec::new()
        };

        // 3. Scan 128-byte aligned blocks for CFB Directory Entries and wipe both stream sectors and directory entries
        for chunk_offset in (512..output.len()).step_by(128) {
            if chunk_offset + 128 > output.len() {
                break;
            }
            budget.check_deadline()?;
            let entry = &output[chunk_offset..chunk_offset + 128];
            let name_len = u16::from_le_bytes([entry[64], entry[65]]) as usize;
            let obj_type = entry[66];

            // Valid CFB directory entry types: 1 = Storage, 2 = Stream, 5 = Root
            if !matches!(obj_type, 1 | 2 | 5)
                || name_len < 2
                || name_len > 64
                || (name_len % 2 != 0)
            {
                continue;
            }

            let utf16_chars: Vec<u16> = entry[..name_len - 2]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            if utf16_chars.iter().any(|&c| c == 0 || c < 0x20) {
                continue;
            }
            let name = String::from_utf16_lossy(&utf16_chars);
            let name_lower = name.to_ascii_lowercase();

            let is_macro_entry = Self::is_macro_entry_name(&name_lower);
            let is_ole_package = Self::is_ole_package_name(&name_lower);

            if (policy.strip_office_macros && is_macro_entry)
                || (policy.strip_office_ole_objects && is_ole_package)
            {
                budget.charge_object()?;
                let start_sec =
                    u32::from_le_bytes([entry[116], entry[117], entry[118], entry[119]]);
                let raw_size = u64::from_le_bytes([
                    entry[120], entry[121], entry[122], entry[123], entry[124], entry[125],
                    entry[126], entry[127],
                ]);
                let stream_size = if sector_shift == 9 {
                    raw_size & 0xFFFF_FFFF
                } else {
                    raw_size
                };

                // Wipe stream data sectors via FAT chain or MiniFAT chain (`Row 134`)
                if obj_type == 2 && start_sec < DIFSECT {
                    let use_ministream = stream_size > 0
                        && stream_size < mini_stream_cutoff
                        && !minifat_sector_ids.is_empty()
                        && !root_ministream_sectors.is_empty();

                    if use_ministream {
                        Self::wipe_ministream_chain(
                            &mut output,
                            &minifat_sector_ids,
                            &root_ministream_sectors,
                            sector_size,
                            mini_sector_size,
                            start_sec,
                        );
                    } else {
                        Self::wipe_regular_fat_chain(
                            &mut output,
                            &fat_sector_ids,
                            sector_size,
                            start_sec,
                        );
                    }
                }

                // Zero out the entire 128-byte directory entry and set sibling/child links to NOSTREAM (0xFFFFFFFF)
                output[chunk_offset..chunk_offset + 128].fill(0);
                output[chunk_offset + 68..chunk_offset + 72]
                    .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
                output[chunk_offset + 72..chunk_offset + 76]
                    .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
                output[chunk_offset + 76..chunk_offset + 80]
                    .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

                reports.push(DisarmReportItem::new(
                    if is_macro_entry {
                        "OLE2_VBA_STORAGE"
                    } else {
                        "OLE2_EMBEDDED_PACKAGE"
                    },
                    format!("CFB_Directory/{}", name),
                    "WIPED_STREAM_SECTORS_AND_DIRECTORY",
                ));
            }
        }

        Ok((output, reports))
    }

    pub fn is_macro_entry_name(name_lower: &str) -> bool {
        matches!(
            name_lower,
            "macros"
                | "vba"
                | "_vba_project"
                | "_vba_project_cur"
                | "dir"
                | "module1"
                | "thisdocument"
                | "thisworkbook"
        )
    }

    pub fn is_ole_package_name(name_lower: &str) -> bool {
        matches!(
            name_lower,
            "objpool" | "package" | "ole10native" | "\u{0001}ole10native" | "contents"
        )
    }

    /// Used by `CdrEngine::verify_sanitized_output` to confirm no active macro or OLE package directory
    /// entries remain in the sanitized CFB output (`Row 110, Row 134`).
    pub fn has_residual_active_streams(bytes: &[u8], policy: &SanitizationPolicy) -> bool {
        if bytes.len() < 512 || bytes[..8] != OLE2_MAGIC {
            return true;
        }
        for chunk_offset in (512..bytes.len()).step_by(128) {
            if chunk_offset + 128 > bytes.len() {
                break;
            }
            let entry = &bytes[chunk_offset..chunk_offset + 128];
            let name_len = u16::from_le_bytes([entry[64], entry[65]]) as usize;
            let obj_type = entry[66];
            if !matches!(obj_type, 1 | 2 | 5)
                || name_len < 2
                || name_len > 64
                || (name_len % 2 != 0)
            {
                continue;
            }
            let utf16_chars: Vec<u16> = entry[..name_len - 2]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            if utf16_chars.iter().any(|&c| c == 0 || c < 0x20) {
                continue;
            }
            let name_lower = String::from_utf16_lossy(&utf16_chars).to_ascii_lowercase();
            if (policy.strip_office_macros && Self::is_macro_entry_name(&name_lower))
                || (policy.strip_office_ole_objects && Self::is_ole_package_name(&name_lower))
            {
                return true;
            }
        }
        false
    }

    fn sector_offset(sec_id: u32, sector_size: usize, total_len: usize) -> Option<usize> {
        // Standard MS-CFB offset: `(sec_id + 1) * sector_size`, with fallback to `512 + sec_id * sector_size`
        // for v4 files with a 512-byte unpadded header in synthetic tests.
        let standard = (sec_id as usize).checked_add(1)?.checked_mul(sector_size)?;
        if standard + sector_size <= total_len {
            Some(standard)
        } else {
            let unpadded = 512usize.checked_add((sec_id as usize).checked_mul(sector_size)?)?;
            if unpadded + sector_size <= total_len {
                Some(unpadded)
            } else {
                None
            }
        }
    }

    fn collect_fat_sectors(
        bytes: &[u8],
        sector_size: usize,
        first_difat_sec: u32,
        num_difat_secs: usize,
    ) -> Vec<u32> {
        let mut fat_secs = Vec::new();
        for off in (76..512).step_by(4) {
            let s = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
            if s < DIFSECT {
                fat_secs.push(s);
            }
        }
        let mut difat_sec = first_difat_sec;
        let mut visited = HashSet::new();
        let entries_per_difat = (sector_size / 4).saturating_sub(1);
        for _ in 0..num_difat_secs.min(1024) {
            if difat_sec >= DIFSECT || !visited.insert(difat_sec) {
                break;
            }
            let Some(base) = Self::sector_offset(difat_sec, sector_size, bytes.len()) else {
                break;
            };
            for i in 0..entries_per_difat {
                let pos = base + i * 4;
                let s = u32::from_le_bytes([
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                ]);
                if s < DIFSECT {
                    fat_secs.push(s);
                }
            }
            let next_pos = base + entries_per_difat * 4;
            difat_sec = u32::from_le_bytes([
                bytes[next_pos],
                bytes[next_pos + 1],
                bytes[next_pos + 2],
                bytes[next_pos + 3],
            ]);
        }
        fat_secs
    }

    fn read_and_clear_table_entry(
        output: &mut [u8],
        table_sector_ids: &[u32],
        sector_size: usize,
        index: u32,
        clear: bool,
    ) -> Option<u32> {
        let entries_per_sector = sector_size / 4;
        if entries_per_sector == 0 {
            return None;
        }
        let table_sec_idx = (index as usize) / entries_per_sector;
        let slot_in_sec = (index as usize) % entries_per_sector;
        let &table_sec_id = table_sector_ids.get(table_sec_idx)?;
        let sec_base = Self::sector_offset(table_sec_id, sector_size, output.len())?;
        let entry_offset = sec_base + slot_in_sec * 4;
        if entry_offset + 4 > output.len() {
            return None;
        }
        let next = u32::from_le_bytes([
            output[entry_offset],
            output[entry_offset + 1],
            output[entry_offset + 2],
            output[entry_offset + 3],
        ]);
        if clear {
            output[entry_offset..entry_offset + 4].copy_from_slice(&FREESECT.to_le_bytes());
        }
        Some(next)
    }

    fn follow_chain(
        output: &[u8],
        fat_sector_ids: &[u32],
        sector_size: usize,
        start_sec: u32,
    ) -> Vec<u32> {
        let entries_per_sector = sector_size / 4;
        if entries_per_sector == 0 {
            return Vec::new();
        }
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut curr = start_sec;
        while curr < DIFSECT && visited.insert(curr) && chain.len() < 65_536 {
            chain.push(curr);
            let table_sec_idx = (curr as usize) / entries_per_sector;
            let slot_in_sec = (curr as usize) % entries_per_sector;
            let Some(&table_sec_id) = fat_sector_ids.get(table_sec_idx) else {
                break;
            };
            let Some(sec_base) = Self::sector_offset(table_sec_id, sector_size, output.len()) else {
                break;
            };
            let entry_offset = sec_base + slot_in_sec * 4;
            if entry_offset + 4 > output.len() {
                break;
            }
            curr = u32::from_le_bytes([
                output[entry_offset],
                output[entry_offset + 1],
                output[entry_offset + 2],
                output[entry_offset + 3],
            ]);
        }
        chain
    }

    fn wipe_regular_fat_chain(
        output: &mut [u8],
        fat_sector_ids: &[u32],
        sector_size: usize,
        start_sec: u32,
    ) {
        let mut visited = HashSet::new();
        let mut curr = start_sec;
        while curr < DIFSECT && visited.insert(curr) && visited.len() <= 65_536 {
            if let Some(sec_off) = Self::sector_offset(curr, sector_size, output.len()) {
                output[sec_off..sec_off + sector_size].fill(0);
            }
            match Self::read_and_clear_table_entry(output, fat_sector_ids, sector_size, curr, true) {
                Some(next) if next < DIFSECT && next != FATSECT => curr = next,
                _ => break,
            }
        }
    }

    fn wipe_ministream_chain(
        output: &mut [u8],
        minifat_sector_ids: &[u32],
        root_ministream_sectors: &[u32],
        sector_size: usize,
        mini_sector_size: usize,
        start_mini_sec: u32,
    ) {
        let mini_per_regular = sector_size / mini_sector_size.max(1);
        if mini_per_regular == 0 {
            return;
        }
        let mut visited = HashSet::new();
        let mut curr = start_mini_sec;
        while curr < DIFSECT && visited.insert(curr) && visited.len() <= 65_536 {
            let reg_idx = (curr as usize) / mini_per_regular;
            let mini_slot = (curr as usize) % mini_per_regular;
            if let Some(&reg_sec_id) = root_ministream_sectors.get(reg_idx) {
                if let Some(reg_off) = Self::sector_offset(reg_sec_id, sector_size, output.len()) {
                    let mini_off = reg_off + mini_slot * mini_sector_size;
                    if mini_off + mini_sector_size <= output.len() {
                        output[mini_off..mini_off + mini_sector_size].fill(0);
                    }
                }
            }
            match Self::read_and_clear_table_entry(
                output,
                minifat_sector_ids,
                sector_size,
                curr,
                true,
            ) {
                Some(next) if next < DIFSECT => curr = next,
                _ => break,
            }
        }
    }
}

