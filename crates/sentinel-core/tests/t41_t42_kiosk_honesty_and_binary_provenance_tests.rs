//! Behavioral & Adversarial Verification Suite for Master Security Hardening Plan v3
//! Sub-Phase 0.3 (`CSE-17`, `ADR-014`): `T42` — Honest Binary Provenance (`.dep-v0` vs Full Exe Hash).

use std::fs;
use std::path::PathBuf;

use sentinel_core::enterprise::kiosk::{
    compute_current_binary_provenance, extract_dep_v0_section_sha256, verify_kiosk_passport,
    AirGappedKioskManager, KioskConfig, KioskSanitizationPassport, PASSPORT_MANIFEST_FILENAME,
    PASSPORT_PUBKEY_FILENAME,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

/// Builds a minimal valid PE32+ binary image with one section named `section_name` carrying `payload`.
fn build_synthetic_pe(section_name: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    let pe_off: usize = 0x80;
    let opt_hdr_size: usize = 0xF0;
    let sec_table_off: usize = pe_off + 24 + opt_hdr_size;
    let raw_data_ptr: usize = 0x200;
    let mut img = vec![0u8; raw_data_ptr + payload.len()];

    // DOS header
    img[0..2].copy_from_slice(b"MZ");
    img[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());

    // PE signature + COFF header
    img[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_off + 4;
    img[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    img[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
    img[coff + 16..coff + 18].copy_from_slice(&(opt_hdr_size as u16).to_le_bytes());

    // Optional header magic (PE32+)
    img[coff + 20..coff + 22].copy_from_slice(&0x020Bu16.to_le_bytes());

    // Section table entry (40 bytes)
    img[sec_table_off..sec_table_off + 8].copy_from_slice(section_name);
    img[sec_table_off + 8..sec_table_off + 12]
        .copy_from_slice(&(payload.len() as u32).to_le_bytes()); // VirtualSize
    img[sec_table_off + 16..sec_table_off + 20]
        .copy_from_slice(&(payload.len() as u32).to_le_bytes()); // SizeOfRawData
    img[sec_table_off + 20..sec_table_off + 24]
        .copy_from_slice(&(raw_data_ptr as u32).to_le_bytes()); // PointerToRawData

    img[raw_data_ptr..raw_data_ptr + payload.len()].copy_from_slice(payload);
    img
}

/// Builds a minimal valid ELF64 little-endian image with `.shstrtab` and one custom section `section_name`.
fn build_synthetic_elf64(section_name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut shstrtab = Vec::new();
    shstrtab.push(0); // index 0 = ""
    let shstrtab_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");
    let custom_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(section_name);
    shstrtab.push(0);

    let shstrtab_off: usize = 64;
    let payload_off: usize = shstrtab_off + shstrtab.len();
    let shoff: usize = (payload_off + payload.len() + 7) & !7;
    let shentsize: usize = 64;
    let shnum: usize = 3; // 0: NULL, 1: .shstrtab, 2: custom

    let mut img = vec![0u8; shoff + shnum * shentsize];
    img[0..4].copy_from_slice(b"\x7fELF");
    img[4] = 2; // ELFCLASS64
    img[5] = 1; // ELFDATA2LSB
    img[6] = 1; // EV_CURRENT
    img[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    img[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
    img[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
    img[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx = 1

    img[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(&shstrtab);
    img[payload_off..payload_off + payload.len()].copy_from_slice(payload);

    // Section 1: .shstrtab
    let s1 = shoff + shentsize;
    img[s1..s1 + 4].copy_from_slice(&shstrtab_name_off.to_le_bytes());
    img[s1 + 24..s1 + 32].copy_from_slice(&(shstrtab_off as u64).to_le_bytes());
    img[s1 + 32..s1 + 40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());

    // Section 2: custom
    let s2 = shoff + 2 * shentsize;
    img[s2..s2 + 4].copy_from_slice(&custom_name_off.to_le_bytes());
    img[s2 + 24..s2 + 32].copy_from_slice(&(payload_off as u64).to_le_bytes());
    img[s2 + 32..s2 + 40].copy_from_slice(&(payload.len() as u64).to_le_bytes());

    img
}

#[test]
fn t42_passport_distinguishes_exe_sha256_from_real_dep_v0_section() {
    let dep_v0_payload = br#"{"packages":[{"name":"sentinel-core","version":"0.1.0"}]}"#;
    let expected_dep_v0_sha = hex::encode(Sha256::digest(dep_v0_payload));

    // 1. PE32+ with `.dep-v0` section returns exact section SHA-256 (not full PE SHA-256!)
    let pe_with_dep = build_synthetic_pe(b".dep-v0\0", dep_v0_payload);
    let full_pe_sha = hex::encode(Sha256::digest(&pe_with_dep));
    let extracted_pe = extract_dep_v0_section_sha256(&pe_with_dep)
        .expect("PE32+ with .dep-v0 section must return Some(sha256)");
    assert_eq!(extracted_pe, expected_dep_v0_sha);
    assert_ne!(
        extracted_pe, full_pe_sha,
        ".dep-v0 hash must hash the section bytes, never the full executable"
    );

    // 2. PE32+ without `.dep-v0` returns `None` honestly
    let pe_without_dep = build_synthetic_pe(b".rdata\0\0", dep_v0_payload);
    assert_eq!(
        extract_dep_v0_section_sha256(&pe_without_dep),
        None,
        "PE without .dep-v0 must return None"
    );

    // 3. ELF64 with `.dep-v0` section returns exact section SHA-256
    let elf_with_dep = build_synthetic_elf64(b".dep-v0", dep_v0_payload);
    let extracted_elf = extract_dep_v0_section_sha256(&elf_with_dep)
        .expect("ELF64 with .dep-v0 section must return Some(sha256)");
    assert_eq!(extracted_elf, expected_dep_v0_sha);

    // 4. ELF64 without `.dep-v0` returns `None`, and malformed/empty bytes return `None` without panicking
    let elf_without_dep = build_synthetic_elf64(b".rodata", dep_v0_payload);
    assert_eq!(extract_dep_v0_section_sha256(&elf_without_dep), None);
    assert_eq!(extract_dep_v0_section_sha256(b""), None);
    assert_eq!(extract_dep_v0_section_sha256(b"MZtruncated"), None);
    assert_eq!(extract_dep_v0_section_sha256(b"\x7fELFtruncated"), None);

    // 5. Live `compute_current_binary_provenance()` + `KioskSanitizationPassport` verification
    let (exe_sha, dep_v0_opt) = compute_current_binary_provenance();
    assert_eq!(
        exe_sha.len(),
        64,
        "binary_exe_sha256 must be 64-hex SHA-256"
    );
    if let Some(ref dep_sha) = dep_v0_opt {
        assert_ne!(
            dep_sha, &exe_sha,
            "binary_dep_v0_sha256 must never equal full binary_exe_sha256"
        );
    }

    let tmp = tempdir().expect("tempdir");
    let kiosk_dir = tmp.path().join("kiosk_t42");
    let export_dir = tmp.path().join("export_t42");
    let kiosk = AirGappedKioskManager::new(KioskConfig::default(), kiosk_dir);
    let batch = vec![(
        PathBuf::from("report.txt"),
        b"CLEAN_RECONSTRUCTED_TEXT_T42".to_vec(),
        "DEEP_CDR_RECONSTRUCTED:Text".to_string(),
    )];
    let passport = kiosk
        .export_sanitized_batch_with_passport(&export_dir, "USB-T42-01", "POL-T42", 9, &batch)
        .expect("emit passport");
    assert_eq!(passport.binary_exe_sha256, exe_sha);
    assert_eq!(passport.binary_dep_v0_sha256, dep_v0_opt);

    let pub_bytes = fs::read(export_dir.join(PASSPORT_PUBKEY_FILENAME)).expect("read pubkey");
    let verified = verify_kiosk_passport(&export_dir, Some(&pub_bytes)).expect("verify intact");
    assert_eq!(verified.binary_exe_sha256, exe_sha);
    assert_eq!(verified.binary_dep_v0_sha256, dep_v0_opt);

    // Tampering with `binary_dep_v0_sha256` (injecting a spoofed hash) MUST fail signature verification
    let manifest_path = export_dir.join(PASSPORT_MANIFEST_FILENAME);
    let mut spoofed: KioskSanitizationPassport =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest")).expect("parse");
    spoofed.binary_dep_v0_sha256 = Some("f".repeat(64));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&spoofed).expect("serialize"),
    )
    .expect("write spoofed manifest");
    let err = verify_kiosk_passport(&export_dir, Some(&pub_bytes))
        .expect_err("Tampered binary_dep_v0_sha256 must fail signature verification");
    assert!(err.contains("PASSPORT_SIGNATURE_INVALID"));
}
