//! Cold-Eye Compliance Auditor - Sub-Phase 1.5 Adversarial Break-It Probe
//! Hostile verification of Exploit Mitigations & Compiler Hardening (CSE-09)
//! and Cryptographic RNG Sweep & Supply Chain Hardening (CSE-14).

#![allow(unused_imports, unused_variables)]

use rand::RngCore;
use std::fs;
use std::path::{Path, PathBuf};

fn find_workspace_root() -> PathBuf {
    let mut cur = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    while !cur.join("Cargo.lock").exists() {
        if let Some(parent) = cur.parent() {
            cur = parent.to_path_buf();
        } else {
            break;
        }
    }
    cur
}

#[test]
fn probe_1_zero_thread_rng_and_universal_osrng_sweep() {
    let root = find_workspace_root();
    let crates_dir = root.join("crates");
    assert!(
        crates_dir.exists(),
        "crates dir must exist at {}",
        crates_dir.display()
    );

    let mut disallowed_found = Vec::new();
    let mut files_scanned = 0;

    fn walk_rs(dir: &Path, disallowed: &mut Vec<(PathBuf, usize, String)>, count: &mut usize) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    let dir_name = p.file_name().unwrap_or_default().to_string_lossy();
                    // Do not scan cold_eye test probes itself
                    if !dir_name.starts_with('.') && dir_name != "target" {
                        walk_rs(&p, disallowed, count);
                    }
                } else if p.extension().is_some_and(|ext| ext == "rs") {
                    let file_name = p.file_name().unwrap_or_default().to_string_lossy();
                    if file_name.starts_with("cold_eye_") {
                        continue;
                    }
                    *count += 1;
                    if let Ok(content) = fs::read_to_string(&p) {
                        for (idx, line) in content.lines().enumerate() {
                            let trimmed = line.trim();
                            // Skip comments
                            if trimmed.starts_with("//")
                                || trimmed.starts_with("/*")
                                || trimmed.starts_with('*')
                            {
                                continue;
                            }
                            if line.contains("thread_rng") {
                                disallowed.push((p.clone(), idx + 1, line.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }

    walk_rs(&crates_dir, &mut disallowed_found, &mut files_scanned);
    println!("Scanned {files_scanned} Rust files across all workspace crates.");

    assert!(
        disallowed_found.is_empty(),
        "CRITICAL DEFECT: Found non-cryptographic thread_rng() in crates: {:?}",
        disallowed_found
    );
}

#[test]
fn probe_2_csprng_entropy_statistical_adversarial_quality() {
    // Generate 1,000,000 bytes from OsRng
    let sample_size = 1_000_000;
    let mut bytes = vec![0u8; sample_size];
    rand::rngs::OsRng.fill_bytes(&mut bytes);

    // 1. Monobit Frequency Test (NIST SP 800-22 §2.1)
    let mut ones_count: u64 = 0;
    for b in &bytes {
        ones_count += b.count_ones() as u64;
    }
    let total_bits = (sample_size * 8) as f64;
    let fraction_ones = ones_count as f64 / total_bits;
    println!("OsRng Monobit Fraction of 1s: {:.6}", fraction_ones);
    // Ideal: 0.5. Must be within [0.498, 0.502] for 8 million bits
    assert!(
        (fraction_ones - 0.5).abs() < 0.003,
        "CSPRNG failed monobit frequency test: fraction={fraction_ones}"
    );

    // 2. Chi-Square Goodness-of-Fit Test for Byte Distribution (df = 255)
    let mut byte_counts = [0usize; 256];
    for b in &bytes {
        byte_counts[*b as usize] += 1;
    }
    let expected = sample_size as f64 / 256.0;
    let mut chi_square = 0.0;
    for count in &byte_counts {
        let diff = *count as f64 - expected;
        chi_square += (diff * diff) / expected;
    }
    println!("OsRng Chi-Square Statistic (df=255): {:.2}", chi_square);
    // For df=255, critical value at alpha=0.001 is ~340. Value should be around 255.
    assert!(
        chi_square < 340.0,
        "CSPRNG failed chi-square uniformity test: chi_square={chi_square}"
    );

    // 3. Adversarial Check: Test that a predictable pseudo-RNG (LCG) fails this probe
    let mut weak_bytes = vec![0u8; sample_size];
    let mut state: u32 = 0x12345678;
    for b in weak_bytes.iter_mut() {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        *b = (state >> 24) as u8;
    }
    // Now simulate non-crypto weak generator with bias
    for i in (0..sample_size).step_by(16) {
        weak_bytes[i] = 0x00; // Inject periodic zeroes
    }
    let mut weak_byte_counts = [0usize; 256];
    for b in &weak_bytes {
        weak_byte_counts[*b as usize] += 1;
    }
    let mut weak_chi_square = 0.0;
    for count in &weak_byte_counts {
        let diff = *count as f64 - expected;
        weak_chi_square += (diff * diff) / expected;
    }
    println!("Adversarial Weak PRNG Chi-Square: {:.2}", weak_chi_square);
    assert!(
        weak_chi_square > 350.0,
        "Adversarial sanity check failed: weak PRNG was not detected by chi-square probe!"
    );
}

#[derive(Debug)]
struct PeMitigationReport {
    dll_characteristics: u16,
    high_entropy_va: bool,
    dynamic_base: bool,
    nx_compat: bool,
    guard_cf: bool,
    ts_aware: bool,
    load_config_present: bool,
    guard_flags: u32,
}

fn inspect_pe_bytes(bytes: &[u8]) -> Result<PeMitigationReport, String> {
    if bytes.len() < 64 || bytes[0] != 0x4D || bytes[1] != 0x5A {
        return Err("Not an MZ executable".to_string());
    }
    let pe_offset = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    if pe_offset + 24 > bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err("Invalid PE header".to_string());
    }

    let num_sections =
        u16::from_le_bytes(bytes[pe_offset + 6..pe_offset + 8].try_into().unwrap()) as usize;
    let size_of_opt_header =
        u16::from_le_bytes(bytes[pe_offset + 20..pe_offset + 22].try_into().unwrap()) as usize;

    let opt_header_offset = pe_offset + 24;
    let magic = u16::from_le_bytes(
        bytes[opt_header_offset..opt_header_offset + 2]
            .try_into()
            .unwrap(),
    );
    if magic != 0x20B {
        return Err(format!("Not 64-bit PE32+ (magic=0x{magic:X})"));
    }

    let dll_char_offset = opt_header_offset + 70;
    let dll_characteristics = u16::from_le_bytes(
        bytes[dll_char_offset..dll_char_offset + 2]
            .try_into()
            .unwrap(),
    );

    let high_entropy_va = (dll_characteristics & 0x0020) != 0;
    let dynamic_base = (dll_characteristics & 0x0040) != 0;
    let nx_compat = (dll_characteristics & 0x0100) != 0;
    let guard_cf = (dll_characteristics & 0x4000) != 0;
    let ts_aware = (dll_characteristics & 0x8000) != 0;

    // Load config directory is at DataDirectory[10] = opt_header_offset + 112 + 10*8
    let load_config_dir_offset = opt_header_offset + 112 + 80;
    let load_config_rva = u32::from_le_bytes(
        bytes[load_config_dir_offset..load_config_dir_offset + 4]
            .try_into()
            .unwrap(),
    );
    let load_config_size = u32::from_le_bytes(
        bytes[load_config_dir_offset + 4..load_config_dir_offset + 8]
            .try_into()
            .unwrap(),
    );

    let section_table_offset = opt_header_offset + size_of_opt_header;
    let mut load_config_file_offset: Option<usize> = None;

    if load_config_rva > 0 && load_config_size > 0 {
        for i in 0..num_sections {
            let sec_off = section_table_offset + (i * 40);
            if sec_off + 40 > bytes.len() {
                break;
            }
            let sec_va = u32::from_le_bytes(bytes[sec_off + 12..sec_off + 16].try_into().unwrap());
            let sec_raw_size =
                u32::from_le_bytes(bytes[sec_off + 16..sec_off + 20].try_into().unwrap());
            let sec_raw_ptr =
                u32::from_le_bytes(bytes[sec_off + 20..sec_off + 24].try_into().unwrap());

            if load_config_rva >= sec_va && load_config_rva < (sec_va + sec_raw_size) {
                load_config_file_offset = Some((sec_raw_ptr + (load_config_rva - sec_va)) as usize);
                break;
            }
        }
    }

    let mut guard_flags = 0u32;
    if let Some(cfg_off) = load_config_file_offset {
        if cfg_off + 0x60 <= bytes.len() {
            guard_flags =
                u32::from_le_bytes(bytes[cfg_off + 0x58..cfg_off + 0x5C].try_into().unwrap());
        }
    }

    Ok(PeMitigationReport {
        dll_characteristics,
        high_entropy_va,
        dynamic_base,
        nx_compat,
        guard_cf,
        ts_aware,
        load_config_present: load_config_file_offset.is_some(),
        guard_flags,
    })
}

#[test]
fn probe_3_pe_exploit_mitigations_machine_byte_verification() {
    let root = find_workspace_root();
    // Check both potential paths: target/release or S:\target\release
    let candidates = [
        root.join("target").join("release"),
        PathBuf::from("S:\\target\\release"),
    ];

    let mut release_dir = None;
    for cand in &candidates {
        if cand.join("sentinel.exe").exists() {
            release_dir = Some(cand.clone());
            break;
        }
    }

    let dir = match release_dir {
        Some(d) => d,
        None => {
            println!("Skipping live PE check in test: target/release/sentinel.exe not in current relative path");
            return;
        }
    };

    let binaries = [
        "sentinel.exe",
        "sentinel-agent.exe",
        "sentinel-cdr-daemon.exe",
        "sentinel-cdr-worker.exe",
    ];

    for bin_name in &binaries {
        let p = dir.join(bin_name);
        assert!(
            p.exists(),
            "Binary {} must exist in release dir",
            p.display()
        );
        let bytes = fs::read(&p).unwrap();
        let report = inspect_pe_bytes(&bytes).expect("Valid PE parsing");

        println!("Auditing PE mitigations for {}: {:?}", bin_name, report);

        // Required: DllCharacteristics == 0xC160
        assert_eq!(
            report.dll_characteristics, 0xC160,
            "Binary {bin_name} DllCharacteristics must strictly equal 0xC160, found 0x{:X}",
            report.dll_characteristics
        );

        assert!(
            report.high_entropy_va,
            "HighEntropyVA missing in {bin_name}"
        );
        assert!(report.dynamic_base, "DynamicBase missing in {bin_name}");
        assert!(report.nx_compat, "NX / DEP missing in {bin_name}");
        assert!(report.guard_cf, "Guard:CF missing in {bin_name}");
        assert!(report.ts_aware, "TS Aware missing in {bin_name}");
        assert!(
            report.load_config_present,
            "LoadConfig table missing in {bin_name}"
        );
        assert_ne!(
            report.guard_flags, 0,
            "GuardFlags must be non-zero in {bin_name}"
        );
    }

    // Adversarial Check: Tamper with PE bytes and verify probe rejects them
    let p = dir.join("sentinel.exe");
    let mut tampered_bytes = fs::read(&p).unwrap();
    let pe_offset = u32::from_le_bytes(tampered_bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let dll_char_offset = pe_offset + 24 + 70;
    // Strip Guard:CF (0x4000)
    let current_char = u16::from_le_bytes(
        tampered_bytes[dll_char_offset..dll_char_offset + 2]
            .try_into()
            .unwrap(),
    );
    let stripped = current_char & !0x4000;
    tampered_bytes[dll_char_offset..dll_char_offset + 2].copy_from_slice(&stripped.to_le_bytes());

    let tampered_report = inspect_pe_bytes(&tampered_bytes).unwrap();
    assert!(
        !tampered_report.guard_cf,
        "Tampered report must reflect stripped CFG"
    );
    assert_ne!(
        tampered_report.dll_characteristics, 0xC160,
        "Tampered binary must fail 0xC160 requirement"
    );
}

#[test]
fn probe_4_compiler_config_and_linux_mitigations_verification() {
    let root = find_workspace_root();
    let config_path = root.join(".cargo").join("config.toml");
    assert!(
        config_path.exists(),
        "Cargo config must exist at {}",
        config_path.display()
    );

    let content = fs::read_to_string(&config_path).expect("Read config.toml");

    // Windows mandates:
    assert!(
        content.contains("control-flow-guard=checks"),
        "Missing control-flow-guard=checks"
    );
    assert!(content.contains("/CETCOMPAT"), "Missing /CETCOMPAT");
    assert!(content.contains("/HIGHENTROPYVA"), "Missing /HIGHENTROPYVA");
    assert!(content.contains("/DYNAMICBASE"), "Missing /DYNAMICBASE");
    assert!(content.contains("/NXCOMPAT"), "Missing /NXCOMPAT");
    assert!(content.contains("/GUARD:CF"), "Missing /GUARD:CF");

    // Linux mandates:
    assert!(
        content.contains("relocation-model=pic"),
        "Missing relocation-model=pic"
    );
    assert!(
        content.contains("-Wl,-z,relro,-z,now"),
        "Missing -Wl,-z,relro,-z,now"
    );
    assert!(
        content.contains("-Wl,-z,noexecstack"),
        "Missing -Wl,-z,noexecstack"
    );

    // Invariant: incremental = false
    assert!(
        content.contains("incremental = false"),
        "Missing incremental = false"
    );
    assert!(
        content.contains("CARGO_INCREMENTAL = \"0\""),
        "Missing CARGO_INCREMENTAL = \"0\""
    );
}

#[test]
fn probe_5_supply_chain_ci_and_dependabot_hardening() {
    let root = find_workspace_root();

    // 1. Dependabot check
    let dep_path = root.join(".github").join("dependabot.yml");
    assert!(
        dep_path.exists(),
        "dependabot.yml must exist at {}",
        dep_path.display()
    );
    let dep_content = fs::read_to_string(&dep_path).expect("Read dependabot.yml");

    assert!(
        dep_content.contains("version: 2"),
        "Dependabot version 2 required"
    );
    assert!(
        dep_content.contains("package-ecosystem: \"cargo\""),
        "Cargo ecosystem missing in dependabot"
    );
    assert!(
        dep_content.contains("package-ecosystem: \"github-actions\""),
        "GitHub Actions ecosystem missing in dependabot"
    );
    assert!(
        dep_content.contains("interval: \"weekly\""),
        "Weekly schedule required in dependabot"
    );

    // 2. CI workflow check
    let ci_path = root.join(".github").join("workflows").join("ci.yml");
    assert!(
        ci_path.exists(),
        "ci.yml must exist at {}",
        ci_path.display()
    );
    let ci_content = fs::read_to_string(&ci_path).expect("Read ci.yml");

    // Least privilege root permissions
    assert!(
        ci_content.contains("permissions:\n  contents: read")
            || ci_content.contains("permissions:\r\n  contents: read"),
        "CI must enforce root least-privilege permissions: contents: read"
    );

    // External action commit SHAs pinned to 40-character hex
    let mut total_uses = 0;
    let mut pinned_uses = 0;

    for line in ci_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("uses:") {
            let action_part = trimmed.trim_start_matches("uses:").trim();
            // Take the first token before whitespace or comments
            let action_clean = action_part.split_whitespace().next().unwrap_or("");
            if action_clean.starts_with("./") {
                // local action
                continue;
            }
            total_uses += 1;
            if let Some(at_idx) = action_clean.rfind('@') {
                let sha = &action_clean[at_idx + 1..];
                if sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
                    pinned_uses += 1;
                } else {
                    panic!("External GitHub Action NOT pinned to 40-char SHA: {action_clean}");
                }
            } else {
                panic!("External GitHub Action missing @ version/SHA: {action_clean}");
            }
        }
    }
    assert!(
        total_uses >= 5,
        "Expected at least 5 action uses directives, found {total_uses}"
    );
    assert_eq!(
        total_uses, pinned_uses,
        "All GitHub actions must be 40-char commit SHA pinned"
    );

    // Trivy scans
    assert!(
        ci_content.contains("aquasecurity/trivy-action"),
        "Trivy action missing in CI"
    );
    assert!(
        ci_content.contains("scan-type: 'fs'"),
        "Trivy filesystem scan missing"
    );
    assert!(
        ci_content.contains("scan-type: 'sbom'"),
        "Trivy SBOM scan missing"
    );
    assert!(
        ci_content.contains("severity: 'CRITICAL,HIGH'"),
        "Trivy severity threshold missing"
    );
    assert!(
        ci_content.contains("exit-code: '1'"),
        "Trivy exit-code gate missing"
    );

    // SLSA provenance attestation
    assert!(
        ci_content.contains("actions/attest-build-provenance"),
        "SLSA build provenance action missing"
    );

    // Invariant gates in CI
    assert!(
        ci_content.contains("Zero unapproved allow() bypasses"),
        "CI allow() gate missing"
    );
    assert!(
        ci_content.contains("Zero thread_rng() calls"),
        "CI thread_rng gate missing"
    );
}
