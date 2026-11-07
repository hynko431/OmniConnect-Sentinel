use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Instant;

use sentinel_sys::{sign_ecdsa_p256_with_private_blob, verify_ecdsa_p256_digest};

use crate::enterprise::ledger::AuditLedger;
use crate::error::{DegradationEvent, SentinelError};
use crate::scanner::content_scanner::ContentScanner;

/// Default embedded YARA rule definitions compiled at startup (`Rows 154, 186`).
pub const DEFAULT_YARA_RULES_SOURCE: &str = r#"
rule YARA_EICAR_STANDARD_ANTIVIRUS_TEST {
    meta:
        description = "EICAR Standard Anti-Virus Test File signature"
        requires_pe = "false"
        min_matches = "1"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        all of them
}

rule YARA_CREDENTIAL_DUMPER_MIMIKATZ {
    meta:
        description = "Mimikatz LSASS credential extraction module indicators"
        requires_pe = "false"
        min_matches = "2"
    strings:
        $s1 = "sekurlsa::logonpasswords"
        $s2 = "lsadump::sam"
        $s3 = "privilege::debug"
        $s4 = "gentilkiwi"
    condition:
        2 of them
}

rule YARA_PE_PROCESS_HOLLOWING_INJECTOR {
    meta:
        description = "PE binary importing full process-hollowing API chain (VirtualAllocEx + WriteProcessMemory + NtUnmapViewOfSection/CreateRemoteThread)"
        requires_pe = "true"
        min_matches = "3"
    strings:
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
        $a4 = "NtUnmapViewOfSection"
        $a5 = "SetThreadContext"
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule YARA_REFLECTIVE_DLL_LOADER {
    meta:
        description = "In-memory Reflective DLL Injection export stub"
        requires_pe = "true"
        min_matches = "2"
    strings:
        $r1 = "ReflectiveLoader"
        $r2 = "VirtualAlloc"
        $r3 = "FlushInstructionCache"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
"#;

/// Known-threat SHA-256 intelligence table (`Rows 156, 229`).
pub const KNOWN_THREAT_SHA256_TABLE: &[([u8; 32], &str, &str)] = &[(
    // SHA-256 of standard 68-byte EICAR test string
    [
        0x27, 0x5a, 0x02, 0x1b, 0xbf, 0xb6, 0x48, 0x9e, 0x54, 0xd4, 0x71, 0x89, 0x9f, 0x7d, 0xb9,
        0xd1, 0x66, 0x3f, 0xc6, 0x95, 0xec, 0x2f, 0xe2, 0xa2, 0xc4, 0x53, 0x8a, 0xab, 0xf6, 0x51,
        0xfd, 0x0f,
    ],
    "INTEL_SHA256_EICAR_TEST_PAYLOAD",
    "Known SHA-256 threat intelligence match: EICAR test signature",
)];

/// Fast 2048-bit (32 x u64) Bloom Filter for O(1) SHA-256 threat-intelligence pre-screening (`Row 229`).
#[derive(Debug, Clone)]
pub struct ThreatIntelBloomFilter {
    bits: [u64; 32],
    known_hashes: Vec<([u8; 32], String, String)>,
}

impl Default for ThreatIntelBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelBloomFilter {
    pub fn new() -> Self {
        let mut filter = Self {
            bits: [0u64; 32],
            known_hashes: Vec::new(),
        };
        for &(digest, rule_id, desc) in KNOWN_THREAT_SHA256_TABLE {
            filter.insert_digest(digest, rule_id, desc);
        }
        filter
    }

    pub fn insert_digest(
        &mut self,
        digest: [u8; 32],
        rule_id: impl Into<String>,
        description: impl Into<String>,
    ) {
        for &bit_idx in &Self::bloom_indices(&digest) {
            let word = (bit_idx / 64) as usize;
            let bit = bit_idx % 64;
            self.bits[word] |= 1u64 << bit;
        }
        self.known_hashes
            .push((digest, rule_id.into(), description.into()));
    }

    pub fn lookup(&self, digest: &[u8; 32]) -> Option<(String, String)> {
        for &bit_idx in &Self::bloom_indices(digest) {
            let word = (bit_idx / 64) as usize;
            let bit = bit_idx % 64;
            if (self.bits[word] & (1u64 << bit)) == 0 {
                return None;
            }
        }
        for (known, id, desc) in &self.known_hashes {
            if known == digest {
                return Some((id.clone(), desc.clone()));
            }
        }
        None
    }

    fn bloom_indices(digest: &[u8; 32]) -> [u16; 4] {
        let h0 = u16::from_le_bytes([digest[0], digest[1]]) & 2047;
        let h1 = u16::from_le_bytes([digest[2], digest[3]]) & 2047;
        let h2 = u16::from_le_bytes([digest[4], digest[5]]) & 2047;
        let h3 = u16::from_le_bytes([digest[6], digest[7]]) & 2047;
        [h0, h1, h2, h3]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_ptr: u32,
    pub raw_data_size: u32,
    pub characteristics: u32,
    pub entropy: f32,
    pub is_writable_executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeStructureAnalysis {
    pub is_pe64: bool,
    pub entry_point_rva: u32,
    pub entry_point_in_last_section: bool,
    pub sections: Vec<PeSectionInfo>,
    pub imported_dlls: Vec<String>,
    pub imported_functions: Vec<String>,
    pub has_rmnet_section: bool,
    pub has_wx_section: bool,
    pub has_high_entropy_executable_section: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfStructureAnalysis {
    pub is_64bit: bool,
    pub entry_point: u64,
    pub has_rwx_segment: bool,
    pub program_header_count: u16,
    pub section_header_count: u16,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub matched: bool,
    pub rule_name: Option<String>,
    pub threat_Details: Option<String>,
    pub scan_duration_micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicYaraRule {
    pub id: String,
    pub description: String,
    pub required_markers_hex: Vec<String>,
    pub min_matches: usize,
    pub requires_pe_header: bool,
}

/// Cryptographically Signed YARA Rule Pack (`Row 186`, Master Plan v2 §3.3 & §4.4)
///
/// Signs the canonical rule pack payload (`pack_id`, `version`, `rules`) with an asymmetric
/// ECDSA P-256 keypair and enforces monotonic versioning (`pack.version > current_version`)
/// to block rule downgrade attacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRulePack {
    pub pack_id: String,
    pub version: u32,
    pub rules: Vec<DynamicYaraRule>,
    pub signature_hex: String,
    pub signer_public_key_hex: String,
}

impl SignedRulePack {
    pub fn signing_digest(
        pack_id: &str,
        version: u32,
        rules: &[DynamicYaraRule],
    ) -> Result<[u8; 32], String> {
        let rules_json = serde_json::to_vec(rules)
            .map_err(|e| format!("Failed serializing YARA rules for digest: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(b"SENTINEL-YARA-RULEPACK-V2:");
        hasher.update(pack_id.as_bytes());
        hasher.update(b"|");
        hasher.update(&version.to_le_bytes());
        hasher.update(b"|");
        hasher.update(&rules_json);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    pub fn sign(
        pack_id: impl Into<String>,
        version: u32,
        rules: Vec<DynamicYaraRule>,
        private_key_blob: &[u8],
        public_key_blob: &[u8],
    ) -> Result<Self, String> {
        let pack_id = pack_id.into();
        let digest = Self::signing_digest(&pack_id, version, &rules)?;
        let sig_bytes = sign_ecdsa_p256_with_private_blob(private_key_blob, &digest)
            .map_err(|e| format!("Failed signing YARA rule pack with ECDSA P-256: {}", e))?;
        Ok(Self {
            pack_id,
            version,
            rules,
            signature_hex: hex::encode(sig_bytes),
            signer_public_key_hex: hex::encode(public_key_blob),
        })
    }

    pub fn verify_signature(&self, trusted_public_key: &[u8]) -> Result<(), SentinelError> {
        let digest = Self::signing_digest(&self.pack_id, self.version, &self.rules)
            .map_err(SentinelError::PolicySignatureInvalid)?;
        let sig_bytes = hex::decode(&self.signature_hex).map_err(|e| {
            SentinelError::PolicySignatureInvalid(format!(
                "Invalid rule pack signature hex encoding: {}",
                e
            ))
        })?;
        let verified =
            verify_ecdsa_p256_digest(trusted_public_key, &digest, &sig_bytes).map_err(|e| {
                SentinelError::PolicySignatureInvalid(format!(
                    "ECDSA P-256 rule pack signature verification error: {}",
                    e
                ))
            })?;
        if !verified {
            return Err(SentinelError::PolicySignatureInvalid(format!(
                "ECDSA P-256 signature invalid for rule pack '{}' (version {})",
                self.pack_id, self.version
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CompiledYaraRule {
    pub id: String,
    pub description: String,
    pub required_markers: Vec<Vec<u8>>,
    pub min_matches: usize,
    pub requires_pe_header: bool,
}

/// Compiles `.yar` rule source text into `Vec<CompiledYaraRule>` (`Row 154`).
pub fn compile_yara_source(yar_source: &str) -> Result<Vec<CompiledYaraRule>, String> {
    let mut compiled = Vec::new();
    for block in yar_source.split("rule ") {
        let trimmed = block.trim();
        if trimmed.is_empty() {
            continue;
        }
        let header_end = trimmed
            .find('{')
            .ok_or_else(|| format!("Malformed YARA rule block missing '{{': {}", trimmed))?;
        let rule_id = trimmed[..header_end].trim().to_string();
        if rule_id.is_empty() {
            return Err("Empty YARA rule identifier".to_string());
        }
        let body = &trimmed[header_end + 1..];
        let mut description = rule_id.clone();
        let mut requires_pe_header = body.contains("uint16(0) == 0x5A4D");
        let mut min_matches: usize = 1;
        let mut markers: Vec<Vec<u8>> = Vec::new();

        for raw_line in body.lines() {
            let line = raw_line.trim();
            if let Some(rest) = line.strip_prefix("description") {
                if let Some(q1) = rest.find('"') {
                    if let Some(q2) = rest[q1 + 1..].rfind('"') {
                        description = rest[q1 + 1..q1 + 1 + q2].to_string();
                    }
                }
            } else if let Some(rest) = line.strip_prefix("requires_pe") {
                if rest.contains("\"true\"") {
                    requires_pe_header = true;
                }
            } else if let Some(rest) = line.strip_prefix("min_matches") {
                if let Some(q1) = rest.find('"') {
                    if let Some(q2) = rest[q1 + 1..].rfind('"') {
                        if let Ok(parsed) = rest[q1 + 1..q1 + 1 + q2].parse::<usize>() {
                            min_matches = parsed.max(1);
                        }
                    }
                }
            } else if line.starts_with('$') {
                if let Some(eq_idx) = line.find('=') {
                    let rhs = line[eq_idx + 1..].trim();
                    if let Some(q1) = rhs.find('"') {
                        if let Some(q2) = rhs[q1 + 1..].rfind('"') {
                            let literal = rhs[q1 + 1..q1 + 1 + q2].replace("\\\\", "\\");
                            if !literal.is_empty() {
                                markers.push(literal.into_bytes());
                            }
                        }
                    }
                }
            } else if line.contains("all of them") && !markers.is_empty() {
                min_matches = markers.len();
            } else if line.contains("3 of them") {
                min_matches = 3;
            } else if line.contains("2 of them") {
                min_matches = 2;
            }
        }

        if markers.is_empty() {
            return Err(format!(
                "YARA rule '{}' defines zero string markers",
                rule_id
            ));
        }
        compiled.push(CompiledYaraRule {
            id: rule_id,
            description,
            required_markers: markers,
            min_matches,
            requires_pe_header,
        });
    }
    Ok(compiled)
}

pub type Tier0SignatureScanner = Tier0YaraScanner;

/// Tier-0 Multi-Condition YARA, Structural PE32/PE32+ IAT/Section & SHA-256 Intel Scanner
/// (`BUG-CORE-10`, `BUG-CORE-11`, `Rows 69, 78, 154, 156, 186, 228, 229`)
pub struct Tier0YaraScanner {
    rules: Vec<CompiledYaraRule>,
    rule_pack_version: u32,
    ledger_path: PathBuf,
    intel_bloom: ThreatIntelBloomFilter,
}

impl Default for Tier0YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Tier0YaraScanner {
    pub fn new() -> Self {
        let rules = compile_yara_source(DEFAULT_YARA_RULES_SOURCE).unwrap_or_default();
        Self {
            rules,
            rule_pack_version: 1,
            ledger_path: std::env::temp_dir()
                .join(format!("omniconnect_sentinel_yara_{}", std::process::id()))
                .join("yara_rulepack_ledger.jsonl"),
            intel_bloom: ThreatIntelBloomFilter::new(),
        }
    }

    pub fn with_ledger_path(mut self, ledger_path: PathBuf) -> Self {
        self.ledger_path = ledger_path;
        self
    }

    pub fn intel_bloom_mut(&mut self) -> &mut ThreatIntelBloomFilter {
        &mut self.intel_bloom
    }

    pub fn rule_pack_version(&self) -> u32 {
        self.rule_pack_version
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Verifies the ECDSA P-256 signature and strict monotonic version (`pack.version > self.rule_pack_version`)
    /// before compiling and activating `pack` (`Row 186`, `Row 198`).
    pub fn apply_signed_rule_pack(
        &mut self,
        pack: &SignedRulePack,
        trusted_public_key: &[u8],
    ) -> Result<u32, SentinelError> {
        if let Err(sig_err) = pack.verify_signature(trusted_public_key) {
            let mut ledger = AuditLedger::open(&self.ledger_path);
            let _ = ledger.append_event(
                DegradationEvent::PolicyRejected.event_code(),
                serde_json::json!({
                    "component": "Tier0YaraScanner",
                    "reason": "rulepack_signature_invalid",
                    "pack_id": pack.pack_id,
                    "candidate_version": pack.version,
                    "retained_version": self.rule_pack_version,
                }),
            );
            return Err(sig_err);
        }

        if pack.version <= self.rule_pack_version {
            let err = SentinelError::PolicySignatureInvalid(format!(
                "YARA rule pack rollback rejected: candidate version {} <= active version {}",
                pack.version, self.rule_pack_version
            ));
            let mut ledger = AuditLedger::open(&self.ledger_path);
            let _ = ledger.append_event(
                DegradationEvent::PolicyRejected.event_code(),
                serde_json::json!({
                    "component": "Tier0YaraScanner",
                    "reason": "rulepack_monotonic_rollback",
                    "pack_id": pack.pack_id,
                    "candidate_version": pack.version,
                    "retained_version": self.rule_pack_version,
                }),
            );
            return Err(err);
        }

        let mut compiled_additions = Vec::with_capacity(pack.rules.len());
        for dyn_rule in &pack.rules {
            let mut markers = Vec::with_capacity(dyn_rule.required_markers_hex.len());
            for m_hex in &dyn_rule.required_markers_hex {
                let decoded = hex::decode(m_hex).map_err(|e| {
                    SentinelError::PolicySignatureInvalid(format!(
                        "Invalid marker hex in rule '{}': {}",
                        dyn_rule.id, e
                    ))
                })?;
                if decoded.is_empty() {
                    return Err(SentinelError::PolicySignatureInvalid(format!(
                        "Empty marker in rule '{}'",
                        dyn_rule.id
                    )));
                }
                markers.push(decoded);
            }
            compiled_additions.push(CompiledYaraRule {
                id: dyn_rule.id.clone(),
                description: dyn_rule.description.clone(),
                required_markers: markers,
                min_matches: dyn_rule.min_matches.max(1),
                requires_pe_header: dyn_rule.requires_pe_header,
            });
        }

        let prev_ver = self.rule_pack_version;
        self.rules.extend(compiled_additions);
        self.rule_pack_version = pack.version;

        let mut ledger = AuditLedger::open(&self.ledger_path);
        let _ = ledger.append_event(
            "YARA_RULEPACK_UPDATED",
            serde_json::json!({
                "pack_id": pack.pack_id,
                "previous_version": prev_ver,
                "new_version": self.rule_pack_version,
                "rules_added": pack.rules.len(),
            }),
        );

        Ok(self.rule_pack_version)
    }

    pub fn scan_bytes(&self, bytes: &[u8], context_name: &str) -> YaraScanResult {
        let mut cursor = Cursor::new(bytes);
        self.scan_reader(&mut cursor, context_name)
    }

    /// Streams `reader` in 64 KiB windows with a 4 KiB (`4096`-byte) overlap (`Rows 69, 78, 154, 156, 228, 229`),
    /// computing the full-file SHA-256 digest for Bloom-filtered threat intelligence lookup, evaluating
    /// multi-condition YARA rules across the entire stream, and running structural PE32/PE32+ (and ELF)
    /// section, entropy, and Import Address Table (IAT) analysis.
    pub fn scan_reader<R: Read + Seek>(
        &self,
        reader: &mut R,
        _context_name: &str,
    ) -> YaraScanResult {
        let start = Instant::now();
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return YaraScanResult {
                matched: false,
                rule_name: None,
                threat_Details: None,
                scan_duration_micros: start.elapsed().as_micros() as u64,
            };
        }

        const WINDOW_SIZE: usize = 64 * 1024;
        const OVERLAP_SIZE: usize = 4 * 1024;
        let mut chunk = vec![0u8; WINDOW_SIZE];
        let mut overlap = Vec::with_capacity(OVERLAP_SIZE);
        let mut window = Vec::with_capacity(WINDOW_SIZE + OVERLAP_SIZE);
        let mut first_window = Vec::new();
        let mut hasher = Sha256::new();

        let mut rule_matched_markers: Vec<HashSet<usize>> = vec![HashSet::new(); self.rules.len()];

        loop {
            let n = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            hasher.update(&chunk[..n]);
            if first_window.len() < WINDOW_SIZE {
                let take = (WINDOW_SIZE - first_window.len()).min(n);
                first_window.extend_from_slice(&chunk[..take]);
            }

            window.clear();
            window.extend_from_slice(&overlap);
            window.extend_from_slice(&chunk[..n]);

            for (r_idx, rule) in self.rules.iter().enumerate() {
                if rule_matched_markers[r_idx].len() >= rule.min_matches {
                    continue;
                }
                for (m_idx, marker) in rule.required_markers.iter().enumerate() {
                    if !rule_matched_markers[r_idx].contains(&m_idx)
                        && Self::contains_subslice(&window, marker)
                    {
                        rule_matched_markers[r_idx].insert(m_idx);
                    }
                }
            }

            overlap.clear();
            let tail_start = n.saturating_sub(OVERLAP_SIZE);
            overlap.extend_from_slice(&chunk[tail_start..n]);
        }

        let digest: [u8; 32] = hasher.finalize().into();

        // 0. SHA-256 Threat Intelligence Bloom Filter + Exact Table Check (`Rows 156, 229`)
        if let Some((intel_id, intel_desc)) = self.intel_bloom.lookup(&digest) {
            return YaraScanResult {
                matched: true,
                rule_name: Some(intel_id),
                threat_Details: Some(intel_desc),
                scan_duration_micros: start.elapsed().as_micros() as u64,
            };
        }

        let is_pe = Self::is_valid_pe(&first_window);

        // 1. Evaluate multi-condition compiled YARA rules
        for (r_idx, rule) in self.rules.iter().enumerate() {
            if rule.requires_pe_header && !is_pe {
                continue;
            }
            if rule_matched_markers[r_idx].len() >= rule.min_matches {
                return YaraScanResult {
                    matched: true,
                    rule_name: Some(rule.id.clone()),
                    threat_Details: Some(rule.description.clone()),
                    scan_duration_micros: start.elapsed().as_micros() as u64,
                };
            }
        }

        // 2. Structural PE32/PE32+ section table, entropy, W+X & Import Address Table inspection (`Rows 154, 156, 228`)
        if is_pe {
            if let Some((rule_id, details)) =
                Self::inspect_pe_sections_reader(reader, &first_window)
            {
                return YaraScanResult {
                    matched: true,
                    rule_name: Some(rule_id),
                    threat_Details: Some(details),
                    scan_duration_micros: start.elapsed().as_micros() as u64,
                };
            }
        }

        // 3. Structural ELF binary inspection (`Row 154`)
        if let Some(elf) = Self::parse_elf_structure(&first_window) {
            if elf.has_rwx_segment {
                return YaraScanResult {
                    matched: true,
                    rule_name: Some("YARA_ELF_RWX_LOAD_SEGMENT".to_string()),
                    threat_Details: Some(
                        "ELF binary declares a writable + executable (PF_W | PF_X) PT_LOAD segment characteristic of packed/injected ELF payloads"
                            .to_string(),
                    ),
                    scan_duration_micros: start.elapsed().as_micros() as u64,
                };
            }
        }

        YaraScanResult {
            matched: false,
            rule_name: None,
            threat_Details: None,
            scan_duration_micros: start.elapsed().as_micros() as u64,
        }
    }

    pub fn is_valid_pe(bytes: &[u8]) -> bool {
        if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
            return false;
        }
        let pe_offset =
            u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        if pe_offset + 4 <= bytes.len() && &bytes[pe_offset..pe_offset + 4] == b"PE\0\0" {
            return true;
        }
        false
    }

    /// Full PE32 / PE32+ structural parser (`Rows 154, 156, 228`):
    /// Walks the COFF header, Optional Header (`0x10B` PE32 / `0x20B` PE32+), Data Directories,
    /// `IMAGE_SECTION_HEADER` table (section characteristics, `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE`,
    /// entry-point-in-last-section, and Shannon entropy), and resolves RVAs to parse the Import
    /// Directory Table (`IMAGE_IMPORT_DESCRIPTOR` + Import Lookup/Address Table function names).
    pub fn parse_pe_structure(bytes: &[u8]) -> Option<PeStructureAnalysis> {
        let mut cursor = Cursor::new(bytes);
        Self::parse_pe_structure_reader(&mut cursor, bytes)
    }

    pub fn parse_pe_structure_reader<R: Read + Seek>(
        reader: &mut R,
        head_bytes: &[u8],
    ) -> Option<PeStructureAnalysis> {
        if head_bytes.len() < 0x40 || &head_bytes[0..2] != b"MZ" {
            return None;
        }
        let pe_offset = u32::from_le_bytes([
            head_bytes[0x3C],
            head_bytes[0x3D],
            head_bytes[0x3E],
            head_bytes[0x3F],
        ]) as usize;
        if pe_offset + 24 > head_bytes.len() || &head_bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return None;
        }

        let num_sections =
            u16::from_le_bytes([head_bytes[pe_offset + 6], head_bytes[pe_offset + 7]]) as usize;
        let size_of_opt_header =
            u16::from_le_bytes([head_bytes[pe_offset + 20], head_bytes[pe_offset + 21]]) as usize;
        let opt_offset = pe_offset + 24;
        let section_table_offset = opt_offset + size_of_opt_header;

        let mut is_pe64 = false;
        let mut entry_point_rva = 0u32;
        let mut import_table_rva = 0u32;

        if size_of_opt_header >= 20 && opt_offset + size_of_opt_header <= head_bytes.len() {
            let magic = u16::from_le_bytes([head_bytes[opt_offset], head_bytes[opt_offset + 1]]);
            is_pe64 = magic == 0x020B;
            entry_point_rva = u32::from_le_bytes([
                head_bytes[opt_offset + 16],
                head_bytes[opt_offset + 17],
                head_bytes[opt_offset + 18],
                head_bytes[opt_offset + 19],
            ]);

            let data_dir_offset = if magic == 0x020B {
                opt_offset + 112
            } else if magic == 0x010B {
                opt_offset + 96
            } else {
                0
            };
            // Import Directory is DataDirectory[1] (at `data_dir_offset + 8`)
            if data_dir_offset > 0 && data_dir_offset + 16 <= opt_offset + size_of_opt_header {
                import_table_rva = u32::from_le_bytes([
                    head_bytes[data_dir_offset + 8],
                    head_bytes[data_dir_offset + 9],
                    head_bytes[data_dir_offset + 10],
                    head_bytes[data_dir_offset + 11],
                ]);
            }
        }

        let capped_sections = num_sections.min(64);
        let mut sections = Vec::with_capacity(capped_sections);
        let mut has_rmnet_section = false;
        let mut has_wx_section = false;
        let mut has_high_entropy_executable_section = false;
        let mut entry_point_in_last_section = false;

        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

        for idx in 0..capped_sections {
            let sec_off = section_table_offset + idx * 40;
            if sec_off + 40 > head_bytes.len() {
                break;
            }
            let raw_name = &head_bytes[sec_off..sec_off + 8];
            let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let sec_name = String::from_utf8_lossy(&raw_name[..name_end]).to_ascii_lowercase();

            let virtual_size = u32::from_le_bytes([
                head_bytes[sec_off + 8],
                head_bytes[sec_off + 9],
                head_bytes[sec_off + 10],
                head_bytes[sec_off + 11],
            ]);
            let virtual_address = u32::from_le_bytes([
                head_bytes[sec_off + 12],
                head_bytes[sec_off + 13],
                head_bytes[sec_off + 14],
                head_bytes[sec_off + 15],
            ]);
            let raw_data_size = u32::from_le_bytes([
                head_bytes[sec_off + 16],
                head_bytes[sec_off + 17],
                head_bytes[sec_off + 18],
                head_bytes[sec_off + 19],
            ]);
            let raw_data_ptr = u32::from_le_bytes([
                head_bytes[sec_off + 20],
                head_bytes[sec_off + 21],
                head_bytes[sec_off + 22],
                head_bytes[sec_off + 23],
            ]);
            let characteristics = u32::from_le_bytes([
                head_bytes[sec_off + 36],
                head_bytes[sec_off + 37],
                head_bytes[sec_off + 38],
                head_bytes[sec_off + 39],
            ]);

            let is_exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            let is_write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            let is_wx = is_exec && is_write;

            // Sample up to 64 KiB of the section body via seekable reader to compute Shannon entropy
            let mut entropy = 0.0f32;
            if raw_data_ptr > 0 && raw_data_size > 0 {
                let sample_len = (raw_data_size as usize).min(64 * 1024);
                let mut sec_buf = vec![0u8; sample_len];
                if reader.seek(SeekFrom::Start(raw_data_ptr as u64)).is_ok() {
                    if let Ok(n) = reader.read(&mut sec_buf) {
                        if n > 0 {
                            entropy = ContentScanner::shannon_entropy(&sec_buf[..n]);
                        }
                    }
                }
            }

            if sec_name == ".rmnet" {
                has_rmnet_section = true;
            }
            if is_wx {
                has_wx_section = true;
            }
            if is_exec && entropy > 7.4 {
                has_high_entropy_executable_section = true;
            }

            let span = virtual_size.max(raw_data_size);
            if idx + 1 == capped_sections
                && capped_sections >= 2
                && entry_point_rva > 0
                && entry_point_rva >= virtual_address
                && entry_point_rva < virtual_address.saturating_add(span)
            {
                entry_point_in_last_section = true;
            }

            sections.push(PeSectionInfo {
                name: sec_name,
                virtual_address,
                virtual_size,
                raw_data_ptr,
                raw_data_size,
                characteristics,
                entropy,
                is_writable_executable: is_wx,
            });
        }

        let mut imported_dlls = Vec::new();
        let mut imported_functions = Vec::new();

        if import_table_rva > 0 {
            if let Some(mut imp_file_off) = Self::rva_to_file_offset(import_table_rva, &sections) {
                for _ in 0..64 {
                    if imp_file_off + 20 > head_bytes.len() {
                        break;
                    }
                    let desc = &head_bytes[imp_file_off..imp_file_off + 20];
                    if desc.iter().all(|&b| b == 0) {
                        break;
                    }
                    let orig_first_thunk = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
                    let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]);
                    let first_thunk = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);

                    if let Some(dll_off) = Self::rva_to_file_offset(name_rva, &sections) {
                        if let Some(dll_name) = Self::read_c_string(head_bytes, dll_off, 128) {
                            imported_dlls.push(dll_name);
                        }
                    }

                    let thunk_rva = if orig_first_thunk != 0 {
                        orig_first_thunk
                    } else {
                        first_thunk
                    };
                    if let Some(mut thunk_off) = Self::rva_to_file_offset(thunk_rva, &sections) {
                        let step = if is_pe64 { 8 } else { 4 };
                        for _ in 0..256 {
                            if thunk_off + step > head_bytes.len() {
                                break;
                            }
                            let hint_name_rva = if is_pe64 {
                                let v = u64::from_le_bytes([
                                    head_bytes[thunk_off],
                                    head_bytes[thunk_off + 1],
                                    head_bytes[thunk_off + 2],
                                    head_bytes[thunk_off + 3],
                                    head_bytes[thunk_off + 4],
                                    head_bytes[thunk_off + 5],
                                    head_bytes[thunk_off + 6],
                                    head_bytes[thunk_off + 7],
                                ]);
                                if v == 0 {
                                    break;
                                }
                                if (v & (1u64 << 63)) != 0 {
                                    thunk_off += step;
                                    continue;
                                }
                                (v & 0x7FFF_FFFF) as u32
                            } else {
                                let v = u32::from_le_bytes([
                                    head_bytes[thunk_off],
                                    head_bytes[thunk_off + 1],
                                    head_bytes[thunk_off + 2],
                                    head_bytes[thunk_off + 3],
                                ]);
                                if v == 0 {
                                    break;
                                }
                                if (v & 0x8000_0000) != 0 {
                                    thunk_off += step;
                                    continue;
                                }
                                v & 0x7FFF_FFFF
                            };

                            if let Some(fn_off) = Self::rva_to_file_offset(hint_name_rva, &sections)
                            {
                                // Skip 2-byte `Hint` field in `IMAGE_IMPORT_BY_NAME`
                                if let Some(fn_name) =
                                    Self::read_c_string(head_bytes, fn_off + 2, 128)
                                {
                                    imported_functions.push(fn_name);
                                }
                            }
                            thunk_off += step;
                        }
                    }

                    imp_file_off += 20;
                }
            }
        }

        Some(PeStructureAnalysis {
            is_pe64,
            entry_point_rva,
            entry_point_in_last_section,
            sections,
            imported_dlls,
            imported_functions,
            has_rmnet_section,
            has_wx_section,
            has_high_entropy_executable_section,
        })
    }

    fn rva_to_file_offset(rva: u32, sections: &[PeSectionInfo]) -> Option<usize> {
        for sec in sections {
            let span = sec.virtual_size.max(sec.raw_data_size);
            if rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(span) {
                let delta = rva - sec.virtual_address;
                return sec.raw_data_ptr.checked_add(delta).map(|v| v as usize);
            }
        }
        if (rva as usize) < 4096 {
            return Some(rva as usize);
        }
        None
    }

    fn read_c_string(bytes: &[u8], offset: usize, max_len: usize) -> Option<String> {
        if offset >= bytes.len() {
            return None;
        }
        let rem = &bytes[offset..bytes.len().min(offset + max_len)];
        let nul_pos = rem.iter().position(|&b| b == 0)?;
        if nul_pos == 0 {
            return None;
        }
        let s = &rem[..nul_pos];
        if s.iter().all(|&b| b.is_ascii_graphic()) {
            Some(String::from_utf8_lossy(s).to_string())
        } else {
            None
        }
    }

    /// Parses ELF32 / ELF64 header and Program Header table (`Row 154`).
    pub fn parse_elf_structure(bytes: &[u8]) -> Option<ElfStructureAnalysis> {
        if bytes.len() < 52 || &bytes[0..4] != b"\x7FELF" {
            return None;
        }
        let class = bytes[4]; // 1 = 32-bit, 2 = 64-bit
        let is_64bit = class == 2;
        if is_64bit && bytes.len() < 64 {
            return None;
        }
        let (entry_point, phoff, phentsize, phnum, shnum) = if is_64bit {
            let ep = u64::from_le_bytes([
                bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30],
                bytes[31],
            ]);
            let phoff = u64::from_le_bytes([
                bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38],
                bytes[39],
            ]) as usize;
            let phentsize = u16::from_le_bytes([bytes[54], bytes[55]]) as usize;
            let phnum = u16::from_le_bytes([bytes[56], bytes[57]]);
            let shnum = u16::from_le_bytes([bytes[60], bytes[61]]);
            (ep, phoff, phentsize, phnum, shnum)
        } else {
            let ep = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as u64;
            let phoff = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]) as usize;
            let phentsize = u16::from_le_bytes([bytes[42], bytes[43]]) as usize;
            let phnum = u16::from_le_bytes([bytes[44], bytes[45]]);
            let shnum = u16::from_le_bytes([bytes[48], bytes[49]]);
            (ep, phoff, phentsize, phnum, shnum)
        };

        let mut has_rwx_segment = false;
        if phentsize >= 32 {
            for idx in 0..(phnum as usize).min(64) {
                let off = phoff + idx * phentsize;
                if off + phentsize > bytes.len() {
                    break;
                }
                let p_type = u32::from_le_bytes([
                    bytes[off],
                    bytes[off + 1],
                    bytes[off + 2],
                    bytes[off + 3],
                ]);
                let p_flags = if is_64bit {
                    u32::from_le_bytes([
                        bytes[off + 4],
                        bytes[off + 5],
                        bytes[off + 6],
                        bytes[off + 7],
                    ])
                } else {
                    u32::from_le_bytes([
                        bytes[off + 24],
                        bytes[off + 25],
                        bytes[off + 26],
                        bytes[off + 27],
                    ])
                };
                // PT_LOAD == 1, PF_X == 1, PF_W == 2
                if p_type == 1 && (p_flags & 0x3) == 0x3 {
                    has_rwx_segment = true;
                }
            }
        }

        Some(ElfStructureAnalysis {
            is_64bit,
            entry_point,
            has_rwx_segment,
            program_header_count: phnum,
            section_header_count: shnum,
        })
    }

    /// Parses the PE `IMAGE_SECTION_HEADER` and Import Address Table to detect `.rmnet` (Win32.Ramnit),
    /// entry-point-in-last-section + W+X + high-entropy infector anomalies (`Row 228`), and IAT
    /// process-hollowing chains without relying on spoofable file sizes (`BUG-CORE-10`, `BUG-CORE-11`).
    pub fn inspect_pe_sections(bytes: &[u8]) -> Option<(String, String)> {
        let mut cursor = Cursor::new(bytes);
        Self::inspect_pe_sections_reader(&mut cursor, bytes)
    }

    pub fn inspect_pe_sections_reader<R: Read + Seek>(
        reader: &mut R,
        head_bytes: &[u8],
    ) -> Option<(String, String)> {
        let analysis = Self::parse_pe_structure_reader(reader, head_bytes)?;

        if analysis.has_rmnet_section {
            let sha256 = hex::encode(Sha256::digest(head_bytes));
            return Some((
                "YARA_WIN32_RAMNIT_PE_SECTION".to_string(),
                format!(
                    "PE section '.rmnet' characteristic of Win32.Ramnit file infector (SHA256: {})",
                    &sha256[..16]
                ),
            ));
        }

        if analysis.entry_point_in_last_section
            && analysis.has_wx_section
            && analysis
                .sections
                .last()
                .map(|s| s.is_writable_executable && s.entropy > 7.4)
                .unwrap_or(false)
        {
            return Some((
                "YARA_PE_LAST_SECTION_WX_PACKER_OR_INFECTOR".to_string(),
                format!(
                    "PE entry point (RVA 0x{:X}) resides in final W+X high-entropy section",
                    analysis.entry_point_rva
                ),
            ));
        }

        let has_iat_valloc = analysis
            .imported_functions
            .iter()
            .any(|f| f.eq_ignore_ascii_case("VirtualAllocEx"));
        let has_iat_wpm = analysis
            .imported_functions
            .iter()
            .any(|f| f.eq_ignore_ascii_case("WriteProcessMemory"));
        let has_iat_exec = analysis.imported_functions.iter().any(|f| {
            f.eq_ignore_ascii_case("CreateRemoteThread")
                || f.eq_ignore_ascii_case("NtUnmapViewOfSection")
                || f.eq_ignore_ascii_case("SetThreadContext")
                || f.eq_ignore_ascii_case("QueueUserAPC")
        });

        if has_iat_valloc && has_iat_wpm && has_iat_exec {
            return Some((
                "YARA_PE_IAT_PROCESS_HOLLOWING".to_string(),
                "PE Import Address Table (IAT) imports full remote process-hollowing chain"
                    .to_string(),
            ));
        }

        None
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
