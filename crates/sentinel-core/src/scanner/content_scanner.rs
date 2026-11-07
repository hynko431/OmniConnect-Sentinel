use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use zip::ZipArchive;

use crate::scanner::universal_scanner::{CarrierCategory, ThreatSeverity, UniversalThreat};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFinding {
    pub category: String,
    pub severity: String,
    pub indicator: String,
    pub description: String,
}

/// Deep Document, Script, LNK, & Ransomware Heuristic Scanner (`BUG-CORE-03`, `BUG-CORE-05`, Phase 1.3)
pub struct ContentScanner;

impl ContentScanner {
    pub fn scan(path: &Path, bytes: &[u8]) -> Vec<ContentFinding> {
        let mut cursor = Cursor::new(bytes);
        Self::scan_with_reader(path, bytes, &mut cursor)
    }

    /// Backwards-compatible entry point returning the highest-priority `UniversalThreat`.
    pub fn inspect_content(path: &Path, bytes: &[u8], _file_size: u64) -> Option<UniversalThreat> {
        let mut cursor = Cursor::new(bytes);
        Self::inspect_with_reader(path, bytes, &mut cursor)
            .into_iter()
            .max_by_key(|t| t.risk_score)
    }

    pub fn inspect_with_reader<R: Read + Seek>(
        path: &Path,
        head_bytes: &[u8],
        seekable_reader: &mut R,
    ) -> Vec<UniversalThreat> {
        let findings = Self::scan_with_reader(path, head_bytes, seekable_reader);
        findings
            .into_iter()
            .map(|f| Self::finding_to_universal_threat(path, f))
            .collect()
    }

    fn finding_to_universal_threat(path: &Path, f: ContentFinding) -> UniversalThreat {
        let (carrier_category, threat_name, severity, risk_score, mitre, can_cdr) =
            match f.category.as_str() {
                "RANSOMWARE_ENCRYPTED_ARTIFACT" | "RANSOMWARE_NOTE" => (
                    CarrierCategory::Ransomware,
                    format!("Ransomware Indicator: {}", f.indicator),
                    ThreatSeverity::Critical,
                    100,
                    "T1486 (Data Encrypted for Impact)".to_string(),
                    false,
                ),
                "MALICIOUS_LNK_SHORTCUT"
                | "BLOCKED_CONTAINER_OR_SHORTCUT"
                | "ENCRYPTED_ARCHIVE_BLOCKED"
                | "MALFORMED_OR_ENCRYPTED_ZIP" => (
                    CarrierCategory::FilesystemHidden,
                    format!("Quarantined Container / Shortcut Vector ({})", f.indicator),
                    ThreatSeverity::Critical,
                    96,
                    "T1204.002 / T1553.005 (Container / Shortcut Mark-of-the-Web Bypass)"
                        .to_string(),
                    false,
                ),
                "PDF_DEEP_NESTING_ATTACK" => (
                    CarrierCategory::Document,
                    "Weaponized PDF: Excessive Structural Nesting Bomb".to_string(),
                    ThreatSeverity::Critical,
                    99,
                    "T1499.004 (Application or System Exploitation / Parser DoS)".to_string(),
                    false,
                ),
                "PDF_LAUNCH_ACTION" => (
                    CarrierCategory::Document,
                    "Weaponized PDF: /Launch OS Command Execution".to_string(),
                    ThreatSeverity::Critical,
                    98,
                    "T1204.002 (Malicious Document /Launch)".to_string(),
                    true,
                ),
                "PDF_ACTIVE_CONTENT" => (
                    CarrierCategory::Document,
                    "Weaponized PDF: Embedded /JavaScript (/JS)".to_string(),
                    ThreatSeverity::High,
                    92,
                    "T1059.007 (PDF Embedded JavaScript)".to_string(),
                    true,
                ),
                "PDF_AUTO_ACTION" | "PDF_EMBEDDED_ATTACHMENT" => (
                    CarrierCategory::Document,
                    format!("PDF Suspicious Trigger ({})", f.indicator),
                    ThreatSeverity::Medium,
                    80,
                    "T1204.002 (User Execution: Malicious File)".to_string(),
                    true,
                ),
                "OFFICE_EXTERNAL_RELATIONSHIP" | "OFFICE_DDE_INJECTION" => (
                    CarrierCategory::Document,
                    format!("Weaponized Office Document ({})", f.indicator),
                    ThreatSeverity::Critical,
                    97,
                    "T1221 / T1559.002 (Template Injection / DDE)".to_string(),
                    true,
                ),
                "OFFICE_VBA_MACRO" | "OFFICE_EMBEDDED_OLE" | "OLE2_VBA_MACRO" => (
                    CarrierCategory::Document,
                    format!("Embedded Office Macro / OLE Payload ({})", f.indicator),
                    ThreatSeverity::High,
                    90,
                    "T1137 (Office Application Startup / VBA Macro)".to_string(),
                    true,
                ),
                "SVG_SCRIPT_PAYLOAD" => (
                    CarrierCategory::Image,
                    "Weaponized SVG Image (Embedded Script)".to_string(),
                    ThreatSeverity::High,
                    91,
                    "T1059.007 (JavaScript inside SVG)".to_string(),
                    true,
                ),
                _ => (
                    CarrierCategory::ScriptCode,
                    format!(
                        "Malicious Script Execution Cradle ({}) - {}",
                        f.indicator, f.description
                    ),
                    ThreatSeverity::Critical,
                    96,
                    "T1059.001 / T1562.001 (Defense Evasion / Script Execution)".to_string(),
                    false,
                ),
            };

        UniversalThreat {
            file_path: path.to_path_buf(),
            carrier_category,
            threat_name,
            severity,
            risk_score,
            mitre_technique: mitre,
            technical_details: f.description,
            overlay_offset: None,
            stream_name: None,
            can_disarm_via_cdr: can_cdr,
        }
    }

    pub fn scan_with_reader<R: Read + Seek>(
        path: &Path,
        head_bytes: &[u8],
        seekable_reader: &mut R,
    ) -> Vec<ContentFinding> {
        let mut findings = Vec::new();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // 1. Ransomware Heuristics (`BUG-CORE-05` #1 & #2)
        Self::check_ransomware_indicators(&file_name, &ext, head_bytes, &mut findings);

        // 1b. Always-Quarantined Container, Shortcut & Encrypted Archive Policy (Master Plan v2 §2.6 & §5 `allowlist_blocks_containers`, `Row 76`)
        Self::check_blocked_containers_and_encrypted_archives(
            &file_name,
            &ext,
            head_bytes,
            seekable_reader,
            &mut findings,
        );

        // 2. Windows Shortcut (.LNK) Binary Structure Inspection
        if ext == "lnk" || head_bytes.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])
        {
            Self::scan_lnk_binary(head_bytes, &mut findings);
        }

        // 3. PDF Structural & Token-Boundary Inspection over streaming 64 KiB reader (`BUG-CORE-03`, `BUG-CORE-05` #3, `Row 70`)
        if head_bytes.starts_with(b"%PDF-") || ext == "pdf" {
            Self::scan_pdf_reader(seekable_reader, head_bytes, &mut findings);
        }

        // 4. OpenXML / ZIP Container Inspection using full seekable reader (`BUG-CORE-03`, `Row 70`)
        if head_bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04])
            || matches!(
                ext.as_str(),
                "docx" | "docm" | "xlsx" | "xlsm" | "pptx" | "pptm" | "zip"
            )
        {
            Self::scan_openxml_reader(seekable_reader, &mut findings);
        }

        // 5. Legacy OLE2 Compound File Binary Inspection over streaming 64 KiB reader
        if head_bytes.len() >= 8 && &head_bytes[0..8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
            Self::scan_ole2_reader(seekable_reader, head_bytes, &mut findings);
        }

        // 6. SVG / HTML / Script / Autorun Inspection over 64 KiB streaming windows (`Rows 69, 78`)
        if matches!(
            ext.as_str(),
            "ps1" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "hta" | "bat" | "cmd" | "inf" | "svg"
        ) || file_name == "autorun.inf"
        {
            Self::scan_script_or_svg_reader(
                &file_name,
                &ext,
                head_bytes,
                seekable_reader,
                &mut findings,
            );
        }

        findings
    }

    /// Enforces Master Plan v2 §2.6 (`allowlist_blocks_containers`, `Row 76, 135`, `High #11`):
    /// Always quarantines shortcut, disk-image, script, and help-container formats
    /// (`.lnk`, `.url`, `.iso`, `.img`, `.vhd`, `.vhdx`, `.hta`, `.chm`, `.wsf`, `.scr`, `.one`, `.library-ms`, etc.),
    /// magic-byte matches (`LNK`, `ITSF`/`.chm`, `conectix`/`.vhd`, `vhdxfile`/`.vhdx`, `CD001`/`.iso`, `.one`),
    /// and password-protected/encrypted ZIP archives (`gp_flags & 0x0001 != 0` or WinZip AE method 99 across all central/local headers).
    fn check_blocked_containers_and_encrypted_archives<R: Read + Seek>(
        file_name: &str,
        ext: &str,
        head_bytes: &[u8],
        seekable_reader: &mut R,
        findings: &mut Vec<ContentFinding>,
    ) {
        const ALWAYS_QUARANTINED_EXTS: &[&str] = &[
            "lnk",
            "url",
            "iso",
            "img",
            "vhd",
            "vhdx",
            "hta",
            "chm",
            "wsf",
            "scr",
            "one",
            "library-ms",
            "scf",
            "searchconnector-ms",
            "pif",
            "cpl",
            "msi",
            "msp",
            "cab",
            "7z",
            "rar",
            "dmg",
            "jar",
            "vbs",
            "vbe",
            "jse",
            "reg",
        ];

        let mut blocked_container_matched = false;
        if ALWAYS_QUARANTINED_EXTS.contains(&ext) {
            blocked_container_matched = true;
            findings.push(ContentFinding {
                category: "BLOCKED_CONTAINER_OR_SHORTCUT".to_string(),
                severity: "CRITICAL".to_string(),
                indicator: format!(".{}", ext),
                description: format!(
                    "Default-deny format allowlist quarantined high-risk container/shortcut '{}' (.{} bypasses MOTW or executes host code)",
                    file_name, ext
                ),
            });
        }

        // Magic-byte inspection for disguised containers (`.lnk`, `.chm`, `.vhd`, `.vhdx`, `.iso`, `.one`, `.7z`, `.rar`, `.cab`)
        if !blocked_container_matched {
            let magic_indicator = if head_bytes
                .starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])
            {
                Some("Windows Shell Link (.lnk magic)")
            } else if head_bytes.starts_with(b"ITSF") {
                Some("Compiled HTML Help (.chm ITSF magic)")
            } else if head_bytes.starts_with(b"conectix")
                || head_bytes.starts_with(b"vhdxfile")
                || Self::has_vhd_footer_magic(seekable_reader)
            {
                Some("Virtual Hard Disk (.vhd/.vhdx magic)")
            } else if head_bytes.starts_with(b"ISO9660")
                || Self::has_iso9660_pvd_magic(seekable_reader)
            {
                Some("ISO-9660 Optical Disk Image (CD001 magic)")
            } else if head_bytes.starts_with(&[0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D]) {
                Some("Microsoft OneNote Container (.one magic)")
            } else if head_bytes.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
                || head_bytes.starts_with(b"Rar!")
                || head_bytes.starts_with(b"MSCF")
            {
                Some("Opaque Archive Container (.7z/.rar/.cab magic)")
            } else {
                None
            };

            if let Some(ind) = magic_indicator {
                findings.push(ContentFinding {
                    category: "BLOCKED_CONTAINER_OR_SHORTCUT".to_string(),
                    severity: "CRITICAL".to_string(),
                    indicator: ind.to_string(),
                    description: format!(
                        "Default-deny format allowlist quarantined container '{}' matching {}",
                        file_name, ind
                    ),
                });
            }
        }

        // Check for encrypted ZIP local (`PK\x03\x04`) or central directory (`PK\x01\x02`) headers
        // across the entire archive (`gp_flags & 0x0001 != 0` or WinZip AE method 99) (`Row 135`)
        if head_bytes.starts_with(b"PK\x03\x04")
            && Self::has_encrypted_zip_headers_reader(seekable_reader, head_bytes)
        {
            findings.push(ContentFinding {
                category: "ENCRYPTED_ARCHIVE_BLOCKED".to_string(),
                severity: "HIGH".to_string(),
                indicator: "Encrypted ZIP Archive".to_string(),
                description: format!(
                    "Password-protected/encrypted archive '{}' blocked by default-deny allowlist",
                    file_name
                ),
            });
        }
    }

    fn has_iso9660_pvd_magic<R: Read + Seek>(reader: &mut R) -> bool {
        let mut magic = [0u8; 5];
        for &offset in &[0x8001u64, 0x8801u64, 0x9001u64] {
            if reader.seek(std::io::SeekFrom::Start(offset)).is_ok()
                && reader.read_exact(&mut magic).is_ok()
                && &magic == b"CD001"
            {
                return true;
            }
        }
        false
    }

    fn has_vhd_footer_magic<R: Read + Seek>(reader: &mut R) -> bool {
        let end = match reader.seek(std::io::SeekFrom::End(0)) {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if end < 512 {
            return false;
        }
        let mut magic = [0u8; 8];
        reader.seek(std::io::SeekFrom::Start(end - 512)).is_ok()
            && reader.read_exact(&mut magic).is_ok()
            && &magic == b"conectix"
    }

    /// Streams `reader` in 64 KiB windows with a 4 KiB overlap (`Rows 69, 78, 135`) and checks
    /// bit 0 of the general-purpose bit flag (and WinZip AE method 99) across **all** central
    /// directory (`PK\x01\x02`) and local file (`PK\x03\x04`) headers.
    fn has_encrypted_zip_headers_reader<R: Read + Seek>(reader: &mut R, head_bytes: &[u8]) -> bool {
        let check_slice = |buf: &[u8]| -> bool {
            if buf.len() >= 10 {
                for i in 0..=(buf.len() - 10) {
                    if &buf[i..i + 4] == b"PK\x03\x04" {
                        let gp_flags = u16::from_le_bytes([buf[i + 6], buf[i + 7]]);
                        let comp_method = u16::from_le_bytes([buf[i + 8], buf[i + 9]]);
                        if (gp_flags & 0x0001) != 0 || comp_method == 99 {
                            return true;
                        }
                    } else if i + 12 <= buf.len() && &buf[i..i + 4] == b"PK\x01\x02" {
                        let gp_flags = u16::from_le_bytes([buf[i + 8], buf[i + 9]]);
                        let comp_method = u16::from_le_bytes([buf[i + 10], buf[i + 11]]);
                        if (gp_flags & 0x0001) != 0 || comp_method == 99 {
                            return true;
                        }
                    }
                }
            }
            false
        };

        if check_slice(head_bytes) {
            return true;
        }
        if reader.seek(std::io::SeekFrom::Start(0)).is_err() {
            return false;
        }
        const WINDOW_SIZE: usize = 64 * 1024;
        const OVERLAP_SIZE: usize = 4 * 1024;
        let mut chunk = vec![0u8; WINDOW_SIZE];
        let mut overlap = Vec::with_capacity(OVERLAP_SIZE);
        let mut window = Vec::with_capacity(WINDOW_SIZE + OVERLAP_SIZE);
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    window.clear();
                    window.extend_from_slice(&overlap);
                    window.extend_from_slice(&chunk[..n]);
                    if check_slice(&window) {
                        return true;
                    }
                    overlap.clear();
                    let tail_start = n.saturating_sub(OVERLAP_SIZE);
                    overlap.extend_from_slice(&chunk[tail_start..n]);
                }
                Err(_) => break,
            }
        }
        false
    }

    /// Checks ransomware extensions (gated strictly by `entropy >= 7.2`, fixing `BUG-CORE-05` #1, `Row 75`)
    /// and ransom note filenames (gated by >= 2 ransom keywords in content, fixing `BUG-CORE-05` #2, `Row 76`).
    fn check_ransomware_indicators(
        file_name: &str,
        ext: &str,
        bytes: &[u8],
        findings: &mut Vec<ContentFinding>,
    ) {
        const RANSOM_EXTS: &[&str] = &[
            "locked",
            "encrypted",
            "crypt",
            "enc",
            "ryuk",
            "lockbit",
            "conti",
            "blackcat",
            "akira",
            "wannacry",
            "wnry",
        ];

        if RANSOM_EXTS.contains(&ext) && !bytes.is_empty() {
            let entropy = Self::shannon_entropy(bytes);
            if entropy >= 7.2 {
                findings.push(ContentFinding {
                    category: "RANSOMWARE_ENCRYPTED_ARTIFACT".to_string(),
                    severity: "CRITICAL".to_string(),
                    indicator: format!(".{} (Entropy: {:.2} bits/byte)", ext, entropy),
                    description: format!(
                        "High-entropy ({:.2} b/B) file with known ransomware extension '.{}'",
                        entropy, ext
                    ),
                });
            }
        }

        let is_candidate_note_name = file_name.contains("decrypt_instructions")
            || file_name.contains("how_to_decrypt")
            || file_name.contains("restore_files")
            || file_name.contains("ransom_note")
            || file_name.ends_with("_readme.txt");

        if is_candidate_note_name {
            let text_lower =
                String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]).to_ascii_lowercase();
            const RANSOM_KEYWORDS: &[&str] = &[
                "bitcoin",
                "monero",
                "decrypt",
                "torproject",
                ".onion",
                "ransom",
                "btc",
                "wallet",
                "private key",
                "encrypted",
            ];
            let matched_keywords: usize = RANSOM_KEYWORDS
                .iter()
                .filter(|&&kw| text_lower.contains(kw))
                .count();

            // Require at least 2 distinct ransom note keywords inside the file body so normal
            // developer files like `project_readme.txt` are never falsely flagged (`BUG-CORE-05` #2).
            if matched_keywords >= 2 {
                findings.push(ContentFinding {
                    category: "RANSOMWARE_NOTE".to_string(),
                    severity: "HIGH".to_string(),
                    indicator: file_name.to_string(),
                    description: format!(
                        "Ransomware extortion note detected ({} ransom indicators in '{}')",
                        matched_keywords, file_name
                    ),
                });
            }
        }
    }

    fn scan_lnk_binary(bytes: &[u8], findings: &mut Vec<ContentFinding>) {
        let ascii_lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        let utf16_units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let utf16_lower = String::from_utf16_lossy(&utf16_units).to_ascii_lowercase();

        let combined = format!("{} {}", ascii_lower, utf16_lower);
        const LOLBINS: &[(&str, &str)] = &[
            ("powershell", "PowerShell execution via LNK shortcut"),
            ("pwsh", "PowerShell Core execution via LNK shortcut"),
            ("cmd.exe", "Command Prompt execution via LNK shortcut"),
            ("mshta", "MSHTA HTML Application execution via LNK shortcut"),
            ("wscript", "Windows Script Host execution via LNK shortcut"),
            ("cscript", "Console Script Host execution via LNK shortcut"),
            ("rundll32", "RunDLL32 proxy execution via LNK shortcut"),
            ("regsvr32", "Regsvr32 proxy execution via LNK shortcut"),
            ("certutil", "Certutil download/decode via LNK shortcut"),
            ("bitsadmin", "Bitsadmin transfer via LNK shortcut"),
        ];

        for &(bin, desc) in LOLBINS {
            if combined.contains(bin) {
                findings.push(ContentFinding {
                    category: "MALICIOUS_LNK_SHORTCUT".to_string(),
                    severity: "CRITICAL".to_string(),
                    indicator: bin.to_string(),
                    description: desc.to_string(),
                });
            }
        }
    }

    /// Streams through a PDF file in 64 KiB windows with a 64-byte overlap (`Row 70`, `BUG-CORE-03`, `BUG-CORE-05` #3)
    /// using token-boundary matching so `/JSON` or `/JSMath` is never confused with `/JS`,
    /// and flags `/Encrypt` password-protected PDFs for quarantine (`Row 76`).
    fn scan_pdf_reader<R: Read + Seek>(
        reader: &mut R,
        head_bytes: &[u8],
        findings: &mut Vec<ContentFinding>,
    ) {
        let mut saw_js = false;
        let mut saw_launch = false;
        let mut saw_auto = false;
        let mut saw_embed = false;
        let mut saw_encrypt = false;
        let mut saw_deep_nesting = false;
        let mut nesting_depth: usize = 0;
        let mut in_comment = false;
        let mut string_paren_depth: usize = 0;
        let mut escaped = false;
        let mut pending_lt = false;
        let mut pending_gt = false;

        let mut advance_nesting_lexer = |slice: &[u8]| {
            if saw_deep_nesting {
                return;
            }
            for &b in slice {
                if in_comment {
                    if b == b'\r' || b == b'\n' {
                        in_comment = false;
                    }
                    continue;
                }
                if string_paren_depth > 0 {
                    if escaped {
                        escaped = false;
                    } else if b == b'\\' {
                        escaped = true;
                    } else if b == b'(' {
                        string_paren_depth = string_paren_depth.saturating_add(1);
                    } else if b == b')' {
                        string_paren_depth = string_paren_depth.saturating_sub(1);
                    }
                    continue;
                }
                if pending_lt {
                    pending_lt = false;
                    if b == b'<' {
                        nesting_depth = nesting_depth.saturating_add(1);
                        if nesting_depth > 64 {
                            saw_deep_nesting = true;
                            return;
                        }
                        continue;
                    }
                }
                if pending_gt {
                    pending_gt = false;
                    if b == b'>' {
                        nesting_depth = nesting_depth.saturating_sub(1);
                        continue;
                    }
                }
                match b {
                    b'%' => in_comment = true,
                    b'(' => {
                        string_paren_depth = 1;
                        escaped = false;
                    }
                    b'[' => {
                        nesting_depth = nesting_depth.saturating_add(1);
                        if nesting_depth > 64 {
                            saw_deep_nesting = true;
                            return;
                        }
                    }
                    b']' => {
                        nesting_depth = nesting_depth.saturating_sub(1);
                    }
                    b'<' => pending_lt = true,
                    b'>' => pending_gt = true,
                    _ => {}
                }
            }
        };

        let mut check_window = |window: &[u8]| {
            if !saw_js
                && (Self::has_pdf_name_token(window, b"/JavaScript")
                    || Self::has_pdf_name_token(window, b"/JS"))
            {
                saw_js = true;
            }
            if !saw_launch && Self::has_pdf_name_token(window, b"/Launch") {
                saw_launch = true;
            }
            if !saw_auto
                && (Self::has_pdf_name_token(window, b"/OpenAction")
                    || Self::has_pdf_name_token(window, b"/AA"))
            {
                saw_auto = true;
            }
            if !saw_embed
                && (Self::has_pdf_name_token(window, b"/EmbeddedFiles")
                    || Self::has_pdf_name_token(window, b"/RichMedia"))
            {
                saw_embed = true;
            }
            if !saw_encrypt && Self::has_pdf_name_token(window, b"/Encrypt") {
                saw_encrypt = true;
            }
        };

        if reader.seek(std::io::SeekFrom::Start(0)).is_ok() {
            const WINDOW_SIZE: usize = 64 * 1024;
            const OVERLAP_SIZE: usize = 4 * 1024;
            let mut chunk = vec![0u8; WINDOW_SIZE];
            let mut overlap = Vec::with_capacity(OVERLAP_SIZE);
            let mut window = Vec::with_capacity(WINDOW_SIZE + OVERLAP_SIZE);
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        advance_nesting_lexer(&chunk[..n]);
                        window.clear();
                        window.extend_from_slice(&overlap);
                        window.extend_from_slice(&chunk[..n]);
                        check_window(&window);
                        overlap.clear();
                        let tail_start = n.saturating_sub(OVERLAP_SIZE);
                        overlap.extend_from_slice(&chunk[tail_start..n]);
                    }
                    Err(_) => {
                        advance_nesting_lexer(head_bytes);
                        check_window(head_bytes);
                        break;
                    }
                }
            }
        } else {
            advance_nesting_lexer(head_bytes);
            check_window(head_bytes);
        }

        if saw_deep_nesting {
            findings.push(ContentFinding {
                category: "PDF_DEEP_NESTING_ATTACK".to_string(),
                severity: "CRITICAL".to_string(),
                indicator: "PDF nesting depth > 64".to_string(),
                description:
                    "PDF array/dictionary nesting depth exceeded 64 levels (RUSTSEC-2026-0187 vector)"
                        .to_string(),
            });
        }

        if saw_encrypt {
            findings.push(ContentFinding {
                category: "ENCRYPTED_ARCHIVE_BLOCKED".to_string(),
                severity: "HIGH".to_string(),
                indicator: "Encrypted PDF (/Encrypt)".to_string(),
                description:
                    "Password-protected/encrypted PDF document blocked by default-deny allowlist"
                        .to_string(),
            });
        }
        if saw_js {
            findings.push(ContentFinding {
                category: "PDF_ACTIVE_CONTENT".to_string(),
                severity: "HIGH".to_string(),
                indicator: "/JavaScript or /JS".to_string(),
                description: "Embedded JavaScript execution dictionary inside PDF".to_string(),
            });
        }
        if saw_launch {
            findings.push(ContentFinding {
                category: "PDF_LAUNCH_ACTION".to_string(),
                severity: "CRITICAL".to_string(),
                indicator: "/Launch".to_string(),
                description: "PDF /Launch action capable of spawning OS commands".to_string(),
            });
        }
        if saw_auto {
            findings.push(ContentFinding {
                category: "PDF_AUTO_ACTION".to_string(),
                severity: "MEDIUM".to_string(),
                indicator: "/OpenAction or /AA".to_string(),
                description: "PDF automatic open/additional-action trigger".to_string(),
            });
        }
        if saw_embed {
            findings.push(ContentFinding {
                category: "PDF_EMBEDDED_ATTACHMENT".to_string(),
                severity: "MEDIUM".to_string(),
                indicator: "/EmbeddedFiles or /RichMedia".to_string(),
                description: "Embedded file stream or Flash/RichMedia inside PDF".to_string(),
            });
        }
    }

    /// Checks whether a PDF Name token (e.g. `/JS`) appears in `bytes` followed by a PDF
    /// delimiter or whitespace (never an ASCII letter/digit like `/JSON`).
    pub fn has_pdf_name_token(bytes: &[u8], token: &[u8]) -> bool {
        let tlen = token.len();
        if bytes.len() < tlen {
            return false;
        }
        for i in 0..=(bytes.len() - tlen) {
            if &bytes[i..i + tlen] == token {
                let next_byte = bytes.get(i + tlen).copied();
                let is_boundary = match next_byte {
                    None => true,
                    Some(b) => {
                        b.is_ascii_whitespace()
                            || matches!(b, b'/' | b'<' | b'>' | b'(' | b')' | b'[' | b']' | b'{')
                    }
                };
                if is_boundary {
                    return true;
                }
            }
        }
        false
    }

    /// Scans an OOXML / ZIP archive using a seekable reader so >4 MB archives are scanned
    /// without truncation (`BUG-CORE-03`, `Row 70`). Fails closed on corrupt/encrypted archives (`Row 74, 135`).
    pub fn scan_openxml_reader<R: Read + Seek>(reader: &mut R, findings: &mut Vec<ContentFinding>) {
        let _ = reader.seek(std::io::SeekFrom::Start(0));
        let mut archive = match ZipArchive::new(reader) {
            Ok(a) => a,
            Err(e) => {
                findings.push(ContentFinding {
                    category: "MALFORMED_OR_ENCRYPTED_ZIP".to_string(),
                    severity: "HIGH".to_string(),
                    indicator: "Corrupt or Encrypted ZIP Container".to_string(),
                    description: format!("Failed parsing ZIP/OOXML container (fail-closed): {}", e),
                });
                return;
            }
        };

        let mut reported_encrypted = false;
        for i in 0..archive.len().min(2048) {
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(zip::result::ZipError::UnsupportedArchive(msg))
                    if msg.to_ascii_lowercase().contains("password")
                        || msg.to_ascii_lowercase().contains("encrypt") =>
                {
                    if !reported_encrypted {
                        reported_encrypted = true;
                        findings.push(ContentFinding {
                            category: "ENCRYPTED_ARCHIVE_BLOCKED".to_string(),
                            severity: "HIGH".to_string(),
                            indicator: "Encrypted ZIP Entry".to_string(),
                            description:
                                "Password-protected/encrypted ZIP entry detected in central directory"
                                    .to_string(),
                        });
                    }
                    continue;
                }
                Err(e) => {
                    findings.push(ContentFinding {
                        category: "MALFORMED_OR_ENCRYPTED_ZIP".to_string(),
                        severity: "HIGH".to_string(),
                        indicator: "Corrupt ZIP Entry".to_string(),
                        description: format!(
                            "Failed reading ZIP entry #{} (fail-closed): {}",
                            i, e
                        ),
                    });
                    continue;
                }
            };
            let name = file.name().replace('\\', "/");
            let lower = name.to_ascii_lowercase();

            if lower.ends_with("vbaproject.bin") || lower.contains("/macrosheets/") {
                findings.push(ContentFinding {
                    category: "OFFICE_VBA_MACRO".to_string(),
                    severity: "HIGH".to_string(),
                    indicator: name.clone(),
                    description: format!("Embedded VBA Macro project detected at '{}'", name),
                });
                continue;
            }

            if lower.contains("embeddings/") || lower.contains("activex/") {
                findings.push(ContentFinding {
                    category: "OFFICE_EMBEDDED_OLE".to_string(),
                    severity: "HIGH".to_string(),
                    indicator: name.clone(),
                    description: format!(
                        "Embedded OLE/ActiveX binary object detected at '{}'",
                        name
                    ),
                });
                continue;
            }

            if lower.ends_with(".rels") || lower.ends_with(".xml") {
                let mut xml_buf = Vec::new();
                if (&mut file)
                    .take(512 * 1024)
                    .read_to_end(&mut xml_buf)
                    .is_ok()
                {
                    let xml_lower = String::from_utf8_lossy(&xml_buf).to_ascii_lowercase();
                    if lower.ends_with(".rels") {
                        let has_external_mode = xml_lower.contains("targetmode=\"external\"")
                            || xml_lower.contains("targetmode='external'")
                            || xml_lower.contains("targetmode = \"external\"")
                            || xml_lower.contains("targetmode = 'external'")
                            || xml_lower.contains("ms-msdt:")
                            || xml_lower.contains("mhtml:");

                        if has_external_mode {
                            findings.push(ContentFinding {
                                category: "OFFICE_EXTERNAL_RELATIONSHIP".to_string(),
                                severity: "CRITICAL".to_string(),
                                indicator: name.clone(),
                                description: format!(
                                    "External template/relationship target in '{}' (CVE-2022-30190 Follina vector)",
                                    name
                                ),
                            });
                        }
                    } else if xml_lower.contains("ddeauto")
                        || xml_lower.contains("<ddelink")
                        || xml_lower.contains("<externallink")
                        || xml_lower.contains("includepicture")
                        || xml_lower.contains("cmd|")
                    {
                        findings.push(ContentFinding {
                            category: "OFFICE_DDE_INJECTION".to_string(),
                            severity: "CRITICAL".to_string(),
                            indicator: name.clone(),
                            description: format!(
                                "Dynamic Data Exchange (DDE) or external field instruction in '{}'",
                                name
                            ),
                        });
                    }
                }
            }
        }
    }

    fn scan_ole2_reader<R: Read + Seek>(
        reader: &mut R,
        head_bytes: &[u8],
        findings: &mut Vec<ContentFinding>,
    ) {
        let mut saw_vba = false;
        let mut saw_encrypted = false;

        let mut check_chunk = |bytes: &[u8]| {
            let utf16_units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let utf16_lower = String::from_utf16_lossy(&utf16_units).to_ascii_lowercase();
            if utf16_lower.contains("_vba_project") || utf16_lower.contains("macros") {
                saw_vba = true;
            }
            if utf16_lower.contains("encryptedpackage")
                || utf16_lower.contains("strongencryptiondataspace")
            {
                saw_encrypted = true;
            }
        };

        if reader.seek(std::io::SeekFrom::Start(0)).is_ok() {
            const WINDOW_SIZE: usize = 64 * 1024;
            const OVERLAP_SIZE: usize = 4 * 1024;
            let mut chunk = vec![0u8; WINDOW_SIZE];
            let mut overlap = Vec::with_capacity(OVERLAP_SIZE);
            let mut window = Vec::with_capacity(WINDOW_SIZE + OVERLAP_SIZE);
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        window.clear();
                        window.extend_from_slice(&overlap);
                        window.extend_from_slice(&chunk[..n]);
                        check_chunk(&window);
                        overlap.clear();
                        let tail_start = n.saturating_sub(OVERLAP_SIZE);
                        overlap.extend_from_slice(&chunk[tail_start..n]);
                    }
                    Err(_) => {
                        check_chunk(head_bytes);
                        break;
                    }
                }
            }
        } else {
            check_chunk(head_bytes);
        }

        if saw_encrypted {
            findings.push(ContentFinding {
                category: "ENCRYPTED_ARCHIVE_BLOCKED".to_string(),
                severity: "HIGH".to_string(),
                indicator: "EncryptedPackage (OLE2)".to_string(),
                description:
                    "Password-protected/encrypted Office document blocked by default-deny allowlist"
                        .to_string(),
            });
        }
        if saw_vba {
            findings.push(ContentFinding {
                category: "OLE2_VBA_MACRO".to_string(),
                severity: "HIGH".to_string(),
                indicator: "_VBA_PROJECT".to_string(),
                description: "Legacy OLE2 Compound File Binary contains VBA Macro storage"
                    .to_string(),
            });
        }
    }

    fn scan_script_or_svg_reader<R: Read + Seek>(
        file_name: &str,
        ext: &str,
        head_bytes: &[u8],
        reader: &mut R,
        findings: &mut Vec<ContentFinding>,
    ) {
        if reader.seek(std::io::SeekFrom::Start(0)).is_ok() {
            const WINDOW_SIZE: usize = 64 * 1024;
            const OVERLAP_SIZE: usize = 4 * 1024;
            let mut chunk = vec![0u8; WINDOW_SIZE];
            let mut overlap = Vec::with_capacity(OVERLAP_SIZE);
            let mut window = Vec::with_capacity(WINDOW_SIZE + OVERLAP_SIZE);
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        window.clear();
                        window.extend_from_slice(&overlap);
                        window.extend_from_slice(&chunk[..n]);
                        Self::scan_script_or_svg(file_name, ext, &window, findings);
                        overlap.clear();
                        let tail_start = n.saturating_sub(OVERLAP_SIZE);
                        overlap.extend_from_slice(&chunk[tail_start..n]);
                    }
                    Err(_) => {
                        Self::scan_script_or_svg(file_name, ext, head_bytes, findings);
                        break;
                    }
                }
            }
        } else {
            Self::scan_script_or_svg(file_name, ext, head_bytes, findings);
        }
    }

    fn scan_script_or_svg(
        file_name: &str,
        ext: &str,
        bytes: &[u8],
        findings: &mut Vec<ContentFinding>,
    ) {
        let content_lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();

        if file_name == "autorun.inf"
            && (content_lower.contains("shellexecute")
                || content_lower.contains("open=")
                || content_lower.contains("shell\\open"))
        {
            findings.push(ContentFinding {
                category: "USB_AUTORUN_INF".to_string(),
                severity: "CRITICAL".to_string(),
                indicator: "autorun.inf".to_string(),
                description: "Legacy USB Autorun execution directive detected".to_string(),
            });
        }

        if ext == "svg"
            && (content_lower.contains("<script")
                || content_lower.contains("onload=")
                || content_lower.contains("onerror=")
                || content_lower.contains("javascript:"))
        {
            findings.push(ContentFinding {
                category: "SVG_SCRIPT_PAYLOAD".to_string(),
                severity: "HIGH".to_string(),
                indicator: "<script> / on* handler".to_string(),
                description: "Active JavaScript or event handler embedded inside SVG image"
                    .to_string(),
            });
        }

        const SCRIPT_PATTERNS: &[(&str, &str)] = &[
            (" -enc ", "Encoded PowerShell command line (-enc)"),
            (" -encodedcommand ", "Encoded PowerShell command line"),
            ("frombase64string", ".NET Base64 payload decoding in script"),
            (
                "invoke-expression",
                "PowerShell Invoke-Expression dynamic eval",
            ),
            (
                "downloadstring",
                "WebClient DownloadString in-memory cradle",
            ),
            ("wscript.shell", "WScript.Shell COM command execution"),
            ("amsiutils", "AMSI bypass reflection indicator"),
        ];

        for &(pat, desc) in SCRIPT_PATTERNS {
            if content_lower.contains(pat) {
                findings.push(ContentFinding {
                    category: "MALICIOUS_SCRIPT_CRADLE".to_string(),
                    severity: "CRITICAL".to_string(),
                    indicator: pat.trim().to_string(),
                    description: desc.to_string(),
                });
            }
        }
    }

    pub fn shannon_entropy(bytes: &[u8]) -> f32 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let len = bytes.len() as f64;
        let mut entropy = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = (c as f64) / len;
                entropy -= p * p.log2();
            }
        }
        entropy as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_pdf_reader_detects_deep_nesting_attack_rustsec_2026_0187() {
        let mut deep_pdf = b"%PDF-1.7\n1 0 obj\n".to_vec();
        deep_pdf.extend_from_slice(&b"[".repeat(80));
        deep_pdf.extend_from_slice(&b"]".repeat(80));
        deep_pdf.extend_from_slice(b"\nendobj\n%%EOF\n");

        let findings = ContentScanner::scan(Path::new("bomb.pdf"), &deep_pdf);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "PDF_DEEP_NESTING_ATTACK" && f.severity == "CRITICAL"),
            "ContentScanner::scan must emit PDF_DEEP_NESTING_ATTACK (CRITICAL) when nesting exceeds 64, got: {findings:?}"
        );

        let mut safe_pdf = b"%PDF-1.7\n1 0 obj\n(".to_vec();
        safe_pdf.extend_from_slice(&b"[".repeat(100));
        safe_pdf.extend_from_slice(b")\nendobj\n%%EOF\n");
        let safe_findings = ContentScanner::scan(Path::new("safe.pdf"), &safe_pdf);
        assert!(
            !safe_findings
                .iter()
                .any(|f| f.category == "PDF_DEEP_NESTING_ATTACK"),
            "Brackets inside PDF string literals must not trigger PDF_DEEP_NESTING_ATTACK"
        );
    }
}
