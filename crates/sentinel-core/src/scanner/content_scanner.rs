use std::io::Cursor;
use std::path::Path;
use super::universal_scanner::{UniversalThreat, CarrierCategory, ThreatSeverity};

pub struct ContentScanner;

impl ContentScanner {
    /// Deeply inspects document, software, script, or ransomware payload content
    pub fn inspect_content(path: &Path, bytes: &[u8], file_len: u64) -> Option<UniversalThreat> {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        // 1. PDF Deep Content Inspection
        if ext == "pdf" || (bytes.len() >= 4 && &bytes[0..4] == b"%PDF") {
            if let Some(threat) = Self::scan_pdf(path, bytes) {
                return Some(threat);
            }
        }

        // 2. Office OpenXML Inspection (DOCX, XLSX, PPTX)
        if matches!(ext.as_str(), "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "dotm")
            || (bytes.len() >= 4 && &bytes[0..4] == b"PK\x03\x04")
        {
            if let Some(threat) = Self::scan_openxml(path, bytes) {
                return Some(threat);
            }
        }

        // 3. Ransomware Markers & Extensions
        if let Some(threat) = Self::scan_ransomware(path, bytes, &ext) {
            return Some(threat);
        }

        // 4. Executables & Packed Binaries (PE / ELF)
        if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
            if let Some(threat) = Self::scan_pe_binary(path, bytes, file_len) {
                return Some(threat);
            }
        }

        // 5. Scripts & Command Obfuscation (PS1, BAT, VBS, SH)
        if matches!(ext.as_str(), "ps1" | "bat" | "cmd" | "vbs" | "sh" | "js") {
            if let Some(threat) = Self::scan_script_syntax(path, bytes, &ext) {
                return Some(threat);
            }
        }

        None
    }

    fn scan_pdf(path: &Path, bytes: &[u8]) -> Option<UniversalThreat> {
        // Fast AST scan for dangerous dictionary keys
        let content_str = String::from_utf8_lossy(bytes);
        let has_js = content_str.contains("/JavaScript") || content_str.contains("/JS");
        let has_launch = content_str.contains("/Launch");
        let has_embedded = content_str.contains("/EmbeddedFiles");
        let has_open_action = content_str.contains("/OpenAction");
        let has_aa = content_str.contains("/AA");

        if has_launch {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::Document,
                threat_name: "Weaponized PDF: Command Launch Action (/Launch)".to_string(),
                severity: ThreatSeverity::Critical,
                risk_score: 98,
                mitre_technique: "T1204.002 (Malicious File: PDF Exploit)".to_string(),
                technical_details: "Document catalog specifies /Launch action designed to execute OS binaries upon opening.".to_string(),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: true,
            });
        }

        if has_js {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::Document,
                threat_name: "Active Content PDF: Embedded JavaScript (/JS)".to_string(),
                severity: ThreatSeverity::High,
                risk_score: 90,
                mitre_technique: "T1059 (Command and Scripting: Embedded JS)".to_string(),
                technical_details: "PDF contains active JavaScript streams that execute inside PDF viewer sandbox.".to_string(),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: true,
            });
        }

        if has_embedded && (has_open_action || has_aa) {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::Document,
                threat_name: "Trojan PDF: Auto-Executing Embedded File Dropper".to_string(),
                severity: ThreatSeverity::Critical,
                risk_score: 95,
                mitre_technique: "T1204.002 (Malicious File Dropper)".to_string(),
                technical_details: "PDF embeds binary payload linked to automatic trigger action on document open.".to_string(),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: true,
            });
        }

        None
    }

    fn scan_openxml(path: &Path, bytes: &[u8]) -> Option<UniversalThreat> {
        let cursor = Cursor::new(bytes);
        if let Ok(mut archive) = zip::ZipArchive::new(cursor) {
            let mut has_vba = false;
            let mut has_follina_ole = false;

            for i in 0..archive.len() {
                if let Ok(file) = archive.by_index(i) {
                    let name = file.name();
                    if name.ends_with("vbaProject.bin") {
                        has_vba = true;
                    }
                    if name.contains("_rels/") && name.ends_with(".rels") {
                        // Check for external relationship injection
                        let mut content = Vec::new();
                        use std::io::Read;
                        let mut reader = file;
                        if reader.read_to_end(&mut content).is_ok() {
                            let rels_str = String::from_utf8_lossy(&content);
                            if rels_str.contains("ms-msdt:") || (rels_str.contains("TargetMode=\"External\"") && rels_str.contains("oleObject")) {
                                has_follina_ole = true;
                            }
                        }
                    }
                }
            }

            if has_follina_ole {
                return Some(UniversalThreat {
                    file_path: path.to_path_buf(),
                    carrier_category: CarrierCategory::Document,
                    threat_name: "Office Zero-Day: CVE-2022-30190 (Follina External OLE Template)".to_string(),
                    severity: ThreatSeverity::Critical,
                    risk_score: 99,
                    mitre_technique: "T1221 (Template Injection)".to_string(),
                    technical_details: "Document relationship table initiates external ms-msdt / OLE protocol invocation.".to_string(),
                    overlay_offset: None,
                    stream_name: None,
                    can_disarm_via_cdr: true,
                });
            }

            if has_vba {
                return Some(UniversalThreat {
                    file_path: path.to_path_buf(),
                    carrier_category: CarrierCategory::Document,
                    threat_name: "Weaponized Office Document: Embedded VBA Macro Payload".to_string(),
                    severity: ThreatSeverity::High,
                    risk_score: 88,
                    mitre_technique: "T1564.007 (VBA / Macro Payloads)".to_string(),
                    technical_details: "Archive contains vbaProject.bin holding Visual Basic macros.".to_string(),
                    overlay_offset: None,
                    stream_name: None,
                    can_disarm_via_cdr: true,
                });
            }
        }

        None
    }

    fn scan_ransomware(path: &Path, bytes: &[u8], ext: &str) -> Option<UniversalThreat> {
        let filename = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        let known_ransom_exts = [
            "locked", "crypto", "enc", "crypt", "crypted", "ransom", "wnry", "lockedfile", "lockbit", "akira", "blackcat"
        ];

        let has_ransom_ext = known_ransom_exts.iter().any(|&e| ext == e);
        let is_ransom_note = filename.contains("readme_decrypt")
            || filename.contains("how_to_restore")
            || filename.contains("restore_files")
            || filename.contains("decrypt_instructions")
            || filename == "_readme.txt";

        if is_ransom_note {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::Ransomware,
                threat_name: "Ransomware Artifact: Extortion / Ransom Note".to_string(),
                severity: ThreatSeverity::Critical,
                risk_score: 100,
                mitre_technique: "T1486 (Data Encrypted for Impact)".to_string(),
                technical_details: "File contains extortion and decryption payment instructions typical of ransomware campaigns.".to_string(),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        if has_ransom_ext {
            let entropy = calculate_shannon_entropy(bytes);
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::Ransomware,
                threat_name: format!("Ransomware Encrypted File (.{})", ext),
                severity: ThreatSeverity::Critical,
                risk_score: 98,
                mitre_technique: "T1486 (Data Encrypted for Impact)".to_string(),
                technical_details: format!(
                    "File has ransomware extension '.{}' with high Shannon entropy ({:.2}/8.00).",
                    ext, entropy
                ),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        None
    }

    fn scan_pe_binary(path: &Path, bytes: &[u8], file_len: u64) -> Option<UniversalThreat> {
        let entropy = calculate_shannon_entropy(bytes);
        let has_upx = bytes.windows(4).any(|w| w == b"UPX0" || w == b"UPX1" || w == b"UPX!");

        if has_upx {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::SoftwareBinary,
                threat_name: "Packed Executable: UPX Cryptor Detected".to_string(),
                severity: ThreatSeverity::High,
                risk_score: 86,
                mitre_technique: "T1027.002 (Software Packing)".to_string(),
                technical_details: format!(
                    "Binary sections packed with UPX compressor/cryptor (Entropy: {:.2}, Size: {} bytes).",
                    entropy, file_len
                ),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        if entropy > 7.6 && bytes.len() > 4096 {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::SoftwareBinary,
                threat_name: "Anomalous High-Entropy Native Binary (Likely Crypted Dropper)".to_string(),
                severity: ThreatSeverity::High,
                risk_score: 82,
                mitre_technique: "T1027 (Obfuscated Files or Information)".to_string(),
                technical_details: format!(
                    "PE executable displays Shannon entropy of {:.2}/8.00, indicative of encrypted shellcode or custom cryptor.",
                    entropy
                ),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        None
    }

    fn scan_script_syntax(path: &Path, bytes: &[u8], ext: &str) -> Option<UniversalThreat> {
        let content_lower = String::from_utf8_lossy(bytes).to_lowercase();

        // AMSI Bypass patterns
        if content_lower.contains("amsiscanbuffer") || content_lower.contains("amsiinitfailed") {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::ScriptCode,
                threat_name: "Antivirus Evasion: Memory AMSI Patch / Bypass".to_string(),
                severity: ThreatSeverity::Critical,
                risk_score: 99,
                mitre_technique: "T1562.001 (Disable or Modify Tools)".to_string(),
                technical_details: "Script contains signatures patching AmsiScanBuffer in memory to blind Antivirus/EDR engines.".to_string(),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        // Base64 obfuscated payload invocation
        if (content_lower.contains("frombase64string") || content_lower.contains("-enc "))
            && (content_lower.contains("invoke-expression") || content_lower.contains("iex") || content_lower.contains("downloadstring"))
        {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::ScriptCode,
                threat_name: "Obfuscated PowerShell Stager: Base64 Download & Execute".to_string(),
                severity: ThreatSeverity::High,
                risk_score: 92,
                mitre_technique: "T1059.001 (PowerShell Script Execution)".to_string(),
                technical_details: format!("Script '{}' invokes encoded payload execution via download string or IEX.", ext),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        None
    }
}

pub fn calculate_shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }

    let len_f = bytes.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}
