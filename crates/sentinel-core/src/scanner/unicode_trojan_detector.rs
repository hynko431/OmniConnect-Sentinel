use std::path::Path;
use super::universal_scanner::{UniversalThreat, CarrierCategory, ThreatSeverity};

pub struct UnicodeTrojanDetector;

impl UnicodeTrojanDetector {
    /// Inspects file names and path components for deceptive Unicode BiDi overrides, zero-width characters, and DOS devices
    pub fn inspect_path(path: &Path) -> Option<UniversalThreat> {
        let filename = match path.file_name() {
            Some(name) => name.to_string_lossy(),
            None => return None,
        };

        // 1. Unicode BiDi Override Check (CVE-2021-42574)
        for c in filename.chars() {
            if matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}') {
                return Some(UniversalThreat {
                    file_path: path.to_path_buf(),
                    carrier_category: CarrierCategory::FilesystemHidden,
                    threat_name: "Unicode Trojan Source: Bidirectional Override (BiDi)".to_string(),
                    severity: ThreatSeverity::Critical,
                    risk_score: 99,
                    mitre_technique: "T1036.002 (Right-to-Left Override)".to_string(),
                    technical_details: format!(
                        "Filename contains deceptive Unicode control char U+{:04X}. Visually inverts characters to camouflage actual file extension.",
                        c as u32
                    ),
                    overlay_offset: None,
                    stream_name: None,
                    can_disarm_via_cdr: false,
                });
            }
        }

        // 2. Zero-Width Spaces Check
        for c in filename.chars() {
            if matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}') {
                return Some(UniversalThreat {
                    file_path: path.to_path_buf(),
                    carrier_category: CarrierCategory::FilesystemHidden,
                    threat_name: "Filesystem Cloaking: Zero-Width Unicode Characters".to_string(),
                    severity: ThreatSeverity::High,
                    risk_score: 85,
                    mitre_technique: "T1564.001 (Hidden Files and Directories)".to_string(),
                    technical_details: format!(
                        "Filename embeds invisible zero-width character U+{:04X} to evade file string matching.",
                        c as u32
                    ),
                    overlay_offset: None,
                    stream_name: None,
                    can_disarm_via_cdr: false,
                });
            }
        }

        // 3. DOS Reserved Device Names (CON, PRN, AUX, NUL, COM1..9, LPT1..9)
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_uppercase())
            .unwrap_or_default();

        let is_reserved_dos = matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" |
            "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" |
            "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
        );

        if is_reserved_dos {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::FilesystemHidden,
                threat_name: "DOS Reserved Device Name Exploitation".to_string(),
                severity: ThreatSeverity::High,
                risk_score: 88,
                mitre_technique: "T1564.001 (Hidden Files and Directories)".to_string(),
                technical_details: format!(
                    "Filename uses reserved device name '{}', causing standard OS deletion APIs to fail without extended UNC pathing.",
                    stem
                ),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        // 4. CLSID GUID Folder Cloaking
        if filename.contains(".{") && filename.ends_with('}') {
            return Some(UniversalThreat {
                file_path: path.to_path_buf(),
                carrier_category: CarrierCategory::FilesystemHidden,
                threat_name: "Windows Shell CLSID Directory Cloaking".to_string(),
                severity: ThreatSeverity::High,
                risk_score: 92,
                mitre_technique: "T1564.001 (Hidden Files and Directories)".to_string(),
                technical_details: "Folder leverages Windows Shell CLSID suffix to redirect Windows Explorer clicks to system applets.".to_string(),
                overlay_offset: None,
                stream_name: None,
                can_disarm_via_cdr: false,
            });
        }

        None
    }

    /// Inspects source code or script content bytes for embedded Trojan Source BiDi overrides
    pub fn inspect_content(path: &Path, content: &[u8]) -> Option<UniversalThreat> {
        let text = String::from_utf8_lossy(content);
        for c in text.chars() {
            if matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}') {
                return Some(UniversalThreat {
                    file_path: path.to_path_buf(),
                    carrier_category: CarrierCategory::ScriptCode,
                    threat_name: "Source Code Trojan Source (CVE-2021-42574)".to_string(),
                    severity: ThreatSeverity::Critical,
                    risk_score: 97,
                    mitre_technique: "T1036.002 (Right-to-Left Override)".to_string(),
                    technical_details: format!(
                        "File contains embedded BiDi control U+{:04X}. Visually inverts logic seen by human reviewers while compiler interprets raw instructions.",
                        c as u32
                    ),
                    overlay_offset: None,
                    stream_name: None,
                    can_disarm_via_cdr: false,
                });
            }
        }
        None
    }
}
