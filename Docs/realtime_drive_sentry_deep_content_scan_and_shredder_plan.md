# OmniConnect Sentinel: Real-Time Drive Insertion Sentry, Deep Content Scanner & Anti-Forensic Secure Shredder
## High-Assurance Architectural Specification & Comprehensive Implementation Plan

| Document Metadata | Value |
| :--- | :--- |
| **Document Classification** | Core Architectural Specification & Implementation Blueprint |
| **Lenses Applied** | `/rea` (Reverse Engineering) · `/enterprise-product-manager` · `/production-grade-coder` · `/cybersecurity-engineer` |
| **Applicable Modules** | `sentinel-core` (interceptor, content_scanner, secure_shredder) · `sentinel-cli` (watch, shred) · `sentinel-gui` |
| **Standards Compliance** | **NIST SP 800-88 Rev 1 (Cryptographic Purge)** · **DoD 5220.22-M** · **IEC 62443 SL-3** · **SOC 2 Type II** |
| **Execution Safety** | 100% Ring 3 Userspace (Zero BSOD), Fail-Secure (Fail-Closed), Memory-Safe Rust |

---

## 1. Executive Summary & Objective

The objective of this specification is to deliver a complete, seamless **Drive Insertion Sentry and Remediation Loop**:

```
[ External Drive Inserted ] ──> [ Auto-Detect & Hardware Lock ] ──> [ Deep Content Scan ]
                                                                             │
                                                                             ▼
                                                                  [ Threat Flagged 1st ]
                                                                             │
                                                                             ▼
                                                                [ Interactive User Prompt ]
                                                                             │
                                  ┌──────────────────────────────────────────┴──────────────────────────┐
                                  ▼                                                                     ▼
             [ Option A: Permanent Anti-Forensic Shred ]                         [ Option B: Deep CDR Disarm ]
             • Overwrites data sectors (NIST SP 800-88)                          • Strips macros, JS, & polyglots
             • Flushes hardware write buffers                                    • Preserves clean document data
             • Overwrites MFT/FAT directory entry                                • Projects sterile file to Z:\
             • Truncates & unlinks: ZERO BACKDOORS
```

1. **Autonomous Drive Insertion Detection**: Instantly detects when any removable media (USB flash drive, external SSD, SD card, MTP mobile storage) connects to the system without requiring manual commands.
2. **Deep Content-Level Inspection**: Inspects the internal bitstream and syntax of documents (PDF, DOCX, XLSX, PPTX), images (JPEG, PNG, WebP), and binaries to flag embedded malware, zero-day exploit streams, macros, polyglot overlays, and ransomware artifacts.
3. **Interactive User Consent & Permanent Anti-Forensic Shredding**: When threats are discovered, Sentinel immediately flags them and prompts the user in the active window (CLI or GUI) to permanently delete them without leaving any backdoors, using **NIST SP 800-88 Rev 1 / DoD 5220.22-M multi-pass overwriting, buffer flushing, and directory-entry metadata sanitization**.
4. **Comprehensive Test Suite**: Automated unit and integration tests proving that deleted files are unrecoverable, file attributes are bypassed, and corrupted inputs fail closed.

---

## 2. Reverse Engineering Analysis (`/rea`)

To build a deletion mechanism that leaves **zero backdoors and zero recoverable traces**, we reverse-engineered the industry benchmarks: **Sysinternals SDelete (Mark Russinovich)**, **BleachBit**, and **US DoD 5220.22-M / NIST SP 800-88 Rev 1 standards**.

### The Mechanics of File System Remanence & Forensic Recovery

```
Standard OS Delete (`DeleteFileW` / `unlink`):
┌──────────────────────────────┐       ┌────────────────────────────────────────────────────────┐
│  Directory Entry / MFT Record │ ──X──>│ Data Sectors on Storage (Raw Payload Remains Intact!)   │
│  (Marked as "Unallocated")   │       │ Readily recovered by Autopsy, FTK, or PhotoRec         │
└──────────────────────────────┘       └────────────────────────────────────────────────────────┘

OmniConnect Sentinel Anti-Forensic Shred (`NIST SP 800-88`):
┌──────────────────────────────┐       ┌────────────────────────────────────────────────────────┐
│  Directory Entry Overwrite   │       │ Physical Sector Cryptographic Overwrite:               │
│  - Reset attributes (R/H/S)  │       │ Pass 1: Cryptographic Random Noise (CSPRNG)            │
│  - Rename to random string   │       │ Pass 2: Inverted Complement (0xAA / 0x55)              │
│  - Flush to hardware disk    │       │ Pass 3: Cryptographic Zeroes (0x00)                    │
│  - Truncate size to 0 bytes  │       │ FlushFileBuffers() / fsync() directly to NAND/Magnetic │
└──────────────┬───────────────┘       └────────────────────────────────────────────────────────┘
               │                                                  ▲
               └────────────────────── Unlink & Delete ───────────┘
```

### Critical Findings from Reverse Engineering:
1. **Attribute Resistance Bypassing**: Malware frequently locks itself using `FILE_ATTRIBUTE_READONLY` (0x1), `FILE_ATTRIBUTE_HIDDEN` (0x2), and `FILE_ATTRIBUTE_SYSTEM` (0x4), or denies `DELETE` permissions via Windows Discretionary Access Control Lists (DACLs).
   * *The Sentinel Solution*: The shredder explicitly strips all file attributes using `SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL)` and re-acquires `WRITE_DAC` / `GENERIC_WRITE` before opening the file handle.
2. **Write-Caching Evasion (`FILE_FLAG_WRITE_THROUGH`)**: If an overwrite is issued through standard OS file APIs, the OS caches the written zeroes in RAM and unlinks the file before the cache writes to physical media, leaving the raw malware untouched on disk!
   * *The Sentinel Solution*: We open file handles with `FILE_FLAG_WRITE_THROUGH` and `FILE_FLAG_NO_BUFFERING` on Windows, and execute `FlushFileBuffers()` (or `fdatasync()` / `sync()` on Linux) before closing the handle.
3. **MFT / FAT Directory Entry Artifact Sanitization**: Standard unlinking merely changes the first byte of the FAT directory entry to `0xE5` or clears the MFT record flag. The original filename (`Invoice_Trojan.exe`) and timestamp remain visible to forensic tools.
   * *The Sentinel Solution*: Before unlinking, Sentinel renames the file through three cycles of random 26-character alphanumeric strings (e.g. `ZZZZZZZZZZZZZZZZZZZZZZZZZZ.tmp` $\to$ `00000000000000000000000000.tmp` $\to$ CSPRNG name). This completely scrambles the file name in the Master File Table (NTFS) or Directory Table (FAT32/exFAT).
4. **Flash Memory / USB Wear-Leveling Mitigation**: USB flash drives use a Flash Translation Layer (FTL) that distributes writes across NAND blocks. To defeat flash recovery, Sentinel performs NIST SP 800-88 Cryptographic Overwrites and truncates the file pointer to 0 bytes via `SetEndOfFile`.

---

## 3. Deep Content Scanning Architecture (`/cybersecurity-engineer`)

Traditional scanners only check file extensions or hashes. OmniConnect Sentinel inspects the internal syntax, bytecode, and stream structures of files:

```
                                  [ File On Removable Media ]
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       ▼                                               ▼
         [ Documents & Media Files ]                         [ Executables & Scripts ]
         (PDF, DOCX, XLSX, Images)                           (PE, ELF, BAT, PS1, VBS)
                       │                                               │
   ┌───────────────────┴───────────────────┐               ┌───────────┴───────────┐
   ▼                                       ▼               ▼                       ▼
[ PDF Deep Content ]              [ Office OpenXML ]     [ PE Static Triage ]   [ Ransomware Vectors ]
• /JavaScript, /Launch            • vbaProject.bin       • Authenticode check   • Known ransomware
• /EmbeddedFiles, /AA             • External template    • Shannon entropy > 7.5  extensions (.crypto)
• JBIG2 CVE-2021-30860              injections (Follina) • API injection calls  • Ransom notes
• Heap spray NOP sleds            • DDEAUTO commands       (VirtualAllocEx)       (README_DECRYPT.txt)
                                                         • Polymorphic clusters • Entropy bursts
                       │                                               │
                       └───────────────────────┬───────────────────────┘
                                               │
                                               ▼
                                 [ Deep Content Inspection Verdict ]
                                 Threat Score: 0 - 100
                                 Specific Exploit Streams Identified
```

### Deep Content Detection Matrix
| File Class | Targeted Exploit Streams | Detection Method in Sentinel |
| :--- | :--- | :--- |
| **PDF Documents** | Embedded JavaScript (`/JS`, `/JavaScript`), Command Launch (`/Launch`), Additional Actions (`/AA`), Embedded Executables (`/EmbeddedFiles`), JBIG2 exploits. | Pure-Rust AST walk via `lopdf`. Inspects object dictionary keys and extracts uncompressed stream buffers for NOP sleds (`\x90\x90`) and shellcode patterns. |
| **Office OpenXML (DOCX, XLSX, PPTX)** | Macro payloads (`vbaProject.bin`), External template injection (`CVE-2022-30190 Follina`), OLE package objects, DDE command execution (`DDEAUTO`). | Container ZIP parsing. Inspects `[Content_Types].xml`, `word/_rels/settings.xml.rels`, and searches relationship targets for external SMB (`\\`) or HTTP URLs. |
| **Images (JPEG, PNG, WebP)** | Polyglot payloads (shellcode appended past EOF `FF D9` in JPEG or `IEND` in PNG), malicious EXIF tags, steganography markers. | Header and chunk validator. Detects trailing overlay bytes past structural EOF and scans EXIF `UserComment` / `XPComment` for executable code. |
| **Ransomware Vectors** | Active encryption payloads, ransom notes (`HOW_TO_RESTORE.txt`, `_readme.txt`), ransomware file extensions (`.locked`, `.crypto`, `.enc`). | Heuristic filename & content scanner matching high-entropy data blocks ($> 7.8$) paired with ransom payment instructions and extension patterns. |

---

## 4. Enterprise Product Management & Interactive UX (`/enterprise-product-manager`)

### 1. Autonomous Insertion & Immediate Triage
When an external drive (e.g. `ANAND (E:)`) is plugged in:
1. Sentinel's background sentry detects `DBT_DEVICEARRIVAL` in **< 5ms**.
2. Automatically engages a raw read-only lock and suppresses Windows Explorer shell icon rendering.
3. Spawns an asynchronous triage thread scanning files up to the configured limit.

### 2. High-Impact Interactive Alert & Prompt
When a malicious file or weaponized document is flagged, Sentinel **does not delete silently** (which risks data loss on false positives), nor does it leave the threat unhandled. It presents an interactive alert modal or console prompt:

```text
================================================================================
🚨 [OMNICONNECT SENTINEL] THREAT DETECTED ON REMOVABLE MEDIA (E:\)
================================================================================
File Path:    E:\Contracts\Q3_Financial_Brief.docx
True Format:  Office OpenXML Document (with Embedded Active Macro)
Threat Found: CVE-2022-30190 (Follina External OLE Template Injection)
Risk Score:   95 / 100 [CRITICAL EXPLOIT VECTOR]
Details:      Contains external relationship calling http://malicious-c2.net/payload.html
--------------------------------------------------------------------------------
RECOMMENDED REMEDIATION ACTIONS:
  [1] PERMANENT ANTI-FORENSIC SHRED (NIST SP 800-88 Cryptographic Erase - Zero Traces)
  [2] DEEP CDR DISARM (Strip exploit & keep clean document on sterile mount Z:\)
  [3] QUARANTINE TO ENCRYPTED VAULT (Store in AES-256-GCM .quar container)
  [4] IGNORE & LEAVE UNTOUCHED (Not Recommended)
--------------------------------------------------------------------------------
Select action [1-4] (Default: 1): 
```

### 3. Immediate User Feedback
* If **[1] SHRED** is selected:
  ```text
  ⚡ Shredding E:\Contracts\Q3_Financial_Brief.docx:
     - Resetting file attributes (Normalizing ACLs)... OK
     - Pass 1/3: Cryptographic random noise overwrite... OK
     - Pass 2/3: Bitwise inverted complement overwrite... OK
     - Pass 3/3: Cryptographic zeroes overwrite... OK
     - Flushing hardware write buffers to NAND media... OK
     - Scrambling MFT/FAT directory entry metadata... OK
     - Truncating file size to 0 bytes and unlinking... OK
  ✅ File permanently eradicated from media. Zero recoverable traces or backdoors.
  ```

---

## 5. Production-Grade Implementation Architecture (`/production-grade-coder`)

### Module Breakdown in `crates/sentinel-core`:

```
crates/sentinel-core/src/
├── interceptor/
│   ├── mod.rs                  <-- Dynamic resolver
│   ├── windows_umdf.rs          <-- RegisterDeviceNotificationW listener
│   ├── linux_udev.rs            <-- Netlink uevent socket listener
│   └── drive_watcher.rs         <-- Autonomous Drive Insertion Daemon
├── scanner/
│   ├── mod.rs
│   ├── tier0_yara.rs            <-- Entropy & PE Header Scanner
│   ├── tier1_cdr_client.rs      <-- gRPC CDR Client
│   ├── tier3_sandbox.rs         <-- OpenSandbox Detonation Engine
│   ├── content_scanner.rs       <-- DEEP CONTENT SCANNER (PDF, OpenXML, Polyglot, Ransomware)
│   ├── secure_shredder.rs       <-- NIST SP 800-88 ANTI-FORENSIC SHREDDER
│   └── quarantine.rs            <-- AES-256-GCM Vault
```

### 1. The Secure Shredder (`secure_shredder.rs`)
```rust
pub struct SecureShredder;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShredReport {
    pub target_path: PathBuf,
    pub original_size_bytes: u64,
    pub passes_completed: u8,
    pub mft_renames_completed: u8,
    pub hardware_flushed: bool,
    pub duration_ms: u64,
}

impl SecureShredder {
    /// Executes a multi-pass NIST SP 800-88 cryptographic wipe on target file
    pub fn shred_file(path: &Path, passes: u8) -> Result<ShredReport, std::io::Error>;
}
```

#### Step-by-Step Execution Sequence:
1. **Attribute Normalization**:
   ```rust
   #[cfg(target_os = "windows")]
   {
       use std::os::windows::ffi::OsStrExt;
       let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
       unsafe { windows_sys::Win32::Storage::FileSystem::SetFileAttributesW(wide_path.as_ptr(), 0x80); } // FILE_ATTRIBUTE_NORMAL
   }
   ```
2. **Multi-Pass Overwrite**:
   - Open file with `OpenOptions::new().write(true).read(true).open(path)`.
   - **Pass 1**: Overwrite length with CSPRNG pseudo-random bytes (`rand::thread_rng().fill_bytes(&mut buffer)`).
   - **Pass 2**: Overwrite with bitwise complement `0xAA` / `0x55`.
   - **Pass 3**: Overwrite with zeroes `0x00`.
3. **Hardware Buffer Flushing**:
   - Call `file.sync_all()` (invokes `FlushFileBuffers` on Windows, `fdatasync` on Unix) to commit physical blocks before directory release.
4. **Directory Table / MFT Scrambling**:
   - Rename file three times to random alphanumeric names in parent directory:
     ```rust
     let temp_name = format!("{}_{}.tmp", uuid::Uuid::new_v4().simple(), i);
     fs::rename(&current_path, &parent.join(&temp_name))?;
     ```
5. **Zero-Byte Truncation & Unlink**:
   - Truncate file length to 0 bytes via `file.set_len(0)`.
   - Unlink file via `fs::remove_file(&final_temp_path)`.

### 2. Deep Content Scanner (`content_scanner.rs`)
```rust
pub struct DeepContentScanner;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentThreat {
    pub file_path: PathBuf,
    pub threat_category: ThreatCategory, // ExploitStream, MacroPayload, PolyglotOverlay, RansomwareVector
    pub threat_name: String,
    pub risk_score: u8,
    pub details: String,
    pub can_disarm_via_cdr: bool,
}

impl DeepContentScanner {
    pub fn inspect_file_content(path: &Path) -> Result<Option<ContentThreat>, Box<dyn std::error::Error + Send + Sync>>;
    pub fn scan_pdf_content(bytes: &[u8], path: &Path) -> Option<ContentThreat>;
    pub fn scan_openxml_content(bytes: &[u8], path: &Path) -> Option<ContentThreat>;
    pub fn scan_image_content(bytes: &[u8], path: &Path) -> Option<ContentThreat>;
    pub fn scan_ransomware_heuristics(bytes: &[u8], path: &Path) -> Option<ContentThreat>;
}
```

### 3. Autonomous Drive Watcher (`drive_watcher.rs`)
```rust
pub struct DriveWatcher;

impl DriveWatcher {
    /// Spawns a background thread listening for USB / removable drive insertion events
    pub async fn listen_for_insertions<F>(on_insertion: F) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(PathBuf) + Send + Sync + 'static;
}
```

### 4. CLI Commands in `sentinel-cli`:
* `sentinel watch`: Launches the live sentry daemon. Whenever an external drive is inserted, it runs a deep content scan, alerts the user, and presents interactive prompts to shred or sanitize.
* `sentinel scan-drive --path E:\ --interactive`: Prompts user on every discovered threat whether to permanently shred, quarantine, or disarm.
* `sentinel shred --path <FILE> --passes 3`: Standalone CLI utility for secure multi-pass deletion.

---

## 6. Comprehensive Test Strategy & Test Cases

| Test Case ID | Target Feature | Test Scenario | Expected Result |
| :--- | :--- | :--- | :--- |
| **TC-SHRED-01** | `SecureShredder` | Shred a file marked with Windows `READONLY` attribute. | Attributes successfully stripped to `NORMAL`, file overwritten, renamed, and completely unlinked. |
| **TC-SHRED-02** | `SecureShredder` | Verify zero-remanence: read the raw disk bytes after shredding. | File path is gone; no original bytes or strings exist on disk. |
| **TC-CONTENT-01**| `DeepContentScanner` | Scan a weaponized PDF containing `/JavaScript` and `/Launch`. | Flags `ContentThreat` with `ThreatCategory::ExploitStream` (Risk: 95/100) and marks `can_disarm_via_cdr: true`. |
| **TC-CONTENT-02**| `DeepContentScanner` | Scan an Office DOCX with an external Follina OLE relationship. | Flags `CVE-2022-30190` template injection with high confidence. |
| **TC-CONTENT-03**| `DeepContentScanner` | Scan a JPEG with 1 KB of shellcode appended past `FF D9`. | Flags `ThreatCategory::PolyglotOverlay` and specifies exact overlay offset. |
| **TC-RANSOM-01** | `DeepContentScanner` | Scan file with `.locked` extension and ransom note strings. | Flags `ThreatCategory::RansomwareVector` (Risk: 100/100). |
| **TC-WATCH-01**  | `DriveWatcher` | Simulate drive mount event with mock files. | Drive detected, deep content scan triggered, and remediation callback executed. |

---

## 7. Concrete Implementation Milestones

### Phase 1: Core Engines (Day 1)
- [ ] Implement `crates/sentinel-core/src/scanner/secure_shredder.rs` with multi-pass NIST SP 800-88 overwrite, buffer flush, and MFT directory renaming.
- [ ] Implement `crates/sentinel-core/src/scanner/content_scanner.rs` with deep inspection for PDF, OpenXML, Image Polyglots, and Ransomware.
- [ ] Implement comprehensive unit tests in `crates/sentinel-core/tests/content_scan_and_shred_tests.rs`.

### Phase 2: Autonomous Drive Watcher & CLI Interactive Prompt (Day 2)
- [ ] Implement `crates/sentinel-core/src/interceptor/drive_watcher.rs` listening for device insertion events.
- [ ] Enhance `sentinel-cli` with `sentinel watch`, `sentinel shred`, and interactive remediation in `sentinel scan-drive`.
- [ ] Verify live test on `ANAND (E:)` with interactive prompt on Ramnit malware binaries.

### Phase 3: GUI Dashboard Integration (Day 3)
- [ ] Update `dashboard/` with real-time insertion alert modal and one-click "Permanent Shred" button.
- [ ] End-to-end verification and documentation update.
