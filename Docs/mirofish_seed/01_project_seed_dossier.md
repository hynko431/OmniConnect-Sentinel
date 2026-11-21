# MiroFish Project Seed Dossier: OmniConnect Sentinel

> **Purpose:** Ground-truth seed dossier for multi-agent AI world validation (`666ghj/MiroFish` and Antigravity Multi-Agent Adversarial World Simulation). Engineered to avoid GraphRAG confirmation bias by presenting **verified engineering capabilities alongside concrete architectural constraints, commercial assumptions, and unvalidated market claims**.

---

## 1. Project Identity & Core Value Proposition
- **Project Name:** OmniConnect Sentinel (`v0.1.0` Cargo workspace / dashboard branded `v2.4.0 Ring 3`)
- **Category:** Endpoint & OT/ICS Removable Media / Peripheral Zero-Trust Security Platform
- **Tech Stack:** Pure Rust (`Cargo` workspace, Rust 2021 edition, `#![forbid(unsafe_code)]` on 4 of 5 crates; OS FFI isolated in `sentinel-sys`), Windows + Linux targets.
- **Core Pitch:** Replaces reactive post-mount antivirus scanning and \$50k+ dedicated hardware kiosks with a **100% Ring 3 userspace** (zero custom kernel driver `.sys`/`.ko`) software platform providing:
  1. **Pre-Mount Hardware Hold (`I1`)**: Disables OS auto-mount (`IOCTL_MOUNTMGR_SET_AUTO_MOUNT`, `IOCTL_VOLUME_OFFLINE`, `DeleteVolumeMountPointW`, `NoDriveTypeAutoRun=0xFF`, `DisableAutoplay=1` on Windows; `udev` / `authorized=0` / `UDISKS_IGNORE=1` on Linux) for `BusTypeUsb (0x07)` storage before userspace access.
  2. **Read-Once Encrypted ShadowCache (`I2`)**: Reads each USB file once into a host-local `AES-256-GCM` `.enc` cache (`512 MiB` / `10,000` file session cap, `ZeroizingBytes<32>` pinned RAM key) to defeat USB microcontroller block-switching TOCTOU attacks.
  3. **Userspace Virtual Filesystem Projection**: Projects sanitized files via inbox Windows **ProjFS** (`ProjectedFSLib.dll`, optional Windows feature `Client-ProjFS`) with read-only staging fallback + Mark-of-the-Web (`ZoneId=3`), or Linux **FUSE3** (`ro,nosuid,nodev,noexec`).
  4. **Out-of-Process Sandboxed Pure-Rust CDR (`I4`)**: Spawns an ephemeral `sentinel-cdr-worker` per file inside Win32 Zero-Capability AppContainer + Job Object (`256 MiB` RAM, `30s` deadline, `ActiveProcess=1`, ACG/CIG) or Linux `seccomp-bpf` + namespaces + Landlock to mathematically disassemble & rebuild PDF (`lopdf`), Office OpenXML (`.docx`/`.xlsx`/`.pptx`), SVG, Raster images (`JPEG`/`PNG`/`WebP`), and plain text/CSV. Default-deny blocks `.iso`, `.vhd`, `.vhdx`, `.img`, `.cab`, `.7z`, `.rar`, `.lnk`, `.svg`, `.doc`.
  5. **Hardware-Sealed Quarantine Vault & Audit Ledger (`I5`)**: `.quar` (`SNTLQV02`) AES-256-GCM envelopes with AAD header binding, HKDF-SHA256 DEK wrapping, TPM 2.0 (`NCrypt`) / Machine DPAPI (Windows) or root-only `0400` file keyring (Linux), offline RSA-2048-OAEP SOC escrow, and SHA-256 hash-chained JSONL audit ledger signed with ECDSA P-256 (`p256` / CNG).
  6. **NIST SP 800-88 Anti-Forensic Shredder**: 3-pass write-through overwrite (`0x00`, `0xFF`, `OsRng`) + read-back SHA-256 verify + `FSCTL_FILE_LEVEL_TRIM` + 3-cycle filename scrambling, labeled honestly as `Clear (logical)` on flash media, plus `Cryptographic Erase` for `.enc`/`.quar`.
  7. **Out-of-Band Behavioral Detonation (`tier3_sandbox.rs`)**: Claims microVM detonation (`WHVP`/`KVM` OpenSandbox) with explicit `SANDBOX_OFFLINE_EMULATED` degradation fallback when hypervisor is unavailable.
  8. **Enterprise Integration & Surfaces**: CLI (`sentinel`), endpoint daemon (`sentinel-agent`), gRPC CDR daemon over ACL'd Named Pipe (`sentinel-cdr-daemon`), Microsoft Intune OMA-URI SyncML export, CrowdStrike Falcon FDR NDJSON & ArcSight CEF streaming, IEC 62443-3-3 SL-3 Air-Gapped Kiosk mode (`sentinel kiosk`), and Localhost Cyber Defense Station UI (`127.0.0.1:8088` web + Rune native GPU desktop UI).

---

## 2. Stated Business Model & Market Positioning (from ADR-004 & README)
- **Target Segments:**
  - *Mode A (Air-Gapped Industrial Kiosk)*: Substations, SCADA/ICS control rooms, defense SCIFs, manufacturing floors (competing against \$50k+ OPSWAT MetaDefender Kiosk / Honeywell SMX / Fortinet / air-gap appliances).
  - *Mode B (Managed Enterprise Endpoint Fleet)*: Corporate Windows 11 & Ubuntu/RHEL developer/executive laptops (competing against Microsoft Defender for Endpoint / Intune USB Device Control, CrowdStrike Falcon Device Control, SentinelOne, Trellix DLP, Forcepoint, OPSWAT MetaDefender Endpoint).
- **Proposed Monetization (ADR-004 §3):**
  - *Community / Prosumer*: Free on-device CDR.
  - *Enterprise B2B*: Multi-tenant OpenSandbox + Intune/Falcon SIEM feeds at **\$8–\$18 / seat / month**.
  - *Air-Gapped Kiosk*: Dedicated walk-up media inspection station for critical infrastructure.
- **Compliance & Regulatory Claims in Docs:**
  - NIST SP 800-88 Rev 1 / Rev 2, NIST SP 800-53 Rev 5, NIST SP 800-207, IEC 62443-3-3 SL-3, SOC 2 Type II, ISO/IEC 27001:2022, CIS Controls v8, HIPAA, GDPR Art. 25, India DPDP Act 2023 & CERT-In 180-day log retention, FIPS 186-5 ECDSA P-256, SLSA v1.0, CycloneDX SBOM/CBOM.

---

## 3. Explicit Technical & Operational Facts (For Adversarial Stress-Testing)
1. **Ring 3 Architecture Trade-Off**: Zero custom kernel drivers eliminates BSOD risk and WHQL/EV kernel driver signing costs, **but** relies on OS-provided global knobs (`MountMgr` auto-mount disable, registry policies, `udev` rules, `Client-ProjFS` optional feature) and polling/UMDF-level userspace APIs rather than a minifilter (`FltMgr`) or USB bus filter driver.
2. **ShadowCache Quotas**: Hard-capped at `512 MiB` total disk and `10,000` files per session; CDR worker capped at `256 MiB` RAM and `30 s` wall-clock timeout; ZIP entries capped at `4,096` and `5:1` decompression ratio.
3. **Supported vs. Blocked Formats**: Pure-Rust CDR supports PDF, OpenXML (`.docx`/`.xlsx`/`.pptx`), JPEG/PNG/WebP, SVG (blocked by default), OLE2 (inspection/block), plain text/CSV. Default-deny blocks `.iso`, `.vhd`, `.img`, `.7z`, `.rar`, `.cab`, `.lnk`, `.doc`, and unsigned binaries.
4. **USB Bus & Peripheral Scope**: Focuses on `BusTypeUsb (0x07)` storage volumes; BadUSB HID challenge-response exists in software (`confirm-device`), while physical pin-decoupling schematic in UI is userspace visualization/emulation unless paired with external relay hardware.
5. **Cryptographic Implementation**: Uses RustCrypto crates (`aes-gcm`, `p256`, `rsa`, `ml-kem`, `sha2`, `hkdf`, `hmac`) + Windows CNG/DPAPI where available; none of the pure-Rust crates hold independent **FIPS 140-3 CMVP** module validation certificates.
6. **Platform Coverage**: Windows & Linux implemented; macOS DriverKit / EndpointSecurity and mobile (iOS/Android) mentioned in ADR-004 vision ("Can Be Used Anywhere") but not implemented in the workspace crates.
7. **Enterprise Fleet Control Plane**: Intune SyncML XML export and local signed policy bundle verification exist, **but** there is no central cloud/on-prem fleet management server, console, RBAC, remote break-glass approval workflow, or fleet-wide telemetry database yet.
8. **Sandboxing / Detonation Reality**: `tier3_sandbox.rs` implements a microVM contract with `SANDBOX_OFFLINE_EMULATED` fallback rather than shipping a full production WHVP/KVM guest OS image pipeline with Sysmon/INetSim out of the box.

---

## 4. Core Validation Questions for the AI Agents World
1. **Security & Adversarial Reality:** Can a motivated attacker bypass OmniConnect Sentinel's Ring 3 controls, pre-mount hold, BadUSB protections, CDR parsers, ProjFS/FUSE projection, or localhost UI?
2. **Enterprise Procurement & Competitive Moats:** Why would a Fortune 500 CISO pay \$8–\$18/seat/month for a standalone USB/CDR agent on top of Microsoft E5 / CrowdStrike Falcon / OPSWAT?
3. **Operational & IT Deployment Friction:** What breaks across a 50,000-device enterprise fleet or an air-gapped industrial SCADA plant when global `MountMgr` auto-mount disable, `Client-ProjFS`, `512 MiB` caps, and default-deny CDR hit real workflows?
4. **User Rebellion & Shadow IT:** How do engineers, field technicians, and executives bypass or force rollback of Sentinel within 30 days?
5. **Compliance, Legal & Liability Exposure:** Which regulatory/standards claims (FIPS, IEC 62443 SL-3, NIST 800-88, SOC 2, HIPAA) fail audit scrutiny or create legal liability if CDR corrupts critical files?
6. **Product Strategy & Pivot Verdict:** Is the core idea viable as-is, fatally flawed in Mode B (corporate laptops), or viable ONLY if pivoted to a razor-sharp niche (e.g., Mode A air-gapped OT/ICS kiosk + software-defined media transfer station, or OEM SDK)?
