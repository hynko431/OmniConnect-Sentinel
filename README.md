# OmniConnect Sentinel

**Universal Zero-Trust Peripheral, Wireless & Wire Connection Threat Interceptor & Deep CDR Engine**

---

## 🚀 Architecture Overview

OmniConnect Sentinel is an enterprise-grade endpoint security system that replaces post-mount antivirus scanning with **zero-trust pre-mount interception and Deep Content Disarm & Reconstruction (CDR)**. It reverse-engineers the security model of dedicated industrial air-gap kiosks (OPSWAT MetaDefender) and adapts it into a lightweight, 100% userspace daemon across **Windows, Linux, macOS, and Android**.

```
omni-sentinel/
├── Cargo.toml                      # Root Cargo Workspace
├── crates/
│   ├── sentinel-proto/             # Protocol Buffers & gRPC Streaming Definitions
│   │   ├── proto/sentinel_cdr.proto
│   │   └── build.rs
│   ├── sentinel-cdr/               # Pure-Rust Deep CDR Microservice Daemon
│   │   ├── src/sanitizers/pdf.rs   # PDF AST deconstruction & re-linearization
│   │   ├── src/sanitizers/openxml.rs# Office OpenXML (DOCX/XLSX) macro/template stripping
│   │   ├── src/sanitizers/image.rs # JPEG/PNG/WebP re-encoding & overlay truncation
│   │   ├── src/engine.rs           # Core dispatch coordinator
│   │   └── src/service.rs          # Bi-directional gRPC streaming service
│   ├── sentinel-core/              # Core Agent Daemon
│   │   ├── src/interceptor/        # Windows UMDF v2 & Linux udev Userspace Interceptors
│   │   ├── src/vfs/                # ProjFS & WinFsp Virtual Storage Providers
│   │   ├── src/scanner/            # Tier 0 YARA triage + Tier 1 gRPC CDR Client
│   │   ├── src/enterprise/         # Microsoft Intune CSP & CrowdStrike Falcon Bridges
│   │   └── src/scanner/quarantine.rs# AES-256-GCM Cryptographic Vault
│   └── sentinel-cli/               # Developer & SecOps CLI tool
```

---

## 🛡️ Key Technical Pillars

1. **Zero BSOD Userspace Interception**:
   - **Windows**: UMDF v2 + Windows Projected File System (`ProjFS`) with `WinFsp` fallback. Suppresses AutoPlay and isolates the device before Windows Explorer mounts it.
   - **Linux**: `udev` netlink rules (`ATTR{authorized}="0"`) with Rust-FUSE virtual mounts.
   - **macOS**: DriverKit `IOUserServer` dext + `DiskArbitration.framework` approval callbacks.
   - **Android**: `UsbManager` Host API with exclusive interface claims.

2. **Native Rust Deep CDR (`sentinel-cdr`)**:
   - Reconstructs files to known-good specifications (ISO 32000 for PDF, ECMA-376 for Office, ISO/IEC 10918 for JPEG).
   - Strips active macros, JavaScript, embedded files, external template injections (CVE-2022-30190), and truncates steganographic overlay bytes past EOF.
   - Operates over high-speed bi-directional gRPC streams.

3. **Enterprise Telemetry & MDM**:
   - Synchronizes policy profiles via **Microsoft Intune Custom CSPs**.
   - Streams real-time peripheral forensic telemetry to **CrowdStrike Falcon FDR/XDR** and triggers automated network containment playbooks for critical threats.

---

## 📦 Building & Running

### Prerequisites
- Rust 1.78+ (`rustup install stable`)
- Protocol Buffers Compiler (`protoc` in PATH)

### Build All Crates
```bash
cargo build --release
```

### Start Standalone CDR Daemon
```bash
cargo run --bin sentinel-cdr-daemon
```

### Run the Sentinel Agent
```bash
cargo run --bin sentinel-agent
```

### Test File Sanitization with CLI
```bash
# Sanitize a weaponized or macro-laden PDF
cargo run --bin sentinel -- sanitize --input malicious.pdf --output clean.pdf

# Inspect file format and polyglot risk markers
cargo run --bin sentinel -- inspect --path suspicious_image.jpg
```
