# Offline REA Release Binary Verification Playbook (`CSE-29`, `ADR-012`)

> **Scope Boundary:** This playbook is an **offline, out-of-band release engineering verification procedure**. Reverse Engineer Anything (REA) inspection tools are **never** linked into, invoked by, or shipped with OmniConnect Sentinel runtime binaries (`sentinel`, `sentinel-agent`, `sentinel-cdr-daemon`, `sentinel-cdr-worker`).

---

## 1. Release Artifacts Covered

Every production release builds **4 cross-platform auditable binaries** via `cargo auditable build --workspace --release --locked` across both Linux (`ubuntu-latest`) and Windows (`windows-latest`):

| Artifact | Windows PE (`x86_64-pc-windows-msvc`) | Linux ELF (`x86_64-unknown-linux-gnu`) | Security Boundary |
| :--- | :--- | :--- | :--- |
| Operator CLI & Defense Station | `target/release/sentinel.exe` | `target/release/sentinel` | `#![forbid(unsafe_code)]`, loopback UI auth, passport/vault/shred CLI |
| Endpoint Interceptor Daemon | `target/release/sentinel-agent.exe` | `target/release/sentinel-agent` | `#![forbid(unsafe_code)]`, Windows SCM service / Linux daemon |
| CDR IPC Server | `target/release/sentinel-cdr-daemon.exe` | `target/release/sentinel-cdr-daemon` | `#![forbid(unsafe_code)]`, ACL-hardened Named Pipe / Unix Domain Socket |
| Isolated Parser Worker | `target/release/sentinel-cdr-worker.exe` | `target/release/sentinel-cdr-worker` | `#![forbid(unsafe_code)]`, AppContainer / Job Object / `seccomp-bpf` + Landlock |

---

## 2. Automated CI Pre-Gate (`.github/workflows/ci.yml`)

Before offline release sign-off, CI automatically verifies:
1. **Embedded `.dep-v0` Provenance on Linux & Windows:**
   - Linux (`supply-chain-and-sbom` job): `readelf -S "$bin" | grep -q '\.dep-v0'` + `python3 tests/verify_auditable_dep_v0.py ...` (validates ELF `.dep-v0` section header, zlib decompression, and non-empty JSON `packages` list).
   - Windows (`windows-auditable-release` job): `python tests/verify_auditable_dep_v0.py ...` (validates PE32+ `.dep-v0` COFF section header, non-zero `SizeOfRawData`, zlib decompression, and non-empty JSON `packages` list).
2. **SLSA v1.0 Build Provenance Attestation:** `actions/attest-build-provenance` signs all Linux ELF binaries, Windows PE `.exe` binaries, `sbom.cdx.json`, and `sentinel-cbom.cdx.json` on `main`/`master`.
3. **Out-of-Band Anti-Forensic Shred Oracle (`anti-forensic-shred-oracle` job):** `tests/ci_shred_verify_oracle.sh` verifies 0 residual 64-byte canary bytes across real 16 MiB `ext4` and 36 MiB `FAT32` loopback images.

---

## 3. Offline REA Binary Inspection Procedure (Pre-Release Sign-Off)

On an air-gapped release verification workstation holding the CI release artifacts, run the following offline REA inspection checks against each binary:

### Step 3.1 — Rust Binary & `.dep-v0` Provenance Inspection (`inspect_rust_binary`)
Run REA's `inspect_rust_binary` provider against each Windows `.exe` and Linux ELF artifact:
- **Verify compiler & panic profile:** Confirm expected Rust stable toolchain string, release optimization profile, and absence of unstripped local workstation paths where prohibited.
- **Extract and cross-check `.dep-v0` crate graph:** Compare the decompressed `.dep-v0` crate list against `Cargo.lock` and `sbom.cdx.json`. Confirm:
  - **0 denied crates** from `deny.toml` (`kamadak-exif`, `chacha20poly1305`).
  - **0 DFIR carving/undelete crates or wrappers** (`ADR-012`: no PhotoRec, TestDisk, SleuthKit, Scalpel, Foremost, or raw disk-carving engines).
  - **0 legacy hand-rolled SHA-1 OAEP or `thread_rng` symbol references** (`CSE-28`).
  - **Exact audited crypto crate versions** matching `sentinel-cbom.cdx.json` (`ml-kem@0.2.3`, `rsa@0.10.0`, `aes-gcm@0.10.3`, `p256@0.14.0`, `hkdf@0.12.4`, `hmac@0.12.1`, `sha2@0.10.9`, `sha3@0.10.9`, `rustls@0.23.46`, `rand@0.8.8`).

### Step 3.2 — Windows PE Hardening & Resource Verification (`inspect_pe_resources`)
Run REA's `inspect_pe_resources` (and PE header inspection) against `sentinel.exe`, `sentinel-agent.exe`, `sentinel-cdr-daemon.exe`, and `sentinel-cdr-worker.exe`:
- **PE Security Characteristics (`DllCharacteristics`):**
  - `IMAGE_DLLCHARACTERISTICS_GUARD_CF` (`0x4000`, MSVC Control Flow Guard from `.cargo/config.toml` `-C control-flow-guard=checks` + `-C link-arg=/GUARD:CF`) MUST be set.
  - `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (`0x0040`, ASLR) and `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` (`0x0020`, 64-bit ASLR) MUST be set.
  - `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` (`0x0100`, DEP) MUST be set.
- **PE Sections & Import Table:**
  - `.dep-v0` section present with `SizeOfRawData > 0` and valid zlib JSON payload.
  - `sentinel-cdr-worker.exe` MUST NOT import networking sockets (`ws2_32.dll` connect/socket APIs) or unnecessary shell execution wrappers.
  - Verify Authenticode signature (when code-signed for distribution) and PE version/manifest resources (`inspect_pe_resources`) report unified version `0.1.0` with no unexpected embedded manifests requesting `highestAvailable` elevation on `sentinel-cdr-worker.exe`.

### Step 3.3 — Linux ELF Hardening Verification
Inspect `sentinel`, `sentinel-agent`, `sentinel-cdr-daemon`, and `sentinel-cdr-worker`:
- **ELF Mitigations:** Verify `PIE` (`ET_DYN`), non-executable stack (`GNU_STACK` without `E`), and `RELRO` headers via `readelf -lW` / `readelf -d`.
- **`.dep-v0` Section:** Confirm `readelf -S "$bin" | grep '\.dep-v0'` succeeds and `tests/verify_auditable_dep_v0.py` exits `0`.
- **Passport Digest Cross-Check:** Verify `KioskSanitizationPassport.binary_dep_v0_sha256` emitted by a release `sentinel` binary equals the exact `sha256sum` of the raw `.dep-v0` section bytes extracted by `objcopy --dump-section .dep-v0=dep.bin <bin>` (`ADR-014`, `CSE-17`).

---

## 4. Release Gate Sign-Off Criteria

A release candidate **FAILS** sign-off if any of the following occur:
1. Any of the 4 Windows PE or 4 Linux ELF binaries lacks a valid, zlib-decompressible `.dep-v0` section.
2. Any crate in `.dep-v0` is absent from `Cargo.lock` or violates `deny.toml` / `sentinel-cbom.cdx.json`.
3. Any Windows PE release binary lacks `/GUARD:CF` (`0x4000`), `DYNAMIC_BASE`, `HIGH_ENTROPY_VA`, or `NX_COMPAT`.
4. Any DFIR carving binary/library or unapproved runtime dependency appears in binary imports or `.dep-v0`.

---
*Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*
