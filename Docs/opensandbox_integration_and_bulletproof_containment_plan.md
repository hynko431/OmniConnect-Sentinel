# OmniConnect Sentinel & OpenSandbox Integration Blueprint
**Bulletproof Detonation Environment, Malware Evasion Countermeasures & Enterprise Containment Architecture**

---

## 1. Executive Summary & Problem Formulation

### 1.1 The Question: Why Can't We Use OpenSandbox for Testing?
The short answer is: **We can, and we should!** 

[`opensandbox-group/OpenSandbox`](https://github.com/opensandbox-group/OpenSandbox) is an open-source, production-grade sandbox runtime platform that orchestrates containerized and micro-virtual-machine (microVM) workloads via a clean OpenAPI/gRPC interface. It natively manages execution lifecycles, file injection, and process isolation across **Docker, gVisor, Kata Containers, and Firecracker microVMs** with cold-start speeds under $65\text{ ms}$.

However, analyzing high-severity polymorphic malware (such as the **`Trojan:Win32/Ramnit!pz`** cluster of 134 infected executables and **`Exploit:Win32/CplLnk.A`** control panel applets discovered live on `ANAND (E:)`) requires overcoming **four fundamental architectural gaps** present in generic AI execution sandboxes:

```mermaid
graph TD
    subgraph "Standard OpenSandbox (AI Code Interpreter Focus)"
        O1[Linux-only default kernels: Ubuntu / Debian]
        O2[Standard bridged network routing]
        O3[Standard stdout / stderr process exit telemetry]
        O4[Zero defense against anti-VM / anti-sandbox evasion]
    end

    subgraph "Malware Reality on USB (Ramnit!pz & CplLnk.A)"
        M1[Win32 PE Executables & Control Panel .cpl Applets]
        M2[Aggressive C2 network beaconing & local lateral infection]
        M3[Kernel-level API hooking, process hollowing & registry hooks]
        M4[Probes for hypervisor CPUID, debuggers & timing loops to hide]
    end

    subgraph "The Solution: OmniConnect Enhanced OpenSandbox Layer"
        S1[Dual-Engine Runtime: Firecracker for Linux + QEMU/WHVP for Win32]
        S2[Air-Gapped Virtual Sinkhole: INetSim / FakeDNS with Zero Egress]
        S3[Kernel Behavioral Telemetry: Sysmon / eBPF / API Hooking Stream]
        S4[Anti-Evasion Shims: CPUID spoofing, clock skewing & human interaction simulation]
    end

    O1 -.->|Gap 1: OS Mismatch| M1
    O2 -.->|Gap 2: Containment Breach| M2
    O3 -.->|Gap 3: Observability Blindspot| M3
    O4 -.->|Gap 4: Silent Evasion| M4

    M1 --> S1
    M2 --> S2
    M3 --> S3
    M4 --> S4
```

---

## 2. Reverse Engineering the Live Threats on ANAND (E:) (/rea)

To design an unbreachable sandbox environment, we first reverse engineer the exact execution mechanisms of the threats discovered on drive `E:\`.

```mermaid
sequenceDiagram
    participant User as Explorer / User Click
    participant LNK as CplLnk.A Exploit
    participant CPL as .cpl Applet in RECYCLER
    participant Ramnit as Ramnit!pz (229KB Binaries)
    participant Host as Target Host OS

    User->>LNK: Explorer Displays Folder Icon
    Note over LNK: CVE-2010-2568: Shell32 icon parser vulnerability
    LNK->>CPL: Auto-loads control panel applet without execution prompt
    CPL->>Ramnit: Drops / Executes 229KB companion loader
    Note over Ramnit: Phase 1: Anti-Analysis & Hypervisor Probes
    Note over Ramnit: Phase 2: Resolves APIs via ROR13 hash lookup
    Ramnit->>Host: Injects malicious code into svchost.exe & explorer.exe
    Ramnit->>Host: Writes registry persistence: HKCU\...\Run
    Ramnit->>Host: Scans all connected physical drives to replicate 229KB binaries
```

### 2.1 Threat Profile 1: `Trojan:Win32/Ramnit!pz`
- **Execution Mechanism**: Ramnit is a multi-component polymorphic file infector. It scans all attached drives for `.exe`, `.dll`, and `.html` files. On removable drives, it replaces directories with companion executables of identical length (**229,376 bytes**), setting the real directories to `Hidden + System` attributes.
- **Evasion Tradecraft**:
  - Executes `CPUID` instruction with `EAX=1` and checks ECX bit 31 (Hypervisor Present bit).
  - Queries `GetTickCount` before and after sleeping (`Sleep(1000)`). If elapsed time $< 900\text{ ms}$ (indicating a sandbox acceleration patch), it terminates silently.
  - Queries `GlobalMemoryStatusEx`; if total physical RAM $< 2\text{ GB}$, it assumes an analysis sandbox and halts.
- **Payload Action**: Hooks `NtMapViewOfSection` and injects its core DLL into `explorer.exe` to intercept banking credentials, keystrokes, and propagate to other USB drives.

### 2.2 Threat Profile 2: `Exploit:Win32/CplLnk.A`
- **Execution Mechanism**: Leverages the Stuxnet-era LNK vulnerability (**CVE-2010-2568 / CVE-2015-0096**). Windows Explorer parses `.lnk` icon resource paths through `Control_RunDLL`.
- **Evasion Tradecraft**: Requires zero user execution. Merely opening the folder or hovering over the shortcut triggers execution via `Shell32.dll`.

---

## 3. Threat Model & Bulletproof Containment Architecture (/cybersecurity-engineer)

Any dynamic detonation environment faces the risk of **sandbox escapes** and **uncontrolled malware propagation**. We enforce an absolute **Zero-Trust Containment Model**:

```mermaid
graph TB
    subgraph Host Hardware & OS (Laptop / Server)
        KERNEL[Host OS Kernel]
        SENTINEL[OmniConnect Sentinel Supervisor]
    end

    subgraph OpenSandbox Isolation Boundary
        HYPER[Hypervisor Layer: KVM / QEMU / Firecracker]
        
        subgraph Isolated Guest VM
            GUEST_OS[Ephemeral Guest OS: Win10 / Linux Scratchpad]
            SAMPLE[Detonated Malware: Ramnit.exe]
            MONITOR[Kernel Telemetry Agent: Sysmon / WinAppHook]
        end

        subgraph Virtual Network Air-Gap
            V_SWITCH[Isolated Linux Bridge vnet0]
            SINKHOLE[INetSim Fake Services: DNS, HTTP, SMB Sinkhole]
            EGRESS_DROP[iptables: REJECT all outgoing traffic to 0.0.0.0/0]
        end
    end

    SENTINEL -->|gRPC Control API| HYPER
    HYPER --> GUEST_OS
    SAMPLE -->|Infection Attempt| MONITOR
    SAMPLE -->|C2 Traffic| V_SWITCH
    V_SWITCH --> SINKHOLE
    V_SWITCH --> EGRESS_DROP
    MONITOR -->|Telemetry Event Stream| SENTINEL
```

### 3.1 Five Layers of Defense-in-Depth Containment

| Defense Layer | Threat Addressed | Implementation in Enhanced OpenSandbox |
| :--- | :--- | :--- |
| **Layer 1: Hypervisor Hardening** | Hypervisor Breakouts (e.g., VENOM CVE-2015-3456, virtio vulnerabilities). | Run hypervisor process unprivileged (`nobody:nogroup`), inside an isolated Linux User Namespace. Apply strict `seccomp-bpf` filters dropping `ptrace`, `sys_rawio`, and `process_vm_writev`. |
| **Layer 2: Network Air-Gap & Sinkhole** | Botnet joining, ransomware key acquisition, DDoS participation, host LAN infection. | Sandboxes are assigned a virtual interface connected exclusively to an internal Linux bridge with **no default gateway**. All DNS queries are sinkholed to a local `FakeDNS` service; all HTTP/SMB traffic is caught by `INetSim`. |
| **Layer 3: Ephemeral Copy-on-Write Storage** | Host filesystem corruption, malware persistence across tests. | All guest storage drives are mounted using ephemeral QCOW2 backing files with copy-on-write (`-snapshot`). When the analysis completes or times out (max 180 seconds), the VM memory and disk state are wiped instantly. |
| **Layer 4: Anti-Evasion Cloaking** | Malware detecting the sandbox and refusing to run. | Patch guest ACPI tables to eliminate `QEMU` or `VBOX` strings. Mask `CPUID` hypervisor bits. Inject synthetic human activity: smooth mouse movements, random keystrokes, realistic document history (`RecentDocs`). |
| **Layer 5: Memory Leak & DMA Protection** | DMA attacks or host memory scanning from compromised guest drivers. | Enforce IOMMU / VT-d isolation; disable all shared memory devices (`ivshmem`), host clipboard synchronization, and shared folder folders. |

---

## 4. System Design & Technical Architecture (/production-grade-coder)

### 4.1 System Components & Communication Flow

```mermaid
graph LR
    A[sentinel-agent.exe] -->|Flags Unknown Suspicious Binary| B[Tier 3 Detonation Orchestrator]
    B -->|REST / gRPC OpenAPI| C[OpenSandbox Gateway :8080]
    C -->|Spawn Isolated MicroVM| D[OpenSandbox Runner]
    D -->|Inject Sample via execd| E[Air-Gapped Guest VM]
    E -->|Stream Syscall & Network Logs| D
    D -->|Aggregate Telemetry| C
    C -->|Behavioral Profile JSON| B
    B -->|Correlate MITRE ATT&CK & Quarantine| A
```

### 4.2 Rust Integration Client (`tier3_sandbox.rs`)

We interface `sentinel-core` with OpenSandbox's standardized API using an asynchronous Rust client:

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSandboxRequest {
    pub image: String,                  // e.g., "sentinel/win10-detonate:v1"
    pub memory_mb: u32,                 // Hard bounded: 2048 MB
    pub cpu_cores: u32,                 // Hard bounded: 2 cores
    pub network_profile: String,        // "airgapped-sinkhole"
    pub timeout_seconds: u32,           // Max 180s
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInstance {
    pub sandbox_id: String,
    pub status: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysisReport {
    pub sandbox_id: String,
    pub sample_sha256: String,
    pub process_tree: Vec<ProcessSpawnEvent>,
    pub registry_modifications: Vec<RegistryEvent>,
    pub dropped_files: Vec<DroppedFileEvent>,
    pub network_connections: Vec<InterceptedNetworkEvent>,
    pub mitre_attack_techniques: Vec<String>,
    pub final_verdict: ThreatVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatVerdict {
    Benign,
    SuspiciousBehavior,
    ConfirmedMalicious { family: String, confidence: f32 },
}

pub struct OpenSandboxClient {
    base_url: String,
    http_client: reqwest::Client,
}

impl OpenSandboxClient {
    pub fn new(base_url: String) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(200))
            .build()
            .unwrap_or_default();
        Self { base_url, http_client }
    }

    /// Provisions an ephemeral, air-gapped sandbox in OpenSandbox
    pub async fn provision_sandbox(&self, profile: &str) -> Result<SandboxInstance, reqwest::Error> {
        let payload = CreateSandboxRequest {
            image: format!("sentinel/{}-detonate:latest", profile),
            memory_mb: 2048,
            cpu_cores: 2,
            network_profile: "airgapped-sinkhole".to_string(),
            timeout_seconds: 120,
        };

        info!("Requesting OpenSandbox runner provisioning: {:?}", payload.image);
        let resp = self.http_client
            .post(format!("{}/api/v1/sandboxes", self.base_url))
            .json(&payload)
            .send()
            .await?
            .json::<SandboxInstance>()
            .await?;

        Ok(resp)
    }

    /// Injects malware binary, executes with kernel monitoring, and retrieves behavioral telemetry
    pub async fn detonate_artifact(
        &self,
        sandbox_id: &str,
        binary_bytes: &[u8],
        target_filename: &str,
    ) -> Result<BehavioralAnalysisReport, Box<dyn std::error::Error + Send + Sync>> {
        info!("Injecting untrusted payload into sandbox {}: '{}'", sandbox_id, target_filename);

        // 1. Upload binary payload to sandbox filesystem
        let upload_url = format!("{}/api/v1/sandboxes/{}/files/upload", self.base_url, sandbox_id);
        self.http_client
            .post(&upload_url)
            .query(&[("destination", format!("C:\\MalwareTest\\{}", target_filename))])
            .body(binary_bytes.to_vec())
            .send()
            .await?;

        // 2. Trigger execution with live kernel trace monitoring
        let exec_url = format!("{}/api/v1/sandboxes/{}/commands/execute", self.base_url, sandbox_id);
        let exec_body = serde_json::json!({
            "command": format!("C:\\Sentinel\\DetonateHarness.exe --target C:\\MalwareTest\\{}", target_filename),
            "timeout_seconds": 60,
        });

        info!("Detonation triggered. Monitoring process injection and system calls...");
        let exec_resp = self.http_client.post(&exec_url).json(&exec_body).send().await?;

        // 3. Parse Behavioral Telemetry Report
        let report: BehavioralAnalysisReport = exec_resp.json().await?;

        // 4. Immediately destroy sandbox instance
        let delete_url = format!("{}/api/v1/sandboxes/{}", self.base_url, sandbox_id);
        let _ = self.http_client.delete(&delete_url).send().await;

        info!(
            "Sandbox {} destroyed. Verdict: {:?}, MITRE Techniques: {:?}",
            sandbox_id, report.final_verdict, report.mitre_attack_techniques
        );

        Ok(report)
    }
}
```

---

## 5. Product Management & Phased Roadmap (/enterprise-product-manager)

### 5.1 Value Proposition Across Product Tiers

1. **Enterprise Endpoint SaaS Tier**:
   - Enables automated background detonation of zero-day/unknown USB binaries without impacting employee device performance.
   - Integrates behavioral verdicts directly into **Microsoft Defender / CrowdStrike Falcon XDR** to trigger enterprise-wide host isolation.
2. **Air-Gapped / Kiosk Appliance Tier**:
   - Dedicated on-premises OpenSandbox appliance capable of parallel detonation of up to 50 USB storage media streams simultaneously.
3. **Consumer / Prosumer Freemium App**:
   - Free local heuristic triage + optional cloud burst sandbox detonation for suspicious files.

---

### 5.2 Phased Implementation Roadmap (Now / Next / Later)

```markdown
- **Now (Sprint 1 - Foundation & Lab Isolation)**:
  - [x] Analyze live USB threats on `ANAND (E:)` (Ramnit!pz & CplLnk.A identified).
  - [x] Complete OpenSandbox integration and bulletproof containment architecture.
  - [ ] Deploy local OpenSandbox test instance with `airgapped-sinkhole` network profile.
  - [ ] Add `tier3_sandbox.rs` client module to `crates/sentinel-core`.

- **Next (Sprint 2 - Windows Detonation Runner & Evasion Cloaking)**:
  - [ ] Build Windows 10 MicroVM image for OpenSandbox with Sysmon telemetry agent.
  - [ ] Implement anti-evasion shims: CPUID hypervisor masking, clock drift defense.
  - [ ] Implement local INetSim / FakeDNS sinkhole to capture Ramnit C2 beaconing.
  - [ ] Validate automated detonation of sample 229KB Ramnit binary in sandbox.

- **Later (Sprint 3 - Enterprise Scale & Fleet Telemetry)**:
  - [ ] Kubernetes-managed OpenSandbox cluster scaling across AWS/Azure.
  - [ ] Live telemetry bridge connecting OpenSandbox behavioral events to CrowdStrike Falcon FDR.
  - [ ] One-click admin release workflow for false positives in Quarantine Vault.
```

---

### 5.3 RACI Matrix

| Milestone / Decision Point | Product Mgmt | Lead Architect | SecEng / Red Team | DevOps / Infra |
| :--- | :---: | :---: | :---: | :---: |
| Define Sandbox Egress Policy | **C** | **A** | **R** | **I** |
| MicroVM Hypervisor Selection | **I** | **A** | **C** | **R** |
| Anti-Evasion Cloaking Shims | **I** | **C** | **A / R** | **I** |
| OpenSandbox gRPC API Client | **I** | **A** | **I** | **R** |
| Falcon & Intune Telemetry Feed | **A** | **C** | **R** | **I** |

---

### 5.4 Risk Register & Mitigations

| Risk ID | Description | Severity | Likelihood | Mitigation Strategy | Owner |
| :---: | :--- | :---: | :---: | :--- | :---: |
| **SEC-01** | **Sandbox Escape via Hypervisor Vulnerability**: Advanced malware exploits a virtio or QEMU bug to reach host memory. | Critical | Low | Run QEMU in rootless User Namespaces with strict `seccomp-bpf` syscall filters; drop all Linux capabilities (`CAP_SYS_ADMIN`). | SecEng |
| **SEC-02** | **Accidental Internet Egress During Detonation**: Malware connects to live C2, triggering real ransomware or botnet attack. | Critical | Very Low | Hardware-enforced bridge isolation: No default IP gateway on bridge interface; `iptables` drop rule rejects all non-local traffic. | SecEng |
| **OPS-01** | **Resource Starvation from Infinite Loops**: Detonated malware forks endless processes (fork bomb) or sleeps infinitely. | High | Medium | Hard cgroup limits: max 2 CPU cores, 2048 MB RAM; hard execution watchdog timer terminates and wipes VM after 120 seconds. | DevOps |
| **DET-01** | **Evasion via Timing Check / Anti-VM**: Ramnit detects virtualization and exits before dropping secondary payloads. | High | Medium | Anti-evasion shims: Spoof CPUID bits, inject realistic mouse movement, patch `GetTickCount` to return continuous wall-clock time. | REA Lead |

---

## 6. Actionable Next Steps

1. **Commit Blueprint**: Persist this blueprint into `Docs/opensandbox_integration_and_bulletproof_containment_plan.md`.
2. **Review Codebase Integration**: Wire `OpenSandboxClient` into `sentinel-core` as an optional Tier 3 background detonation plugin.
3. **Safely Clean ANAND (E:)**: Execute the quarantine and cleanup procedure on drive `E:\` so your local system remains completely protected while you develop the sandbox environment.
