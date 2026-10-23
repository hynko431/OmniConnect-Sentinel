// ==========================================================================
// OmniConnect Sentinel Cyber Defense Dashboard & Kiosk Controller
// Implemented with: emil-design-eng, anatomy, ask-sonner, break-ui, framer-motion
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const appLayout = document.getElementById('appLayout');
  const modeSocBtn = document.getElementById('modeSocBtn');
  const modeKioskBtn = document.getElementById('modeKioskBtn');
  const socView = document.getElementById('socView');
  const kioskView = document.getElementById('kioskView');

  const safeChargingToggle = document.getElementById('safeChargingToggle');
  const anatomyContainer = document.getElementById('anatomyContainer');
  const anatomyReadout = document.getElementById('anatomyReadout');
  const interlockStatusText = document.getElementById('interlockStatusText');
  const pinStateIndicator = document.getElementById('pinStateIndicator');

  const btnScan = document.getElementById('btnScan');
  const targetPath = document.getElementById('targetPath');
  const scanProgressBox = document.getElementById('scanProgressBox');
  const scanProgressBar = document.getElementById('scanProgressBar');
  const scanProgressPct = document.getElementById('scanProgressPct');
  const scanSpeedMetric = document.getElementById('scanSpeedMetric');
  const scanTimeMetric = document.getElementById('scanTimeMetric');

  const statFiles = document.getElementById('statFiles');
  const statThreats = document.getElementById('statThreats');
  const statVectors = document.getElementById('statVectors');
  const statDisarmed = document.getElementById('statDisarmed');

  const logContainer = document.getElementById('logContainer');
  const feedFilterBtns = document.querySelectorAll('.feed-filter-btn');

  const btnDetonate = document.getElementById('btnDetonate');
  const sandboxResults = document.getElementById('sandboxResults');
  const mitreTags = document.querySelectorAll('.mitre-tag');
  const mitreModal = document.getElementById('mitreModal');
  const mitreModalTitle = document.getElementById('mitreModalTitle');
  const mitreModalBody = document.getElementById('mitreModalBody');
  const btnCloseMitreModal = document.getElementById('btnCloseMitreModal');

  const btnOpenCdrDiff = document.getElementById('btnOpenCdrDiff');
  const cdrDiffModal = document.getElementById('cdrDiffModal');
  const btnCloseCdrModal = document.getElementById('btnCloseCdrModal');
  const btnVerifyCdrHash = document.getElementById('btnVerifyCdrHash');

  const sectorGrid = document.getElementById('sectorGrid');
  const btnShredAll = document.getElementById('btnShredAll');
  const shredButtons = document.querySelectorAll('.btn-shred');

  const btnKioskSanitize = document.getElementById('btnKioskSanitize');
  const kioskCert = document.getElementById('kioskCert');
  const btnKioskEject = document.getElementById('btnKioskEject');
  const kioskStep1 = document.getElementById('kioskStep1');
  const kioskStep2 = document.getElementById('kioskStep2');
  const kioskStep3 = document.getElementById('kioskStep3');

  const btnDataDemo = document.getElementById('btnDataDemo');
  const btnDataWorst = document.getElementById('btnDataWorst');
  const toastContainer = document.getElementById('toastContainer');

  // ========================================================================
  // 1. Toast Notification Infrastructure (ask-sonner inspired)
  // ========================================================================
  function showToast(type, title, message, duration = 4200) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = '⚡';
    if (type === 'crit') icon = '🛑';
    if (type === 'success') icon = '✅';
    if (type === 'warn') icon = '⚠️';

    toast.innerHTML = `
      <div style="font-size: 1.2rem;">${icon}</div>
      <div style="flex: 1;">
        <div style="font-weight: 700; color: #f8fafc; font-family: var(--font-mono); font-size: 0.76rem;">${title}</div>
        <div style="color: #94a3b8; font-size: 0.72rem; margin-top: 2px;">${message}</div>
      </div>
    `;

    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px) scale(0.95)';
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }

  // ========================================================================
  // 2. Persona Switcher: SOC Analyst HUD <-> Air-Gapped Kiosk
  // ========================================================================
  modeSocBtn.addEventListener('click', () => {
    modeSocBtn.classList.add('active');
    modeKioskBtn.classList.remove('active');
    socView.classList.add('active');
    kioskView.classList.remove('active');
    showToast('info', 'VIEWPORT SWITCHED', 'Active Mode: SOC Analyst Tactical HUD');
  });

  modeKioskBtn.addEventListener('click', () => {
    modeKioskBtn.classList.add('active');
    modeSocBtn.classList.remove('active');
    kioskView.classList.add('active');
    socView.classList.remove('active');
    showToast('warn', 'KIOSK AIRLOCK ENGAGED', 'Touchscreen station armed for removable media triage.');
  });

  // ========================================================================
  // 3. Hardware Safe-Charging Interlock & Isometric Anatomy (anatomy skill)
  // ========================================================================
  safeChargingToggle.addEventListener('change', (e) => {
    const isChargeOnly = e.target.checked;
    if (isChargeOnly) {
      anatomyContainer.classList.add('safe-charge-active');
      anatomyReadout.textContent = 'VBUS: 5.02V / 2.1A (CHARGING ONLY) | D+/D-: SEVERED (0 bps)';
      anatomyReadout.style.color = 'var(--accent-orange)';
      interlockStatusText.innerHTML = '<span class="status-badge status-isolated">⚡ SAFE CHARGING ENGAGED (Data Pins Decoupled)</span>';
      pinStateIndicator.textContent = 'DATA LINES: SEVERED (0 bps)';
      pinStateIndicator.style.color = 'var(--accent-orange)';

      addLog('WARN', 'HARDWARE RELAY', 'D+/D- lines physically opened via solid-state interlock. Juice-jacking impossible.');
      showToast('warn', 'SAFE CHARGING ACTIVATED', 'Physical data lines severed. Zero data can cross to the host OS.');
    } else {
      anatomyContainer.classList.remove('safe-charge-active');
      anatomyReadout.textContent = 'VBUS: 5.02V | D+/D-: 480 Mbps (FILTERED)';
      anatomyReadout.style.color = 'var(--accent-cyan)';
      interlockStatusText.innerHTML = '<span class="status-badge status-monitoring">● UMDF FILTER ACTIVE (D+/D- Intercepted)</span>';
      pinStateIndicator.textContent = 'DATA LINES: CONNECTED (Ring 3 Guard)';
      pinStateIndicator.style.color = '#94a3b8';

      addLog('INFO', 'INTERCEPTOR ACTIVE', 'D+/D- data lines reconnected under strict Ring 3 UMDF v2 filter monitoring.');
      showToast('info', 'DATA MONITORING RESTORED', 'UMDF v2 user-mode interceptor armed on high-speed USB bus.');
    }
  });

  // ========================================================================
  // 4. Sector Shredder Visualizer (64 Blocks)
  // ========================================================================
  function initSectorGrid() {
    sectorGrid.innerHTML = '';
    for (let i = 0; i < 64; i++) {
      const block = document.createElement('div');
      block.className = 'sector-block';
      // Seed with some initial infected sectors
      if ([4, 12, 19, 27, 33, 41, 48, 55, 59].includes(i)) {
        block.classList.add('dot-infected');
      }
      sectorGrid.appendChild(block);
    }
  }
  initSectorGrid();

  function runSectorShredAnimation(onComplete) {
    const blocks = Array.from(sectorGrid.children);
    showToast('warn', 'NIST SP 800-88 PURGE', 'Executing 3-Pass CSPRNG in-place sector overwrite...');

    // Pass 1: 0x00 Zero-fill
    blocks.forEach((b, idx) => {
      setTimeout(() => {
        b.className = 'sector-block dot-zero';
      }, idx * 12);
    });

    // Pass 2: 0xFF One-fill
    setTimeout(() => {
      blocks.forEach((b, idx) => {
        setTimeout(() => {
          b.className = 'sector-block dot-one';
        }, idx * 10);
      });
    }, 900);

    // Pass 3: CSPRNG Random Noise
    setTimeout(() => {
      blocks.forEach((b, idx) => {
        setTimeout(() => {
          b.className = 'sector-block dot-csprng';
        }, idx * 8);
      });
    }, 1700);

    // Final Pass: Sterile Zero Remanence
    setTimeout(() => {
      blocks.forEach((b, idx) => {
        setTimeout(() => {
          b.className = 'sector-block dot-sterile';
        }, idx * 6);
      });
      showToast('success', 'SHRED ATTESTED', 'NIST SP 800-88 Rev 1 sanitization complete. 0 physical residue.');
      if (onComplete) onComplete();
    }, 2400);
  }

  btnShredAll.addEventListener('click', () => {
    btnShredAll.disabled = true;
    runSectorShredAnimation(() => {
      btnShredAll.disabled = false;
      document.querySelectorAll('#vaultTable tbody tr').forEach(row => {
        row.style.opacity = '0.35';
        row.querySelector('.btn-shred').textContent = 'Verified Purged';
        row.querySelector('.btn-shred').disabled = true;
      });
      addLog('SUCCESS', 'CRYPTOGRAPHIC PURGE', 'All 4 quarantined carriers pulverized via NIST SP 800-88.');
    });
  });

  shredButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      const row = e.target.closest('tr');
      const targetPath = btn.getAttribute('data-path');
      btn.disabled = true;
      btn.textContent = 'Shredding...';

      runSectorShredAnimation(() => {
        row.style.opacity = '0.35';
        btn.textContent = 'Purged (0-Trace)';
        addLog('SUCCESS', 'NIST SHRED COMPLETE', `Permanently eliminated ${targetPath} with zero remanence.`);
      });
    });
  });

  // ========================================================================
  // 5. Zero-Trust Drive Sweep & Deep CDR Simulation
  // ========================================================================
  btnScan.addEventListener('click', () => {
    const drive = targetPath.value.trim() || 'E:\';
    btnScan.disabled = true;
    btnScan.querySelector('.btn-text').textContent = 'Sanitizing...';
    scanProgressBox.style.display = 'flex';

    addLog('INFO', 'SWEEP INITIATED', `Beginning zero-trust deep inspection on volume: ${drive}`);
    showToast('info', 'DEEP SWEEP STARTED', `Analyzing 1,134 files on ${drive} with Pure-Rust CDR Engine.`);

    let pct = 0;
    const interval = setInterval(() => {
      pct += 15;
      if (pct > 100) pct = 100;
      scanProgressBar.style.width = pct + '%';
      scanProgressPct.textContent = pct + '%';

      if (pct === 45) {
        addLog('CRIT', 'VIRUS DETECTED', `Found 134 identical 229,376-byte files [Trojan:Win32/Ramnit!pz] on ${drive}`);
      } else if (pct === 75) {
        addLog('WARN', 'SHORTCUT VECTOR', `Neutralized 33 malicious .lnk shortcuts [Exploit:Win32/CplLnk.A]`);
      } else if (pct === 100) {
        clearInterval(interval);
        addLog('SUCCESS', 'CDR SANITIZED', `Cleaned 967 documents & media files in 28ms; projected to Z:\`);
        showToast('success', 'SWEEP COMPLETE', '967 files disarmed. Sterile virtual volume mounted on Z:\');

        btnScan.disabled = false;
        btnScan.querySelector('.btn-text').textContent = 'Execute Zero-Trust Sweep';
      }
    }, 180);
  });

  function addLog(type, badge, message) {
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type.toLowerCase()}`;
    entry.setAttribute('data-type', type.toLowerCase());

    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];

    entry.innerHTML = `
      <span class="log-time">${timeStr}</span>
      <span class="log-badge">${badge}</span>
      <span class="log-msg">${message}</span>
    `;

    logContainer.prepend(entry);
  }

  // Filter feed logs
  feedFilterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      feedFilterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const filter = btn.getAttribute('data-filter');
      const entries = logContainer.querySelectorAll('.log-entry');

      entries.forEach(e => {
        if (filter === 'all') {
          e.style.display = 'flex';
        } else if (filter === 'crit' && (e.classList.contains('log-crit') || e.classList.contains('log-warn'))) {
          e.style.display = 'flex';
        } else if (filter === 'cdr' && e.classList.contains('log-success')) {
          e.style.display = 'flex';
        } else {
          e.style.display = 'none';
        }
      });
    });
  });

  // ========================================================================
  // 6. Deep CDR Split-Screen Diff Studio Modal
  // ========================================================================
  btnOpenCdrDiff.addEventListener('click', () => {
    cdrDiffModal.style.display = 'flex';
  });

  btnCloseCdrModal.addEventListener('click', () => {
    cdrDiffModal.style.display = 'none';
  });

  btnVerifyCdrHash.addEventListener('click', () => {
    showToast('success', 'ATTESTATION VERIFIED', 'Cryptographic SHA-256 certificate signed by sentinel-cdr engine.');
  });

  // ========================================================================
  // 7. MITRE ATT&CK Matrix Interactive Explainer
  // ========================================================================
  const mitreDetails = {
    'T1091': {
      title: 'T1091: Replication Through Removable Media',
      tactic: 'Initial Access / Lateral Movement',
      desc: 'Adversaries move malware onto systems by copying payloads to removable media like USB drives. Ramnit and Stuxnet propagate by injecting into all drive binaries and replacing folders with weaponized .lnk shortcuts.',
      remediation: 'OmniConnect Sentinel Pre-Mount UMDF interceptor blocks autorun.inf parsing and neutralizes shortcut icon execution before Windows Explorer can parse it.'
    },
    'T1055.002': {
      title: 'T1055.002: Process Injection (Portable Executable Injection)',
      tactic: 'Defense Evasion / Privilege Escalation',
      desc: 'The payload attempts to write raw PE executable code directly into the virtual address space of running explorer.exe and svchost.exe processes to hide execution.',
      remediation: 'Tier 2 OpenSandbox hypervisor detects NtWriteVirtualMemory / CreateRemoteThread API calls and instantly terminates the injector.'
    },
    'T1547.001': {
      title: 'T1547.001: Boot or Logon Autostart Execution: Registry Run Keys',
      tactic: 'Persistence',
      desc: 'Malware modifies HKCU\Software\Microsoft\Windows\CurrentVersion\Run to achieve persistent survival across system reboots.',
      remediation: 'MicroVM sandbox isolates registry mutations in ephemeral copy-on-write memory; writes are completely discarded.'
    },
    'T1071.001': {
      title: 'T1071.001: Application Layer Protocol: Web Protocols',
      tactic: 'Command and Control',
      desc: 'Adversary uses HTTP/HTTPS beacons to communicate with C2 servers on port 80/443, mimicking legitimate traffic.',
      remediation: 'Air-gapped network sinkhole (INetSim) intercepts all DNS queries, spoofing 127.0.0.1 and returning dummy responses.'
    },
    'T1497.001': {
      title: 'T1497.001: Virtualization/Sandbox Evasion: System Checks',
      tactic: 'Discovery / Defense Evasion',
      desc: 'Payload executes CPUID hypervisor checks, RDTSC timing queries, and detects mouse inactivity to evade dynamic analysis.',
      remediation: 'OpenSandbox shims hook CPUID and RDTSC instructions, returning bare-metal physical hardware clock signatures.'
    },
    'T1564.004': {
      title: 'T1564.004: Hide Artifacts: NTFS File and Directory Permissions',
      tactic: 'Defense Evasion',
      desc: 'Executables are hidden inside alternate data streams (e.g. Brief.docx:evil.exe) invisible to standard directory listings.',
      remediation: 'Universal Threat Sentry enumerates all ::$DATA streams on raw NTFS partitions and flags hidden PE headers.'
    }
  };

  mitreTags.forEach(tag => {
    tag.addEventListener('click', () => {
      const tech = tag.getAttribute('data-tech');
      const info = mitreDetails[tech] || {
        title: tech,
        tactic: 'Adversary Technique',
        desc: 'Advanced persistent threat vector mapped by MITRE ATT&CK framework.',
        remediation: 'Neutralized by OmniConnect Sentinel multi-tier defense.'
      };

      mitreModalTitle.textContent = info.title;
      mitreModalBody.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 12px; font-family: var(--font-sans);">
          <div><strong style="color: var(--accent-purple); font-size: 0.8rem; font-family: var(--font-mono);">TACTIC: ${info.tactic}</strong></div>
          <div style="font-size: 0.82rem; color: #cbd5e1; line-height: 1.5;">${info.desc}</div>
          <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 12px; border-radius: 8px;">
            <div style="color: #34d399; font-weight: 700; font-size: 0.78rem; font-family: var(--font-mono);">SENTINEL COUNTERMEASURE:</div>
            <div style="color: #a7f3d0; font-size: 0.76rem; margin-top: 4px;">${info.remediation}</div>
          </div>
        </div>
      `;

      mitreModal.style.display = 'flex';
    });
  });

  btnCloseMitreModal.addEventListener('click', () => {
    mitreModal.style.display = 'none';
  });

  // MicroVM Detonation Simulation
  btnDetonate.addEventListener('click', () => {
    btnDetonate.disabled = true;
    btnDetonate.querySelector('.btn-text').textContent = 'Detonating in MicroVM...';
    showToast('warn', 'SANDBOX DETONATION', 'Spawning ephemeral win11-whvp-microvm with air-gapped network sinkhole...');

    setTimeout(() => {
      btnDetonate.disabled = false;
      btnDetonate.querySelector('.btn-text').textContent = 'Execute MicroVM Detonation';
      sandboxResults.style.display = 'flex';
      showToast('crit', 'VERDICT: MALICIOUS', 'Payload scored 100/100 risk. C2 beacons successfully sinkholed.');
    }, 1400);
  });

  // ========================================================================
  // 8. Air-Gapped Kiosk 3-Step Guided Workflow
  // ========================================================================
  btnKioskSanitize.addEventListener('click', () => {
    btnKioskSanitize.disabled = true;
    btnKioskSanitize.innerHTML = '<span>⏳ DISARMING & PURGING USB MEDIA...</span>';

    setTimeout(() => {
      kioskStep1.classList.remove('active');
      kioskStep2.classList.remove('active');
      kioskStep3.classList.add('active');
      kioskCert.style.display = 'flex';

      showToast('success', 'AIRLOCK SANITIZATION PASSED', 'Certificate issued: CERT-NIST-800-88-2026-9921');
    }, 1500);
  });

  btnKioskEject.addEventListener('click', () => {
    showToast('info', 'MEDIA EJECTED', 'Safe to physically remove USB drive. Host filesystem dismounted cleanly.');
    setTimeout(() => {
      kioskStep3.classList.remove('active');
      kioskStep1.classList.add('active');
      kioskCert.style.display = 'none';
      btnKioskSanitize.disabled = false;
      btnKioskSanitize.innerHTML = '<span>🚀 START HARDWARE DISARM & PURGE</span>';
    }, 1200);
  });

  // ========================================================================
  // 9. Adversarial Stress-Test Toggle (break-ui skill)
  // ========================================================================
  btnDataWorst.addEventListener('click', () => {
    btnDataWorst.classList.add('active');
    btnDataDemo.classList.remove('active');

    // Feed worst-case data
    statFiles.textContent = '52,891';
    statThreats.textContent = '1,492';
    statVectors.textContent = '388';
    statDisarmed.textContent = '51,011';

    targetPath.value = 'E:\Enterprise\Acquisition\2026\Confidential\Corporate_Defense_Brief_Final_Approved_v2_Signed.pdf';

    addLog('CRIT', 'UNICODE BIDI SPOOF', 'Flagged receipt_\u202Ecod.exe using Right-To-Left Override Trojan spoofing');
    addLog('WARN', 'EXTREME DEPTH', 'Traversed 42-level deep directory tree without stack overflow or layout break');

    showToast('warn', 'WORST-CASE DATA LOADED', 'Testing 50,000 files, deep nested paths, and Unicode RTL trojans.');
  });

  btnDataDemo.addEventListener('click', () => {
    btnDataDemo.classList.add('active');
    btnDataWorst.classList.remove('active');

    statFiles.textContent = '1,134';
    statThreats.textContent = '134';
    statVectors.textContent = '33';
    statDisarmed.textContent = '967';
    targetPath.value = 'E:\';

    showToast('info', 'BASELINE RESTORED', 'Standard physical drive ANAND (E:) dataset active.');
  });

  // Close modals on clicking outside
  window.addEventListener('click', (e) => {
    if (e.target === cdrDiffModal) cdrDiffModal.style.display = 'none';
    if (e.target === mitreModal) mitreModal.style.display = 'none';
  });
});
