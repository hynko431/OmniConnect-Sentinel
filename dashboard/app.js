/**
 * OmniConnect Sentinel — Enterprise Dashboard Logic
 * Lenses: /impeccable · /taste-skill · /emil-design-eng
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const safeChargingToggle = document.getElementById('safeChargingToggle');
  const safeChargeBadge = document.getElementById('safeChargeBadge');
  const kpiPinStatusText = document.getElementById('kpiPinStatusText');
  const kpiPinSubtext = document.getElementById('kpiPinSubtext');
  
  // SVG Pin Elements
  const lineDataMinusLeft = document.getElementById('lineDataMinusLeft');
  const switchArmMinus = document.getElementById('switchArmMinus');
  const lineDataMinusRight = document.getElementById('lineDataMinusRight');
  
  const lineDataPlusLeft = document.getElementById('lineDataPlusLeft');
  const switchArmPlus = document.getElementById('switchArmPlus');
  const lineDataPlusRight = document.getElementById('lineDataPlusRight');

  // Sector Shredder Elements
  const sectorGrid64 = document.getElementById('sectorGrid64');
  const btnInitiateSanitize = document.getElementById('btnInitiateSanitize');
  const sanitizePassText = document.getElementById('sanitizePassText');

  // Modals
  const cdrModal = document.getElementById('cdrModal');
  const btnInspectCdr = document.getElementById('btnInspectCdr');
  const btnCloseCdrModal = document.getElementById('btnCloseCdrModal');

  const mitreModal = document.getElementById('mitreModal');
  const mitreModalId = document.getElementById('mitreModalId');
  const mitreModalHeading = document.getElementById('mitreModalHeading');
  const mitreModalDesc = document.getElementById('mitreModalDesc');
  const mitreModalMitigation = document.getElementById('mitreModalMitigation');
  const btnCloseMitreModal = document.getElementById('btnCloseMitreModal');
  const mitreChips = document.querySelectorAll('.mitre-chip');

  // Persona Elements
  const btnSocHUD = document.getElementById('btnSocHUD');
  const btnKioskMode = document.getElementById('btnKioskMode');
  const socView = document.getElementById('socView');
  const kioskView = document.getElementById('kioskView');

  // Kiosk Elements
  const kioskStep1 = document.getElementById('kioskStep1');
  const kioskStep2 = document.getElementById('kioskStep2');
  const kioskStep3 = document.getElementById('kioskStep3');
  const btnKioskSimulate = document.getElementById('btnKioskSimulate');
  const btnKioskEject = document.getElementById('btnKioskEject');

  // Telemetry Simulation
  const btnTogglePinSimulation = document.getElementById('btnTogglePinSimulation');
  const valVoltage = document.getElementById('valVoltage');
  const valCurrent = document.getElementById('valCurrent');
  const valPower = document.getElementById('valPower');
  const valDeviceName = document.getElementById('valDeviceName');

  // Stress Testing
  const btnStressToggle = document.getElementById('btnStressToggle');
  let isStressed = false;

  /* ==========================================================================
     1. Safe Charging Interlock Logic
     ========================================================================== */
  function updateSafeChargingState(isDecoupled) {
    if (isDecoupled) {
      // Data lines cut
      kpiPinStatusText.textContent = 'DECOUPLED';
      kpiPinStatusText.style.color = 'var(--color-status-danger)';
      kpiPinSubtext.textContent = 'Safe Charge: Active (No Data)';
      kpiPinSubtext.className = 'kpi-delta safe';
      
      safeChargeBadge.textContent = 'ACTIVE: DATA ISOLATED';
      safeChargeBadge.className = 'kpi-delta safe';

      // SVG open switch position
      if (switchArmMinus) {
        switchArmMinus.setAttribute('x2', '310');
        switchArmMinus.setAttribute('y2', '78');
        switchArmMinus.setAttribute('stroke', '#dc2626');
      }
      if (switchArmPlus) {
        switchArmPlus.setAttribute('x2', '310');
        switchArmPlus.setAttribute('y2', '118');
        switchArmPlus.setAttribute('stroke', '#dc2626');
      }
      if (lineDataMinusLeft) lineDataMinusLeft.setAttribute('stroke', '#dc2626');
      if (lineDataPlusLeft) lineDataPlusLeft.setAttribute('stroke', '#dc2626');
      if (lineDataMinusRight) lineDataMinusRight.setAttribute('stroke', '#cbd5e1');
      if (lineDataPlusRight) lineDataPlusRight.setAttribute('stroke', '#cbd5e1');
    } else {
      // Data lines coupled (Normal USB Drive mode)
      kpiPinStatusText.textContent = 'COUPLED';
      kpiPinStatusText.style.color = 'var(--color-status-info)';
      kpiPinSubtext.textContent = 'UMDF Ring 3 Filter Active';
      kpiPinSubtext.className = 'kpi-delta info';

      safeChargeBadge.textContent = 'OFF: DATA LINES ACTIVE';
      safeChargeBadge.className = 'kpi-delta info';

      // SVG closed switch position
      if (switchArmMinus) {
        switchArmMinus.setAttribute('x2', '340');
        switchArmMinus.setAttribute('y2', '95');
        switchArmMinus.setAttribute('stroke', '#0284c7');
      }
      if (switchArmPlus) {
        switchArmPlus.setAttribute('x2', '340');
        switchArmPlus.setAttribute('y2', '135');
        switchArmPlus.setAttribute('stroke', '#0284c7');
      }
      if (lineDataMinusLeft) lineDataMinusLeft.setAttribute('stroke', '#0284c7');
      if (lineDataPlusLeft) lineDataPlusLeft.setAttribute('stroke', '#0284c7');
      if (lineDataMinusRight) lineDataMinusRight.setAttribute('stroke', '#0284c7');
      if (lineDataPlusRight) lineDataPlusRight.setAttribute('stroke', '#0284c7');
    }
  }

  if (safeChargingToggle) {
    safeChargingToggle.addEventListener('change', (e) => {
      updateSafeChargingState(e.target.checked);
    });
    // Initialize
    updateSafeChargingState(safeChargingToggle.checked);
  }

  /* ==========================================================================
     2. NIST SP 800-88 64-Block Sector Shredder Grid
     ========================================================================== */
  if (sectorGrid64) {
    sectorGrid64.innerHTML = '';
    for (let i = 0; i < 64; i++) {
      const cell = document.createElement('div');
      cell.className = 'sector-cell';
      cell.id = `sector-${i}`;
      cell.setAttribute('title', `LBA Sector ${i * 4096} - Ready`);
      sectorGrid64.appendChild(cell);
    }
  }

  if (btnInitiateSanitize) {
    btnInitiateSanitize.addEventListener('click', async () => {
      btnInitiateSanitize.disabled = true;
      const cells = document.querySelectorAll('.sector-cell');

      // Pass 1: 0x00 pattern
      sanitizePassText.innerHTML = 'Status: <strong style="color: #64748b;">Pass 1/3 (0x00 Overwrite)</strong>';
      for (let i = 0; i < cells.length; i++) {
        cells[i].className = 'sector-cell pass-1';
        if (i % 8 === 0) await new Promise(r => setTimeout(r, 20));
      }

      await new Promise(r => setTimeout(r, 120));

      // Pass 2: 0xFF complement
      sanitizePassText.innerHTML = 'Status: <strong style="color: #334155;">Pass 2/3 (0xFF Inversion)</strong>';
      for (let i = 0; i < cells.length; i++) {
        cells[i].className = 'sector-cell pass-2';
        if (i % 8 === 0) await new Promise(r => setTimeout(r, 20));
      }

      await new Promise(r => setTimeout(r, 120));

      // Pass 3: Cryptographic Random (Verified Clean)
      sanitizePassText.innerHTML = 'Status: <strong style="color: var(--color-status-safe);">Pass 3/3 (Crypto Random)</strong>';
      for (let i = 0; i < cells.length; i++) {
        cells[i].className = 'sector-cell pass-3';
        if (i % 8 === 0) await new Promise(r => setTimeout(r, 20));
      }

      sanitizePassText.innerHTML = 'Status: <strong style="color: var(--color-status-safe);">NIST SP 800-88 Verified (Purged)</strong>';
      btnInitiateSanitize.disabled = false;
    });
  }

  /* ==========================================================================
     3. Deep CDR Split-Screen Diff Modal
     ========================================================================== */
  function openCdrModal() {
    cdrModal.classList.add('open');
    cdrModal.setAttribute('aria-hidden', 'false');
  }

  function closeCdrModal() {
    cdrModal.classList.remove('open');
    cdrModal.setAttribute('aria-hidden', 'true');
  }

  if (btnInspectCdr) btnInspectCdr.addEventListener('click', openCdrModal);
  if (btnCloseCdrModal) btnCloseCdrModal.addEventListener('click', closeCdrModal);
  if (cdrModal) {
    cdrModal.addEventListener('click', (e) => {
      if (e.target === cdrModal) closeCdrModal();
    });
  }

  /* ==========================================================================
     4. MITRE ATT&CK Technical Modal & Drawer
     ========================================================================== */
  const MITRE_DATA = {
    'T1091': {
      title: 'Replication Through Removable Media',
      desc: 'Adversaries move into systems by copying malware to removable media and taking advantage of auto-run features, shortcut (LNK) stomping, or hidden device directories.',
      mitigation: 'Ring 3 Userspace Storage Interceptor disables volume mounting until deep heuristic inspection passes. Windows AutoRun and Shell Hardware Detection are intercepted at UMDF boundary.'
    },
    'T1052': {
      title: 'Exfiltration Over Physical Medium',
      desc: 'Adversaries attempt to bypass network monitoring by writing sensitive confidential documents, database exports, or source code directly to external flash media.',
      mitigation: 'Enforces Ring 3 Write-Blocker by default. Any unapproved outbound file writes are rejected with STATUS_ACCESS_DENIED, leaving read-only data access strictly verified.'
    },
    'T1200': {
      title: 'Hardware Additions (BadUSB & Rogue HID)',
      desc: 'Malicious microcontrollers masquerading as flash drives inject automated keystrokes into the OS to download remote payloads or spawn elevated administrative shells.',
      mitigation: 'Hardware Descriptor Interlock analyzes USB device class descriptors before interface binding. Non-mass-storage interfaces (HID, CDC, composite keyboards) are quarantined.'
    },
    'T1025': {
      title: 'Data from Removable Media',
      desc: 'Adversaries search for sensitive files on connected USB drives to collect intelligence or execute second-stage malicious payloads.',
      mitigation: 'All file streams are disassembled in pure userspace memory by the Rust CDR Engine. Active macros, OLE objects, and hidden streams are purged before presentation to explorer.exe.'
    }
  };

  function openMitreModal(techniqueId) {
    const data = MITRE_DATA[techniqueId] || {
      title: techniqueId,
      desc: 'Enterprise hardware threat vector.',
      mitigation: 'Ring 3 Userspace mitigation active.'
    };

    mitreModalId.textContent = techniqueId;
    mitreModalHeading.textContent = data.title;
    mitreModalDesc.textContent = data.desc;
    mitreModalMitigation.textContent = data.mitigation;

    mitreModal.classList.add('open');
    mitreModal.setAttribute('aria-hidden', 'false');
  }

  function closeMitreModal() {
    mitreModal.classList.remove('open');
    mitreModal.setAttribute('aria-hidden', 'true');
  }

  mitreChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const tech = chip.getAttribute('data-technique');
      openMitreModal(tech);
    });
    chip.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openMitreModal(chip.getAttribute('data-technique'));
      }
    });
  });

  if (btnCloseMitreModal) btnCloseMitreModal.addEventListener('click', closeMitreModal);
  if (mitreModal) {
    mitreModal.addEventListener('click', (e) => {
      if (e.target === mitreModal) closeMitreModal();
    });
  }

  // Keyboard Accessibility: Escape key closes any open modal immediately (Emil Kowalski)
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (cdrModal && cdrModal.classList.contains('open')) closeCdrModal();
      if (mitreModal && mitreModal.classList.contains('open')) closeMitreModal();
    }
  });

  /* ==========================================================================
     5. Persona Switcher (SOC HUD vs Air-Gapped Kiosk)
     ========================================================================== */
  function setPersona(persona) {
    if (persona === 'kiosk') {
      btnSocHUD.classList.remove('active');
      btnSocHUD.setAttribute('aria-pressed', 'false');
      btnKioskMode.classList.add('active');
      btnKioskMode.setAttribute('aria-pressed', 'true');

      socView.style.display = 'none';
      socView.setAttribute('aria-hidden', 'true');

      kioskView.classList.add('active');
      kioskView.setAttribute('aria-hidden', 'false');
    } else {
      btnKioskMode.classList.remove('active');
      btnKioskMode.setAttribute('aria-pressed', 'false');
      btnSocHUD.classList.add('active');
      btnSocHUD.setAttribute('aria-pressed', 'true');

      kioskView.classList.remove('active');
      kioskView.setAttribute('aria-hidden', 'true');

      socView.style.display = 'block';
      socView.setAttribute('aria-hidden', 'false');
    }
  }

  if (btnSocHUD) btnSocHUD.addEventListener('click', () => setPersona('soc'));
  if (btnKioskMode) btnKioskMode.addEventListener('click', () => setPersona('kiosk'));

  /* ==========================================================================
     6. Air-Gapped Kiosk State Machine
     ========================================================================== */
  let kioskInterval = null;

  if (btnKioskSimulate) {
    btnKioskSimulate.addEventListener('click', () => {
      btnKioskSimulate.disabled = true;
      btnKioskEject.disabled = true;

      // Step 1: Insert Drive
      kioskStep1.classList.add('active');
      kioskStep2.classList.remove('active');
      kioskStep3.classList.remove('active');

      setTimeout(() => {
        // Step 2: Automatic Cleanse
        kioskStep1.classList.remove('active');
        kioskStep2.classList.add('active');

        setTimeout(() => {
          // Step 3: Safe to Remove
          kioskStep2.classList.remove('active');
          kioskStep3.classList.add('active');

          btnKioskSimulate.disabled = false;
          btnKioskEject.disabled = false;
        }, 1800);
      }, 1200);
    });
  }

  if (btnKioskEject) {
    btnKioskEject.addEventListener('click', () => {
      kioskStep1.classList.add('active');
      kioskStep2.classList.remove('active');
      kioskStep3.classList.remove('active');
      btnKioskEject.disabled = true;
    });
  }

  /* ==========================================================================
     7. Peripheral Simulation Telemetry
     ========================================================================== */
  const DEVICES = [
    { name: 'Kingston 3.0 (E:)', v: '5.02 V', a: '0.92 A', w: '4.62 W' },
    { name: 'SanDisk Ultra (F:)', v: '4.98 V', a: '0.85 A', w: '4.23 W' },
    { name: 'Samsung T7 Shield (G:)', v: '5.10 V', a: '1.45 A', w: '7.40 W' },
    { name: 'YubiKey 5 NFC (HID)', v: '4.95 V', a: '0.08 A', w: '0.40 W' }
  ];
  let devIdx = 0;

  if (btnTogglePinSimulation) {
    btnTogglePinSimulation.addEventListener('click', () => {
      devIdx = (devIdx + 1) % DEVICES.length;
      const dev = DEVICES[devIdx];
      valDeviceName.textContent = dev.name;
      valVoltage.textContent = dev.v;
      valCurrent.textContent = dev.a;
      valPower.textContent = dev.w;
    });
  }

  /* ==========================================================================
     8. Adversarial Stress Testing Toggle (break-ui)
     ========================================================================== */
  if (btnStressToggle) {
    btnStressToggle.addEventListener('click', () => {
      isStressed = !isStressed;
      const streamBox = document.getElementById('cdrStreamBox');

      if (isStressed) {
        btnStressToggle.textContent = 'Reset Normal Data';
        btnStressToggle.style.backgroundColor = 'var(--color-status-warn-bg)';
        btnStressToggle.style.borderColor = 'var(--color-status-warn-border)';
        btnStressToggle.style.color = 'var(--color-status-warn)';

        // Feed stress payloads: long names, RTL Unicode, deep paths
        valDeviceName.textContent = 'EXT_NVME_001_VERY_LONG_NAME_TEST_PARTITION_LABEL_EXCEEDING_STANDARD_BUFFER_SIZE_X64 (H:)';
        
        if (streamBox) {
          streamBox.innerHTML = `
            <div class="cdr-item">
              <div class="cdr-file-meta">
                <span class="cdr-file-name">deeply/nested/path/to/enterprise/financial/2026/quarterly/audit_report_financial_statement_encrypted_macro_payload_test_string_exceeding_character_limits.xlsm</span>
                <span class="cdr-file-detail">Excel Sheet • Stripped: Recursive Obfuscated VBA ShellCode()</span>
              </div>
              <span class="cdr-badge sanitized">✓ Rebuilt Safe</span>
            </div>
            <div class="cdr-item">
              <div class="cdr-file-meta">
                <span class="cdr-file-name">تقرير_سري_للغاية_مراجعة_الأمان_المؤسسي_٢٠٢٦.pdf</span>
                <span class="cdr-file-detail">PDF Document • RTL Arabic Verified • 0 Malicious Traces</span>
              </div>
              <span class="cdr-badge sanitized">✓ Rebuilt Safe</span>
            </div>
          `;
        }
      } else {
        btnStressToggle.textContent = 'Adversarial Stress Test (break-ui)';
        btnStressToggle.style.backgroundColor = '';
        btnStressToggle.style.borderColor = '';
        btnStressToggle.style.color = '';

        valDeviceName.textContent = 'Kingston 3.0 (E:)';
        if (streamBox) {
          streamBox.innerHTML = `
            <div class="cdr-item">
              <div class="cdr-file-meta">
                <span class="cdr-file-name">Q3_Financial_Statement.xlsm</span>
                <span class="cdr-file-detail">Excel Sheet • Stripped: VBA Macro Execute()</span>
              </div>
              <span class="cdr-badge sanitized">✓ Rebuilt Safe</span>
            </div>
            <div class="cdr-item">
              <div class="cdr-file-meta">
                <span class="cdr-file-name">Vendor_Onboarding_Form.pdf</span>
                <span class="cdr-file-detail">PDF Document • Purged: Embedded JS /Launch</span>
              </div>
              <span class="cdr-badge sanitized">✓ Rebuilt Safe</span>
            </div>
            <div class="cdr-item">
              <div class="cdr-file-meta">
                <span class="cdr-file-name">Device_Firmware_Update.bin</span>
                <span class="cdr-file-detail">Raw Binary • Hash Mismatch: Quarantine</span>
              </div>
              <span class="cdr-badge purged">✕ Blocked</span>
            </div>
          `;
        }
      }
    });
  }
});
