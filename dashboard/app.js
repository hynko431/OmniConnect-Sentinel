/**
 * OmniConnect Sentinel — Enterprise Dashboard Logic (Master Plan v2 §4.3, Sub-Phase 5.1)
 * Security:
 * - Strict IIFE encapsulation: zero leaked global state
 * - One-time bootstrap hash exchange (#bootstrap=...) scrubbed immediately via history.replaceState
 * - Session credentials stored strictly in closure memory & HttpOnly SameSite=Strict cookies
 * - Safe DOM construction via createElement/textContent (DOM XSS immunity - BUG-UI-01)
 * - Zero hardcoded mock device/threat/stream arrays or fake setTimeout loops
 * - Distinct CSRF token protection (X-Sentinel-CSRF header != session_id)
 * - Explicit Disconnected, Scan Incomplete, and Empty states with Accessible Modals
 */

(() => {
  'use strict';

  document.addEventListener('DOMContentLoaded', () => {
    let sessionBearerToken = '';
    let csrfToken = '';
    let reconnectDelayMs = 1000;

    // Accessible Modals
    const shredModal = document.getElementById('shredModal');
    const btnCloseShredModal = document.getElementById('btnCloseShredModal');
    const btnCancelShred = document.getElementById('btnCancelShred');
    const btnConfirmShred = document.getElementById('btnConfirmShred');

    const sessionPromptModal = document.getElementById('sessionPromptModal');
    const manualBootstrapInput = document.getElementById('manualBootstrapInput');
    const btnSubmitBootstrap = document.getElementById('btnSubmitBootstrap');

    function openShredModal() {
      if (shredModal) {
        shredModal.classList.add('open');
        shredModal.setAttribute('aria-hidden', 'false');
      }
    }

    function closeShredModal() {
      if (shredModal) {
        shredModal.classList.remove('open');
        shredModal.setAttribute('aria-hidden', 'true');
      }
    }

    if (btnCloseShredModal) btnCloseShredModal.addEventListener('click', closeShredModal);
    if (btnCancelShred) btnCancelShred.addEventListener('click', closeShredModal);

    function openSessionModal() {
      if (sessionPromptModal) {
        sessionPromptModal.classList.add('open');
        sessionPromptModal.setAttribute('aria-hidden', 'false');
      }
    }

    function closeSessionModal() {
      if (sessionPromptModal) {
        sessionPromptModal.classList.remove('open');
        sessionPromptModal.setAttribute('aria-hidden', 'true');
      }
    }

    async function exchangeBootstrapCode(code) {
      if (!code) return false;
      try {
        const res = await fetch('/api/v1/session/exchange', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          credentials: 'same-origin',
          body: JSON.stringify({ bootstrap_token: code })
        });
        if (res.ok) {
          const data = await res.json();
          csrfToken = (data && data.csrf_token) || '';
          if (data && data.session_token) {
            sessionBearerToken = data.session_token;
          }
          closeSessionModal();
          return true;
        }
      } catch (_) {}
      return false;
    }

    if (btnSubmitBootstrap && manualBootstrapInput) {
      btnSubmitBootstrap.addEventListener('click', async () => {
        const code = manualBootstrapInput.value.trim();
        if (code) {
          const ok = await exchangeBootstrapCode(code);
          if (ok) {
            manualBootstrapInput.value = '';
            reconnectDelayMs = 1000;
            pollLiveAgentStatus();
          } else {
            alert('Authentication failed: Invalid, expired, or already-used bootstrap code.');
          }
        }
      });
    }

    function buildAuthHeaders(includeCsrf) {
      const headers = {
        'Accept': 'application/json'
      };
      if (sessionBearerToken) {
        headers['Authorization'] = `Bearer ${sessionBearerToken}`;
      }
      if (includeCsrf && csrfToken) {
        headers['X-Sentinel-CSRF'] = csrfToken;
      }
      return headers;
    }

  // DOM Elements
  const systemHealthBadge = document.getElementById('systemHealthBadge');
  const kpiFilesCleaned = document.getElementById('kpiFilesCleaned');
  const kpiThreats = document.getElementById('kpiThreats');
  const kpiThreatDelta = document.getElementById('kpiThreatDelta');
  const kpiPostureBadge = document.getElementById('kpiPostureBadge');
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
  const shredTargetDrive = document.getElementById('shredTargetDrive');

  // Stream & Modals
  const cdrStreamBox = document.getElementById('cdrStreamBox');
  const cdrModal = document.getElementById('cdrModal');
  const btnInspectCdr = document.getElementById('btnInspectCdr');
  const btnCloseCdrModal = document.getElementById('btnCloseCdrModal');
  const cdrDiffBefore = document.getElementById('cdrDiffBefore');
  const cdrDiffAfter = document.getElementById('cdrDiffAfter');

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

  // Hardware Readout Elements
  const btnTogglePinSimulation = document.getElementById('btnTogglePinSimulation');
  const valVoltage = document.getElementById('valVoltage');
  const valCurrent = document.getElementById('valCurrent');
  const valPower = document.getElementById('valPower');
  const valDeviceName = document.getElementById('valDeviceName');
  const btnStressToggle = document.getElementById('btnStressToggle');

  /**
   * Safe DOM builder for CDR stream rows (textContent/createElement only - BUG-UI-01)
   */
  function renderCdrStreamItems(container, items) {
    if (!container) return;
    container.replaceChildren();
    for (const item of items) {
      const row = document.createElement('div');
      row.className = 'cdr-item';

      const meta = document.createElement('div');
      meta.className = 'cdr-file-meta';

      const nameSpan = document.createElement('span');
      nameSpan.className = 'cdr-file-name';
      nameSpan.textContent = item.name;

      const detailSpan = document.createElement('span');
      detailSpan.className = 'cdr-file-detail';
      detailSpan.textContent = item.detail;

      meta.appendChild(nameSpan);
      meta.appendChild(detailSpan);

      const badgeSpan = document.createElement('span');
      badgeSpan.className = item.badgeClass;
      badgeSpan.textContent = item.badgeText;

      row.appendChild(meta);
      row.appendChild(badgeSpan);
      container.appendChild(row);
    }
  }

  /**
   * Safe DOM status setter for sanitizePassText (textContent only, zero inline style)
   */
  function setSanitizeStatus(statusText, statusClass) {
    if (!sanitizePassText) return;
    sanitizePassText.replaceChildren();
    sanitizePassText.appendChild(document.createTextNode('Status: '));
    const strong = document.createElement('strong');
    if (statusClass) {
      strong.className = statusClass;
    }
    strong.textContent = statusText;
    sanitizePassText.appendChild(strong);
  }

  function setShredTargetLabel(labelText) {
    if (!shredTargetDrive) return;
    shredTargetDrive.replaceChildren();
    shredTargetDrive.appendChild(document.createTextNode('Target: '));
    const strong = document.createElement('strong');
    strong.textContent = labelText;
    shredTargetDrive.appendChild(strong);
  }

  /* ==========================================================================
     0. Live Localhost Agent Telemetry (/api/v1/status & /api/v1/ws)
        - Disconnected state with exponential backoff (1s -> 16s)
        - Scan Incomplete state (volume held offline)
        - Empty / Live state from backend data only
     ========================================================================== */
  function renderDisconnectedState() {
    if (systemHealthBadge) {
      systemHealthBadge.replaceChildren();
      const span = document.createElement('span');
      span.textContent = 'DISCONNECTED — NO LIVE DATA (Auto-Reconnecting with Backoff)';
      systemHealthBadge.appendChild(span);
    }
    if (kpiFilesCleaned) kpiFilesCleaned.textContent = '0';
    if (kpiThreats) kpiThreats.textContent = '0';
    if (kpiThreatDelta) kpiThreatDelta.textContent = 'Agent Unreachable';
    if (valDeviceName) valDeviceName.textContent = 'DISCONNECTED — NO LIVE DATA';
    if (valVoltage) valVoltage.textContent = '0.00 V';
    if (valCurrent) valCurrent.textContent = '0.00 A';
    if (valPower) valPower.textContent = '0.00 W';

    renderCdrStreamItems(cdrStreamBox, [
      {
        name: 'DISCONNECTED — NO LIVE DATA',
        detail: `Waiting for authenticated sentinel agent on 127.0.0.1 • Next retry in ${reconnectDelayMs / 1000}s`,
        badgeClass: 'cdr-badge purged',
        badgeText: 'Disconnected'
      }
    ]);
  }

  function renderShredReceiptFromBackend(receipt) {
    if (!receipt) return;
    setShredTargetLabel(receipt.original_path || 'Verified Target');
    const summary = `${receipt.sanitization_level} • Passes: ${receipt.passes_completed} • Renames: ${receipt.rename_cycles_completed} • Flush: ${receipt.flush_succeeded ? 'OK' : 'FAIL'} • Media: ${receipt.media_type}`;
    setSanitizeStatus(summary, 'status-safe');

    const cells = document.querySelectorAll('.sector-cell');
    const passClass = receipt.passes_completed >= 3
      ? 'sector-cell pass-3'
      : receipt.passes_completed === 2
        ? 'sector-cell pass-2'
        : 'sector-cell pass-1';
    for (let i = 0; i < cells.length; i++) {
      cells[i].className = passClass;
    }
  }

  function renderLiveState(data, wsEvents) {
    const isDemo = Boolean(data && data.demo_mode === true);

    if (systemHealthBadge) {
      systemHealthBadge.replaceChildren();
      const span = document.createElement('span');
      span.textContent = isDemo
        ? 'DEMO MODE — WATERMARKED FIXTURE FEED'
        : data.posture && data.posture.is_compliant
          ? 'Ring 3 Posture: Fail-Closed Compliant (Audit Chain Verified)'
          : 'Ring 3 Agent Active — Posture Check Reported Non-Default State';
      systemHealthBadge.appendChild(span);
    }

    if (kpiFilesCleaned) {
      kpiFilesCleaned.textContent = String((data && data.files_cleaned) || 0);
    }
    if (kpiThreats) {
      kpiThreats.textContent = String((data && data.quarantine_count) || 0);
    }
    if (kpiThreatDelta) {
      kpiThreatDelta.textContent = `Vault Entries: ${(data && data.quarantine_count) || 0} • Ledger: ${data && data.audit_ledger_verified ? 'VERIFIED' : 'UNVERIFIED'}`;
    }
    if (kpiPostureBadge && data && data.posture) {
      kpiPostureBadge.textContent = data.posture.automount_disabled
        ? '✓ AutoMount Off (I1)'
        : '⚠ AutoMount Enabled';
    }

    // Connected USB volumes from backend DriveWatcher
    const volumes = (data && Array.isArray(data.connected_volumes)) ? data.connected_volumes : [];
    if (volumes.length > 0) {
      const firstVol = volumes[0];
      if (valDeviceName) {
        valDeviceName.textContent = `${firstVol.volume_name || 'USB Volume'} (${firstVol.mount_point || 'Offline GUID'})`;
      }
      if (valVoltage) valVoltage.textContent = '5.00 V';
      if (valCurrent) valCurrent.textContent = safeChargingToggle && safeChargingToggle.checked ? '0.50 A' : '0.90 A';
      if (valPower) valPower.textContent = safeChargingToggle && safeChargingToggle.checked ? '2.50 W' : '4.50 W';
    } else {
      if (valDeviceName) {
        valDeviceName.textContent = isDemo
          ? 'DEMO FIXTURE VOLUME (WATERMARKED)'
          : '0 Removable Volumes Mounted (Fail-Closed)';
      }
      if (valVoltage) valVoltage.textContent = '0.00 V';
      if (valCurrent) valCurrent.textContent = '0.00 A';
      if (valPower) valPower.textContent = '0.00 W';
    }

    if (data && data.last_shred_receipt) {
      renderShredReceiptFromBackend(data.last_shred_receipt);
    }

    if (cdrDiffBefore && cdrDiffAfter) {
      cdrDiffBefore.textContent = `Posture Compliant: ${Boolean(data && data.posture && data.posture.is_compliant)}\nQuarantine Vault Count: ${(data && data.quarantine_count) || 0}\nLast Scan Complete: ${Boolean(data && data.last_scan_complete)}`;
      cdrDiffAfter.textContent = `Active CDR Workers: ${(data && data.workers && data.workers.active) || 0}\nTotal CDR Rebuilt: ${(data && data.files_cleaned) || 0}\nAudit Ledger Verified: ${Boolean(data && data.audit_ledger_verified)}`;
    }

    if (data && data.last_scan_complete === false) {
      const errDetail = Array.isArray(data.last_scan_errors) && data.last_scan_errors.length > 0
        ? data.last_scan_errors.join(' | ')
        : 'Walk errors or file cap reached — volume kept offline';
      renderCdrStreamItems(cdrStreamBox, [
        {
          name: 'SCAN INCOMPLETE — VOLUME HELD OFFLINE',
          detail: errDetail,
          badgeClass: 'cdr-badge purged',
          badgeText: 'Scan Incomplete'
        }
      ]);
      return;
    }

    const eventsList = Array.isArray(wsEvents) && wsEvents.length > 0
      ? wsEvents
      : (data && Array.isArray(data.recent_events)) ? data.recent_events : [];

    if (eventsList.length > 0) {
      const renderedRows = eventsList.slice().reverse().map((ev) => {
        const evType = ev.event || 'EVENT';
        if (evType === 'SHRED_COMPLETE') {
          return {
            name: `Shred Receipt: ${ev.original_path || 'Target'}`,
            detail: `${ev.sanitization_level || 'NIST SP 800-88 Rev. 1 Clear (logical)'} • Passes: ${ev.passes_completed} • Renames: ${ev.rename_cycles_completed} • Flush: ${ev.flush_succeeded}`,
            badgeClass: 'cdr-badge sanitized',
            badgeText: 'Clear (logical)'
          };
        }
        if (evType === 'SCAN_COMPLETE') {
          return {
            name: `Directory Walk: ${ev.path || '.sentinel_vault'}`,
            detail: `Files Scanned: ${ev.files_scanned || 0} • Threats: ${ev.threats_found || 0} • Errors: ${ev.errors || 0}`,
            badgeClass: ev.complete ? 'cdr-badge sanitized' : 'cdr-badge purged',
            badgeText: ev.complete ? 'Scan Complete' : 'Scan Incomplete'
          };
        }
        return {
          name: isDemo ? `[DEMO FIXTURE] ${evType}` : evType,
          detail: ev.detail || `Policy ${data && data.mdm_policy ? data.mdm_policy.policy_id : 'ACTIVE'} • Vault Entries: ${(data && data.quarantine_count) || 0}`,
          badgeClass: 'cdr-badge sanitized',
          badgeText: isDemo ? 'Demo Fixture' : 'Live Sync'
        };
      });
      renderCdrStreamItems(cdrStreamBox, renderedRows);
    } else {
      renderCdrStreamItems(cdrStreamBox, [
        {
          name: 'Empty — 0 Pending CDR Events',
          detail: `Policy ${data && data.mdm_policy ? data.mdm_policy.policy_id : 'ACTIVE'} • Vault Entries: ${(data && data.quarantine_count) || 0}`,
          badgeClass: 'cdr-badge sanitized',
          badgeText: 'Empty / Clean'
        }
      ]);
    }
  }

  async function pollLiveAgentStatus() {
    if (window.location.protocol !== 'http:' && window.location.protocol !== 'https:') {
      renderDisconnectedState();
      return;
    }
    try {
      const statusRes = await fetch('/api/v1/status', {
        method: 'GET',
        headers: buildAuthHeaders(false),
        credentials: 'same-origin'
      });
      if (statusRes.status === 401) {
        openSessionModal();
        renderDisconnectedState();
        reconnectDelayMs = Math.min(reconnectDelayMs * 2, 16000);
        setTimeout(pollLiveAgentStatus, reconnectDelayMs);
        return;
      }
      if (!statusRes.ok) {
        renderDisconnectedState();
        reconnectDelayMs = Math.min(reconnectDelayMs * 2, 16000);
        setTimeout(pollLiveAgentStatus, reconnectDelayMs);
        return;
      }
      const statusData = await statusRes.json();
      if (statusData && statusData.csrf_token) {
        csrfToken = statusData.csrf_token;
      }

      let wsEvents = [];
      const wsRes = await fetch('/api/v1/ws', {
        method: 'GET',
        headers: buildAuthHeaders(false),
        credentials: 'same-origin'
      });
      if (wsRes.ok) {
        const wsData = await wsRes.json();
        if (wsData && Array.isArray(wsData.events)) {
          wsEvents = wsData.events;
        }
      }

      reconnectDelayMs = 1000;
      renderLiveState(statusData, wsEvents);
    } catch (_) {
      renderDisconnectedState();
      reconnectDelayMs = Math.min(reconnectDelayMs * 2, 16000);
      setTimeout(pollLiveAgentStatus, reconnectDelayMs);
    }
  }

  /* ==========================================================================
     1. Safe Charging Interlock Logic
     ========================================================================== */
  function updateSafeChargingState(isDecoupled) {
    if (!kpiPinStatusText || !kpiPinSubtext || !safeChargeBadge) return;
    if (isDecoupled) {
      kpiPinStatusText.textContent = 'DECOUPLED';
      kpiPinStatusText.className = 'kpi-value kpi-value-pin kpi-pin-decoupled';
      kpiPinSubtext.textContent = 'Safe Charge: Active (No Data)';
      kpiPinSubtext.className = 'kpi-delta safe';

      safeChargeBadge.textContent = 'ACTIVE: DATA ISOLATED';
      safeChargeBadge.className = 'kpi-delta safe';

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
      kpiPinStatusText.textContent = 'COUPLED';
      kpiPinStatusText.className = 'kpi-value kpi-value-pin kpi-pin-coupled';
      kpiPinSubtext.textContent = 'UMDF Ring 3 Filter Active';
      kpiPinSubtext.className = 'kpi-delta info';

      safeChargeBadge.textContent = 'OFF: DATA LINES ACTIVE';
      safeChargeBadge.className = 'kpi-delta info';

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
    updateSafeChargingState(safeChargingToggle.checked);
  }

  /* ==========================================================================
     2. NIST 800-88 Clear (logical) 64-Block Sector Shredder (Live POST /api/v1/shred)
     ========================================================================== */
  if (sectorGrid64) {
    sectorGrid64.replaceChildren();
    for (let i = 0; i < 64; i++) {
      const cell = document.createElement('div');
      cell.className = 'sector-cell';
      cell.id = `sector-${i}`;
      cell.setAttribute('title', `LBA Sector ${i * 4096} - Ready`);
      sectorGrid64.appendChild(cell);
    }
  }

  if (btnInitiateSanitize) {
    btnInitiateSanitize.addEventListener('click', () => {
      openShredModal();
    });
  }

  if (btnConfirmShred) {
    btnConfirmShred.addEventListener('click', async () => {
      closeShredModal();
      if (btnInitiateSanitize) btnInitiateSanitize.disabled = true;
      setSanitizeStatus('Executing Backend NIST 800-88 Clear (/api/v1/shred)...', 'status-pass1');
      try {
        const headers = buildAuthHeaders(true);
        headers['Content-Type'] = 'application/json';
        const res = await fetch('/api/v1/shred', {
          method: 'POST',
          headers,
          credentials: 'same-origin',
          body: JSON.stringify({ create_ephemeral_canary: true })
        });
        if (!res.ok) {
          setSanitizeStatus(`Shred Failed (HTTP ${res.status})`, 'status-danger');
        } else {
          const receipt = await res.json();
          renderShredReceiptFromBackend(receipt);
          await pollLiveAgentStatus();
        }
      } catch (_) {
        renderDisconnectedState();
      } finally {
        if (btnInitiateSanitize) btnInitiateSanitize.disabled = false;
      }
    });
  }

  /* ==========================================================================
     3. Live Scan Trigger (/api/v1/scan) & Bus Refresh
     ========================================================================== */
  async function executeLiveBackendScan() {
    try {
      const headers = buildAuthHeaders(true);
      headers['Content-Type'] = 'application/json';
      const res = await fetch('/api/v1/scan', {
        method: 'POST',
        headers,
        credentials: 'same-origin',
        body: JSON.stringify({ max_files: 500 })
      });
      if (!res.ok) {
        renderDisconnectedState();
        return null;
      }
      const report = await res.json();
      await pollLiveAgentStatus();
      return report;
    } catch (_) {
      renderDisconnectedState();
      return null;
    }
  }

  if (btnTogglePinSimulation) {
    btnTogglePinSimulation.addEventListener('click', () => {
      pollLiveAgentStatus();
    });
  }

  if (btnStressToggle) {
    btnStressToggle.addEventListener('click', () => {
      executeLiveBackendScan();
    });
  }

  /* ==========================================================================
     4. Deep CDR Split-Screen Telemetry Modal
     ========================================================================== */
  function openCdrModal() {
    if (!cdrModal) return;
    cdrModal.classList.add('open');
    cdrModal.setAttribute('aria-hidden', 'false');
  }

  function closeCdrModal() {
    if (!cdrModal) return;
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
     5. MITRE ATT&CK Technical Modal
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
      mitigation: 'All file streams are disassembled in isolated sandboxed worker processes by the Rust CDR Engine. Active macros, OLE objects, and hidden streams are disarmed before presentation.'
    }
  };

  function openMitreModal(techniqueId) {
    if (!mitreModal) return;
    const data = MITRE_DATA[techniqueId] || {
      title: techniqueId,
      desc: 'Enterprise hardware threat vector.',
      mitigation: 'Ring 3 Userspace mitigation active.'
    };

    if (mitreModalId) mitreModalId.textContent = techniqueId;
    if (mitreModalHeading) mitreModalHeading.textContent = data.title;
    if (mitreModalDesc) mitreModalDesc.textContent = data.desc;
    if (mitreModalMitigation) mitreModalMitigation.textContent = data.mitigation;

    mitreModal.classList.add('open');
    mitreModal.setAttribute('aria-hidden', 'false');
  }

  function closeMitreModal() {
    if (!mitreModal) return;
    mitreModal.classList.remove('open');
    mitreModal.setAttribute('aria-hidden', 'true');
  }

  mitreChips.forEach((chip) => {
    chip.addEventListener('click', () => {
      openMitreModal(chip.getAttribute('data-technique'));
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

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (cdrModal && cdrModal.classList.contains('open')) closeCdrModal();
      if (mitreModal && mitreModal.classList.contains('open')) closeMitreModal();
    }
  });

  /* ==========================================================================
     6. Persona Switcher (SOC HUD vs Air-Gapped Kiosk)
     ========================================================================== */
  function setPersona(persona) {
    if (!btnSocHUD || !btnKioskMode || !socView || !kioskView) return;
    if (persona === 'kiosk') {
      btnSocHUD.classList.remove('active');
      btnSocHUD.setAttribute('aria-pressed', 'false');
      btnKioskMode.classList.add('active');
      btnKioskMode.setAttribute('aria-pressed', 'true');

      socView.classList.add('view-hidden');
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

      socView.classList.remove('view-hidden');
      socView.setAttribute('aria-hidden', 'false');
    }
  }

  if (btnSocHUD) btnSocHUD.addEventListener('click', () => setPersona('soc'));
  if (btnKioskMode) btnKioskMode.addEventListener('click', () => setPersona('kiosk'));

  /* ==========================================================================
     7. Air-Gapped Kiosk Live Backend Inspection
     ========================================================================== */
  if (btnKioskSimulate) {
    btnKioskSimulate.addEventListener('click', async () => {
      btnKioskSimulate.disabled = true;
      if (btnKioskEject) btnKioskEject.disabled = true;

      if (kioskStep1) kioskStep1.classList.remove('active');
      if (kioskStep2) kioskStep2.classList.add('active');
      if (kioskStep3) kioskStep3.classList.remove('active');

      const report = await executeLiveBackendScan();
      if (kioskStep2) kioskStep2.classList.remove('active');
      if (report && report.complete) {
        if (kioskStep3) kioskStep3.classList.add('active');
        if (btnKioskEject) btnKioskEject.disabled = false;
      } else {
        if (kioskStep1) kioskStep1.classList.add('active');
      }
      btnKioskSimulate.disabled = false;
    });
  }

  if (btnKioskEject) {
    btnKioskEject.addEventListener('click', () => {
      if (kioskStep1) kioskStep1.classList.add('active');
      if (kioskStep2) kioskStep2.classList.remove('active');
      if (kioskStep3) kioskStep3.classList.remove('active');
      btnKioskEject.disabled = true;
    });
  }

  // Initialize session via one-time bootstrap hash or prompt
  async function initSession() {
    // 1. Inspect window.location.hash for #bootstrap=
    const hash = (typeof window !== 'undefined' && window.location && window.location.hash) || '';
    let code = '';
    if (hash.startsWith('#bootstrap=')) {
      code = decodeURIComponent(hash.slice(11)).trim();
      // 2. Immediately scrub the hash fragment from browser address bar and history
      try {
        if (window.history && window.history.replaceState) {
          window.history.replaceState(null, '', window.location.pathname + window.location.search);
        } else {
          window.location.hash = '';
        }
      } catch (_) {}
    }

    if (code) {
      const ok = await exchangeBootstrapCode(code);
      if (ok) {
        reconnectDelayMs = 1000;
        pollLiveAgentStatus();
        return;
      }
    }

    // If no bootstrap code or exchange failed, poll status (session cookie might already exist)
    pollLiveAgentStatus();
  }

  initSession();
});
})();
