document.addEventListener('DOMContentLoaded', () => {
  const safeChargingToggle = document.getElementById('safeChargingToggle');
  const btnScan = document.getElementById('btnScan');
  const btnDetonate = document.getElementById('btnDetonate');
  const targetPath = document.getElementById('targetPath');
  const logContainer = document.getElementById('logContainer');

  // 1. Safe Charging Toggle
  safeChargingToggle.addEventListener('change', (e) => {
    const isChargeOnly = e.target.checked;
    if (isChargeOnly) {
      addLog('WARN', 'HARDWARE ISOLATION', 'USB D+/D- data pins severed. VBUS 5V charging maintained.');
      alert('⚡ Safe Charging Mode Engaged!\nData pins D+/D- have been electronically de-authorized.\nNo data transfer or BadUSB attacks can penetrate the OS.');
    } else {
      addLog('INFO', 'INTERCEPTOR ACTIVE', 'Data pins restored under strict UMDF v2 filter monitoring.');
    }
  });

  // 2. Drive Scan Simulation / Trigger
  btnScan.addEventListener('click', () => {
    const path = targetPath.value.trim() || 'E:\\';
    btnScan.disabled = true;
    btnScan.querySelector('.btn-text').textContent = 'Scanning...';

    addLog('INFO', 'SWEEP INITIATED', `Executing zero-trust sweep on target: ${path}`);

    setTimeout(() => {
      addLog('CRIT', 'VIRUS DETECTED', `Found 134 identical 229,376-byte files [Trojan:Win32/Ramnit!pz] on ${path}`);
      addLog('WARN', 'SHORTCUT VECTOR', `Neutralized 33 malicious .lnk shortcuts [Exploit:Win32/CplLnk.A]`);
      addLog('SUCCESS', 'CDR SANITIZED', `Cleaned 967 documents & media files in 28ms; projected to Z:\\`);

      document.getElementById('statFiles').textContent = '1,134';
      document.getElementById('statThreats').textContent = '134';
      document.getElementById('statVectors').textContent = '33';
      document.getElementById('statDisarmed').textContent = '967';

      btnScan.disabled = false;
      btnScan.querySelector('.btn-text').textContent = 'Execute Zero-Trust Sweep';
    }, 1200);
  });

  // 3. OpenSandbox Detonation Trigger
  btnDetonate.addEventListener('click', () => {
    btnDetonate.disabled = true;
    btnDetonate.textContent = 'Detonating in MicroVM...';

    setTimeout(() => {
      addLog('WARN', 'SANDBOX DETONATED', 'MicroVM execution completed in 42ms. Process injection caught.');
      btnDetonate.disabled = false;
      btnDetonate.textContent = 'Run MicroVM Behavioral Detonation';
      alert('🔬 Detonation Finished!\nVerdict: MALICIOUS (Score: 100/100)\nCaptured C2 Beacons & Registry Persistence Mapped to MITRE ATT&CK.');
    }, 1500);
  });

  // Helper: Append log
  function addLog(level, badge, msg) {
    const timeStr = new Date().toTimeString().split(' ')[0];
    const logItem = document.createElement('div');
    logItem.className = `log-entry log-${level === 'CRIT' ? 'crit' : level === 'WARN' ? 'warn' : 'success'}`;
    logItem.innerHTML = `
      <span class="log-time">${timeStr}</span>
      <span class="log-badge">${badge}</span>
      <span class="log-msg">${msg}</span>
    `;
    logContainer.prepend(logItem);
  }

  // 4. Purge Buttons
  document.querySelectorAll('.btn-danger').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const row = e.target.closest('tr');
      const id = row.querySelector('code').textContent;
      if (confirm(`Permanently purge encrypted quarantine container for ${id}?`)) {
        row.style.opacity = '0.3';
        row.style.pointerEvents = 'none';
        addLog('INFO', 'VAULT PURGED', `Cryptographic container for ${id} erased from disk.`);
      }
    });
  });
});
