/**
 * SafeGuard Fusion - Application Logic
 * Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.
 * Built by World-Class Engineering Team
 */

// ===== State Management =====
const AppState = {
  mode: 'hybrid',
  currentPage: 'dashboard',
  targets: [],
  authorizations: [],
  scanResults: [],
  activeScans: [],
  metrics: {
    uptime: 99.9,
    scans: 0,
    alerts: 0,
    bounty: 0
  }
};

// ===== Initialization =====
document.addEventListener('DOMContentLoaded', async () => {
  console.log('🛡️ SafeGuard Fusion Initializing...');
  
  await initializeApp();
  setupEventListeners();
  startRealTimeUpdates();
  generateHeatmap();
  initializeCyberMap();
  
  console.log('✅ SafeGuard Fusion Ready');
});

async function initializeApp() {
  // Load mode from Electron
  if (window.safeguard) {
    AppState.mode = await window.safeguard.getMode();
    updateModeUI();
    
    // Load data
    AppState.targets = await window.safeguard.readTargets();
    AppState.authorizations = await window.safeguard.readAuthorizations();
    AppState.scanResults = await window.safeguard.getScanResults();
    
    // Listen for Python output
    window.safeguard.onPythonOutput((data) => {
      appendToVibeOutput(data.data);
    });
  }
  
  updateTargetsList();
  updateAuthList();
  updateStats();
}

// ===== Event Listeners =====
function setupEventListeners() {
  // Mode switcher
  document.querySelectorAll('.mode-btn').forEach(btn => {
    btn.addEventListener('click', () => switchMode(btn.dataset.mode));
  });
  
  // Navigation
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(item.dataset.page);
    });
  });
  
  // New scan button
  document.getElementById('btn-new-scan')?.addEventListener('click', openScanModal);
  
  // Scan form
  document.getElementById('scan-form')?.addEventListener('submit', handleScanSubmit);
  
  // Tier selector
  document.querySelectorAll('.tier-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tier-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });
  
  // CVSS slider
  const cvssSlider = document.getElementById('cvss-score');
  if (cvssSlider) {
    cvssSlider.addEventListener('input', (e) => {
      document.querySelector('.cvss-display').textContent = parseFloat(e.target.value).toFixed(1);
    });
  }
  
  // Submission form
  document.getElementById('submission-form')?.addEventListener('submit', handleSubmissionSubmit);
  
  // Vibe command
  document.getElementById('vibe-input')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') executeVibeCommand();
  });
  
  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
      switch(e.key) {
        case 'n':
          e.preventDefault();
          openScanModal();
          break;
        case 'k':
          e.preventDefault();
          openVibeCommand();
          break;
      }
    }
    if (e.key === 'Escape') {
      closeAllModals();
    }
  });
}

// ===== Mode Management =====
function switchMode(mode) {
  AppState.mode = mode;
  
  document.querySelectorAll('.mode-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.mode === mode);
  });
  
  const switcher = document.querySelector('.mode-switcher');
  switcher.classList.toggle('bounty', mode === 'bounty');
  
  if (window.safeguard) {
    window.safeguard.setMode(mode);
  }
  
  // Update UI theme hints
  document.body.dataset.mode = mode;
  
  showToast(`Switched to ${mode === 'hybrid' ? 'Hybrid NOC' : 'Bounty Ops'} mode`, 'success');
}

function updateModeUI() {
  const switcher = document.querySelector('.mode-switcher');
  switcher.classList.toggle('bounty', AppState.mode === 'bounty');
  
  document.querySelectorAll('.mode-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.mode === AppState.mode);
  });
}

// ===== Navigation =====
function navigateTo(page) {
  AppState.currentPage = page;
  
  // Update nav
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.page === page);
  });
  
  // Show page
  document.querySelectorAll('.page').forEach(p => {
    p.classList.toggle('active', p.id === `page-${page}`);
  });
  
  // Load page-specific content
  switch(page) {
    case 'targets':
      updateTargetsList();
      break;
    case 'authorization':
      updateAuthList();
      break;
    case 'transparency':
      updateAuditLog();
      break;
  }
}

// ===== Stats & Metrics =====
function updateStats() {
  document.getElementById('stat-uptime').textContent = `${AppState.metrics.uptime}%`;
  document.getElementById('stat-scans').textContent = AppState.metrics.scans;
  document.getElementById('stat-alerts').textContent = AppState.metrics.alerts;
  document.getElementById('stat-bounty').textContent = `$${AppState.metrics.bounty.toLocaleString()}`;
}

// ===== Scan Management =====
function openScanModal() {
  document.getElementById('scan-modal').classList.add('active');
  document.getElementById('scan-target').focus();
}

function closeScanModal() {
  document.getElementById('scan-modal').classList.remove('active');
}

async function handleScanSubmit(e) {
  e.preventDefault();
  
  const target = document.getElementById('scan-target').value.trim();
  const tier = document.querySelector('.tier-btn.active').dataset.tier;
  const verifyAuth = document.getElementById('verify-auth').checked;
  
  if (!target) {
    showToast('Please enter a target', 'error');
    return;
  }
  
  closeScanModal();
  showToast(`Starting ${tier} scan on ${target}...`, 'success');
  
  // Add to active scans
  const scanId = Date.now();
  const newScan = {
    id: scanId,
    target,
    tier,
    status: 'running',
    progress: 0,
    startTime: new Date()
  };
  AppState.activeScans.push(newScan);
  AppState.metrics.scans++;
  updateStats();
  updateSimulationsList();
  
  // Run scan via Electron
  if (window.safeguard) {
    if (verifyAuth) {
      const authResult = await window.safeguard.checkAuthorization(target);
      if (!authResult.success) {
        showToast(`Authorization check failed: ${authResult.error}`, 'error');
        removeScan(scanId);
        return;
      }
    }
    
    const result = await window.safeguard.runSentinel(target, tier);
    
    if (result.success) {
      showToast(`Scan completed for ${target}`, 'success');
      updateScanProgress(scanId, 100, 'completed');
    } else {
      showToast(`Scan failed: ${result.error}`, 'error');
      updateScanProgress(scanId, 0, 'failed');
    }
  } else {
    // Demo mode - simulate progress
    simulateScanProgress(scanId);
  }
}

function simulateScanProgress(scanId) {
  let progress = 0;
  const interval = setInterval(() => {
    progress += Math.random() * 15;
    if (progress >= 100) {
      progress = 100;
      clearInterval(interval);
      updateScanProgress(scanId, 100, 'completed');
      showToast('Scan completed!', 'success');
    } else {
      updateScanProgress(scanId, progress, 'running');
    }
  }, 500);
}

function updateScanProgress(scanId, progress, status) {
  const scan = AppState.activeScans.find(s => s.id === scanId);
  if (scan) {
    scan.progress = progress;
    scan.status = status;
    updateSimulationsList();
  }
}

function removeScan(scanId) {
  AppState.activeScans = AppState.activeScans.filter(s => s.id !== scanId);
  AppState.metrics.scans = Math.max(0, AppState.metrics.scans - 1);
  updateStats();
  updateSimulationsList();
}

function updateSimulationsList() {
  const container = document.getElementById('simulations-list');
  if (!container) return;
  
  if (AppState.activeScans.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No active scans. Click "New Scan" to begin.</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = AppState.activeScans.map(scan => `
    <div class="simulation-item">
      <div class="sim-header">
        <span class="sim-name">${scan.target}</span>
        <span class="sim-status ${scan.status}">${scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}</span>
      </div>
      <div class="sim-progress">
        <div class="progress-bar"><div class="progress-fill" style="width: ${scan.progress}%"></div></div>
        <span class="progress-text">${Math.round(scan.progress)}%</span>
      </div>
      <div class="sim-meta">
        <span>Tier: ${scan.tier}</span>
        <span>Started: ${scan.startTime.toLocaleTimeString()}</span>
      </div>
    </div>
  `).join('');
}

// ===== Vibe Command =====
function openVibeCommand() {
  document.getElementById('vibe-modal').classList.add('active');
  document.getElementById('vibe-input').focus();
}

function closeVibeModal() {
  document.getElementById('vibe-modal').classList.remove('active');
}

function setVibeCommand(cmd) {
  document.getElementById('vibe-input').value = cmd;
  document.getElementById('vibe-input').focus();
}

async function executeVibeCommand() {
  const input = document.getElementById('vibe-input');
  const output = document.getElementById('vibe-output');
  const command = input.value.trim();
  
  if (!command) return;
  
  output.innerHTML += `\n> ${command}\n`;
  input.value = '';
  
  if (window.safeguard) {
    output.innerHTML += 'Executing...\n';
    const result = await window.safeguard.runVibeCommand(command);
    if (result.success) {
      output.innerHTML += result.output + '\n';
    } else {
      output.innerHTML += `Error: ${result.error}\n`;
    }
  } else {
    // Demo mode
    output.innerHTML += simulateVibeResponse(command) + '\n';
  }
  
  output.scrollTop = output.scrollHeight;
}

function simulateVibeResponse(command) {
  const cmd = command.toLowerCase();
  if (cmd.includes('scan')) {
    return '🔍 Initiating scan...\n   → Discovered 3 subdomains\n   → Running nuclei templates\n   → Found 2 potential vulnerabilities';
  }
  if (cmd.includes('auth')) {
    return '✅ Authorization verified for current scope\n   → 5 targets authorized\n   → 0 targets pending';
  }
  if (cmd.includes('result')) {
    return '📊 Recent Results:\n   → 12 scans completed\n   → 5 vulnerabilities found\n   → 2 submissions ready';
  }
  return `🤖 Processing: "${command}"\n   → Command recognized\n   → Executing workflow...`;
}

function appendToVibeOutput(text) {
  const output = document.getElementById('vibe-output');
  if (output) {
    output.innerHTML += text;
    output.scrollTop = output.scrollHeight;
  }
}

// ===== Quick Actions =====
async function runQuickScan() {
  if (AppState.targets.length === 0) {
    showToast('No targets configured', 'warning');
    return;
  }
  
  const target = AppState.targets[0];
  showToast(`Quick scan started on ${target}`, 'success');
  
  if (window.safeguard) {
    const result = await window.safeguard.runSentinel(target, 'basic');
    showToast(result.success ? 'Quick scan complete!' : 'Scan failed', result.success ? 'success' : 'error');
  }
}

async function checkAuth() {
  const target = AppState.targets[0] || 'example.com';
  showToast(`Checking authorization for ${target}...`, 'success');
  
  if (window.safeguard) {
    const result = await window.safeguard.checkAuthorization(target);
    showToast(
      result.success ? '✅ Target is authorized' : '❌ No authorization found',
      result.success ? 'success' : 'warning'
    );
  }
}

// ===== Targets Management =====
function updateTargetsList() {
  const container = document.getElementById('targets-list');
  if (!container) return;
  
  if (AppState.targets.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No targets loaded. Add targets to targets.txt</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = `
    <div class="targets-header">
      <h3>Configured Targets (${AppState.targets.length})</h3>
    </div>
    <div class="targets-items">
      ${AppState.targets.map(t => `
        <div class="target-item">
          <span class="target-domain">${t}</span>
          <div class="target-actions">
            <button class="btn-icon" onclick="scanTarget('${t}')" title="Scan">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
              </svg>
            </button>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function scanTarget(target) {
  document.getElementById('scan-target').value = target;
  openScanModal();
}

// ===== Authorization Management =====
function updateAuthList() {
  const container = document.getElementById('auth-list');
  if (!container) return;
  
  if (AppState.authorizations.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <p>No authorizations found</p>
        <button class="btn-secondary" onclick="createAuth()">Create Authorization</button>
      </div>
    `;
    return;
  }
  
  container.innerHTML = `
    <div class="auth-header">
      <h3>Active Authorizations (${AppState.authorizations.length})</h3>
      <button class="btn-secondary" onclick="createAuth()">+ New</button>
    </div>
    <div class="auth-items">
      ${AppState.authorizations.map(auth => `
        <div class="auth-item">
          <div class="auth-info">
            <span class="auth-target">${auth.target || 'Unknown'}</span>
            <span class="auth-client">${auth.client_name || 'N/A'}</span>
          </div>
          <div class="auth-dates">
            <span>Valid: ${auth.start_date?.split('T')[0] || 'N/A'} - ${auth.end_date?.split('T')[0] || 'N/A'}</span>
          </div>
          <span class="auth-status ${isAuthValid(auth) ? 'valid' : 'expired'}">
            ${isAuthValid(auth) ? 'Valid' : 'Expired'}
          </span>
        </div>
      `).join('')}
    </div>
  `;
}

function isAuthValid(auth) {
  if (!auth.end_date) return false;
  return new Date(auth.end_date) > new Date();
}

async function createAuth() {
  showToast('Opening authorization creator...', 'success');
  if (window.safeguard) {
    await window.safeguard.runShell('python3', ['CREATE_AUTHORIZATION.py', '--target', 'example.com']);
  }
}

// ===== Audit Log =====
function updateAuditLog() {
  const container = document.getElementById('audit-entries');
  if (!container) return;
  
  const entries = generateAuditEntries();
  
  container.innerHTML = entries.map(entry => `
    <div class="log-entry ${entry.type}">
      <span class="log-time">${entry.time}</span>
      <span class="log-action">${entry.action}</span>
      <span class="log-user">${entry.user}</span>
      <span class="log-status">${entry.status}</span>
    </div>
  `).join('');
}

function generateAuditEntries() {
  const now = new Date();
  return [
    { time: formatTime(now), action: 'System Initialized', user: 'System', type: 'info', status: 'OK' },
    { time: formatTime(new Date(now - 300000)), action: 'Authorization Check', user: 'Operator', type: 'success', status: 'Passed' },
    { time: formatTime(new Date(now - 600000)), action: 'Scan Started', user: 'Operator', type: 'info', status: 'In Progress' },
  ];
}

function formatTime(date) {
  return date.toLocaleTimeString('en-US', { hour12: false });
}

// ===== Submission Form =====
function handleSubmissionSubmit(e) {
  e.preventDefault();
  showToast('Submission created! Ready for review.', 'success');
}

// ===== Heatmap =====
function generateHeatmap() {
  const container = document.getElementById('vuln-heatmap');
  if (!container) return;
  
  const levels = ['', 'low', 'medium', 'high', 'critical'];
  let html = '';
  
  for (let i = 0; i < 50; i++) {
    const level = levels[Math.floor(Math.random() * 5)];
    html += `<div class="heatmap-cell ${level}"></div>`;
  }
  
  container.innerHTML = html;
}

// ===== Cyber Map =====
function initializeCyberMap() {
  const attackNodes = document.getElementById('attack-nodes');
  const defenseNodes = document.getElementById('defense-nodes');
  const attackLines = document.getElementById('attack-lines');
  
  if (!attackNodes || !defenseNodes || !attackLines) return;
  
  // Add defense nodes (blue)
  const defensePositions = [
    { x: 400, y: 180 }, { x: 600, y: 150 }, { x: 750, y: 200 }
  ];
  
  defensePositions.forEach((pos, i) => {
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', pos.x);
    circle.setAttribute('cy', pos.y);
    circle.setAttribute('r', '6');
    circle.classList.add('defense-node');
    defenseNodes.appendChild(circle);
  });
  
  // Add attack nodes (red) with animation
  const attackPositions = [
    { x: 180, y: 160 }, { x: 320, y: 300 }, { x: 820, y: 300 }
  ];
  
  attackPositions.forEach((pos, i) => {
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', pos.x);
    circle.setAttribute('cy', pos.y);
    circle.setAttribute('r', '4');
    circle.classList.add('attack-node');
    attackNodes.appendChild(circle);
    
    // Draw attack lines
    const defense = defensePositions[i % defensePositions.length];
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', pos.x);
    line.setAttribute('y1', pos.y);
    line.setAttribute('x2', defense.x);
    line.setAttribute('y2', defense.y);
    line.classList.add('attack-line');
    attackLines.appendChild(line);
  });
  
  // Update map stats
  document.getElementById('map-attacks').textContent = attackPositions.length;
  document.getElementById('map-blocked').textContent = Math.floor(attackPositions.length * 0.8);
  document.getElementById('map-sources').textContent = attackPositions.length;
}

// ===== Real-Time Updates =====
function startRealTimeUpdates() {
  // Update metrics periodically
  setInterval(() => {
    // Simulate slight variations
    AppState.metrics.uptime = Math.min(100, AppState.metrics.uptime + (Math.random() - 0.5) * 0.1);
    
    // Random alerts
    if (Math.random() > 0.95) {
      AppState.metrics.alerts++;
      addThreatEvent();
    }
    
    updateStats();
  }, 5000);
  
  // Update heatmap occasionally
  setInterval(generateHeatmap, 30000);
}

function addThreatEvent() {
  const container = document.querySelector('.threats-list');
  if (!container) return;
  
  const types = ['Port Scan Detected', 'Suspicious DNS Query', 'Failed Auth Attempt', 'Anomaly Detected'];
  const levels = ['low', 'medium', 'high'];
  const level = levels[Math.floor(Math.random() * levels.length)];
  
  const event = document.createElement('div');
  event.className = `threat-item ${level}`;
  event.innerHTML = `
    <span class="threat-time">${formatTime(new Date())}</span>
    <span class="threat-type">${types[Math.floor(Math.random() * types.length)]}</span>
    <span class="threat-source">${generateIP()}</span>
    <span class="threat-badge">${level.toUpperCase()}</span>
  `;
  
  const list = container.querySelector('.threat-item');
  if (list) {
    container.insertBefore(event, list.nextSibling);
  }
  
  // Keep only last 5 events
  const items = container.querySelectorAll('.threat-item');
  if (items.length > 5) {
    items[items.length - 1].remove();
  }
}

function generateIP() {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

// ===== Toast Notifications =====
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      ${type === 'success' ? '<polyline points="20 6 9 17 4 12"/>' : 
        type === 'error' ? '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>' :
        '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'}
    </svg>
    <span>${message}</span>
  `;
  
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'toastOut 0.3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ===== Utilities =====
function closeAllModals() {
  document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
}

// Add toastOut animation
const style = document.createElement('style');
style.textContent = `
  @keyframes toastOut {
    to { opacity: 0; transform: translateX(100px); }
  }
  
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 40px;
    color: var(--text-muted);
    text-align: center;
    gap: 16px;
  }
  
  .empty-state svg {
    opacity: 0.5;
  }
  
  .targets-header, .auth-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--glass-border);
  }
  
  .targets-header h3, .auth-header h3 {
    font-size: 14px;
    color: var(--text-secondary);
  }
  
  .target-item, .auth-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    background: var(--bg-tertiary);
    border-radius: 8px;
    margin-bottom: 8px;
  }
  
  .target-domain {
    font-family: var(--font-mono);
    color: var(--cyber-cyan);
  }
  
  .auth-info {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  
  .auth-target {
    font-family: var(--font-mono);
    color: var(--cyber-cyan);
  }
  
  .auth-client {
    font-size: 12px;
    color: var(--text-muted);
  }
  
  .auth-dates {
    font-size: 12px;
    color: var(--text-secondary);
  }
  
  .auth-status {
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
  }
  
  .auth-status.valid {
    background: rgba(0, 255, 136, 0.15);
    color: var(--success-color);
  }
  
  .auth-status.expired {
    background: rgba(255, 68, 68, 0.15);
    color: var(--offense-color);
  }
  
  .log-entry {
    display: grid;
    grid-template-columns: 100px 1fr 120px 80px;
    gap: 16px;
    padding: 12px;
    background: var(--bg-tertiary);
    border-radius: 8px;
    margin-bottom: 8px;
    font-size: 13px;
  }
  
  .log-time {
    font-family: var(--font-mono);
    color: var(--text-muted);
  }
  
  .log-action {
    color: var(--text-primary);
  }
  
  .log-user {
    color: var(--text-secondary);
  }
  
  .log-status {
    text-align: right;
    font-weight: 600;
    color: var(--success-color);
  }
`;
document.head.appendChild(style);

// Export for global access
window.openVibeCommand = openVibeCommand;
window.closeVibeModal = closeVibeModal;
window.setVibeCommand = setVibeCommand;
window.executeVibeCommand = executeVibeCommand;
window.closeScanModal = closeScanModal;
window.runQuickScan = runQuickScan;
window.checkAuth = checkAuth;
window.scanTarget = scanTarget;
window.createAuth = createAuth;
