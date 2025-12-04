/**
 * SafeGuard Fusion - Preload Script
 * Secure bridge between main process and renderer
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('safeguard', {
  // Window controls
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close: () => ipcRenderer.send('window-close'),

  // Mode management
  getMode: () => ipcRenderer.invoke('get-mode'),
  setMode: (mode) => ipcRenderer.invoke('set-mode', mode),
  getAppState: () => ipcRenderer.invoke('get-app-state'),

  // Data operations
  readTargets: () => ipcRenderer.invoke('read-targets'),
  readAuthorizations: () => ipcRenderer.invoke('read-authorizations'),
  getScanResults: () => ipcRenderer.invoke('get-scan-results'),

  // Tool execution
  runSentinel: (target, tier) => ipcRenderer.invoke('run-sentinel', target, tier),
  runVibeCommand: (cmd) => ipcRenderer.invoke('run-vibe-command', cmd),
  checkAuthorization: (target) => ipcRenderer.invoke('check-authorization', target),
  runShell: (cmd, args) => ipcRenderer.invoke('run-shell', cmd, args),

  // Event listeners
  onPythonOutput: (callback) => {
    ipcRenderer.on('python-output', (_, data) => callback(data));
  },
  onNavigate: (callback) => {
    ipcRenderer.on('navigate', (_, route) => callback(route));
  },
  
  // Cleanup
  removeAllListeners: () => {
    ipcRenderer.removeAllListeners('python-output');
    ipcRenderer.removeAllListeners('navigate');
  }
});
