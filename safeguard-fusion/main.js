/**
 * SafeGuard Fusion - Desktop Application
 * Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.
 * 
 * Electron Main Process - Hybrid NOC to Bug Bounty Platform
 * Built by World-Class Engineering Team
 */

const { app, BrowserWindow, ipcMain, Menu, shell, dialog, Tray, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

// Constants
const isDev = !app.isPackaged;
const RECON_BASE = path.join(__dirname, '..');

let mainWindow = null;
let tray = null;
let activeProcesses = new Map();

// App state
const appState = {
  mode: 'hybrid',
  scanningActive: false,
  connectedTargets: 0,
  alertCount: 0
};

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1800,
    height: 1100,
    minWidth: 1400,
    minHeight: 900,
    backgroundColor: '#0a0f1a',
    frame: false,
    transparent: false,
    titleBarStyle: 'hidden',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      spellcheck: false
    },
    show: false
  });

  // Elegant fade-in on ready
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Load app
  if (isDev) {
    mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));
    // mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
    terminateAllProcesses();
  });

  setupIPC();
}

function setupIPC() {
  // Window controls
  ipcMain.on('window-minimize', () => mainWindow?.minimize());
  ipcMain.on('window-maximize', () => {
    if (mainWindow?.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow?.maximize();
    }
  });
  ipcMain.on('window-close', () => mainWindow?.close());

  // Mode switching
  ipcMain.handle('get-mode', () => appState.mode);
  ipcMain.handle('set-mode', (_, mode) => {
    appState.mode = mode;
    return appState.mode;
  });

  // Get app state
  ipcMain.handle('get-app-state', () => appState);

  // File system operations
  ipcMain.handle('read-targets', async () => {
    try {
      const targetsPath = path.join(RECON_BASE, 'targets.txt');
      const content = fs.readFileSync(targetsPath, 'utf-8');
      return content.split('\n').filter(t => t.trim());
    } catch (e) {
      return [];
    }
  });

  ipcMain.handle('read-authorizations', async () => {
    try {
      const authDir = path.join(RECON_BASE, 'authorizations');
      if (!fs.existsSync(authDir)) return [];
      const files = fs.readdirSync(authDir).filter(f => f.endsWith('.json'));
      return files.map(f => {
        const content = JSON.parse(fs.readFileSync(path.join(authDir, f), 'utf-8'));
        return { filename: f, ...content };
      });
    } catch (e) {
      return [];
    }
  });

  ipcMain.handle('get-scan-results', async () => {
    try {
      const outputDir = path.join(RECON_BASE, 'output');
      if (!fs.existsSync(outputDir)) return [];
      const files = fs.readdirSync(outputDir)
        .filter(f => f.endsWith('.json'))
        .slice(-20);
      return files.map(f => ({
        name: f,
        path: path.join(outputDir, f),
        modified: fs.statSync(path.join(outputDir, f)).mtime
      }));
    } catch (e) {
      return [];
    }
  });

  // Run Python tools
  ipcMain.handle('run-sentinel', async (_, target, tier) => {
    return runPythonScript('SENTINEL_AGENT.py', [target, '--tier', tier || 'basic']);
  });

  ipcMain.handle('run-vibe-command', async (_, command) => {
    return runPythonScript('VIBE_COMMAND_SYSTEM.py', ['--command', command]);
  });

  ipcMain.handle('check-authorization', async (_, target) => {
    return runPythonScript('LEGAL_AUTHORIZATION_SYSTEM.py', ['--check', target]);
  });

  // Shell commands
  ipcMain.handle('run-shell', async (_, cmd, args) => {
    return new Promise((resolve) => {
      const proc = spawn(cmd, args, { cwd: RECON_BASE, shell: true });
      let output = '';
      proc.stdout.on('data', (data) => output += data.toString());
      proc.stderr.on('data', (data) => output += data.toString());
      proc.on('close', (code) => resolve({ code, output }));
    });
  });
}

function runPythonScript(script, args = []) {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(RECON_BASE, script);
    const proc = spawn('python3', [scriptPath, ...args], { cwd: RECON_BASE });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout.on('data', (data) => {
      stdout += data.toString();
      mainWindow?.webContents.send('python-output', { script, data: data.toString() });
    });
    
    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    proc.on('close', (code) => {
      if (code === 0) {
        resolve({ success: true, output: stdout });
      } else {
        resolve({ success: false, error: stderr || stdout });
      }
    });
    
    activeProcesses.set(script, proc);
  });
}

function terminateAllProcesses() {
  activeProcesses.forEach((proc, name) => {
    try {
      proc.kill();
    } catch (e) {}
  });
  activeProcesses.clear();
}

// App lifecycle
app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

app.on('before-quit', terminateAllProcesses);
