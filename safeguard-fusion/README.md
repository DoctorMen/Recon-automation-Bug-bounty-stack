# SafeGuard Fusion 🛡️

**Ethical Hybrid NOC to Bug Bounty Platform**

A world-class desktop application that transforms your security operations with a unified interface for defensive monitoring and offensive security testing. Built with bleeding-edge UI design and seamless integration with your existing recon automation stack.

![SafeGuard Fusion](https://img.shields.io/badge/Version-1.0.0-00d4ff?style=for-the-badge)
![Electron](https://img.shields.io/badge/Electron-28.0-8b5cf6?style=for-the-badge)
![License](https://img.shields.io/badge/License-Proprietary-ff0080?style=for-the-badge)

## 🎯 Features

### Hybrid NOC Mode
- **Real-time Network Monitoring** - Live traffic analysis and system health indicators
- **Threat Detection** - Automated alert system with severity classification
- **SIEM Integration** - Connect to your existing security infrastructure
- **Global Threat Map** - Visualize attacks and defense nodes worldwide

### Bounty Ops Mode
- **Offensive Simulations** - Ethical penetration testing workflows
- **Vulnerability Heatmap** - Visual representation of discovered vulnerabilities
- **SENTINEL Agent Integration** - Automated security scanning
- **Vibe Command System** - Natural language interface for operations

### Compliance & Transparency
- **Legal Authorization System** - Verify authorization before every scan
- **Immutable Audit Logs** - Complete trail of all operations
- **GDPR Compliance** - Built-in support for EU regulations
- **Export Reports** - Generate professional PDF documentation

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- npm or pnpm
- WSL2 (for Windows users)
- Python 3.8+ (for backend tools)

### Installation

```bash
# Navigate to the safeguard-fusion directory
cd safeguard-fusion

# Install dependencies
npm install

# Start the application
npm start
```

### Development Mode

```bash
# Start with hot reload
npm run dev
```

### Build for Production

```bash
# Build for current platform
npm run package

# Build for specific platforms
npm run package:win    # Windows
npm run package:mac    # macOS
npm run package:linux  # Linux
```

## 🎨 UI/UX Design

SafeGuard Fusion features a **Cyber-Tactical** design language:

- **Glassmorphism** - Frosted glass effects with backdrop blur
- **Gradient Accents** - Cyan-to-green gradients for defense, red tones for offense
- **Scanline Animation** - Subtle retro-futuristic effect
- **Dark Theme** - Optimized for long operational hours
- **Responsive Layout** - Adapts to any screen size

### Color Palette
| Purpose | Color | Hex |
|---------|-------|-----|
| Defense | Cyber Cyan | `#00d4ff` |
| Offense | Crimson | `#ff4444` |
| Success | Neon Green | `#00ff88` |
| Warning | Gold | `#ffaa00` |
| Danger | Magenta | `#ff0080` |

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the safeguard-fusion directory:

```env
NODE_ENV=development
RECON_BASE_PATH=../
DEFAULT_MODE=hybrid
```

### Connecting to Backend Tools

SafeGuard Fusion automatically integrates with:

- `SENTINEL_AGENT.py` - Automated security scanning
- `VIBE_COMMAND_SYSTEM.py` - Natural language operations
- `LEGAL_AUTHORIZATION_SYSTEM.py` - Authorization verification
- `targets.txt` - Target management
- `authorizations/` - Authorization files

## 📖 User Guide

### Mode Switching
Click the mode toggle in the title bar to switch between:
- **Hybrid NOC** - Focus on defensive operations
- **Bounty Ops** - Focus on offensive testing and bounty submissions

### Starting a Scan
1. Click "New Scan" or press `Ctrl+N`
2. Enter target domain
3. Select scan tier (Basic, Comprehensive, Aggressive)
4. Enable "Verify Authorization First" (recommended)
5. Click "Start Scan"

### Vibe Command
Press `Ctrl+K` to open the natural language interface:
- "scan all targets"
- "find vulnerabilities"
- "check authorization"
- "show recent results"

### Keyboard Shortcuts
| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | New Scan |
| `Ctrl+K` | Vibe Command |
| `Escape` | Close Modal |

## 🏗️ Architecture

```
safeguard-fusion/
├── main.js           # Electron main process
├── preload.js        # Secure IPC bridge
├── package.json      # Dependencies & scripts
├── src/
│   ├── index.html    # Main application UI
│   ├── styles.css    # Cyber-tactical styling
│   └── app.js        # Application logic
├── assets/
│   └── icon.svg      # Application icon
└── README.md         # This file
```

## 🔐 Security Features

- **Context Isolation** - Secure renderer process
- **CSP Headers** - Content Security Policy enforcement
- **No Node Integration** - Renderer has no direct Node access
- **Preload Script** - Controlled API exposure
- **Authorization Checks** - Mandatory before scanning

## 📊 Integration with Recon Stack

SafeGuard Fusion leverages your existing tools:

| Tool | Function |
|------|----------|
| SENTINEL Agent | Automated vulnerability scanning |
| Vibe Command | Natural language operations |
| Legal Authorization | CFAA compliance verification |
| Nuclei | Template-based scanning |
| Subfinder | Subdomain enumeration |

## 🛠️ Troubleshooting

### App won't start
```bash
# Clear node_modules and reinstall
rm -rf node_modules
npm install
```

### Python tools not found
Ensure Python scripts are in the parent directory and executable:
```bash
chmod +x ../SENTINEL_AGENT.py
chmod +x ../VIBE_COMMAND_SYSTEM.py
```

### Authorization errors
Create an authorization file:
```bash
cd ..
python3 CREATE_AUTHORIZATION.py --target example.com --client "Test"
```

## 📜 License

Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.

This software is proprietary. Unauthorized copying, modification, or distribution is prohibited.

## 🙏 Acknowledgments

Built with:
- [Electron](https://www.electronjs.org/)
- [Orbitron Font](https://fonts.google.com/specimen/Orbitron)
- [Rajdhani Font](https://fonts.google.com/specimen/Rajdhani)
- [JetBrains Mono](https://www.jetbrains.com/lp/mono/)

---

**SafeGuard Fusion** - *Defend. Discover. Dominate.*
