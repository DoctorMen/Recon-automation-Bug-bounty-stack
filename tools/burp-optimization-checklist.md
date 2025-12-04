# Burp Optimization Checklist

## Purpose
Reduce friction and maximize efficiency in Burp Suite based on Episode 147 insights.

## Layout & Display Setup

### Essential Windows Visible
- [ ] Proxy HTTP History
- [ ] Repeater
- [ ] Site Map
- [ ] Target Tools
- [ ] Logger++

### Window Organization
- [ ] Proxy on left, Repeater on right
- [ ] Site Map below Proxy
- [ ] Logger++ at bottom
- [ ] Save layout as custom workspace

## Shortcuts & Hotkeys

### Navigation
- [ ] Ctrl+Shift+R: Send to Repeater
- [ ] Ctrl+R: Send to Intruder
- [ ] Ctrl+Space: Command Palette
- [ ] Ctrl+I: Send to Sequencer

### Request Editing
- [ ] Ctrl+Shift+C: Copy request
- [ ] Ctrl+Shift+V: Paste request
- [ ] Ctrl+F: Find in request
- [ ] Ctrl+H: Replace in request

## Essential Extensions

### Must-Have Extensions
- [ ] Hackverter (custom encoding/decoding)
- [ ] Logger++ (enhanced logging)
- [ ] Autorize (authorization testing)
- [ ] JSON Web Token (JWT analysis)
- [ ] CO2 (CORS testing)
- [ ] Burp Sentinel (AI assistance)

### Optional but Useful
- [ ] Turbo Intruder (performance)
- [ ] J2EEScan (Java apps)
- [ ] WAF Bypass (WAF testing)

## Workflow Optimizations

### Request Handling
- [ ] Set up auto-decoding for common formats (Base64, URL, JSON)
- [ ] Configure match/replace rules for common headers
- [ ] Set up proxy forwarding for mobile testing
- [ ] Configure upstream proxy for corporate networks

### Response Analysis
- [ ] Enable highlight rules for status codes
- [ ] Set up response highlighting for sensitive data
- [ ] Configure content type rendering
- [ ] Enable pretty printing for JSON/XML

## Episode 147 Specific Upgrades

### Command Palette Usage
- [ ] Learn Ctrl+K shortcuts for encoding
- [ ] Set up custom encoding workflows
- [ ] Practice base64, URL encode, hex conversions

### Auto-Decoding Setup
- [ ] Enable Inspector for automatic decoding
- [ ] Set up Hackverter for custom tags
- [ ] Configure Caido convert drawer (if using Caido)

### Clipboard Management
- [ ] Install Raycast (Windows alternative: PowerToys Run)
- [ ] Set up custom scripts for:
  - Cookie redaction
  - JWT parsing
  - URL encoding
  - Match/replace operations

## Testing Setup

### Target Configuration
- [ ] Configure scope for Auth0 program
- [ ] Set up exclusion rules for out-of-scope domains
- [ ] Configure SSL certificate for HTTPS inspection
- [ ] Set up authentication macros

### Project Organization
- [ ] Create project per target program
- [ ] Save state files regularly
- [ ] Export interesting requests for documentation
- [ ] Set up custom tags for finding classification

## Performance Tuning

### Memory Settings
- [ ] Increase heap size for large projects (-Xmx4g)
- [ ] Configure temporary file location
- [ ] Set up proxy logging rotation

### Network Settings
- [ ] Configure timeout values
- [ ] Set up concurrent connections
- [ ] Enable HTTP/2 support if needed

## Daily Workflow Checklist

### Before Testing
- [ ] Launch Burp with saved workspace
- [ ] Verify proxy is intercepting
- [ ] Check target scope is correct
- [ ] Test authentication is working

### During Testing
- [ ] Use Ctrl+Shift+R for quick Repeater testing
- [ ] Tag interesting requests immediately
- [ ] Take notes in request comments
- [ ] Save promising requests to project file

### After Testing
- [ ] Export findings to report format
- [ ] Save project state
- [ ] Clean up proxy history
- [ ] Document any new techniques discovered

## Troubleshooting

### Common Issues
- [ ] Proxy not intercepting → Check browser proxy settings
- [ ] HTTPS errors → Install Burp certificate
- [ ] Slow performance → Increase memory, clear history
- [ ] Extensions not loading → Check compatibility

### Getting Help
- [ ] Burp Suite documentation
- [ ] PortSwigger forums
- [ ] CTBBP community Discord
- [ ] Twitter #bugbounty community

## Monthly Review
- [ ] Check for extension updates
- [ ] Review and optimize shortcuts
- [ ] Clean up old project files
- [ ] Document new workflows discovered
