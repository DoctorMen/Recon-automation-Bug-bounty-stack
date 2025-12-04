<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Dashboard Security & OPSEC Guidelines

**CRITICAL: This dashboard is designed for LOCAL USE ONLY**

---

## 🔒 Security Features Built-In

### 1. **Local-Only Access**
- ✅ No external network calls
- ✅ No telemetry or analytics
- ✅ All resources loaded locally
- ✅ No CDN dependencies

### 2. **Data Protection**
- ✅ Sensitive data redacted by default
- ✅ No credentials displayed
- ✅ Target domains obfuscated in UI
- ✅ API keys/tokens never shown
- ✅ Evidence files marked as sensitive

### 3. **File Permissions**
- ✅ Dashboard files: 0600 (owner read/write only)
- ✅ Evidence directory: 0700 (owner access only)
- ✅ No world-readable sensitive data

### 4. **No External Dependencies**
- ✅ All JavaScript libraries vendored locally
- ✅ No Google Fonts or external CSS
- ✅ No tracking pixels or beacons
- ✅ Completely air-gapped capable

---

## ⚠️ OPSEC Best Practices

### **DO:**
- ✅ Access dashboard only on secure, trusted networks
- ✅ Use VPN when accessing on public networks
- ✅ Close browser tabs when done
- ✅ Clear browser cache periodically
- ✅ Review redaction settings before sharing screenshots

### **DON'T:**
- ❌ Share dashboard URLs publicly
- ❌ Take screenshots with sensitive target info visible
- ❌ Access dashboard on untrusted devices
- ❌ Leave dashboard open on shared computers
- ❌ Commit dashboard to public repositories

---

## 🔐 Data Sensitivity Levels

### **RED (Highly Sensitive)**
- Target domain names
- API keys, tokens, credentials
- Raw vulnerability payloads
- Network request/response data
- Internal IP addresses

### **YELLOW (Sensitive)**
- Subdomain lists
- Technology fingerprints
- Directory structures
- Configuration details

### **GREEN (Safe to Share)**
- Aggregated statistics (no targets)
- Tool status (no data)
- Scan progress (anonymized)
- Severity counts (no details)

---

## 🛡️ Redaction System

The dashboard includes automatic redaction for:
- Email addresses → `***@***.***`
- IP addresses → `xxx.xxx.xxx.xxx`
- Domains → `target-*****.com`
- Tokens/Keys → `***REDACTED***`
- Passwords → `***HIDDEN***`

**Toggle redaction:** Click the 🔒 icon in the top-right corner

---

## 📁 Evidence Security

### **Evidence Storage:**
```
output/
├── evidence/              # 0700 permissions
│   ├── screenshots/      # Sensitive data
│   ├── network_logs/     # RAW requests
│   └── api_responses/    # Unredacted JSON
├── reports/              # 0755 permissions
│   ├── summary.md        # Sanitized
│   └── submission/       # Redacted for clients
```

### **Sharing Guidelines:**
- **Internal use:** Share from `evidence/` (full data)
- **Client delivery:** Share from `reports/` (redacted)
- **Public sharing:** NEVER share raw evidence

---

## 🚨 Incident Response

### **If Dashboard is Accidentally Exposed:**

1. **Immediately close the browser**
2. **Check `.bash_history` for exposed commands**
3. **Review browser history/cache**
4. **Rotate any exposed credentials**
5. **Review firewall logs**
6. **Document incident**

### **Emergency Shutdown:**
```bash
# Kill all dashboard processes
pkill -f "python.*dashboard"
pkill -f "http.server"

# Clear sensitive cache
rm -rf dashboard/.cache
rm -rf output/.temp
```

---

## 🔍 Audit Trail

Dashboard automatically logs:
- Access times (local only)
- Features used
- Data exported
- Redaction toggles

**Log location:** `dashboard/access.log` (0600 permissions)

---

## ✅ Security Checklist

Before using dashboard:
- [ ] Verify local-only access (no 0.0.0.0 binding)
- [ ] Confirm firewall rules (block external access)
- [ ] Check file permissions (0600/0700)
- [ ] Test redaction system
- [ ] Verify no external network calls

Before sharing screenshots:
- [ ] Redaction enabled
- [ ] No sensitive domains visible
- [ ] No credentials in view
- [ ] No internal IPs shown
- [ ] Sanitized for client viewing

---

## 📞 Security Contact

If you discover a security issue with the dashboard:
1. Document the issue
2. Do NOT share publicly
3. Patch locally
4. Update SECURITY.md

---

**Remember: This is a security tool. Treat the dashboard data with the same care as you would production credentials.**

**Default Security Posture: DENY ALL, ALLOW BY EXCEPTION**

