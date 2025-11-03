# Browser Evidence Capture Scripts - Saved for Future Use

**Location:** Multiple locations for easy access

---

## 📁 Script Locations

### Primary Location (Project-Specific)
```
programs/rapyd/findings/automated_browser_evidence_capture.py
```
**Use for:** Rapyd-specific IDOR evidence capture

### General Scripts Location (Reusable)
```
scripts/capture_browser_evidence.py
```
**Use for:** Any bug bounty program that needs browser evidence capture

---

## 🚀 Quick Access Commands

### For Rapyd Testing:
```bash
cd programs/rapyd/findings
python3 automated_browser_evidence_capture.py
```

### For General Use:
```bash
cd scripts
python3 capture_browser_evidence.py
```

---

## 📋 What's Saved

### 1. Evidence Capture Script
- **File:** `automated_browser_evidence_capture.py` (2 locations)
- **Purpose:** Guided browser evidence capture workflow
- **Features:**
  - Step-by-step instructions
  - Progress tracking
  - State management
  - Summary report generation

### 2. Response Redaction Script
- **File:** `programs/rapyd/findings/redact_idor_response.py`
- **Purpose:** Redact sensitive data from API responses
- **Features:**
  - Automated redaction
  - Preserves evidence fields
  - Safe-to-share output

### 3. Documentation
- **File:** `programs/rapyd/findings/BROWSER_CAPTURE_HELPER.md`
- **Purpose:** Complete usage guide

---

## 💡 Usage Tips

1. **Resume Capability:** Script saves progress automatically - safe to interrupt and resume
2. **Idempotent:** Run multiple times safely - completed steps are skipped
3. **State Tracking:** Progress saved to `.capture_state.json`
4. **Evidence Validation:** Automatic checklist ensures all required evidence captured

---

## 🔄 Adapting for Other Programs

To use for other bug bounty programs:

1. **Copy the script:**
   ```bash
   cp scripts/capture_browser_evidence.py programs/[program-name]/findings/
   ```

2. **Modify URLs and steps** in the script for your specific program

3. **Update evidence requirements** based on program guidelines

---

## 📚 Related Files

- `ASSISTANT_AGENT_HELPER_SUMMARY.md` - Overview of created tools
- `BROWSER_CAPTURE_HELPER.md` - Detailed usage guide
- `BROWSER_EVIDENCE_WORKFLOW.md` - Manual workflow reference

---

**Status:** ✅ Saved and ready for future use  
**Last Updated:** 2025-10-31



