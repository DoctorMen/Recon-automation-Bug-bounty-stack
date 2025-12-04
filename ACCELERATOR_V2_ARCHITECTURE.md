# Quantum Accelerator V2 - Production Architecture

## Critical Fixes Applied

### 1. Real Tool Integration
**Before:** Hardcoded predictions, no actual scanning  
**After:** Direct integration with real security tools

```python
# Now integrates with:
- Nuclei (vulnerability scanning)
- HTTPX (HTTP probing)
- Slither (smart contract analysis)
- Mythril (smart contract security)
- Subfinder (subdomain enumeration)
```

### 2. Mandatory Authorization
**Before:** No scope/consent checks  
**After:** Scan blocked without valid authorization

```python
# Every scan requires:
authorized, reason, auth_data = self.auth_checker.check_authorization(target)
if not authorized:
    raise PermissionError(f"Unauthorized: {reason}")
```

### 3. No Auto-Submit
**Before:** `auto_submit=True` (dangerous)  
**After:** Manual approval required for all submissions

```python
submission = {
    "requires_approval": True,
    "auto_submit": False  # NEVER auto-submit
}
```

### 4. Real Database Persistence
**Before:** Single JSON file, no schema  
**After:** SQLite with proper schema and validation

```sql
-- Proper tables with relationships
CREATE TABLE findings (...)
CREATE TABLE programs (...)
CREATE TABLE submission_history (...)
CREATE TABLE tool_logs (...)
```

### 5. Evidence-Based Statistics
**Before:** Hardcoded probabilities (misleading)  
**After:** Calculated from actual submission history

```python
def get_acceptance_rate(self, vulnerability_type: str) -> float:
    # Query actual submission outcomes
    cursor.execute("""
        SELECT COUNT(*), SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END)
        FROM submission_history
    """)
    # Return real rate, or 0 if no data
```

### 6. Proper Error Handling & Logging
**Before:** No error handling, no logging  
**After:** Comprehensive logging and error management

```python
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('quantum_accelerator.log'),
        logging.StreamHandler()
    ]
)
```

---

## Usage

### Basic Scan (with authorization)
```bash
# First, create authorization
python3 CREATE_AUTHORIZATION.py --target kuru.exchange --client "Kuru Bug Bounty"

# Then scan
python3 QUANTUM_ACCELERATOR_V2.py kuru.exchange --scan-type web
```

### Dry Run (no actual scanning)
```bash
python3 QUANTUM_ACCELERATOR_V2.py kuru.exchange --dry-run
```

### View Statistics
```bash
python3 QUANTUM_ACCELERATOR_V2.py --stats
```

### Prepare Submissions
```bash
python3 QUANTUM_ACCELERATOR_V2.py kuru.exchange --program "Kuru Bug Bounty"
# Generates submission files for MANUAL review
```

---

## Data Flow

```
1. Authorization Check
   └── BLOCKED if unauthorized
   
2. Tool Execution
   ├── Nuclei → JSON output
   ├── HTTPX → HTTP data
   └── Slither → Contract issues
   
3. Finding Parser
   └── Structured Finding objects with evidence
   
4. Database Storage
   └── SQLite with schema validation
   
5. Submission Preparation
   └── Markdown reports for HUMAN review
   
6. Manual Submission
   └── User submits to platform manually
```

---

## What's NOT Included (By Design)

- ❌ Auto-submission to any platform
- ❌ Hardcoded probability estimates
- ❌ Marketing-style output text
- ❌ Fabricated "pattern recognition"
- ❌ Guessed acceptance rates

---

## Integration with Existing Pipeline

```bash
# Can be called from run_pipeline.py
python3 QUANTUM_ACCELERATOR_V2.py $TARGET --scan-type web --program "$PROGRAM"

# Or integrated into scripts
from QUANTUM_ACCELERATOR_V2 import QuantumAcceleratorV2
accelerator = QuantumAcceleratorV2()
findings = accelerator.scan_target("example.com")
```

---

## Output Format

### Finding Object (JSON)
```json
{
  "id": "abc123...",
  "target": "kuru.exchange",
  "vulnerability_type": "cve-2023-xxxx",
  "severity": "high",
  "title": "SQL Injection in Login",
  "description": "...",
  "evidence": "HTTP response showing...",
  "reproduction_steps": ["Step 1...", "Step 2..."],
  "tool_source": "nuclei",
  "raw_output": "...",
  "confidence": 0.9,
  "verified": false,
  "submitted": false
}
```

### Submission Report (Markdown)
```markdown
# SQL Injection in Login

## Summary
**Severity:** HIGH
**Target:** kuru.exchange
**Confidence:** 90%

## Evidence
[Actual tool output]

## Reproduction Steps
1. Run: nuclei -t cve-2023-xxxx -u kuru.exchange
```

---

## Future Improvements

1. **Feedback Loop:** Update acceptance rates after each submission outcome
2. **Multi-Tool Correlation:** Cross-reference findings from multiple tools
3. **Scope Validation:** Validate URLs against program scope before scanning
4. **Rate Limiting:** Respect target rate limits
5. **Offline Mode:** Queue scans for later execution
6. **CI/CD Integration:** Run as part of automated pipelines
