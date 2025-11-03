# Quick Start - Evidence Capture

## Navigate to the correct directory:

```bash
cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings
```

Or if you're already in the workspace root:

```bash
cd programs/rapyd/findings
```

## Run the evidence capture script:

```bash
chmod +x capture_idor_evidence.sh
./capture_idor_evidence.sh
```

## Alternative: Run directly with bash

```bash
bash capture_idor_evidence.sh
```

## Check current directory:

```bash
pwd
```

Should show: `/home/ubuntu/Recon-automation-Bug-bounty-stack/programs/rapyd/findings`

## List files to verify:

```bash
ls -la capture_idor_evidence.sh
```

---

**Quick Fix:** If you're getting "No such file or directory", run:

```bash
# Find the workspace directory
find ~ -name "capture_idor_evidence.sh" 2>/dev/null

# Then cd to that directory
cd $(find ~ -name "capture_idor_evidence.sh" 2>/dev/null | xargs dirname)
```



