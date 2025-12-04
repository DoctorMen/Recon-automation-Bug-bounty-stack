<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# ModHarmony™ - Mod Compatibility Testing Software

**ACTUAL WORKING SOFTWARE** - Not just a landing page

## What This Is

This is the **real ModHarmony product** - working Python software that:
- ✅ Scans mod directories for file conflicts
- ✅ Detects file overwrites between mods
- ✅ Calculates conflict severity (low/medium/high)
- ✅ Generates compatibility reports
- ✅ Provides web interface for testing
- ✅ Stores compatibility data in database
- ✅ Offers REST API for integrations

## Installation

```bash
cd modharmony
pip install -r requirements.txt
```

## Usage

### Option 1: Web Interface

```bash
python web_app.py
```

Then open: http://localhost:5000

### Option 2: Python API

```python
from mod_scanner import ModScanner

# Create scanner
scanner = ModScanner()

# Scan mods
mods = {
    "SkyUI": "/path/to/skyui",
    "USSEP": "/path/to/ussep",
    "Frostfall": "/path/to/frostfall"
}

scanner.scan_multiple_mods(mods)

# Get compatibility report
report = scanner.analyze_compatibility()

print(f"Status: {report['status']}")
print(f"Conflicts: {report['total_conflicts']}")
print(f"Critical: {report['critical_conflicts']}")

# Export to JSON
scanner.export_report("my_report.json")
```

### Option 3: REST API

Start the server:
```bash
python web_app.py
```

Make API calls:
```bash
# Scan mods
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "mods": {
      "SkyUI": "/path/to/skyui",
      "USSEP": "/path/to/ussep"
    }
  }'

# Quick compatibility check
curl -X POST http://localhost:5000/api/quick-check \
  -H "Content-Type: application/json" \
  -d '{
    "mod1": "SkyUI",
    "mod2": "USSEP"
  }'

# Get stats
curl http://localhost:5000/api/stats
```

## Features

### 1. File Conflict Detection
- Scans all files in mod directories
- Detects when multiple mods modify the same file
- Calculates MD5 hashes to identify identical vs different files
- Categorizes conflicts by severity

### 2. Compatibility Database
- Stores test results
- Builds compatibility matrix between mods
- Provides quick lookups for known mod pairs
- Crowdsourced data (more tests = better accuracy)

### 3. Web Interface
- User-friendly form for testing mods
- Real-time scanning with progress indicator
- Visual compatibility reports
- Color-coded conflict severity

### 4. REST API
- `/api/scan` - Full mod compatibility scan
- `/api/quick-check` - Quick database lookup
- `/api/upload-mod` - Upload mod files
- `/api/stats` - Database statistics
- `/health` - Service health check

## How It Works

1. **Scanning**: Walks through mod directories, catalogs all files
2. **Hashing**: Calculates MD5 hash of each file for comparison
3. **Conflict Detection**: Identifies files modified by multiple mods
4. **Severity Calculation**: Analyzes file size differences and hash mismatches
5. **Reporting**: Generates detailed compatibility report with recommendations

## Conflict Types

- **duplicate_file**: Same file in multiple mods (identical hash) - LOW severity
- **file_overwrite**: Different versions of same file - HIGH severity
- **load_order**: Plugin dependency issues - MEDIUM severity

## Example Output

```json
{
  "status": "conflicts_detected",
  "total_conflicts": 5,
  "critical_conflicts": 2,
  "warnings": 2,
  "info": 1,
  "mods_scanned": 3,
  "conflicts": [
    {
      "file": "Data/Interface/skyui_cfg.txt",
      "conflict_type": "file_overwrite",
      "severity": "high",
      "mods": ["SkyUI", "SkyUI_SE"],
      "details": [...]
    }
  ],
  "recommendations": [
    "⚠️ 2 critical conflicts detected",
    "Recommendation: Review load order or disable conflicting mods",
    "  - Conflict between: SkyUI, SkyUI_SE"
  ]
}
```

## Testing with Real Mods

To test with actual Skyrim/Fallout mods:

1. Download mods from Nexus Mods
2. Extract to separate folders
3. Run scanner with those paths
4. Get instant compatibility report

Example:
```python
scanner = ModScanner()

mods = {
    "SkyUI": "C:/Games/Skyrim/Mods/SkyUI",
    "USSEP": "C:/Games/Skyrim/Mods/USSEP",
    "Frostfall": "C:/Games/Skyrim/Mods/Frostfall"
}

scanner.scan_multiple_mods(mods)
report = scanner.analyze_compatibility()

if report['status'] == 'compatible':
    print("✓ All mods are compatible!")
else:
    print(f"⚠ Found {report['critical_conflicts']} critical conflicts")
    for conflict in report['conflicts']:
        if conflict['severity'] == 'high':
            print(f"  - {conflict['file']}: {', '.join(conflict['mods'])}")
```

## Roadmap

- [ ] ESP/ESM plugin parser for load order detection
- [ ] AI-powered conflict prediction
- [ ] Steam Workshop integration
- [ ] Nexus Mods API integration
- [ ] Automatic mod version detection
- [ ] Conflict resolution suggestions
- [ ] Cloud-based testing infrastructure

## License

Copyright © 2025 DoctorMen. All Rights Reserved.
ModHarmony™ is a trademark.

## This Is REAL Software

Unlike the landing page, this is **actual working code** that:
- Runs on your computer
- Scans real mod files
- Detects real conflicts
- Generates real reports
- Has a working web interface
- Provides a REST API

**You can use this TODAY to test mod compatibility.**
