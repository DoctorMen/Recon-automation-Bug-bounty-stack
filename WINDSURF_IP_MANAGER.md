# GHOST IP Management in Windsurf

## Quick Actions

### 1. View IP Registry
```bash
cat IP_REGISTRY.md
```

### 2. Update Copyright Notices
```bash
python update_copyright.py
```

### 3. View IP Management Guide
```bash
cat IP_MANAGEMENT_GUIDE.md
```

## Common Tasks

### Add New IP Asset
1. Open `IP_REGISTRY.md`
2. Find the relevant section
3. Add entry:
   ```markdown
   | Asset Name | Version | Registration | Description |
   |------------|---------|--------------|-------------|
   | New Module | 1.0.0   | SRu00123456800 | Description |
   ```

### Update Copyright Year
1. Open `update_copyright.py`
2. Update `CURRENT_YEAR`
3. Run:
   ```bash
   python update_copyright.py
   ```

### Check IP Status
```bash
grep -r "Copyright" . --include="*.py" --include="*.js" --include="*.html" | wc -l
```

## Windsurf Commands

### Open IP Files
```bash
code IP_REGISTRY.md IP_MANAGEMENT_GUIDE.md update_copyright.py
```

### Search for IP Terms
```bash
grep -r "TRADEMARK\|PATENT\|COPYRIGHT" . --include="*.md"
```

---
© 2025 Khallid Hakeem Nurse - All Rights Reserved
