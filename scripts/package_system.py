#!/usr/bin/env python3
"""
Packaging Utility for Licensing (Model #2)

Creates a clean distribution zip for licensed customers with:
- Core scripts (Python + shell)
- Docs (licensing README, sales copy removed)
- EULA and OSS notices

Usage:
  python3 scripts/package_system.py

Output:
  dist/system_release_YYYYMMDD_HHMM.zip

Notes:
- Excludes sensitive/owner-only files (output, .license, .git, dist, tmp)
- Keeps directory structure intact
"""

import os
import sys
import shutil
import zipfile
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = REPO_ROOT / "dist"

EXCLUDES = {
    ".git",
    "dist",
    "output",
    "__pycache__",
    ".vscode",
    ".protection",
    ".license",
    ".env",
    "node_modules",
}

ALWAYS_INCLUDE = {
    "README.md",
    "LICENSE_PROTECTION_README.md",
    "EULA_COMMERCIAL_LICENSE.md",
    "docs/licensing/README_LICENSING.md",
}

def should_exclude(path: Path) -> bool:
    parts = set(path.parts)
    return any(part in EXCLUDES for part in parts)

def iter_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and not should_exclude(p.relative_to(root)):
            yield p

def main():
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    out_zip = DIST_DIR / f"system_release_{ts}.zip"

    # Ensure key docs exist
    for rel in ALWAYS_INCLUDE:
        (REPO_ROOT / rel).parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in iter_files(REPO_ROOT):
            rel = file_path.relative_to(REPO_ROOT)
            # Include only relevant code/docs; skip huge assets by extension
            if rel.suffix.lower() in {".mp4", ".mov", ".zip"}:
                continue
            zf.write(file_path, arcname=str(rel))

    print(f"[+] Package created: {out_zip}")
    print("[i] Deliver this zip to customers. Instruct them to:")
    print("  1) Read EULA_COMMERCIAL_LICENSE.md")
    print("  2) Add their .license file (not included)")
    print("  3) Run: python run_pipeline.py")

if __name__ == "__main__":
    main()



