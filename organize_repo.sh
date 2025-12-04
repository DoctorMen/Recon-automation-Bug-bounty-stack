#!/bin/bash
# Repository Organization Script
# Moves files into logical subdirectories for better GitHub browsing
# Created: December 3, 2025

set -e

REPO_DIR="/home/ubuntu/Recon-automation-Bug-bounty-stack"
cd "$REPO_DIR"

echo "🗂️  Organizing repository structure..."
echo ""

# Create organized directory structure
mkdir -p documentation/{guides,reports,analysis}
mkdir -p configuration/{targets,programs,workflows}
mkdir -p evidence/{findings,submissions,verification}
mkdir -p business/{upwork,client-management,roi-analysis}
mkdir -p security/{legal,opsec,protection}
mkdir -p archived/{old-reports,backups}

echo "✓ Created directory structure"

# Move documentation files
echo "→ Organizing documentation..."
mv *_GUIDE.md documentation/guides/ 2>/dev/null || true
mv *_README.md documentation/guides/ 2>/dev/null || true
mv *_INSTRUCTIONS.md documentation/guides/ 2>/dev/null || true
mv *_ANALYSIS.md documentation/analysis/ 2>/dev/null || true
mv *_ASSESSMENT.md documentation/analysis/ 2>/dev/null || true
mv *_REPORT.md documentation/reports/ 2>/dev/null || true
mv *_SUMMARY.md documentation/reports/ 2>/dev/null || true
mv *_STATUS.md documentation/reports/ 2>/dev/null || true

# Move evidence files
echo "→ Organizing evidence..."
mv evidence_*.txt evidence/findings/ 2>/dev/null || true
mv *_finding_*.json evidence/findings/ 2>/dev/null || true
mv *_submission_*.json evidence/submissions/ 2>/dev/null || true
mv *_verification_*.json evidence/verification/ 2>/dev/null || true
mv verified_*.json evidence/verification/ 2>/dev/null || true
mv undeniable_proof_*.md evidence/verification/ 2>/dev/null || true
mv undeniable_proof_*.json evidence/verification/ 2>/dev/null || true

# Move business files
echo "→ Organizing business files..."
mv *upwork*.* business/upwork/ 2>/dev/null || true
mv *_roi_*.* business/roi-analysis/ 2>/dev/null || true
mv *client*.* business/client-management/ 2>/dev/null || true
mv proposal_*.txt business/client-management/ 2>/dev/null || true
mv service_agreement_*.* business/client-management/ 2>/dev/null || true

# Move security files
echo "→ Organizing security files..."
mv *LEGAL*.md security/legal/ 2>/dev/null || true
mv *PROTECTION*.md security/protection/ 2>/dev/null || true
mv *PRIVACY*.md security/opsec/ 2>/dev/null || true
mv *OPSEC*.md security/opsec/ 2>/dev/null || true

# Move configuration files
echo "→ Organizing configuration..."
mv targets*.txt configuration/targets/ 2>/dev/null || true
mv *_targets.txt configuration/targets/ 2>/dev/null || true
mv programs.json configuration/programs/ 2>/dev/null || true
mv ranked_programs.json configuration/programs/ 2>/dev/null || true

# Move old/duplicate files to archived
echo "→ Archiving old files..."
mv *_20251201_*.* archived/old-reports/ 2>/dev/null || true
mv *.bak* archived/backups/ 2>/dev/null || true

echo ""
echo "✅ Repository organized!"
echo ""
echo "New structure:"
echo "  📁 documentation/"
echo "     ├── guides/       (setup and how-to guides)"
echo "     ├── reports/      (status and summary reports)"
echo "     └── analysis/     (analysis and assessments)"
echo "  📁 evidence/"
echo "     ├── findings/     (vulnerability findings)"
echo "     ├── submissions/  (bug bounty submissions)"
echo "     └── verification/ (proof and verification)"
echo "  📁 business/"
echo "     ├── upwork/       (freelance platform files)"
echo "     ├── client-management/ (proposals, agreements)"
echo "     └── roi-analysis/ (business metrics)"
echo "  📁 security/"
echo "     ├── legal/        (legal protection docs)"
echo "     ├── opsec/        (operational security)"
echo "     └── protection/   (protection systems)"
echo "  📁 configuration/"
echo "     ├── targets/      (target lists)"
echo "     ├── programs/     (program configs)"
echo "     └── workflows/    (workflow configs)"
echo "  📁 archived/"
echo "     ├── old-reports/  (historical reports)"
echo "     └── backups/      (backup files)"
echo ""
echo "Run sync_to_github.sh to push organized structure"
