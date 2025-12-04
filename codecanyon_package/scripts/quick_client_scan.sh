#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Quick Client Scan Script for Upwork Projects
# Usage: ./scripts/quick_client_scan.sh "Client Name" "domain.com"

set -e

CLIENT_NAME="${1:-Unknown Client}"
DOMAIN="${2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 'Client Name' 'domain.com'"
    exit 1
fi

echo "============================================================"
echo "Scanning $DOMAIN for $CLIENT_NAME"
echo "============================================================"
echo ""

# Run scan
echo "Running security scan..."
python3 run_pipeline.py --target "$DOMAIN" || {
    echo "⚠️  Scan failed, continuing with report generation..."
}

# Generate report
REPORT_FILE="output/reports/${CLIENT_NAME}_$(date +%Y%m%d).pdf"
echo ""
echo "Generating professional report..."
python3 scripts/generate_report.py \
  --format professional \
  --client-name "$CLIENT_NAME" \
  --output "$REPORT_FILE" || {
    echo "⚠️  PDF generation failed, trying markdown..."
    REPORT_FILE="output/reports/${CLIENT_NAME}_$(date +%Y%m%d).md"
    python3 scripts/generate_report.py \
      --format professional \
      --client-name "$CLIENT_NAME" \
      --output "$REPORT_FILE"
}

echo ""
echo "============================================================"
echo "✅ SCAN COMPLETE"
echo "============================================================"
echo ""
echo "Report: $REPORT_FILE"
echo ""
echo "Next steps:"
echo "1. Review report"
echo "2. Deliver to client"
echo "3. Request payment and review"
echo ""

