#!/usr/bin/env python3
"""Copyright © 2025 DoctorMen. All Rights Reserved."""
"""
SSRF Report Generator

Generates a Markdown bug bounty report for Server-Side Request Forgery (SSRF)
issues from a simple JSON description file.

This is designed for human-in-the-loop use:
- You prepare a JSON file describing the SSRF finding
- This script renders a ready-to-paste Markdown report
- You review and edit before submitting to a bug bounty platform

Usage:
  python3 scripts/generate_ssrf_report.py \
    --input output/example_ssrf.json \
    --output-dir output/reports

Minimal JSON example:

{
  "program": "Example Corp",
  "title": "SSRF via imageUrl parameter on /api/upload-avatar",
  "severity": "high",
  "asset": "Example web application – avatar upload API /api/upload-avatar (imageUrl parameter)",
  "entrypoint": "POST /api/upload-avatar",
  "entrypoint_host": "app.example.com",
  "ssrf_parameter": "imageUrl",
  "attacker_control_level": "Full control over imageUrl value in JSON request body.",
  "internal_targets": [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/admin"
  ],
  "summary": "The imageUrl parameter in /api/upload-avatar allows SSRF, enabling requests to internal HTTP services such as EC2 metadata and localhost admin endpoints.",
  "impact": [
    "Ability to query EC2 metadata service and potentially retrieve credentials.",
    "Ability to reach internal admin endpoints not exposed to the internet."
  ],
  "steps": [
    "Upload an avatar with imageUrl set to a benign external URL and observe normal behaviour.",
    "Change imageUrl to an internal target such as http://169.254.169.254/latest/meta-data/ and observe that the application returns metadata or a different error pattern.",
    "Optionally, test localhost or other internal hosts and capture any sensitive data returned."
  ],
  "requests": {
    "benign_request": "<HTTP request with external imageUrl>",
    "benign_response": "<HTTP response showing normal behaviour>",
    "ssrf_request": "<HTTP request with internal target in imageUrl>",
    "ssrf_response": "<HTTP response showing internal data, error, or timing difference>"
  }
}
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
OUTPUT_DIR = REPO_ROOT / "output"
REPORTS_DIR = OUTPUT_DIR / "reports"


def sanitize_filename(name: str) -> str:
  """Sanitize a string for safe filesystem use."""
  safe = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in name)
  return safe[:200]


def ensure_list(value: Any) -> List[str]:
  """Ensure value is a list of strings."""
  if value is None:
    return []
  if isinstance(value, list):
    return [str(v) for v in value]
  return [str(value)]


def load_finding(path: Path) -> Dict[str, Any]:
  """Load and parse the JSON description file."""
  with path.open("r", encoding="utf-8") as f:
    data = json.load(f)
  if not isinstance(data, dict):
    raise ValueError("Input JSON must be an object with key/value pairs.")
  return data


def build_ssrf_report(data: Dict[str, Any]) -> str:
  """Render the SSRF report as Markdown."""
  program = data.get("program", "[PROGRAM]")
  title = data.get(
    "title",
    "Server-Side Request Forgery (SSRF) via user-controlled URL parameter",
  )
  severity = str(data.get("severity", "high")).upper()
  asset = data.get("asset", "[Describe impacted asset and endpoint]")
  summary = data.get("summary", "[One sentence describing the SSRF bug]")

  entrypoint = data.get("entrypoint", "")
  entrypoint_host = data.get("entrypoint_host", "[host]")
  ssrf_param = data.get("ssrf_parameter", "[parameter]")
  attacker_control_level = data.get("attacker_control_level", "[Describe how much control the attacker has over the URL]")
  internal_targets = ensure_list(data.get("internal_targets"))

  impact_items = ensure_list(data.get("impact"))
  step_items = ensure_list(data.get("steps"))

  requests = data.get("requests", {}) or {}
  benign_request = requests.get("benign_request")
  benign_response = requests.get("benign_response")
  ssrf_request = requests.get("ssrf_request")
  ssrf_response = requests.get("ssrf_response")

  generated_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

  lines: List[str] = []

  # Title
  lines.append(f"# {title} in {program}")
  lines.append("")

  # Summary & severity
  lines.append("## Summary")
  lines.append(summary)
  lines.append("")

  lines.append("## Severity")
  lines.append(severity)
  lines.append("")

  # Impacted asset
  lines.append("## Impacted Asset")
  lines.append(asset)
  lines.append("")

  # Vulnerability type & CWE mapping
  lines.append("## Vulnerability Type & CWE Mapping")
  lines.append("- Server-Side Request Forgery (SSRF)")
  lines.append("- **CWE-918**: Server-Side Request Forgery (SSRF)")
  lines.append("- **CWE-610**: Externally Controlled Reference to a Resource in Another Sphere")
  lines.append("- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor (if internal data is leaked)")
  lines.append("")

  # Affected functionality
  lines.append("## Affected Functionality")
  if entrypoint:
    lines.append(f"- **Entrypoint**: `{entrypoint}`")
  if entrypoint_host:
    lines.append(f"- **Host**: `{entrypoint_host}`")
  lines.append(f"- **SSRF parameter**: `{ssrf_param}`")
  lines.append(f"- **Attacker control level**: {attacker_control_level}")
  if internal_targets:
    lines.append("- **Confirmed internal targets reachable via SSRF**:")
    for t in internal_targets:
      lines.append(f"  - `{t}`")
  lines.append("")

  # Steps to reproduce
  lines.append("## Steps to Reproduce")
  if step_items:
    for idx, step in enumerate(step_items, start=1):
      lines.append(f"{idx}. {step}")
  else:
    lines.append("1. Identify a feature that accepts a user-controlled URL parameter (e.g., imageUrl, webhook URL, import-from-URL).")
    lines.append("2. Send a request with an external benign URL and confirm expected behaviour.")
    lines.append("3. Change the parameter to an internal target such as http://127.0.0.1/ or http://169.254.169.254/latest/meta-data/.")
    lines.append("4. Observe differences in responses, timing, or error messages that confirm the server is issuing internal requests on behalf of the attacker.")
  lines.append("")

  # Proof of concept
  lines.append("## Proof of Concept")

  if benign_request:
    lines.append("### Benign request (external URL)")
    lines.append("```http")
    lines.append(str(benign_request).strip())
    lines.append("```")
    lines.append("")

  if benign_response:
    lines.append("### Response to benign request")
    lines.append("```http")
    resp_b = str(benign_response)
    if len(resp_b) > 4000:
      resp_b = resp_b[:4000] + "\n... [truncated]"
    lines.append(resp_b.strip())
    lines.append("```")
    lines.append("")

  if ssrf_request:
    lines.append("### SSRF request (internal target)")
    lines.append("```http")
    lines.append(str(ssrf_request).strip())
    lines.append("```")
    lines.append("")

  if ssrf_response:
    lines.append("### Response to SSRF request")
    lines.append("```http")
    resp_s = str(ssrf_response)
    if len(resp_s) > 4000:
      resp_s = resp_s[:4000] + "\n... [truncated]"
    lines.append(resp_s.strip())
    lines.append("```")
    lines.append("")

  # Impact
  lines.append("## Impact")
  if impact_items:
    for item in impact_items:
      lines.append(f"- {item}")
  else:
    lines.append("- Ability to make arbitrary HTTP requests from the server to internal or external systems.")
    lines.append("- Potential access to cloud metadata services (e.g., AWS/GCP/Azure) and sensitive credentials.")
    lines.append("- Potential access to internal admin panels or services not exposed to the internet.")
  lines.append("")

  # Remediation
  lines.append("## Remediation")
  lines.append("- Apply strict allowlists for outbound requests and restrict which hosts and schemes can be contacted.")
  lines.append("- Avoid sending user-controlled URLs directly to HTTP clients or libraries; instead, map user input to vetted destinations.")
  lines.append("- Block access to link-local and loopback addresses (e.g., 127.0.0.0/8, 169.254.0.0/16, ::1) and internal-only hostnames.")
  lines.append("- Consider using network-level egress controls to prevent the application server from reaching internal metadata or admin services.")
  lines.append("")

  # Metadata
  lines.append("## Metadata")
  lines.append(f"- **Generated**: {generated_ts}")
  lines.append("- **Generator**: scripts/generate_ssrf_report.py")
  lines.append("")

  return "\n".join(lines)


def main() -> None:
  parser = argparse.ArgumentParser(
    description="Generate an SSRF bug bounty report from a JSON description file.",
  )
  parser.add_argument(
    "--input",
    required=True,
    help="Path to JSON file describing the SSRF finding",
  )
  parser.add_argument(
    "--output-dir",
    default=str(REPORTS_DIR),
    help="Directory to write the Markdown report to (default: output/reports)",
  )

  args = parser.parse_args()

  input_path = Path(args.input)
  if not input_path.exists():
    raise SystemExit(f"Input file not found: {input_path}")

  finding = load_finding(input_path)

  program = finding.get("program", "program")
  title = finding.get("title", "ssrf_report")

  safe_program = sanitize_filename(program)
  safe_title = sanitize_filename(title)
  timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

  output_dir = Path(args.output_dir)
  output_dir.mkdir(parents=True, exist_ok=True)

  report_path = output_dir / f"{safe_program}_{safe_title}_{timestamp}.md"

  report_md = build_ssrf_report(finding)
  with report_path.open("w", encoding="utf-8") as f:
    f.write(report_md)

  print(f"SSRF report generated: {report_path}")


if __name__ == "__main__":  # pragma: no cover
  main()
