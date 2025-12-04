#!/usr/bin/env python3
"""Copyright © 2025 DoctorMen. All Rights Reserved."""
"""
BOLA / IDOR Report Generator

Generates a Markdown bug bounty report for Broken Object Level Authorization
(BOLA) / IDOR issues from a simple JSON description file.

This is designed for human-in-the-loop use:
- You prepare a JSON file describing the finding
- This script renders a ready-to-paste Markdown report
- You review and edit before submitting to a bug bounty platform

Example usage:

  python3 scripts/generate_bola_report.py \
    --input notion_bola.json \
    --output output/reports/

Example JSON (minimal):

{
  "program": "Notion Labs, Inc.",
  "title": "Cross-account access to private pages via /api/v3/loadCachedPageChunkV2 (BOLA / IDOR)",
  "severity": "high",
  "asset": "Notion web application (https://www.notion.so/) - internal API endpoint /api/v3/loadCachedPageChunkV2",
  "endpoint": "POST /api/v3/loadCachedPageChunkV2",
  "object_type": "page",
  "object_id_parameter": "pageId",
  "privileged_role": "Account A (page owner)",
  "unprivileged_role": "Account B (guest in workspace, not invited to page)",
  "summary": "An authenticated guest user can still read private pages after being removed from sharing by calling the internal API with the pageId.",
  "impact": [
    "Guest can read arbitrary private pages they are not invited to",
    "Leads to confidentiality breach of workspace content"
  ],
  "steps": [
    "Login as Account A (owner) and create a private page.",
    "Share the page with Account B and capture the internal API request containing pageId.",
    "Remove Account B from the page sharing settings and confirm the UI blocks access.",
    "Login as Account B and replay the internal API request with the same pageId; the page content is still returned."
  ],
  "requests": {
    "privileged_request": "<HTTP request as privileged account>",
    "privileged_response": "<HTTP response showing content>",
    "unprivileged_request": "<HTTP request as unprivileged account>",
    "unprivileged_response": "<HTTP response still showing content>"
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


def extract_method_and_path(endpoint: str) -> (Optional[str], str):
  """Best-effort split of "METHOD /path" into (method, path)."""
  if not endpoint:
    return None, ""
  parts = endpoint.split()
  if len(parts) >= 2 and parts[0].isalpha():
    return parts[0].upper(), " ".join(parts[1:])
  return None, endpoint


def build_bola_report(data: Dict[str, Any]) -> str:
  """Render the BOLA / IDOR report as Markdown."""
  program = data.get("program", "[PROGRAM]")
  title = data.get(
    "title",
    "Broken Object Level Authorization (BOLA) via internal API"
  )
  severity = str(data.get("severity", "high")).upper()
  asset = data.get("asset", "[Describe impacted asset]")
  summary = data.get("summary", "[One sentence describing the BOLA / IDOR bug]")

  endpoint = data.get("endpoint", "")
  method, path = extract_method_and_path(endpoint)
  endpoint_host = data.get("endpoint_host", "[host]")
  object_type = data.get("object_type", "object")
  object_id_param = data.get("object_id_parameter", "id")

  privileged_role = data.get("privileged_role", "Privileged account (owner/admin)")
  unprivileged_role = data.get("unprivileged_role", "Unprivileged account (guest / regular user)")

  impact_items = ensure_list(data.get("impact"))
  step_items = ensure_list(data.get("steps"))

  requests = data.get("requests", {}) or {}
  privileged_request = requests.get("privileged_request")
  privileged_response = requests.get("privileged_response")
  unprivileged_request = requests.get("unprivileged_request")
  unprivileged_response = requests.get("unprivileged_response")

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
  lines.append("- Broken Object Level Authorization (BOLA) / Insecure Direct Object Reference (IDOR)")
  lines.append("- **CWE-639**: Authorization Bypass Through User-Controlled Key")
  lines.append("- **CWE-284**: Improper Access Control")
  lines.append("- **CWE-285**: Improper Authorization")
  lines.append("- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor")
  lines.append("")

  # Affected endpoint
  lines.append("## Affected Endpoint")
  if method:
    lines.append(f"- **Method**: {method}")
  if path:
    lines.append(f"- **Path**: `{path}`")
  if endpoint_host:
    lines.append(f"- **Host**: `{endpoint_host}`")
  if object_type:
    lines.append(f"- **Object type**: {object_type}")
  if object_id_param:
    lines.append(f"- **Object identifier parameter**: `{object_id_param}`")
  lines.append("")

  # Roles / preconditions
  lines.append("## Roles & Preconditions")
  lines.append("- Attacker has a valid, low-privileged account:")
  lines.append(f"  - {unprivileged_role}")
  lines.append("- There is at least one more privileged account:")
  lines.append(f"  - {privileged_role}")
  lines.append("- The application exposes an internal API that accepts a user-controlled identifier (e.g. pageId, documentId) for objects of type " + object_type + ".")
  lines.append("")

  # Steps to reproduce
  lines.append("## Steps to Reproduce")
  if step_items:
    for idx, step in enumerate(step_items, start=1):
      lines.append(f"{idx}. {step}")
  else:
    lines.append("1. [Login as privileged account and create a private object].")
    lines.append("2. [Share with unprivileged account and capture the internal API request including the object identifier].")
    lines.append("3. [Revoke access for the unprivileged account in the UI and confirm the UI blocks access].")
    lines.append("4. [Replay the internal API request as the unprivileged account; the sensitive object is still returned].")
  lines.append("")

  # Proof of concept
  lines.append("## Proof of Concept")

  if privileged_request:
    lines.append("### Request as privileged account")
    lines.append("```http")
    lines.append(str(privileged_request).strip())
    lines.append("```")
    lines.append("")

  if privileged_response:
    lines.append("### Response as privileged account")
    lines.append("```http")
    # Avoid extremely large outputs
    resp = str(privileged_response)
    if len(resp) > 4000:
      resp = resp[:4000] + "\n... [truncated]"
    lines.append(resp.strip())
    lines.append("```")
    lines.append("")

  if unprivileged_request:
    lines.append("### Request as unprivileged account")
    lines.append("```http")
    lines.append(str(unprivileged_request).strip())
    lines.append("```")
    lines.append("")

  if unprivileged_response:
    lines.append("### Response as unprivileged account (still returns private data)")
    lines.append("```http")
    resp2 = str(unprivileged_response)
    if len(resp2) > 4000:
      resp2 = resp2[:4000] + "\n... [truncated]"
    lines.append(resp2.strip())
    lines.append("```")
    lines.append("")

  # Impact
  lines.append("## Impact")
  if impact_items:
    for item in impact_items:
      lines.append(f"- {item}")
  else:
    lines.append("- Unprivileged users can read private objects they are not authorized to access.")
    lines.append("- This breaks tenant and account isolation and can expose sensitive data.")
  lines.append("")

  # Remediation
  lines.append("## Remediation")
  lines.append("- Enforce strict server-side authorization checks on every access to objects by identifier.")
  lines.append(f"- For each request to the {object_type} API, verify that the caller is explicitly authorized to access the referenced object.")
  lines.append("- Do not rely on client-side checks or UI sharing state; the API must independently enforce access control.")
  lines.append("- Consider using resource-scoped access checks (e.g., workspace/tenant + objectId) instead of trusting a bare identifier.")
  lines.append("")

  # Metadata
  lines.append("## Metadata")
  lines.append(f"- **Generated**: {generated_ts}")
  lines.append("- **Generator**: scripts/generate_bola_report.py")
  lines.append("")

  return "\n".join(lines)


def main() -> None:
  parser = argparse.ArgumentParser(
    description="Generate a BOLA / IDOR bug bounty report from a JSON description file."
  )
  parser.add_argument(
    "--input",
    required=True,
    help="Path to JSON file describing the BOLA / IDOR finding",
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
  title = finding.get("title", "bola_report")

  safe_program = sanitize_filename(program)
  safe_title = sanitize_filename(title)
  timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

  output_dir = Path(args.output_dir)
  output_dir.mkdir(parents=True, exist_ok=True)

  report_path = output_dir / f"{safe_program}_{safe_title}_{timestamp}.md"

  report_md = build_bola_report(finding)
  with report_path.open("w", encoding="utf-8") as f:
    f.write(report_md)

  print(f"BOLA report generated: {report_path}")


if __name__ == "__main__":  # pragma: no cover
  main()
