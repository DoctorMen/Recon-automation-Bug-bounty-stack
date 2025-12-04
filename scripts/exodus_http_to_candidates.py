#!/usr/bin/env python3
"""Extract Exodus HTTP Burp export into offline candidate JSON.

This script:
- Reads a Burp "HTTP requests and responses in plain text" export (actually XML).
- Filters items where the host ends with exodus.io or exodus.com.
- Decodes base64 request/response bodies.
- Emits a JSON file containing candidate findings suitable for attack_launcher.py.

IMPORTANT:
- This is **offline-only**: it just processes traffic you've already captured.
- It does NOT send any network requests.
- It does NOT guess other users' addresses, IDs, or perform any scanning.
"""

import argparse
import base64
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import xml.etree.ElementTree as ET


def decode_b64(text: Optional[str], max_len: int) -> str:
    if not text:
        return ""
    raw = text.strip()
    try:
        data = base64.b64decode(raw)
    except Exception:  # noqa: BLE001
        return ""
    s = data.decode("utf-8", errors="replace")
    if len(s) > max_len:
        return s[:max_len] + "\n...[truncated]"
    return s


def extract_items(burp_xml: Path, max_items: int) -> List[Dict[str, Any]]:
    tree = ET.parse(burp_xml)
    root = tree.getroot()

    candidates: List[Dict[str, Any]] = []

    for item in root.findall("item"):
        host_el = item.find("host")
        host = host_el.text if host_el is not None and host_el.text else ""
        if not host.endswith("exodus.io") and not host.endswith("exodus.com"):
            continue

        method_el = item.find("method")
        path_el = item.find("path")
        url_el = item.find("url")

        method = method_el.text if method_el is not None and method_el.text else "GET"
        path = path_el.text if path_el is not None and path_el.text else "/"
        url = url_el.text if url_el is not None and url_el.text else ""

        req_el = item.find("request")
        resp_el = item.find("response")

        raw_request = decode_b64(req_el.text if req_el is not None else None, max_len=2000)
        raw_response = decode_b64(resp_el.text if resp_el is not None else None, max_len=2000)

        title = f"Exodus crypto wallet baseline – {method} {host}{path}"

        candidate: Dict[str, Any] = {
            "program": "Exodus Crypto Wallet",
            "title": title,
            "severity": "info",
            "asset": f"Exodus backend API ({host})",
            "endpoint": f"{method} {path}",
            "endpoint_host": host,
            "summary": (
                "Baseline captured Exodus wallet traffic for offline analysis. "
                "This is NOT a confirmed vulnerability; it is a starting point "
                "for BOLA/crypto hypothesis testing using existing tools."
            ),
            "steps": [
                "Start Burp and configure it as the system proxy.",
                "Open and unlock the Exodus desktop wallet.",
                "Perform normal wallet actions that reach this endpoint (view balances, fees, or account data).",
                "Capture the traffic in Burp and export it to an XML file, then run this extractor script.",
            ],
            "requests": {
                "example_request": raw_request,
                "example_response": raw_response,
                "full_url": url,
            },
        }

        candidates.append(candidate)
        if len(candidates) >= max_items:
            break

    return candidates


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert Burp Exodus HTTP export (XML) into offline JSON candidates "
            "for attack_launcher.py. No network traffic is sent."
        )
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Path to Burp 'HTTP requests and responses in plain text' export (XML).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/exodus_session1_candidates.json"),
        help="Where to write the JSON candidates (default: output/exodus_session1_candidates.json)",
    )
    parser.add_argument(
        "--max-items",
        type=int,
        default=10,
        help="Maximum number of Exodus requests to turn into candidates (default: 10)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if not args.input.exists():
        print(f"[!] Input file does not exist: {args.input}")
        return 1

    candidates = extract_items(args.input, args.max_items)
    if not candidates:
        print("[i] No Exodus hosts found in the Burp export.")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        json.dump(candidates, f, indent=2)

    print(f"[i] Wrote {len(candidates)} candidate(s) to {args.output}")
    print("    You can now run: python3 scripts/attack_launcher.py", args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
