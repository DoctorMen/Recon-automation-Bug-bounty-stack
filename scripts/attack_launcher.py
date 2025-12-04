#!/usr/bin/env python3
"""
Offline attack launcher / preview tool.

This script does NOT send any network traffic.
It is designed to:
- Load candidate finding JSON files (BOLA, SSRF, crypto, etc.).
- Summarise potential attacks in a consistent format.
- Help you decide which ones to investigate and report.

Later it can be extended with a strictly gated interactive-execution
layer, but for now it is offline-only by design.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AttackCandidate:
    """Normalised representation of a potential attack."""

    source_file: Path
    program: str
    attack_type: str
    title: str
    severity: str
    endpoint: Optional[str]
    asset: Optional[str]
    summary: str
    steps: List[str]


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:  # noqa: BLE001
        print(f"[!] Failed to load JSON from {path}: {e}", file=sys.stderr)
        return None


def coerce_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def detect_attack_type(data: Dict[str, Any]) -> str:
    if "object_type" in data or "object_id_parameter" in data:
        return "bola"
    if "ssrf_parameter" in data or "internal_targets" in data:
        return "ssrf"
    # Fallbacks based on known crypto fields
    if "crypto" in data.get("title", "").lower() or "jwt" in json.dumps(data).lower():
        return "crypto"
    return "generic"


def normalise_candidate(path: Path, data: Dict[str, Any]) -> AttackCandidate:
    program = str(data.get("program", "Unknown Program"))
    title = str(data.get("title", path.stem))
    severity = str(data.get("severity", "unknown")).lower()

    # Common fields for different templates
    endpoint = None
    asset = None

    if "endpoint" in data:
        endpoint = str(data.get("endpoint"))
    elif "entrypoint" in data:
        endpoint = str(data.get("entrypoint"))

    if "asset" in data:
        asset = str(data.get("asset"))

    summary = str(data.get("summary", ""))
    steps = coerce_list(data.get("steps", []))

    attack_type = detect_attack_type(data)

    return AttackCandidate(
        source_file=path,
        program=program,
        attack_type=attack_type,
        title=title,
        severity=severity,
        endpoint=endpoint,
        asset=asset,
        summary=summary,
        steps=steps,
    )


def find_json_files(target: Path) -> List[Path]:
    if target.is_file():
        return [target]

    paths: List[Path] = []
    for p in target.rglob("*.json"):
        if p.is_file():
            paths.append(p)
    return sorted(paths)


def load_candidates(target: Path, program_filter: Optional[str]) -> List[AttackCandidate]:
    candidates: List[AttackCandidate] = []

    for path in find_json_files(target):
        data = load_json(path)
        if not data:
            continue

        # Some of your JSON files may be lists of findings in the future.
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                candidate = normalise_candidate(path, item)
                if program_filter and program_filter.lower() not in candidate.program.lower():
                    continue
                candidates.append(candidate)
        elif isinstance(data, dict):
            candidate = normalise_candidate(path, data)
            if program_filter and program_filter.lower() not in candidate.program.lower():
                continue
            candidates.append(candidate)

    return candidates


def print_candidate(candidate: AttackCandidate, index: int, total: int) -> None:
    header = f"[{index}/{total}] {candidate.program} – {candidate.title}"
    print("=" * len(header))
    print(header)
    print("=" * len(header))
    print(f"Source:   {candidate.source_file}")
    print(f"Type:     {candidate.attack_type}")
    print(f"Severity: {candidate.severity}")
    if candidate.endpoint:
        print(f"Endpoint: {candidate.endpoint}")
    if candidate.asset:
        print(f"Asset:    {candidate.asset}")
    if candidate.summary:
        print("\nSummary:")
        print(f"  {candidate.summary}")
    if candidate.steps:
        print("\nSuggested steps:")
        for i, step in enumerate(candidate.steps, start=1):
            print(f"  {i}. {step}")
    print()


def run_offline_preview(target: Path, program_filter: Optional[str]) -> int:
    if not target.exists():
        print(f"[!] Target path does not exist: {target}", file=sys.stderr)
        return 1

    candidates = load_candidates(target, program_filter)
    if not candidates:
        print("[i] No candidates found.")
        return 0

    print(f"[i] Loaded {len(candidates)} candidate finding(s).\n")
    for idx, candidate in enumerate(candidates, start=1):
        print_candidate(candidate, idx, len(candidates))

    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Offline attack launcher preview. "
            "Loads finding JSON files (BOLA/SSRF/crypto) and prints a "
            "normalised summary. No network requests are sent."
        )
    )
    parser.add_argument(
        "target",
        metavar="PATH",
        help=(
            "Path to a JSON file or a directory containing JSON files "
            "(e.g. output/notion_bola.json or output/)."
        ),
    )
    parser.add_argument(
        "--program",
        dest="program",
        help="Optional case-insensitive filter on the 'program' field.",
    )
    parser.add_argument(
        "--mode",
        dest="mode",
        default="offline",
        choices=["offline"],
        help="Execution mode. Currently only 'offline' (preview) is supported.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    target = Path(args.target).expanduser()

    if args.mode == "offline":
        return run_offline_preview(target, args.program)

    # This should never be reached due to argparse choices, but keep for safety.
    print(f"[!] Unsupported mode: {args.mode}", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
