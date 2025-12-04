#!/usr/bin/env python3
"""
Offline HackerOne program catalog + BOLA (Broken Object Level Authorization) scoring.

This script is intentionally read-only with respect to targets:
- It only makes HTTP GET requests to https://hackerone.com/<handle>
- It never sends any traffic to customer targets or in-scope assets.
- It produces a local JSON catalog with a simple "bola_potential_score" per program.

Usage:
  python3 scripts/bola_program_catalog.py [--platform hackerone] [--limit N] [--delay SECONDS]

Data sources:
  - bug_bounty_programs.json at the repo root (list of domains by platform)
  - HACKERONE_HANDLES mapping from root domains to HackerOne program handles

You can extend both the JSON file and the handle map as you add more programs.
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from html import unescape
from pathlib import Path
from typing import Dict, List, Optional

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).parent.parent
PROGRAM_LIST_FILE = REPO_ROOT / "bug_bounty_programs.json"
OUTPUT_FILE = REPO_ROOT / "output" / "bola_program_catalog.json"

# Map well-known program domains to their HackerOne handles.
# Extend this as you add more programs.
HACKERONE_HANDLES: Dict[str, str] = {
    "shopify.com": "shopify",
    "starbucks.com": "starbucks",
    "uber.com": "uber",
    "twitter.com": "twitter",
    "github.com": "github",
    "mozilla.org": "mozilla",
    "wordpress.com": "wordpress",
    "automattic.com": "automattic",
    "dropbox.com": "dropbox",
    "yelp.com": "yelp",
    "instagram.com": "instagram",
    "tiktok.com": "tiktok",
    "paypal.com": "paypal",
    "ebay.com": "ebay",
    # Not in bug_bounty_programs.json yet, but useful for future runs
    "notion.so": "notion",
}

# Heuristic keywords for estimating BOLA / object-level access control potential
MULTI_TENANT_TERMS: List[str] = [
    "workspace",
    "space",
    "page",
    "document",
    "doc",
    "board",
    "project",
    "repository",
    "repo",
    "organization",
    "organisation",
    "org",
    "team",
    "group",
    "tenant",
    "account",
    "customer",
    "folder",
    "notebook",
    "wiki",
]

API_TERMS: List[str] = [
    "api",
    "rest api",
    "graphql",
    "json",
    "endpoint",
]

ROLE_TERMS: List[str] = [
    "admin",
    "owner",
    "editor",
    "viewer",
    "guest",
    "member",
    "collaborator",
    "manager",
]

HOST_HINTS: List[str] = [
    "api.",
    "app.",
    "dashboard.",
    "portal.",
    "panel.",
    "admin.",
]

USER_AGENT = "OfflineBolaCatalog/0.1 (+https://hackerone.com/)"


@dataclass
class BolaAnalysis:
    domain: str
    platform: str
    handle: str
    program_url: str
    bola_potential_score: int
    matched_terms: Dict[str, List[str]]
    text_sample: str


def load_program_domains(platform: Optional[str]) -> List[str]:
    if not PROGRAM_LIST_FILE.exists():
        print(f"[!] Program list file not found: {PROGRAM_LIST_FILE}", file=sys.stderr)
        return []

    with PROGRAM_LIST_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if platform:
        by_platform = data.get("by_platform", {})
        domains = by_platform.get(platform.lower(), [])
    else:
        domains = data.get("programs", [])

    return list(dict.fromkeys(domains))  # preserve order, remove duplicates


def fetch_program_html(handle: str, delay: float) -> Optional[str]:
    url = f"https://hackerone.com/{handle}"
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=20) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                print(f"[!] Unexpected content type for {url}: {content_type}", file=sys.stderr)
                return None
            html_bytes = resp.read()
            time.sleep(delay)
            return html_bytes.decode("utf-8", errors="ignore")
    except HTTPError as e:
        print(f"[!] HTTP error for {url}: {e}", file=sys.stderr)
    except URLError as e:
        print(f"[!] URL error for {url}: {e}", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"[!] Unexpected error fetching {url}: {e}", file=sys.stderr)

    return None


def extract_visible_text(html: str) -> str:
    # Remove script and style content
    html = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.IGNORECASE)
    html = re.sub(r"<style[\s\S]*?</style>", " ", html, flags=re.IGNORECASE)
    # Strip all remaining tags
    text = re.sub(r"<[^>]+>", " ", html)
    text = unescape(text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def score_bola_potential(text: str) -> BolaAnalysis:
    lower = text.lower()

    def collect_matches(terms: List[str]) -> List[str]:
        found = {t for t in terms if t in lower}
        return sorted(found)

    multi_tenant_matches = collect_matches(MULTI_TENANT_TERMS)
    api_matches = collect_matches(API_TERMS)
    role_matches = collect_matches(ROLE_TERMS)

    hosts = re.findall(r"https?://([a-z0-9.-]+)", lower)
    host_hits = sorted({h for h in hosts if any(hint in h for hint in HOST_HINTS)})

    score = 0
    if multi_tenant_matches:
        score += 2 * len(multi_tenant_matches)
    if api_matches:
        score += 2 * len(api_matches)
    if role_matches:
        score += 1 * len(role_matches)
    if host_hits:
        score += 2 * len(host_hits)

    matched_terms: Dict[str, List[str]] = {}
    if multi_tenant_matches:
        matched_terms["multi_tenant_terms"] = multi_tenant_matches
    if api_matches:
        matched_terms["api_terms"] = api_matches
    if role_matches:
        matched_terms["role_terms"] = role_matches
    if host_hits:
        matched_terms["host_hints"] = host_hits

    # text_sample is filled by caller; here we only compute score and matches
    return BolaAnalysis(
        domain="",
        platform="",
        handle="",
        program_url="",
        bola_potential_score=score,
        matched_terms=matched_terms,
        text_sample="",
    )


def analyze_programs(platform: Optional[str], limit: Optional[int], delay: float) -> List[BolaAnalysis]:
    domains = load_program_domains(platform)
    if not domains:
        return []

    analyses: List[BolaAnalysis] = []

    for domain in domains:
        handle = HACKERONE_HANDLES.get(domain)
        if not handle:
            print(f"[ ] Skipping {domain}: no HackerOne handle mapping defined", file=sys.stderr)
            continue

        print(f"[*] Fetching program page for {domain} (handle: {handle})")
        html = fetch_program_html(handle, delay=delay)
        if not html:
            continue

        text = extract_visible_text(html)
        base_analysis = score_bola_potential(text)
        sample = text[:1500]

        analysis = BolaAnalysis(
            domain=domain,
            platform=platform or "unknown",
            handle=handle,
            program_url=f"https://hackerone.com/{handle}",
            bola_potential_score=base_analysis.bola_potential_score,
            matched_terms=base_analysis.matched_terms,
            text_sample=sample,
        )
        analyses.append(analysis)

        if limit is not None and len(analyses) >= limit:
            break

    return analyses


def save_catalog(analyses: List[BolaAnalysis]) -> None:
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated": datetime.now().isoformat(),
        "count": len(analyses),
        "records": [asdict(a) for a in analyses],
    }
    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved BOLA catalog to {OUTPUT_FILE}")


def print_summary(analyses: List[BolaAnalysis], top_n: int = 10) -> None:
    if not analyses:
        print("[!] No analyses generated")
        return

    sorted_analyses = sorted(analyses, key=lambda a: a.bola_potential_score, reverse=True)

    print()
    print("Top programs by BOLA potential score:")
    print("-------------------------------------")
    for idx, a in enumerate(sorted_analyses[:top_n], start=1):
        terms = []
        for key, values in a.matched_terms.items():
            if values:
                terms.append(f"{key}={','.join(values[:4])}")
        terms_str = "; ".join(terms)
        print(f"{idx:2d}. {a.domain} ({a.handle}) - score {a.bola_potential_score}")
        if terms_str:
            print(f"    {terms_str}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline HackerOne program catalog + BOLA scoring")
    parser.add_argument("--platform", default="hackerone", help="Platform key from bug_bounty_programs.json (default: hackerone)")
    parser.add_argument("--limit", type=int, default=None, help="Optional limit on number of programs to analyze")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay in seconds between HTTP requests (default: 1.0)")

    args = parser.parse_args()

    print("=" * 60)
    print("Offline HackerOne Program Catalog + BOLA Scoring")
    print("=" * 60)
    print()
    print("This script only talks to https://hackerone.com/<handle> (read-only).")
    print("It does not scan or probe customer targets.")
    print()

    analyses = analyze_programs(platform=args.platform, limit=args.limit, delay=args.delay)
    save_catalog(analyses)
    print_summary(analyses)


if __name__ == "__main__":  # pragma: no cover
    main()
