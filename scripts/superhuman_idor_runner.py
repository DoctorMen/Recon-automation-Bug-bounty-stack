#!/usr/bin/env python3
import argparse
import sys
from typing import Dict, Tuple

import requests


def parse_cookie_header(cookie_header: str) -> Dict[str, str]:
    """Parse a Cookie header string into a dict for requests."""
    cookies: Dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def fetch(url: str, cookies: Dict[str, str], timeout: int = 15) -> Tuple[int, int]:
    try:
        resp = requests.get(
            url,
            cookies=cookies,
            headers={
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
                "User-Agent": "Mozilla/5.0 (IDOR-Runner)",
            },
            timeout=timeout,
            allow_redirects=True,
        )
        return resp.status_code, len(resp.content)
    except requests.RequestException:
        return -1, 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Minimal Superhuman subscription/billing IDOR helper. "
            "Runs A vs B requests against a few high-value endpoints and "
            "prints status/length for comparison."
        )
    )
    parser.add_argument(
        "--cookie-a",
        required=True,
        help=(
            "Cookie header value for Account A, "
            "exactly as copied from the browser (without the 'Cookie: ' prefix)."
        ),
    )
    parser.add_argument(
        "--cookie-b",
        required=True,
        help=(
            "Cookie header value for Account B, "
            "exactly as copied from the browser (without the 'Cookie: ' prefix)."
        ),
    )
    args = parser.parse_args(argv)

    cookies_a = parse_cookie_header(args.cookie_a)
    cookies_b = parse_cookie_header(args.cookie_b)

    base = "https://settings.superhuman.com"
    targets = [
        f"{base}/subscription",
        f"{base}/superhuman/subscription",
        f"{base}/setup/payment-methods",
        f"{base}/update-card",
        f"{base}/submit-draft-invoice",
        f"{base}/true_up",
        f"{base}/workspaces",
    ]

    print("[+] Superhuman IDOR/Billing quick check")
    print("=====================================")

    for url in targets:
        print(f"\nTarget: {url}")
        status_a, len_a = fetch(url, cookies_a)
        status_b, len_b = fetch(url, cookies_b)

        print(f"  A -> {status_a}, length={len_a}")
        print(f"  B -> {status_b}, length={len_b}")

        if status_a == status_b and len_a == len_b:
            print("  [=] Same status and length (likely same generic view)")
        else:
            print("  [!] Difference detected (status or length). Inspect with browser/Burp.")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
