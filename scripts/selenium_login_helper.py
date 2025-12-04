#!/usr/bin/env python3
"""Simple Selenium login helper (manual-password, no brute force).

This script:
- Opens a browser to the given URL.
- Optionally pre-fills an email/username field using common selectors.
- Waits for you to complete login manually (password, 2FA, captchas).
- After you press Enter in the terminal, it dumps cookies to a JSON file.

NO automated account creation, password guessing, or scanning.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from webdriver_manager.chrome import ChromeDriverManager


COMMON_EMAIL_SELECTORS = [
    (By.ID, "email"),
    (By.NAME, "email"),
    (By.NAME, "username"),
    (By.CSS_SELECTOR, "input[type='email']"),
]


def try_fill_email(driver: webdriver.Chrome, email: str) -> None:
    for by, value in COMMON_EMAIL_SELECTORS:
        try:
            elem = driver.find_element(by, value)
            elem.clear()
            elem.send_keys(email)
            return
        except NoSuchElementException:
            continue


def save_cookies(driver: webdriver.Chrome, output_path: Path) -> None:
    cookies = driver.get_cookies()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(cookies, f, indent=2)
    print(f"[i] Saved {len(cookies)} cookies to {output_path}")


def run(url: str, email: Optional[str], output: Path) -> int:
    options = Options()
    # Visible browser; do NOT use headless so you can complete login.
    options.add_argument("--start-maximized")
    # Selenium 4: use Service object instead of passing executable path positionally
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    try:
        print(f"[i] Opening {url} ...")
        driver.get(url)

        if email:
            try_fill_email(driver, email)
            print("[i] Attempted to pre-fill email field.")

        print("\n[i] Complete the login flow manually in the browser.")
        print("    When you are fully logged in (session established), return here and press Enter.")
        input("\nPress Enter here to capture cookies and close the browser...")

        save_cookies(driver, output)
        return 0
    finally:
        driver.quit()


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Manual login helper using Selenium: opens a browser, optionally "
            "fills email, waits for you to log in, then saves cookies."
        )
    )
    parser.add_argument("url", help="Login or app URL to open (e.g., https://www.exodus.com/)")
    parser.add_argument("--email", help="Email/username to pre-fill in common login fields.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("cookies/session_cookies.json"),
        help="Where to save cookies JSON (default: cookies/session_cookies.json)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        return run(args.url, args.email, args.output)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
