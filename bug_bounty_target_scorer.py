#!/usr/bin/env python3
"""
Bug Bounty Target Scorer
Data‑driven target selection to maximize EV.

Usage:
1. Edit programs.json with program data.
2. Run: python3 bug_bounty_target_scorer.py
3. Review ranked list in ranked_programs.json
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# --- Scoring weights (tune to your preferences) ---
WEIGHTS = {
    "recent_activity": 0.30,      # Bounties paid in last 30 days
    "scope_clarity": 0.20,        # How clear the scope is
    "strength_fit": 0.25,        # Fit to your strengths (web + API)
    "competition_level": 0.25     # Fewer researchers = higher score
}

# --- Helper functions ---
def days_ago(days):
    return datetime.now() - timedelta(days=days)

def parse_date(date_str):
    """Parse common date formats."""
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None

def recent_activity_score(program):
    """
    Score based on bounties paid in last 30 days.
    Simple linear scaling: 0–5 bounties = 0–1.0 score.
    """
    last_30 = days_ago(30)
    recent = [b for b in program.get("bounties", []) if parse_date(b.get("paid_date")) >= last_30]
    count = len(recent)
    # Linear scaling up to 5 bounties
    return min(count / 5.0, 1.0)

def scope_clarity_score(program):
    """
    Score based on how clear the scope is.
    - Clear in-scope list (+)
    - Vague "all assets" (-)
    - Explicit out-of-scope (+)
    """
    score = 0.5  # baseline
    scope = program.get("scope", {})
    if scope.get("in_scope_assets"):
        score += 0.3
    if scope.get("out_of_scope_assets"):
        score += 0.2
    if "all assets" in scope.get("notes", "").lower():
        score -= 0.3
    return max(0.0, min(1.0, score))

def strength_fit_score(program):
    """
    Score based on fit to your strengths.
    Prefer: web apps, APIs, auth flows.
    Penalize: mobile-only, hardware, thick client.
    """
    score = 0.5
    tags = [t.lower() for t in program.get("tags", [])]
    assets = [a.lower() for a in program.get("scope", {}).get("in_scope_assets", [])]
    # Positive signals
    if any(t in tags for t in ["web", "api", "saas"]):
        score += 0.3
    if any("api" in a or "web" in a for a in assets):
        score += 0.2
    # Negative signals
    if any(t in tags for t in ["mobile", "ios", "android", "hardware"]):
        score -= 0.3
    return max(0.0, min(1.0, score))

def competition_level_score(program):
    """
    Estimate competition based on researcher count and recent reports.
    Fewer researchers = higher score.
    """
    researchers = program.get("researcher_count", 0)
    recent_reports = program.get("recent_reports", 0)
    # Simple heuristic: fewer researchers + fewer recent reports = higher score
    # Normalize to 0–1 (you can calibrate based on your data)
    researcher_score = max(0.0, 1.0 - researchers / 100.0)  # assume 100 researchers = 0
    report_score = max(0.0, 1.0 - recent_reports / 50.0)      # assume 50 recent reports = 0
    return (researcher_score + report_score) / 2.0

def calculate_score(program):
    """
    Calculate overall weighted score.
    """
    scores = {
        "recent_activity": recent_activity_score(program),
        "scope_clarity": scope_clarity_score(program),
        "strength_fit": strength_fit_score(program),
        "competition_level": competition_level_score(program)
    }
    overall = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)
    return overall, scores

def load_programs(path):
    """Load programs from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Programs file not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] JSON decode error in {path}: {e}")
        sys.exit(1)

def save_ranked(programs, path):
    """Save ranked programs to JSON."""
    ranked = []
    for prog in programs:
        overall, subscores = calculate_score(prog)
        prog["overall_score"] = overall
        prog["subscores"] = subscores
        ranked.append(prog)
    # Sort descending by overall_score
    ranked.sort(key=lambda p: p["overall_score"], reverse=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ranked, f, indent=2, default=str)
    print(f"[+] Saved ranked list to: {path}")

def print_summary(ranked, top_n=10):
    """Print a quick summary of top programs."""
    print("\n--- Top Programs by EV Score ---")
    for i, prog in enumerate(ranked[:top_n], 1):
        print(f"{i:2d}. {prog['name']} (score: {prog['overall_score']:.2f})")
        print(f"    Recent activity: {prog['subscores']['recent_activity']:.2f}")
        print(f"    Scope clarity:    {prog['subscores']['scope_clarity']:.2f}")
        print(f"    Strength fit:     {prog['subscores']['strength_fit']:.2f}")
        print(f"    Competition:      {prog['subscores']['competition_level']:.2f}")
        print()

def main():
    programs_file = Path("programs.json")
    ranked_file = Path("ranked_programs.json")
    if not programs_file.is_file():
        print("[!] Creating stub programs.json – please edit with real data.")
        stub = [
            {
                "name": "Example Program A",
                "platform": "HackerOne",
                "tags": ["web", "api", "saas"],
                "scope": {
                    "in_scope_assets": ["*.example.com", "api.example.com"],
                    "out_of_scope_assets": ["admin.example.com"],
                    "notes": "Clear scope, no third parties"
                },
                "bounties": [
                    {"amount": 500, "paid_date": "2025-11-10"},
                    {"amount": 800, "paid_date": "2025-11-05"}
                ],
                "researcher_count": 45,
                "recent_reports": 12
            },
            {
                "name": "Example Program B",
                "platform": "Bugcrowd",
                "tags": ["mobile", "ios", "android"],
                "scope": {
                    "in_scope_assets": [],
                    "out_of_scope_assets": [],
                    "notes": "All mobile assets"
                },
                "bounties": [
                    {"amount": 300, "paid_date": "2025-09-15"}
                ],
                "researcher_count": 120,
                "recent_reports": 40
            }
        ]
        with open(programs_file, "w", encoding="utf-8") as f:
            json.dump(stub, f, indent=2, default=str)
        print(f"[+] Stub created at: {programs_file}")
        print("[!] Edit programs.json with real program data and re-run.")
        return

    programs = load_programs(programs_file)
    save_ranked(programs, ranked_file)
    ranked = load_programs(ranked_file)
    print_summary(ranked, top_n=10)

if __name__ == "__main__":
    main()
