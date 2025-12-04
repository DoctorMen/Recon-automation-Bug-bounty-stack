#!/usr/bin/env python3
"""Simple PDF knowledge indexer.

Usage:
    python3 tools/pdf_indexer.py --input /path/to/pdfs --output knowledge_index.json

- Recursively walks the input directory
- Extracts text from each .pdf file
- Heuristically extracts headings
- Tags each document by attack surface using keyword matching
- Writes a JSON index that other tools can consume

This is intentionally lightweight; it assumes PyPDF2 is installed:
    pip install PyPDF2
"""

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from typing import Dict, List

try:
    from PyPDF2 import PdfReader
except ImportError:  # pragma: no cover
    raise SystemExit(
        "PyPDF2 is required. Install it with: pip install PyPDF2"
    )


ATTACK_TAGS: Dict[str, List[str]] = {
    "auth_bypass": [
        "authentication",
        "authorize",
        "authorization",
        "session fixation",
        "csrf",
        "login bypass",
        "jwt",
        "token",
    ],
    "ci_cd": [
        "ci/cd",
        "pipeline",
        "gitlab-ci",
        "github actions",
        "runner",
        "build server",
    ],
    "api_abuse": [
        "rest api",
        "graphql",
        "idor",
        "broken object level authorization",
        "rate limit",
    ],
    "ssrf": [
        "ssrf",
        "server-side request forgery",
    ],
    "waf_bypass": [
        "waf",
        "web application firewall",
        "bypass",
        "modsecurity",
    ],
    "cloud_infra": [
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "eks",
        "gke",
        "aks",
    ],
}


def read_pdf_text(path: str) -> str:
    reader = PdfReader(path)
    texts = []
    for page in reader.pages:
        try:
            txt = page.extract_text() or ""
        except Exception:
            txt = ""
        texts.append(txt)
    return "\n".join(texts)


HEADING_RE = re.compile(r"^(?:[0-9]+[.)]\\s+|chapter\\s+|section\\s+|##?\\s+)", re.I)


def extract_headings(text: str, max_len: int = 120) -> List[str]:
    headings: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if len(line) > max_len:
            continue
        if HEADING_RE.match(line) or line.isupper():
            headings.append(line)
    # de-duplicate while preserving order
    seen = set()
    unique = []
    for h in headings:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


def keyword_counts(text: str, keywords: List[str]) -> Dict[str, int]:
    lowered = text.lower()
    counts = {}
    for kw in keywords:
        c = lowered.count(kw.lower())
        if c:
            counts[kw] = c
    return counts


def tag_document(text: str) -> List[str]:
    tags = []
    lowered = text.lower()
    for tag, kws in ATTACK_TAGS.items():
        if any(kw.lower() in lowered for kw in kws):
            tags.append(tag)
    return tags


def build_index(input_dir: str) -> Dict:
    index_docs = []
    all_keywords = set()
    for kws in ATTACK_TAGS.values():
        all_keywords.update(kws)

    for root, _dirs, files in os.walk(input_dir):
        for fname in files:
            if not fname.lower().endswith(".pdf"):
                continue
            path = os.path.join(root, fname)
            rel_path = os.path.relpath(path, input_dir)
            try:
                text = read_pdf_text(path)
            except Exception as e:  # pragma: no cover
                print(f"[WARN] Failed to read {path}: {e}")
                continue

            headings = extract_headings(text)
            tags = tag_document(text)
            kw_counts = keyword_counts(text, sorted(all_keywords))

            doc_entry = {
                "path": rel_path,
                "absolute_path": os.path.abspath(path),
                "title": os.path.splitext(fname)[0],
                "headings": headings,
                "tags": tags,
                "keyword_counts": kw_counts,
            }
            index_docs.append(doc_entry)

    return {"documents": index_docs}


def main() -> None:
    parser = argparse.ArgumentParser(description="Index PDFs into a security knowledge base")
    parser.add_argument("--input", required=True, help="Root directory containing PDF files")
    parser.add_argument("--output", required=True, help="Output JSON file for the knowledge index")
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input)
    if not os.path.isdir(input_dir):
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    index = build_index(input_dir)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)

    print(f"Indexed {len(index['documents'])} PDF documents from {input_dir}")
    print(f"Knowledge index written to {os.path.abspath(args.output)}")


if __name__ == "__main__":
    main()
