#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# bolt_low_noise_checks.sh
# Low-noise recon: fetch primary pages, extract candidate paths + JS chunks.
# Adds retry + exponential backoff + error logging.
set -euo pipefail

OUT=/tmp/bolt_recon
LOG="$OUT/errors.log"
mkdir -p "$OUT"
: > "$LOG"

# Config (tweak as needed)
HOSTS=( "https://food.bolt.eu" "https://bolt.eu" "https://bolt.com" )
CURL_CONNECT_TIMEOUT=6    # seconds to establish TCP
CURL_MAX_TIME=12          # total seconds per attempt
RETRIES=${RETRIES:-2}     # total attempts per host (1 = no retry)
BACKOFF_BASE=2            # exponential backoff base (seconds)
CURL_OPTS=( --silent --show-error --location --fail --tlsv1.2 \
            --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" )

echo "[*] Starting low-noise checks: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
echo "[*] Output dir: $OUT"
echo "[*] Errors log: $LOG"

# Fetch function with retry/backoff
fetch_host() {
  local host="$1"
  local outf="$OUT/$(echo "$host" | sed 's|https://||; s|/||g').html"
  local attempt=1
  while :; do
    echo "[*] Fetching (attempt $attempt): $host"
    if curl "${CURL_OPTS[@]}" "$host" -o "$outf"; then
      echo "[+] OK: $host -> $outf"
      return 0
    else
      local code=$?
      echo "[!] curl failed (code $code) for $host on attempt $attempt" \
        | tee -a "$LOG"
      if [ "$attempt" -ge "$RETRIES" ]; then
        echo "[!] Exhausted attempts for $host (last code $code)" | tee -a "$LOG"
        return 1
      fi
      # backoff
      sleep_time=$(( BACKOFF_BASE ** (attempt - 1) ))
      echo "[*] Backing off ${sleep_time}s before retry..."
      sleep "$sleep_time"
      attempt=$(( attempt + 1 ))
    fi
  done
}

# 1) fetch primary pages
for h in "${HOSTS[@]}"; do
  fetch_host "$h" || echo "$(date -u +%FT%T) FAIL $h" >> "$LOG"
done

# 2) extract candidate paths and JS chunk references (improved regex)
> "$OUT/urls_all.txt"
> "$OUT/paths_found.txt"
> "$OUT/js_chunks.txt"

for f in "$OUT"/*.html; do
  [ -s "$f" ] || continue
  echo "[*] Parsing $f"
  # URLs incl. scheme (allow query, percent-encoding)
  grep -Eo 'https?://[A-Za-z0-9._:/%?=&@-]+' "$f" | sort -u >> "$OUT/urls_all.txt" || true

  # path-like tokens that look interesting (api, auth, admin, etc)
  grep -Eo '/[A-Za-z0-9._/@%?&=:\-]{2,}' "$f" \
    | egrep -i '(api|auth|admin|login|dashboard|partners?|courier|fleet|merchant|signup|openapi|swagger|graphql|manifest|_next|_expo|\.well-known)' \
    | sort -u >> "$OUT/paths_found.txt" || true

  # JS chunk files (Next.js/_next, expo/_expo)
  grep -Eo '/_next/static/[^"'\''[:space:]]+' "$f" | sort -u >> "$OUT/js_chunks.txt" || true
  grep -Eo '/_expo/static/[^"'\''[:space:]]+' "$f" | sort -u >> "$OUT/js_chunks.txt" || true
done

# canonicalize and dedupe outputs
sort -u "$OUT/urls_all.txt" -o "$OUT/urls_all.txt" || true
sort -u "$OUT/paths_found.txt" -o "$OUT/paths_found.txt" || true
sort -u "$OUT/js_chunks.txt" -o "$OUT/js_chunks.txt" || true

echo "=== Quick results ==="
wc -l "$OUT/urls_all.txt" "$OUT/paths_found.txt" "$OUT/js_chunks.txt" "$LOG" || true
echo "=== sample paths (first 40) ==="
head -n 40 "$OUT/paths_found.txt" || true

echo "[*] Done. See files in $OUT and errors in $LOG"
