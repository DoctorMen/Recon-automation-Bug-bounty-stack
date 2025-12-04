#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

extract() {
  local file="$1"
  local dest="$2"
  local type
  type=$(file -b "$file" | awk '{print tolower($0)}')
  if echo "$type" | grep -q "zip"; then unzip -q "$file" -d "$dest"
  elif echo "$type" | grep -q "gzip\|tar"; then tar -xzf "$file" -C "$dest"
  else echo "Unknown archive type: $type"; exit 1; fi
}

install_tool() {
  local name="$1"
  local url="$2"
  local marker="tools/.installed_$name"
  local bin="tools/bin/$name"
  local tmp="tools/tmp/$name.dl"
  if [ -f "$marker" ]; then echo "$name already installed. Skipping."; return; fi
  echo "Downloading $name..."
  mkdir -p tools/bin tools/tmp
  curl -sSL "$url" -o "$tmp"
  mkdir -p tools/tmp/extract_$name
  extract "$tmp" tools/tmp/extract_$name
  file=$(find tools/tmp/extract_$name -type f -executable -name "$name*" | head -n 1)
  cp "$file" "$bin"
  chmod +x "$bin"
  echo "installed $(date)" > "$marker"
  echo "$name installed."
}

install_tool subfinder "https://github.com/projectdiscovery/subfinder/releases/download/v2.9.0/subfinder_2.9.0_linux_amd64.zip"
install_tool amass "https://github.com/owasp-amass/amass/releases/download/v5.0.1/amass_linux_amd64.tar.gz"
install_tool dnsx "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.2/dnsx_1.2.2_linux_amd64.zip"
install_tool httpx "https://github.com/projectdiscovery/httpx/releases/download/v1.7.1/httpx_1.7.1_linux_amd64.zip"
install_tool nuclei "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_linux_amd64.zip"

echo "All installs finished."
