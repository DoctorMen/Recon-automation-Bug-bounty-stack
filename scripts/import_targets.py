#!/usr/bin/env python3
"""
Import Targets from CSV
Reads a CSV (specifically the Exodus/H1 format) and extracts domains/wildcards.
Outputs a clean list for recon.
"""

import csv
import sys
import os
import re

def clean_domain(domain):
    """Cleans up wildcard domains to standard format."""
    domain = domain.strip()
    domain = re.sub(r'^\*\.', '', domain) # Remove leading *.
    domain = re.sub(r'^http://', '', domain)
    domain = re.sub(r'^https://', '', domain)
    domain = domain.strip('/')
    return domain

def process_csv(input_path, output_file):
    print(f"[*] Reading targets from: {input_path}")
    domains = set()
    
    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            # Try to find the 'identifier' or 'Asset' column
            header = next(reader, None)
            col_idx = 0
            
            if header:
                # Try to auto-detect column
                lower_header = [h.lower() for h in header]
                if 'identifier' in lower_header:
                    col_idx = lower_header.index('identifier')
                elif 'asset' in lower_header:
                    col_idx = lower_header.index('asset')
                elif 'target' in lower_header:
                    col_idx = lower_header.index('target')
            
            # Reset file pointer if no header found or just process
            f.seek(0)
            if header: next(reader) # skip header
            
            for row in reader:
                if len(row) > col_idx:
                    item = row[col_idx]
                    # Basic filter: must look like a domain
                    if '.' in item and ' ' not in item:
                        clean = clean_domain(item)
                        domains.add(clean)
                        
        print(f"[*] Extracted {len(domains)} unique targets.")
        
        with open(output_file, 'w') as f:
            for d in sorted(domains):
                f.write(f"https://{d}\n") # specific for JSINT which needs URLs
                
        print(f"[*] Saved formatted list to: {output_file}")
        
    except Exception as e:
        print(f"[-] Error processing CSV: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 import_targets.py <input_csv> <output_txt>")
        sys.exit(1)
        
    process_csv(sys.argv[1], sys.argv[2])
