#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Configuration file for recon stack
# Source this file or export variables before running scripts

# Recon Scanner Configuration
export RECON_TIMEOUT="${RECON_TIMEOUT:-1800}"  # 30 minutes
export PARALLEL_RECON="${PARALLEL_RECON:-false}"

# HTTPx Configuration
export HTTPX_RATE_LIMIT="${HTTPX_RATE_LIMIT:-100}"  # Requests per second
export HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-10}"  # Request timeout in seconds
export HTTPX_THREADS="${HTTPX_THREADS:-50}"  # Concurrent threads

# Nuclei Configuration
export NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-50}"  # Requests per second
export NUCLEI_BULK_SIZE="${NUCLEI_BULK_SIZE:-25}"  # Bulk size for scanning
export NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-10}"  # Request timeout
export NUCLEI_SCAN_TIMEOUT="${NUCLEI_SCAN_TIMEOUT:-3600}"  # Overall scan timeout (1 hour)

# Example: For slower scanning (more conservative)
# export HTTPX_RATE_LIMIT=50
# export NUCLEI_RATE_LIMIT=25

# Example: For faster scanning (use with caution)
# export HTTPX_RATE_LIMIT=200
# export NUCLEI_RATE_LIMIT=100

