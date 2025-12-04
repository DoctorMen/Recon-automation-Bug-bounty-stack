<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Protection System

Idempotent protection mechanisms to prevent unauthorized recreation.

## Quick Start

\\ash
# Generate your unique protection key
bash .protection/generate_key.sh

# Protect a workflow
python3 .protection/obfuscate.py workflows/rapyd-hourly-monitor-enhanced.json

# Verify authenticity
python3 .protection/obfuscate.py workflows/rapyd-hourly-monitor-enhanced_protected.json --verify
\
## Features

- **User-Specific Key**: Tied to your system identity
- **Watermarking**: Hidden watermarks in workflow metadata
- **Idempotency**: Safe to run multiple times
- **Integrity Checks**: Verify workflows haven't been tampered

## Protection Key

Generated from: hostname, username, home directory, MAC address
Stored in: .protection/user_key.enc (not in git)

