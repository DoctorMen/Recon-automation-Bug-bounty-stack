#!/bin/bash
# Rapyd API Credentials Setup
# IMPORTANT: This file contains sensitive credentials - DO NOT COMMIT

# Rapyd Secret Key (Private Key)
export RAPYD_SECRET_KEY="rsk_0171288550b537ece3ee6cd7b27b534278970e09b1b8d50e512f7ead43ba7b14545647cabe9e30dd"

# Rapyd API Key (Public Key) - Add your API key here when available
export RAPYD_API_KEY=""

# API Configuration
export RAPYD_BASE_URL="https://sandboxapi.rapyd.net"
export BUGCROWD_HEADER="Bugcrowd-DoctorMen"

# Usage:
# source programs/rapyd/credentials.sh
# Then use $RAPYD_SECRET_KEY and $RAPYD_API_KEY in your scripts

