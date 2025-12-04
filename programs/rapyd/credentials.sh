#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Rapyd API Credentials Setup
# IMPORTANT: This file contains sensitive credentials - DO NOT COMMIT

# Rapyd Secret Key (Private Key)
export RAPYD_SECRET_KEY="rsk_0171288550b537ece3ee6cd7b27b534278970e09b1b8d50e512f7ead43ba7b14545647cabe9e30dd"

# Rapyd API Key (Public Key) - Add your API key here when available
export RAPYD_API_KEY=""

# API Configuration
export RAPYD_BASE_URL="https://sandboxapi.rapyd.net"
export BUGCROWD_HEADER="Bugcrowd-DoctorMen"

# IDOR Testing Tokens
# For IDOR testing, you need TWO tokens from TWO different accounts:
# - TOKEN_A: API token from Account A (the attacker account)
# - TOKEN_B: API token from Account B (the victim account)
# 
# To get these tokens:
# 1. Log into dashboard.rapyd.net with Account A → Get API token → Set as TOKEN_A
# 2. Log into dashboard.rapyd.net with Account B → Get API token → Set as TOKEN_B
# 3. Create a payment in Account B
# 4. Test if Account A can access Account B's payment (IDOR test)

export TOKEN_A=""
export TOKEN_B=""

# If you only have one account, you can use the same token for both (but won't test IDOR):
# export TOKEN_A="$RAPYD_SECRET_KEY"
# export TOKEN_B="$RAPYD_SECRET_KEY"

# Usage:
# source programs/rapyd/credentials.sh
# Then use $RAPYD_SECRET_KEY and $RAPYD_API_KEY in your scripts
# For IDOR testing, use $TOKEN_A and $TOKEN_B


