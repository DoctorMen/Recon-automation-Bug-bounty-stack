#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Fix bogus screen size issue idempotently

export COLUMNS=80
export LINES=24

# Set terminal size if possible
if command -v stty >/dev/null 2>&1; then
    stty cols 80 rows 24 2>&1 || true
fi

# Verify
echo Screen
