#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Program Selector - Choose which bug bounty program to work on

PROGRAMS_DIR="$HOME/Recon-automation-Bug-bounty-stack/programs"

echo "============================================"
echo "🎯 BUG BOUNTY PROGRAM SELECTOR"
echo "============================================"
echo ""
echo "Available programs:"
echo ""

# List programs
programs=($(ls -d $PROGRAMS_DIR/*/ | xargs -n 1 basename))

for i in "${!programs[@]}"; do
    echo "  $((i+1)). ${programs[$i]}"
done

echo ""
echo "  0. Cancel"
echo ""
read -p "Select program (1-${#programs[@]}): " choice

if [ "$choice" -eq 0 ]; then
    echo "Cancelled"
    exit 0
fi

if [ "$choice" -ge 1 ] && [ "$choice" -le "${#programs[@]}" ]; then
    selected="${programs[$((choice-1))]}"
    target_dir="$PROGRAMS_DIR/$selected"
    
    echo ""
    echo "✅ Selected: $selected"
    echo "📁 Directory: $target_dir"
    echo ""
    
    cd "$target_dir"
    
    # Show what's in this program
    echo "Contents:"
    ls -lh
    
    # Start a subshell in this directory
    exec $SHELL
else
    echo "Invalid selection"
    exit 1
fi
