#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Random Program Selector - Pick a random bug bounty program to work on today
# Prevents getting stuck on one program (like Rapyd)

PROGRAMS_DIR="$HOME/Recon-automation-Bug-bounty-stack/programs"

# Exclude template and example directories
EXCLUDE_DIRS=("template" "example.bak_20251031_113428" "other_targets")

# Get all program directories
all_programs=($(ls -d $PROGRAMS_DIR/*/ | xargs -n 1 basename))

# Filter out excluded directories
programs=()
for prog in "${all_programs[@]}"; do
    exclude=0
    for excl in "${EXCLUDE_DIRS[@]}"; do
        if [[ "$prog" == "$excl" ]]; then
            exclude=1
            break
        fi
    done
    if [[ $exclude -eq 0 ]]; then
        programs+=("$prog")
    fi
done

# Pick a random program
random_index=$((RANDOM % ${#programs[@]}))
selected="${programs[$random_index]}"

target_dir="$PROGRAMS_DIR/$selected"

echo "============================================"
echo "🎲 RANDOM PROGRAM SELECTOR"
echo "============================================"
echo ""
echo "📋 Available programs: ${programs[*]}"
echo ""
echo "🎯 TODAY'S PROGRAM: $selected"
echo "📁 Directory: $target_dir"
echo ""
echo "============================================"

cd "$target_dir"

# Create findings directory if it doesn't exist
if [ ! -d "findings" ]; then
    echo "📁 Creating findings directory..."
    mkdir -p findings
fi

# Show what's in this program
echo ""
echo "📂 Current contents:"
ls -lh
echo ""

# Check if there's a targets.txt or similar
if [ -f "targets.txt" ]; then
    echo "🎯 Targets found:"
    cat targets.txt
    echo ""
fi

if [ -f "config.yaml" ]; then
    echo "⚙️  Config found:"
    cat config.yaml
    echo ""
fi

echo "============================================"
echo "✅ Ready to hunt bugs in: $selected"
echo "============================================"
echo ""
echo "Suggested next steps:"
echo "  1. Review scope: Read program policy"
echo "  2. Reconnaissance: Run subfinder/httpx"
echo "  3. Scanning: Run nuclei on targets"
echo "  4. Testing: Look for vulnerabilities"
echo "  5. Document: Save findings in findings/"
echo ""

# Start a subshell in this directory
exec $SHELL
