#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Smart Program Selector - Weighted random selection with anti-repeat logic
# Prevents getting stuck on the same program repeatedly

PROGRAMS_DIR="$HOME/Recon-automation-Bug-bounty-stack/programs"
HISTORY_FILE="$HOME/Recon-automation-Bug-bounty-stack/.program_history"

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

# Read last selected program
last_program=""
if [ -f "$HISTORY_FILE" ]; then
    last_program=$(tail -n 1 "$HISTORY_FILE" | cut -d',' -f1)
fi

# Remove last program from selection pool to force variety
available_programs=()
for prog in "${programs[@]}"; do
    if [[ "$prog" != "$last_program" ]]; then
        available_programs+=("$prog")
    fi
done

# If all programs were the last one (unlikely), use all programs
if [ ${#available_programs[@]} -eq 0 ]; then
    available_programs=("${programs[@]}")
fi

# Pick a random program (excluding last one)
random_index=$((RANDOM % ${#available_programs[@]}))
selected="${available_programs[$random_index]}"

target_dir="$PROGRAMS_DIR/$selected"

# Save to history
echo "$selected,$(date +%Y-%m-%d-%H:%M:%S)" >> "$HISTORY_FILE"

echo "============================================"
echo "🎲 SMART PROGRAM SELECTOR"
echo "============================================"
echo ""
echo "📋 All programs: ${programs[*]}"
echo ""
if [ -n "$last_program" ]; then
    echo "❌ Excluded (last program): $last_program"
fi
echo ""
echo "🎯 TODAY'S PROGRAM: $selected"
echo "📁 Directory: $target_dir"
echo ""
echo "============================================"

cd "$target_dir"

# Create standard directories if they don't exist
for dir in findings recon exploits reports; do
    if [ ! -d "$dir" ]; then
        echo "📁 Creating $dir/ directory..."
        mkdir -p "$dir"
    fi
done

# Show what's in this program
echo ""
echo "📂 Current contents:"
ls -lh
echo ""

# Check for important files
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

# Show recent history
echo "============================================"
echo "📜 Recent program history:"
if [ -f "$HISTORY_FILE" ]; then
    tail -n 5 "$HISTORY_FILE" | while IFS=',' read -r prog timestamp; do
        echo "  • $prog (on $timestamp)"
    done
else
    echo "  (No history yet)"
fi
echo ""

echo "============================================"
echo "✅ Ready to hunt bugs in: $selected"
echo "============================================"
echo ""
echo "Suggested workflow:"
echo "  1. Review program scope and policy"
echo "  2. Run reconnaissance (subfinder, httpx)"
echo "  3. Scan for vulnerabilities (nuclei)"
echo "  4. Manual testing on interesting endpoints"
echo "  5. Document findings in findings/"
echo ""
echo "To select a different random program: ~/Recon-automation-Bug-bounty-stack/smart_program_selector.sh"
echo ""

# Start a subshell in this directory
exec $SHELL
