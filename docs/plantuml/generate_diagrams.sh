#!/bin/bash
# Generate all PlantUML diagrams in the current directory and subdirectories
# Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.

# Create output directories
mkdir -p png

# Find all .puml files and generate PNGs
find . -name "*.puml" | while read -r file; do
    echo "Generating diagram for $file..."
    filename=$(basename "$file" .puml)
    dir=$(dirname "$file")
    
    # Create output directory structure
    mkdir -p "png/${dir#./}"
    
    # Generate PNG
    plantuml -tpng "$file" -o "$(pwd)/png/${dir#./}"
done

echo "All diagrams generated in the png/ directory"
