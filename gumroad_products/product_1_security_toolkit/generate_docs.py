#!/usr/bin/env python3
"""
GHOST IDE™ Documentation Generator
Copyright (c) 2025 Khallid Hakeem Nurse - All Rights Reserved
"""

import os
import subprocess
import sys
from datetime import datetime

def run_command(command, cwd=None):
    """Execute a shell command and return its output."""
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=True,
            check=True,
            text=True,
            capture_output=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        sys.exit(1)

def generate_plantuml_diagrams():
    """Generate PlantUML diagrams."""
    print("Generating PlantUML diagrams...")
    plantuml_dir = os.path.join("docs", "plantuml")
    
    # Check if PlantUML is installed
    try:
        run_command("plantuml -version")
    except:
        print("PlantUML not found. Please install it first.")
        print("On Ubuntu/Debian: sudo apt-get install plantuml")
        print("On MacOS: brew install plantuml")
        sys.exit(1)
    
    # Generate diagrams
    run_command("plantuml -tpng -output ./png **/*.puml", cwd=plantuml_dir)
    print("Diagrams generated successfully!")

def update_api_docs():
    """Generate API documentation from docstrings."""
    print("Updating API documentation...")
    try:
        # Install pdoc3 if not installed
        run_command("pip install pdoc3")
        
        # Generate API docs
        run_command("pdoc --html --force --output-dir docs/api GHOST_API.py")
        print("API documentation updated!")
    except Exception as e:
        print(f"Error generating API docs: {e}")

def generate_readme():
    """Generate or update the main README.md."""
    print("Updating README.md...")
    with open("README.md", "w") as f:
        f.write(f"""# GHOST IDE™

## Overview
GHOST IDE™ is an AI-powered security automation framework designed for modern security operations.

## Features
- **AI-Powered Analysis**: Leverages advanced AI for security scanning
- **Real-time Monitoring**: Continuous security monitoring
- **Automated Workflows**: Streamline security operations
- **Extensible Architecture**: Plugin-based system for extending functionality

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- Docker (optional)

### Installation
```bash
git clone https://github.com/yourusername/ghost-ide.git
cd ghost-ide
pip install -r requirements.txt
```

### Running the Application
```bash
# Start the API server
python GHOST_API.py

# In a new terminal, start the web interface
cd static
python -m http.server 8001
```

## Documentation

For detailed documentation, please see the [docs](docs/index.md) directory.

## License

© 2025 Khallid Hakeem Nurse - All Rights Reserved
""")
    print("README.md updated!")

def main():
    """Main documentation generation function."""
    print("\n=== GHOST IDE™ Documentation Generator ===\n")
    
    # Create necessary directories
    os.makedirs("docs/api", exist_ok=True)
    os.makedirs("docs/plantuml/png", exist_ok=True)
    
    # Generate documentation
    generate_plantuml_diagrams()
    update_api_docs()
    generate_readme()
    
    print("\nDocumentation generation complete!")
    print("View the documentation at: file://" + os.path.abspath("docs/index.md"))

if __name__ == "__main__":
    main()
