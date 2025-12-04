#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# ModHarmony™ - Quick Install and Run Script

echo "========================================="
echo "  ModHarmony™ Installation"
echo "========================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

echo "✓ Python 3 found"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

echo ""
echo "========================================="
echo "  Installation Complete!"
echo "========================================="
echo ""
echo "To start the web server:"
echo "  python web_app.py"
echo ""
echo "Then open: http://localhost:5000"
echo ""
echo "To use the Python API:"
echo "  python"
echo "  >>> from mod_scanner import ModScanner"
echo "  >>> scanner = ModScanner()"
echo ""
echo "========================================="
