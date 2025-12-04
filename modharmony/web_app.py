#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
ModHarmony™ - Web Application
Flask-based web interface for mod compatibility testing
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import os
import json
from mod_scanner import ModScanner, ModDatabase
from pathlib import Path

app = Flask(__name__)
CORS(app)

# Initialize scanner and database
scanner = ModScanner()
db = ModDatabase()

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_mods():
    """
    API endpoint to scan mods for conflicts
    
    Expects JSON:
    {
        "mods": {
            "ModName1": "/path/to/mod1",
            "ModName2": "/path/to/mod2"
        }
    }
    """
    try:
        data = request.get_json()
        mods = data.get('mods', {})
        
        if not mods:
            return jsonify({"error": "No mods provided"}), 400
        
        # Scan all mods
        scanner_instance = ModScanner()
        scan_results = scanner_instance.scan_multiple_mods(mods)
        
        # Analyze compatibility
        report = scanner_instance.analyze_compatibility()
        
        # Save to database
        mod_names = list(mods.keys())
        db.add_compatibility_test(
            mod_names,
            report['status'],
            report['conflicts']
        )
        
        return jsonify({
            "success": True,
            "report": report,
            "scan_results": scan_results
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/quick-check', methods=['POST'])
def quick_check():
    """
    Quick compatibility check between two mods using database
    
    Expects JSON:
    {
        "mod1": "ModName1",
        "mod2": "ModName2"
    }
    """
    try:
        data = request.get_json()
        mod1 = data.get('mod1')
        mod2 = data.get('mod2')
        
        if not mod1 or not mod2:
            return jsonify({"error": "Both mod names required"}), 400
        
        # Check database
        compatibility = db.check_known_compatibility(mod1, mod2)
        
        if compatibility['tests'] > 0:
            return jsonify({
                "success": True,
                "known": True,
                "compatible": compatibility['compatible'],
                "tests": compatibility['tests'],
                "confidence": min(compatibility['tests'] * 10, 100)
            })
        else:
            return jsonify({
                "success": True,
                "known": False,
                "message": "No compatibility data available. Run a full scan."
            })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/upload-mod', methods=['POST'])
def upload_mod():
    """
    Upload mod files for scanning
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        mod_name = request.form.get('mod_name', 'unknown_mod')
        
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Save uploaded file
        mod_folder = os.path.join(UPLOAD_FOLDER, mod_name)
        os.makedirs(mod_folder, exist_ok=True)
        
        file_path = os.path.join(mod_folder, file.filename)
        file.save(file_path)
        
        return jsonify({
            "success": True,
            "message": f"Uploaded {file.filename}",
            "path": mod_folder
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get database statistics"""
    try:
        total_tests = len(db.data.get('tests', []))
        total_mods = len(db.data.get('mods', {}))
        total_compatibility = len(db.data.get('compatibility', {}))
        
        return jsonify({
            "success": True,
            "stats": {
                "total_tests": total_tests,
                "total_mods": total_mods,
                "compatibility_pairs": total_compatibility
            }
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get a specific compatibility report"""
    # This would retrieve from database
    return jsonify({"message": "Report retrieval not yet implemented"})

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "ModHarmony API",
        "version": "1.0.0"
    })


if __name__ == '__main__':
    print("=" * 60)
    print("ModHarmony™ Web Application")
    print("=" * 60)
    print("\nStarting server...")
    print("Access at: http://localhost:5000")
    print("\nAPI Endpoints:")
    print("  POST /api/scan - Scan mods for conflicts")
    print("  POST /api/quick-check - Quick compatibility check")
    print("  POST /api/upload-mod - Upload mod files")
    print("  GET  /api/stats - Get database stats")
    print("  GET  /health - Health check")
    print("\n" + "=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
