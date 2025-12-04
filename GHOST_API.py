#!/usr/bin/env python3
"""
GHOST IDE™ API Server
Copyright (c) 2025 Khallid Hakeem Nurse - All Rights Reserved
Proprietary and Confidential

Connects GHOST IDE frontend to Python backend for real-time security scanning
Owner: Khallid Hakeem Nurse
System: GHOST IDE™
Date: November 5, 2025
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import subprocess
import json
import os
import threading
import time
from datetime import datetime

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:8001", "http://127.0.0.1:8001", "http://172.24.145.56:8001"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})  # Enable CORS with specific settings

# Track active scans
active_scans = {}
scan_results = {}

def execute_command(cmd, scan_id):
    """Execute command and stream output"""
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        active_scans[scan_id] = {
            'process': process,
            'status': 'running',
            'output': [],
            'start_time': datetime.now().isoformat()
        }
        
        # Read output line by line
        for line in process.stdout:
            active_scans[scan_id]['output'].append({
                'type': 'stdout',
                'line': line.strip(),
                'timestamp': datetime.now().isoformat()
            })
        
        # Read errors
        for line in process.stderr:
            active_scans[scan_id]['output'].append({
                'type': 'stderr',
                'line': line.strip(),
                'timestamp': datetime.now().isoformat()
            })
        
        process.wait()
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['exit_code'] = process.returncode
        active_scans[scan_id]['end_time'] = datetime.now().isoformat()
        
    except Exception as e:
        active_scans[scan_id]['status'] = 'error'
        active_scans[scan_id]['error'] = str(e)

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'message': 'GHOST API is running',
        'active_scans': len([s for s in active_scans.values() if s['status'] == 'running'])
    })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a security scan"""
    data = request.json
    target = data.get('target')
    mode = data.get('mode', 'all')
    scan_type = data.get('type', 'quick')
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # Generate scan ID
    scan_id = f"scan_{int(time.time())}"
    
    # Build command based on available scripts
    if os.path.exists('run_pipeline.py'):
        cmd = f"python3 run_pipeline.py --target {target}"
    elif os.path.exists('DIVERGENT_THINKING_ENGINE.py'):
        cmd = f"python3 DIVERGENT_THINKING_ENGINE.py --target {target} --mode {mode}"
    elif os.path.exists('scripts/run_recon.sh'):
        cmd = f"bash scripts/run_recon.sh {target}"
    else:
        # Fallback to basic recon
        cmd = f"echo 'Starting scan on {target}...'; subfinder -d {target} -silent"
    
    # Start scan in background thread
    thread = threading.Thread(target=execute_command, args=(cmd, scan_id))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'target': target,
        'mode': mode,
        'command': cmd,
        'status': 'started'
    })

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def scan_status(scan_id):
    """Get scan status and output"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = active_scans[scan_id]
    return jsonify({
        'scan_id': scan_id,
        'status': scan['status'],
        'output': scan['output'][-50:],  # Last 50 lines
        'start_time': scan.get('start_time'),
        'end_time': scan.get('end_time'),
        'exit_code': scan.get('exit_code')
    })

@app.route('/api/scan/<scan_id>/stream', methods=['GET'])
def stream_scan(scan_id):
    """Stream scan output in real-time"""
    def generate():
        if scan_id not in active_scans:
            yield f"data: {json.dumps({'error': 'Scan not found'})}\n\n"
            return
        
        last_line = 0
        while True:
            scan = active_scans[scan_id]
            output = scan['output']
            
            # Send new lines
            if len(output) > last_line:
                for line_data in output[last_line:]:
                    yield f"data: {json.dumps(line_data)}\n\n"
                last_line = len(output)
            
            # Check if scan is done
            if scan['status'] in ['completed', 'error']:
                yield f"data: {json.dumps({'status': scan['status'], 'done': True})}\n\n"
                break
            
            time.sleep(0.5)
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/verify', methods=['POST'])
def verify_authorization():
    """Verify target authorization"""
    data = request.json
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # Check if authorization file exists
    auth_file = f"authorizations/{target}.json"
    
    if os.path.exists(auth_file):
        with open(auth_file, 'r') as f:
            auth_data = json.load(f)
        return jsonify({
            'authorized': True,
            'target': target,
            'details': auth_data
        })
    else:
        return jsonify({
            'authorized': False,
            'target': target,
            'message': f'No authorization file found. Create: {auth_file}'
        })

@app.route('/api/targets/safe', methods=['GET'])
def get_safe_targets():
    """Get list of safe targets"""
    safe_config = 'SAFE_TARGETS_CONFIG.json'
    
    if os.path.exists(safe_config):
        with open(safe_config, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    else:
        return jsonify({
            'safe_targets': {
                'test_environments': ['demo.hackerone.com'],
                'ctf_platforms': ['ctf.hacker101.com']
            }
        })

@app.route('/api/modes', methods=['GET'])
def get_modes():
    """Get available thinking modes"""
    return jsonify({
        'modes': [
            {'id': 'lateral', 'name': 'Lateral', 'icon': '🔄', 'description': 'Opposite thinking'},
            {'id': 'parallel', 'name': 'Parallel', 'icon': '⚡', 'description': 'Multiple paths'},
            {'id': 'associative', 'name': 'Associative', 'icon': '🔗', 'description': 'Pattern recognition'},
            {'id': 'generative', 'name': 'Generative', 'icon': '💡', 'description': 'Novel attacks'},
            {'id': 'combinatorial', 'name': 'Combinatorial', 'icon': '🧩', 'description': 'Attack chaining'},
            {'id': 'perspective', 'name': 'Perspective', 'icon': '👁️', 'description': 'Nation-state'},
            {'id': 'constraint-free', 'name': 'Constraint-Free', 'icon': '🚀', 'description': 'Unlimited resources'}
        ]
    })

@app.route('/api/command', methods=['POST'])
def execute_terminal_command():
    """Execute terminal command"""
    data = request.json
    cmd = data.get('command', '').strip()
    
    if not cmd:
        return jsonify({'error': 'Command required'}), 400
    
    # Whitelist safe commands
    safe_commands = ['help', 'status', 'verify', 'scan', 'clear', 'demo', 'ls', 'pwd', 'whoami']
    
    cmd_base = cmd.split()[0] if cmd.split() else ''
    
    if cmd == 'help':
        return jsonify({
            'output': '''Available commands:
  scan <target>  - Start security scan
  verify <target> - Check authorization
  status         - Show system status
  help           - Show this help
  clear          - Clear terminal
            '''
        })
    elif cmd == 'status':
        return jsonify({
            'output': f'''System Status:
Active scans: {len([s for s in active_scans.values() if s["status"] == "running"])}
Total scans: {len(active_scans)}
API: Online
            '''
        })
    elif cmd.startswith('verify '):
        target = cmd.split()[1] if len(cmd.split()) > 1 else ''
        return verify_authorization()
    else:
        return jsonify({
            'output': f'Command: {cmd}\n(Real execution requires scan API)'
        })

if __name__ == '__main__':
    print("=" * 60)
    print("GHOST IDE API Server Starting...")
    print("=" * 60)
    print("Owner: Khallid Hakeem Nurse")
    print("Port: 5000")
    print("URL: http://localhost:5000")
    print("=" * 60)
    print("\nServer ready - GHOST IDE can now connect\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
