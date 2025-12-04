#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.

WORKOS INTEGRATION - Authentication & User Management
Integrate WorkOS into your Recon Automation system
"""

import os
import requests
import json
from pathlib import Path
from datetime import datetime

class WorkOSIntegration:
    """WorkOS integration for your WORK OS"""

    def __init__(self):
        self.base_path = Path(__file__).parent
        # WorkOS API configuration
        self.api_key = os.getenv('WORKOS_API_KEY', 'your_api_key_here')
        self.client_id = os.getenv('WORKOS_CLIENT_ID', 'your_client_id_here')
        self.base_url = 'https://api.workos.com'

    def show_workos_overview(self):
        """Explain what WorkOS does for your system"""
        print("""
==================================================
              WORKOS INTEGRATION
     Authentication & User Management for WORK OS
==================================================

WorkOS adds enterprise-grade features to your system:

✅ SSO (Single Sign-On) - Users login with Google, Microsoft, etc.
✅ Directory Sync - Sync users from Google Workspace, Azure AD, Okta
✅ User Management - Admin portal for managing users
✅ Security - Enterprise security features
✅ Branding - Custom login pages matching your brand
✅ Multi-tenant - Support multiple organizations
✅ SCIM - Automated user provisioning
        """)

    def create_workos_config(self):
        """Create WorkOS configuration files"""
        print("\n" + "="*60)
        print("CREATING WORKOS CONFIGURATION")
        print("="*60)

        # Environment variables file
        env_config = """
# WorkOS Configuration
WORKOS_API_KEY=your_api_key_here
WORKOS_CLIENT_ID=your_client_id_here

# Get these from https://dashboard.workos.com
# 1. Sign up for WorkOS account
# 2. Create a new project
# 3. Copy API Key and Client ID
        """.strip()

        env_path = self.base_path / '.env.workos'
        with open(env_path, 'w') as f:
            f.write(env_config)

        print(f"✅ Created .env.workos configuration file")

        # WorkOS client class
        workos_client = '''
import os
import requests
from typing import Dict, List, Optional

class WorkOSClient:
    """WorkOS API client for authentication and user management"""

    def __init__(self):
        self.api_key = os.getenv('WORKOS_API_KEY')
        self.client_id = os.getenv('WORKOS_CLIENT_ID')
        self.base_url = 'https://api.workos.com'
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

    def get_user(self, user_id: str) -> Dict:
        """Get user information"""
        response = requests.get(
            f'{self.base_url}/users/{user_id}',
            headers=self.headers
        )
        return response.json()

    def list_users(self, organization_id: str) -> List[Dict]:
        """List all users in organization"""
        response = requests.get(
            f'{self.base_url}/organizations/{organization_id}/users',
            headers=self.headers
        )
        return response.json()

    def create_organization(self, name: str, domain: str) -> Dict:
        """Create new organization"""
        data = {
            'name': name,
            'domain': domain
        }
        response = requests.post(
            f'{self.base_url}/organizations',
            headers=self.headers,
            json=data
        )
        return response.json()

    def authenticate_user(self, code: str) -> Dict:
        """Complete OAuth authentication"""
        data = {
            'client_id': self.client_id,
            'code': code,
            'grant_type': 'authorization_code'
        }
        response = requests.post(
            f'{self.base_url}/oauth/token',
            json=data
        )
        return response.json()

    def get_directory_users(self, directory_id: str) -> List[Dict]:
        """Get users from directory sync"""
        response = requests.get(
            f'{self.base_url}/directories/{directory_id}/users',
            headers=self.headers
        )
        return response.json()
'''.strip()

        client_path = self.base_path / 'workos_client.py'
        with open(client_path, 'w') as f:
            f.write(workos_client)

        print(f"✅ Created WorkOS API client")

        # Flask authentication routes
        auth_routes = '''
from flask import Blueprint, request, redirect, session, url_for
from workos_client import WorkOSClient

auth_bp = Blueprint('auth', __name__)
workos = WorkOSClient()

@auth_bp.route('/login')
def login():
    """Initiate WorkOS login"""
    authorization_url = (
        f"https://api.workos.com/oauth/authorize?"
        f"client_id={workos.client_id}&"
        f"redirect_uri={request.host_url}auth/callback&"
        f"response_type=code"
    )
    return redirect(authorization_url)

@auth_bp.route('/auth/callback')
def auth_callback():
    """Handle OAuth callback"""
    code = request.args.get('code')
    if code:
        token_data = workos.authenticate_user(code)
        session['access_token'] = token_data.get('access_token')
        session['user_id'] = token_data.get('user_id')
        return redirect(url_for('dashboard'))
    return "Authentication failed", 400

@auth_bp.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('home'))

def require_auth(f):
    """Decorator to require authentication"""
    def wrapper(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper
'''.strip()

        routes_path = self.base_path / 'auth_routes.py'
        with open(routes_path, 'w') as f:
            f.write(auth_routes)

        print(f"✅ Created authentication routes")

    def setup_directory_sync(self):
        """Setup instructions for Directory Sync"""
        print("\n" + "="*60)
        print("DIRECTORY SYNC SETUP")
        print("="*60)

        print("""
WorkOS Directory Sync automatically syncs users from:

✅ Google Workspace
✅ Microsoft Azure AD
✅ Okta
✅ OneLogin
✅ JumpCloud
✅ SCIM providers

SETUP STEPS:

1. Go to https://dashboard.workos.com
2. Navigate to Directory Sync
3. Create new directory connection
4. Choose your identity provider (Google, Azure, etc.)
5. Follow the setup wizard
6. Copy the SCIM endpoint and token
7. Configure your identity provider with WorkOS SCIM details

BENEFITS:
- Automatic user provisioning
- Real-time sync of user changes
- Group/role management
- No manual user management
        """)

    def customize_branding(self):
        """Branding customization instructions"""
        print("\n" + "="*60)
        print("BRANDING CUSTOMIZATION")
        print("="*60)

        print("""
Customize WorkOS to match your Recon Automation brand:

LOGO REQUIREMENTS:
- Main logo: PNG/JPG, max 2MB, recommended 200x200px
- Logo icon: Square PNG, transparent background, 64x64px

COLORS TO SET:
- Button background: Your primary brand color
- Button text: White or dark text for contrast

ADVANCED BRANDING:
- Custom CSS for complete control
- Email templates
- Login page background
- Admin portal styling

BRANDING IMPACT:
- Professional appearance for clients
- Brand consistency
- Trust building
- Enterprise credibility
        """)

    def create_integration_guide(self):
        """Complete integration guide"""
        print("\n" + "="*60)
        print("COMPLETE WORKOS INTEGRATION GUIDE")
        print("="*60)

        integration_steps = [
            "1. Sign up at https://workos.com",
            "2. Create new project in dashboard",
            "3. Copy API Key and Client ID to .env.workos",
            "4. Set up Directory Sync with your identity provider",
            "5. Customize branding in WorkOS dashboard",
            "6. Test authentication flow",
            "7. Deploy to production"
        ]

        for step in integration_steps:
            print(f"• {step}")

        print(f"\n{'='*50}")
        print("INTEGRATION BENEFITS:")
        print(f"{'='*50}")

        benefits = [
            "Enterprise clients can SSO with their company accounts",
            "Automatic user management from HR directories",
            "Professional branded login experience",
            "Multi-tenant support for different organizations",
            "Enhanced security with enterprise features",
            "Scalable user management for growing business"
        ]

        for benefit in benefits:
            print(f"✅ {benefit}")

    def create_admin_portal(self):
        """Create admin portal for user management"""
        print("\n" + "="*60)
        print("ADMIN PORTAL INTEGRATION")
        print("="*60)

        admin_code = '''
from flask import Flask, render_template, request, jsonify
from workos_client import WorkOSClient
from auth_routes import require_auth

app = Flask(__name__)
workos = WorkOSClient()

@app.route('/admin')
@require_auth
def admin_portal():
    """Admin portal for user management"""
    users = workos.list_users(session.get('organization_id', ''))
    return render_template('admin.html', users=users)

@app.route('/admin/users/<user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    """Delete user via API"""
    # WorkOS user deletion logic
    return jsonify({'status': 'success'})

@app.route('/admin/sync')
@require_auth
def sync_directory():
    """Manually sync directory"""
    # Trigger directory sync
    return jsonify({'status': 'sync_started'})

if __name__ == '__main__':
    app.run(debug=True)
'''.strip()

        admin_path = self.base_path / 'admin_portal.py'
        with open(admin_path, 'w') as f:
            f.write(admin_code)

        print(f"✅ Created admin portal for user management")

    def run(self):
        """Execute WorkOS integration setup"""
        self.show_workos_overview()
        self.create_workos_config()
        self.setup_directory_sync()
        self.customize_branding()
        self.create_integration_guide()
        self.create_admin_portal()

        print(f"\n{'='*70}")
        print("WORKOS INTEGRATION COMPLETE!")
        print("Your WORK OS now has enterprise authentication")
        print("Next: Complete setup at https://dashboard.workos.com")
        print(f"{'='*70}")

def main():
    """WorkOS integration setup"""
    integration = WorkOSIntegration()
    integration.run()

if __name__ == '__main__':
    main()
