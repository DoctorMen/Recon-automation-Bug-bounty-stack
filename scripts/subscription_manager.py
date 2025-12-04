"""
Subscription Manager for YouTube Analyzer Pro

PROPRIETARY AND CONFIDENTIAL
Copyright © 2025 Khallid H Nurse. All Rights Reserved.

This module handles subscription management, license validation, and feature gating.
"""
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List
import hashlib
import uuid

class SubscriptionTier:
    """Different subscription tiers with feature sets."""
    FREE = {
        'name': 'Free',
        'price': 0,
        'features': [
            'Basic video analysis',
            'Standard transcription',
            'Limited to 3 videos/month',
            'Community support'
        ],
        'limits': {
            'max_videos_per_month': 3,
            'max_video_length': 30 * 60,  # 30 minutes
            'export_formats': ['txt']
        }
    }
    
    PRO = {
        'name': 'Pro',
        'price': 29.99,
        'features': [
            'Advanced video analysis',
            'High-accuracy transcription',
            'Up to 50 videos/month',
            'Priority support',
            'PDF/JSON exports',
            'API access'
        ],
        'limits': {
            'max_videos_per_month': 50,
            'max_video_length': 120 * 60,  # 2 hours
            'export_formats': ['txt', 'pdf', 'json', 'md']
        }
    }
    
    ENTERPRISE = {
        'name': 'Enterprise',
        'price': 299.99,
        'features': [
            'Unlimited video analysis',
            'Highest accuracy transcription',
            'Custom model training',
            '24/7 dedicated support',
            'All export formats',
            'White-label reports',
            'API access with webhooks'
        ],
        'limits': {
            'max_videos_per_month': float('inf'),
            'max_video_length': float('inf'),
            'export_formats': ['txt', 'pdf', 'json', 'md', 'html', 'docx']
        }
    }

class SubscriptionManager:
    """Manages user subscriptions and feature access."""
    
    def __init__(self, user_id: str = None):
        self.user_id = user_id or self._generate_user_id()
        self.license_file = Path.home() / '.youtube_analyzer_license'
        self.usage_file = Path.home() / '.youtube_analyzer_usage'
        self.license_data = self._load_license()
        self.usage_data = self._load_usage()
    
    def _generate_user_id(self) -> str:
        """Generate a unique user ID based on system information."""
        system_info = {
            'node': os.uname().nodename,
            'machine': os.uname().machine,
            'username': os.getenv('USER', 'unknown'),
            'timestamp': str(datetime.utcnow())
        }
        return hashlib.sha256(str(system_info).encode()).hexdigest()[:16]
    
    def _load_license(self) -> Dict:
        """Load license data from file."""
        if self.license_file.exists():
            try:
                with open(self.license_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'tier': 'FREE', 'expiry': None, 'license_key': None}
    
    def _load_usage(self) -> Dict:
        """Load usage data from file."""
        if self.usage_file.exists():
            try:
                with open(self.usage_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'videos_this_month': 0, 'last_reset': datetime.utcnow().strftime('%Y-%m')}
    
    def _save_license(self):
        """Save license data to file."""
        with open(self.license_file, 'w') as f:
            json.dump(self.license_data, f)
    
    def _save_usage(self):
        """Save usage data to file."""
        with open(self.usage_file, 'w') as f:
            json.dump(self.usage_data, f)
    
    def get_subscription_tier(self) -> Dict:
        """Get current subscription tier details."""
        tier_name = self.license_data.get('tier', 'FREE').upper()
        return getattr(SubscriptionTier, tier_name, SubscriptionTier.FREE)
    
    def check_quota(self, video_duration: int = 0) -> bool:
        """Check if user has sufficient quota."""
        # Reset counter if it's a new month
        current_month = datetime.utcnow().strftime('%Y-%m')
        if self.usage_data.get('last_reset') != current_month:
            self.usage_data = {'videos_this_month': 0, 'last_reset': current_month}
        
        tier = self.get_subscription_tier()
        
        # Check video duration limit
        if video_duration > tier['limits']['max_video_length']:
            return False, f"Video exceeds maximum length of {tier['limits']['max_video_length'] // 60} minutes"
        
        # Check monthly quota
        if self.usage_data['videos_this_month'] >= tier['limits']['max_videos_per_month']:
            return False, "Monthly video quota exceeded"
            
        return True, ""
    
    def record_usage(self):
        """Record a video analysis in the usage data."""
        current_month = datetime.utcnow().strftime('%Y-%m')
        if self.usage_data.get('last_reset') != current_month:
            self.usage_data = {'videos_this_month': 0, 'last_reset': current_month}
        
        self.usage_data['videos_this_month'] += 1
        self._save_usage()
    
    def upgrade_subscription(self, tier_name: str, license_key: str = None):
        """Upgrade user's subscription tier."""
        tier_name = tier_name.upper()
        if tier_name not in ['PRO', 'ENTERPRISE']:
            raise ValueError("Invalid subscription tier")
        
        # In a real implementation, validate the license key with your payment processor
        if license_key and self._validate_license_key(license_key, tier_name):
            expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()  # 1 month subscription
            self.license_data = {
                'tier': tier_name,
                'expiry': expiry,
                'license_key': license_key,
                'activated_at': datetime.utcnow().isoformat()
            }
            self._save_license()
            return True
        return False
    
    def _validate_license_key(self, key: str, tier: str) -> bool:
        """Validate a license key (stub for implementation)."""
        # In a real implementation, this would validate against your payment processor
        # For now, we'll just check the format
        return len(key) == 32 and key.startswith(tier[0])
    
    def generate_license_key(self, tier: str = 'PRO') -> str:
        """Generate a demo license key (for testing only)."""
        return f"{tier[0]}-{uuid.uuid4().hex[:14]}-{int(datetime.utcnow().timestamp())}"

# Singleton instance
subscription_manager = SubscriptionManager()

# Example usage:
if __name__ == "__main__":
    # Check subscription status
    tier = subscription_manager.get_subscription_tier()
    print(f"Current tier: {tier['name']}")
    print("Features:")
    for feature in tier['features']:
        print(f"- {feature}")
    
    # Check quota
    can_process, reason = subscription_manager.check_quota(60 * 25)  # 25 min video
    if can_process:
        print("You can process this video")
        subscription_manager.record_usage()
    else:
        print(f"Cannot process: {reason}")
