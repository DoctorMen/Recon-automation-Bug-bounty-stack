#!/usr/bin/env python3
"""
Instacart Auto Token Extractor
Automatically extracts auth tokens without Burp Suite
Hunter: shadowstep_131
"""

from playwright.sync_api import sync_playwright
import json
import time
import os
from pathlib import Path

class InstacartTokenExtractor:
    """Automated token extraction for Instacart."""
    
    def __init__(self):
        self.tokens = {
            "customer": None,
            "shopper": None,
            "merchant": None
        }
        self.output_file = Path(__file__).parent / "extracted_tokens.json"
    
    def extract_customer_token(self, email: str, password: str):
        """Extract customer token using Playwright."""
        print(f"🎯 Extracting customer token for: {email}")
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, slow_mo=1000)
            context = browser.new_context()
            page = context.new_page()
            
            # Network interceptor
            def capture_auth_response(response):
                if "login" in response.url or "auth" in response.url:
                    try:
                        data = response.json()
                        print(f"🔍 Auth response: {response.url}")
                        
                        # Look for various token formats
                        token_keys = ["access_token", "jwt", "token", "auth_token"]
                        for key in token_keys:
                            if key in data:
                                self.tokens["customer"] = data[key]
                                print(f"✅ Customer token extracted: {key[:20]}...")
                                return
                                
                        # Check nested structures
                        if "data" in data and isinstance(data["data"], dict):
                            for key in token_keys:
                                if key in data["data"]:
                                    self.tokens["customer"] = data["data"][key]
                                    print(f"✅ Customer token extracted (nested): {key[:20]}...")
                                    return
                                    
                    except Exception as e:
                        print(f"⚠️  Failed to parse auth response: {e}")
            
            page.on("response", capture_auth_response)
            
            try:
                # Navigate to Instacart
                page.goto("https://www.instacart.com")
                page.wait_for_timeout(3000)
                
                # Click login/signup
                page.click("text=Log in", timeout=10000)
                page.wait_for_timeout(2000)
                
                # Fill credentials
                page.fill('input[type="email"]', email)
                page.fill('input[type="password"]', password)
                
                # Submit login
                page.click('button[type="submit"]')
                
                # Wait for token capture
                page.wait_for_timeout(10000)
                
                # Check localStorage as backup
                local_storage = page.evaluate("() => Object.assign({}, localStorage)")
                for key, value in local_storage.items():
                    if "token" in key.lower() and "Bearer" in value:
                        self.tokens["customer"] = value.replace("Bearer ", "")
                        print(f"✅ Customer token from localStorage: {key}")
                
                # Check cookies as backup
                cookies = context.cookies()
                for cookie in cookies:
                    if "token" in cookie["name"].lower():
                        self.tokens["customer"] = cookie["value"]
                        print(f"✅ Customer token from cookies: {cookie['name']}")
                
            except Exception as e:
                print(f"❌ Customer token extraction failed: {e}")
            
            browser.close()
    
    def extract_shopper_token(self, email: str, password: str):
        """Extract shopper token."""
        print(f"🛒 Extracting shopper token for: {email}")
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, slow_mo=1000)
            context = browser.new_context()
            page = context.new_page()
            
            def capture_shopper_auth(response):
                if "shopper" in response.url and ("login" in response.url or "auth" in response.url):
                    try:
                        data = response.json()
                        token_keys = ["access_token", "jwt", "token", "auth_token"]
                        
                        for key in token_keys:
                            if key in data:
                                self.tokens["shopper"] = data[key]
                                print(f"✅ Shopper token extracted: {key[:20]}...")
                                return
                                
                    except:
                        pass
            
            page.on("response", capture_shopper_auth)
            
            try:
                # Go to shopper portal
                page.goto("https://shoppers.instacart.com")
                page.wait_for_timeout(3000)
                
                # Look for login elements
                page.click("text=Log in", timeout=10000)
                page.wait_for_timeout(2000)
                
                # Fill shopper credentials
                page.fill('input[type="email"]', email)
                page.fill('input[type="password"]', password)
                
                # Submit
                page.click('button[type="submit"]')
                page.wait_for_timeout(10000)
                
            except Exception as e:
                print(f"❌ Shopper token extraction failed: {e}")
            
            browser.close()
    
    def extract_merchant_token(self, email: str, password: str):
        """Extract merchant token."""
        print(f"🏪 Extracting merchant token for: {email}")
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, slow_mo=1000)
            context = browser.new_context()
            page = context.new_page()
            
            def capture_merchant_auth(response):
                if "merchant" in response.url or "retail" in response.url:
                    if "login" in response.url or "auth" in response.url:
                        try:
                            data = response.json()
                            token_keys = ["access_token", "jwt", "token", "auth_token"]
                            
                            for key in token_keys:
                                if key in data:
                                    self.tokens["merchant"] = data[key]
                                    print(f"✅ Merchant token extracted: {key[:20]}...")
                                    return
                                    
                        except:
                            pass
            
            page.on("response", capture_merchant_auth)
            
            try:
                # Go to merchant portal
                page.goto("https://retailers.instacart.com")
                page.wait_for_timeout(3000)
                
                # Find and click login
                page.click("text=Log in", timeout=10000)
                page.wait_for_timeout(2000)
                
                # Fill credentials
                page.fill('input[type="email"]', email)
                page.fill('input[type="password"]', password)
                
                # Submit
                page.click('button[type="submit"]')
                page.wait_for_timeout(10000)
                
            except Exception as e:
                print(f"❌ Merchant token extraction failed: {e}")
            
            browser.close()
    
    def test_tokens(self):
        """Test extracted tokens."""
        print("\n🧪 Testing extracted tokens...")
        
        import requests
        
        base_url = "https://api.instacart.com"
        
        for role, token in self.tokens.items():
            if not token:
                print(f"❌ {role}: No token")
                continue
                
            headers = {
                "Authorization": f"Bearer {token}",
                "X-Bug-Bounty": "shadowstep_131",
                "Content-Type": "application/json"
            }
            
            try:
                # Test basic endpoint
                resp = requests.get(f"{base_url}/v1/user", headers=headers, timeout=10)
                
                if resp.status_code == 200:
                    print(f"✅ {role}: Token valid")
                else:
                    print(f"❌ {role}: Token invalid ({resp.status_code})")
                    
            except Exception as e:
                print(f"❌ {role}: Test failed - {e}")
    
    def save_tokens(self):
        """Save tokens to file."""
        with open(self.output_file, "w") as f:
            json.dump(self.tokens, f, indent=2)
        print(f"\n💾 Tokens saved to: {self.output_file}")
    
    def run_full_extraction(self):
        """Run complete token extraction."""
        print("=" * 60)
        print("🚀 INSTACART AUTO TOKEN EXTRACTOR")
        print("Hunter: shadowstep_131")
        print("=" * 60)
        
        # Get credentials
        print("\n📋 Enter credentials (press Enter to skip):")
        
        customer_email = input("Customer email [shadowstep_131@wearehackerone.com]: ") or "shadowstep_131@wearehackerone.com"
        customer_password = input("Customer password: ")
        
        shopper_email = input("Shopper email [shadowstep_131+1@wearehackerone.com]: ") or "shadowstep_131+1@wearehackerone.com"
        shopper_password = input("Shopper password: ")
        
        merchant_email = input("Merchant email [shadowstep_131+2@wearehackerone.com]: ") or "shadowstep_131+2@wearehackerone.com"
        merchant_password = input("Merchant password: ")
        
        # Extract tokens
        if customer_password:
            self.extract_customer_token(customer_email, customer_password)
        
        if shopper_password:
            self.extract_shopper_token(shopper_email, shopper_password)
        
        if merchant_password:
            self.extract_merchant_token(merchant_email, merchant_password)
        
        # Test and save
        self.test_tokens()
        self.save_tokens()
        
        print("\n" + "=" * 60)
        print("🎯 EXTRACTION COMPLETE")
        print("=" * 60)
        
        # Show results
        for role, token in self.tokens.items():
            status = "✅" if token else "❌"
            print(f"{status} {role}: {'EXTRACTED' if token else 'MISSING'}")
        
        if all(self.tokens.values()):
            print("\n🚀 ALL TOKENS READY - Start hunting!")
            print("Run: python3 instacart_hunter.py")
        else:
            print("\n⚠️  Some tokens missing - manual extraction needed")


def main():
    extractor = InstacartTokenExtractor()
    extractor.run_full_extraction()


if __name__ == "__main__":
    main()
