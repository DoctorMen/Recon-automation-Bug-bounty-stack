#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
SecurityScore Backend API
Low-cost ($9) instant security score checker
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import stripe
import os
import uuid
import asyncio
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SecurityScore API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Stripe configuration
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_your_key_here")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "pk_test_your_key_here")

# In-memory storage (use Redis/DB in production)
scan_results = {}
scan_queue = {}

class ScanRequest(BaseModel):
    website: str

class CheckoutRequest(BaseModel):
    website: str
    price: int

@app.post("/api/create-checkout")
async def create_checkout(request: CheckoutRequest):
    """Create Stripe checkout session"""
    try:
        scan_id = str(uuid.uuid4())
        
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'SecurityScore Check',
                        'description': f'Security scan for {request.website}',
                    },
                    'unit_amount': request.price,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=f'https://yourdomain.com/?scan_id={scan_id}&status=success',
            cancel_url='https://yourdomain.com/?status=cancelled',
            metadata={
                'website': request.website,
                'scan_id': scan_id,
            },
            expires_at=int((datetime.now().timestamp() + 3600)),  # 1 hour expiry
        )
        
        scan_queue[scan_id] = {
            'website': request.website,
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        return JSONResponse({
            'sessionId': session.id,
            'scanId': scan_id
        })
    except Exception as e:
        logger.error(f"Checkout creation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan")
async def perform_scan(request: ScanRequest):
    """Perform instant security scan"""
    scan_id = str(uuid.uuid4())
    
    try:
        # Queue scan
        scan_queue[scan_id] = {
            'website': request.website,
            'status': 'processing',
            'created_at': datetime.now().isoformat()
        }
        
        # Perform quick scan (simplified for demo)
        results = await quick_security_scan(request.website)
        
        scan_results[scan_id] = {
            'status': 'completed',
            'website': request.website,
            'results': results,
            'completed_at': datetime.now().isoformat()
        }
        
        return JSONResponse({
            'scanId': scan_id,
            'status': 'completed',
            **results
        })
    except Exception as e:
        logger.error(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan-status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status and results"""
    if scan_id in scan_results:
        return JSONResponse({
            'status': 'completed',
            'results': scan_results[scan_id]['results']
        })
    elif scan_id in scan_queue:
        return JSONResponse({
            'status': scan_queue[scan_id]['status']
        })
    else:
        raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/api/health")
async def health():
    """Health check"""
    return JSONResponse({"status": "healthy", "service": "securityscore-api"})

async def quick_security_scan(website: str):
    """Perform quick security scan"""
    import requests
    from urllib.parse import urlparse
    
    findings = []
    score = 100
    
    try:
        # Normalize URL
        if not website.startswith(('http://', 'https://')):
            website = 'https://' + website
        
        # Quick checks
        response = requests.get(website, timeout=10, allow_redirects=True)
        
        # Check security headers
        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header'
        }
        
        for header, message in security_headers.items():
            if header not in response.headers:
                findings.append({
                    'severity': 'MEDIUM',
                    'name': message,
                    'description': f'Your website is missing the {header} security header.',
                    'recommendation': f'Add {header} header to your server configuration.'
                })
                score -= 5
        
        # Check HTTPS
        parsed = urlparse(website)
        if parsed.scheme != 'https':
            findings.append({
                'severity': 'HIGH',
                'name': 'No HTTPS',
                'description': 'Your website is not using HTTPS encryption.',
                'recommendation': 'Enable SSL/TLS certificate for your website.'
            })
            score -= 15
        
        # Check for exposed server info
        server_header = response.headers.get('Server', '')
        if server_header:
            findings.append({
                'severity': 'MEDIUM',
                'name': 'Server Information Disclosure',
                'description': f'Server version information is exposed: {server_header}',
                'recommendation': 'Configure your server to hide version information.'
            })
            score -= 3
        
        # Check for common vulnerabilities
        if 'admin' in response.text.lower():
            findings.append({
                'severity': 'MEDIUM',
                'name': 'Possible Admin Panel Exposure',
                'description': 'Admin-related content detected. Ensure admin panels are properly secured.',
                'recommendation': 'Implement proper authentication and access controls for admin areas.'
            })
            score -= 5
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        return {
            'score': score,
            'findings': findings[:10],  # Limit to 10 findings
            'scanned_at': datetime.now().isoformat()
        }
        
    except requests.exceptions.SSLError:
        findings.append({
            'severity': 'HIGH',
            'name': 'SSL/TLS Error',
            'description': 'SSL certificate validation failed or certificate is invalid.',
            'recommendation': 'Check your SSL certificate configuration.'
        })
        score -= 20
        return {
            'score': max(0, score),
            'findings': findings,
            'scanned_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Scan error for {website}: {e}")
        return {
            'score': 0,
            'findings': [{
                'severity': 'HIGH',
                'name': 'Scan Failed',
                'description': f'Unable to scan website: {str(e)}',
                'recommendation': 'Please check that the website is accessible and try again.'
            }],
            'scanned_at': datetime.now().isoformat()
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

