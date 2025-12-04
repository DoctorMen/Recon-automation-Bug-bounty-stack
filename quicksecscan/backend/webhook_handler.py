#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
QuickSecScan Backend - Stripe Webhook Handler
Receives payment events, validates domain, queues scan job
"""
import os
import re
import stripe
import dns.resolver
from fastapi import FastAPI, Request, HTTPException
from celery_app import scan_task
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Blocklist: common CDNs, infrastructure domains
BLOCKLIST_PATTERNS = [
    r'.*\.cloudflare\.com$',
    r'.*\.amazonaws\.com$',
    r'.*\.googleusercontent\.com$',
    r'localhost',
    r'127\.0\.0\.1',
]

def is_blocklisted(domain):
    """Check if domain is in blocklist"""
    for pattern in BLOCKLIST_PATTERNS:
        if re.match(pattern, domain, re.IGNORECASE):
            return True
    return False

def validate_domain(domain):
    """Validate domain is resolvable and not blocklisted"""
    domain = domain.strip().lower()
    
    # Basic format check
    if not re.match(r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$', domain):
        return False, "Invalid domain format"
    
    # Blocklist check
    if is_blocklisted(domain):
        return False, "Domain is blocklisted (CDN/infrastructure)"
    
    # DNS resolution check
    try:
        dns.resolver.resolve(domain, 'A')
        return True, "Valid"
    except Exception as e:
        return False, f"Domain not resolvable: {str(e)}"

@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe payment webhook"""
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, WEBHOOK_SECRET
        )
    except ValueError as e:
        logger.error(f"Invalid payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid signature: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    # Handle successful payment
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # Extract metadata
        customer_email = session.get('customer_email') or session['customer_details']['email']
        metadata = session.get('metadata', {})
        domain = metadata.get('domain', '').strip()
        api_endpoint = metadata.get('api_endpoint', '').strip()
        tier = metadata.get('tier', 'basic').lower()
        scan_type = metadata.get('scan_type', 'web').lower()
        
        # Determine scan type based on what's provided
        if api_endpoint and not domain:
            scan_type = 'api'
            target = api_endpoint
        elif domain:
            scan_type = 'web'
            target = domain
        else:
            logger.error(f"No domain or API endpoint in metadata for session {session['id']}")
            return {"status": "error", "message": "No domain or API endpoint provided"}
        
        # Validate target
        if scan_type == 'api':
            # Validate API endpoint format
            if not (api_endpoint.startswith('http://') or api_endpoint.startswith('https://')):
                logger.error(f"Invalid API endpoint format: {api_endpoint}")
                return {"status": "error", "message": "API endpoint must start with http:// or https://"}
        else:
            # Validate domain
            is_valid, message = validate_domain(domain)
            if not is_valid:
                logger.error(f"Invalid domain {domain}: {message}")
                return {"status": "error", "message": message}
        
        # Queue scan job
        logger.info(f"Queueing {scan_type} scan for {target}, customer {customer_email}, tier: {tier}")
        scan_task.delay(
            domain=domain if scan_type == 'web' else None,
            api_endpoint=api_endpoint if scan_type == 'api' else None,
            customer_email=customer_email,
            session_id=session['id'],
            tier=tier,
            scan_type=scan_type
        )
        
        return {"status": "success", "message": f"{scan_type.upper()} scan queued"}
    
    return {"status": "ignored", "type": event['type']}

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "service": "quicksecscan-backend"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

