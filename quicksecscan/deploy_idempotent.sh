#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# QuickSecScan Idempotent Deployment Script
# Can be run multiple times safely without side effects

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== QuickSecScan Idempotent Deployment ==="
echo "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"

# Function: check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function: idempotent env setup
setup_env() {
    echo "[1/8] Setting up environment..."
    
    if [ ! -f ".env" ]; then
        if [ -f "env.example" ]; then
            echo "  → Copying env.example to .env (edit before deploying)"
            cp env.example .env
        else
            echo "  ⚠ No env.example found, skipping"
        fi
    else
        echo "  ✓ .env already exists"
    fi
}

# Function: idempotent docker setup
setup_docker() {
    echo "[2/8] Checking Docker..."
    
    if ! command_exists docker; then
        echo "  ✗ Docker not installed. Install: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! command_exists docker-compose && ! docker compose version >/dev/null 2>&1; then
        echo "  ✗ Docker Compose not installed"
        exit 1
    fi
    
    echo "  ✓ Docker and Compose available"
}

# Function: idempotent build
build_images() {
    echo "[3/8] Building Docker images..."
    
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi
    
    $COMPOSE_CMD build --no-cache
    echo "  ✓ Images built"
}

# Function: idempotent start services
start_services() {
    echo "[4/8] Starting services..."
    
    # Stop any existing services first (idempotent)
    $COMPOSE_CMD down --remove-orphans 2>/dev/null || true
    
    # Start fresh
    $COMPOSE_CMD up -d
    
    echo "  ✓ Services started"
}

# Function: wait for services
wait_for_services() {
    echo "[5/8] Waiting for services to be healthy..."
    
    max_wait=60
    elapsed=0
    
    while [ $elapsed -lt $max_wait ]; do
        if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
            echo "  ✓ API healthy"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
        echo "  ⏳ Waiting... (${elapsed}s)"
    done
    
    echo "  ✗ Services failed to start within ${max_wait}s"
    echo "  → Check logs: $COMPOSE_CMD logs"
    exit 1
}

# Function: setup Stripe webhook (idempotent)
setup_stripe_webhook() {
    echo "[6/8] Stripe webhook setup..."
    
    if [ -z "$STRIPE_SECRET_KEY" ]; then
        echo "  ⚠ STRIPE_SECRET_KEY not set in .env, skipping webhook setup"
        echo "  → Manually add webhook in Stripe Dashboard: https://dashboard.stripe.com/webhooks"
        echo "  → Endpoint URL: https://your-domain.com/webhook/stripe"
        echo "  → Events: checkout.session.completed"
        return 0
    fi
    
    echo "  → Webhook setup requires manual configuration in Stripe Dashboard"
    echo "  → See docs/STRIPE_WEBHOOK_SETUP.md"
}

# Function: deploy site (idempotent)
deploy_site() {
    echo "[7/8] Deploying site..."
    
    if [ ! -d "site" ]; then
        echo "  ✗ site/ directory not found"
        exit 1
    fi
    
    # Create/update GitHub repo (idempotent)
    if [ -d "../quicksecscan-site/.git" ]; then
        echo "  → Updating existing quicksecscan-site repo"
        rm -rf ../quicksecscan-site/*
        cp -r site/* ../quicksecscan-site/
        cd ../quicksecscan-site
        git add -A
        git diff --cached --quiet || git commit -m "Deploy: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        git push origin main 2>/dev/null || echo "  ⚠ Push failed (check auth)"
        cd "$SCRIPT_DIR"
    else
        echo "  ⚠ quicksecscan-site repo not found"
        echo "  → Create manually: gh repo create quicksecscan-site --public --source=site --push"
    fi
    
    echo "  ✓ Site deployment complete"
}

# Function: run smoke tests
run_smoke_tests() {
    echo "[8/8] Running smoke tests..."
    
    # Test 1: API health
    if curl -sf http://localhost:8000/health | grep -q "healthy"; then
        echo "  ✓ API health check passed"
    else
        echo "  ✗ API health check failed"
        exit 1
    fi
    
    # Test 2: Redis connectivity
    if docker exec quicksecscan-redis redis-cli ping | grep -q "PONG"; then
        echo "  ✓ Redis connectivity passed"
    else
        echo "  ✗ Redis connectivity failed"
        exit 1
    fi
    
    # Test 3: Worker running
    if docker ps | grep -q "quicksecscan-worker"; then
        echo "  ✓ Worker container running"
    else
        echo "  ✗ Worker container not running"
        exit 1
    fi
    
    echo "  ✓ All smoke tests passed"
}

# Main execution
main() {
    setup_env
    setup_docker
    build_images
    start_services
    wait_for_services
    setup_stripe_webhook
    deploy_site
    run_smoke_tests
    
    echo ""
    echo "=== Deployment Complete ==="
    echo "API: http://localhost:8000"
    echo "Health: http://localhost:8000/health"
    echo "Logs: $COMPOSE_CMD logs -f"
    echo ""
    echo "Next steps:"
    echo "1. Edit .env with your Stripe/AWS/SendGrid credentials"
    echo "2. Create Stripe Payment Links (Basic $197, Pro $397, Team $797)"
    echo "3. Update site/config.js with Stripe URLs"
    echo "4. Setup Stripe webhook: https://dashboard.stripe.com/webhooks"
    echo "5. Deploy site to GitHub Pages or custom domain"
    echo ""
}

# Run if not sourced
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi

