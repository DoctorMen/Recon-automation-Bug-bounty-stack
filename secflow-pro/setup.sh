#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# SecFlow Pro - One-Command Deployment

echo "🚀 SecFlow Pro - Quick Launch"
echo "================================"

# Check if we're in the right directory
if [ ! -f "run_pipeline.py" ]; then
    echo "❌ Error: Must run from Recon-automation-Bug-bounty-stack root"
    exit 1
fi

# Create structure
echo "📁 Creating structure..."
mkdir -p secflow-pro/{backend,frontend,scripts}
mkdir -p secflow-pro/backend/templates

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install flask python-dotenv 2>/dev/null || echo "Install manually: pip3 install flask python-dotenv"

# Setup webhook
echo "🔧 Setting up webhook..."
chmod +x secflow-pro/backend/webhook.py

# Deploy frontend
echo "🌐 Frontend ready at: secflow-pro/frontend/index.html"
echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Create Stripe products (see LAUNCH.md)"
echo "2. Update Payment Links in frontend/index.html"
echo "3. Deploy frontend (GitHub Pages/Netlify/Vercel)"
echo "4. Run webhook: cd secflow-pro/backend && python3 webhook.py"
echo "5. Configure Stripe webhook endpoint"
echo ""
echo "🚀 Launch instructions: See secflow-pro/LAUNCH.md"

