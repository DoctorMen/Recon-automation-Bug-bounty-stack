#!/bin/bash
# Auto-Package All 5 Gumroad Products
# Copyright © 2025 DoctorMen. All Rights Reserved.

echo "🚀 Packaging 5 Gumroad Products..."
echo ""

BASE_DIR=~/Recon-automation-Bug-bounty-stack
PRODUCTS_DIR=~/Recon-automation-Bug-bounty-stack/gumroad_products

cd $PRODUCTS_DIR

# ============================================
# PRODUCT 1: Security Automation Toolkit
# ============================================
echo "📦 Product 1: Security Automation Toolkit..."

mkdir -p product_1_security_toolkit

# Core automation scripts
cp $BASE_DIR/*.py product_1_security_toolkit/ 2>/dev/null
cp $BASE_DIR/*.sh product_1_security_toolkit/ 2>/dev/null

# Key tools
cp $BASE_DIR/SENTINEL_AGENT.py product_1_security_toolkit/
cp $BASE_DIR/ONE_CLICK_ASSESSMENT.py product_1_security_toolkit/
cp $BASE_DIR/run_pipeline.py product_1_security_toolkit/
cp $BASE_DIR/run_recon.py product_1_security_toolkit/
cp $BASE_DIR/run_nuclei.py product_1_security_toolkit/
cp $BASE_DIR/BUG_HUNT_TONIGHT.py product_1_security_toolkit/

# Documentation
cp $BASE_DIR/README.md product_1_security_toolkit/
cp $BASE_DIR/AUTOMATION_GUIDE.md product_1_security_toolkit/ 2>/dev/null
cp $BASE_DIR/QUICK_START_CHEAT_SHEET.md product_1_security_toolkit/ 2>/dev/null
cp $BASE_DIR/TECHNICAL_DOCUMENTATION.md product_1_security_toolkit/ 2>/dev/null
cp $BASE_DIR/START_HERE.md product_1_security_toolkit/ 2>/dev/null

# Legal
cp $BASE_DIR/LEGAL_*.py product_1_security_toolkit/ 2>/dev/null
cp $BASE_DIR/LEGAL_*.md product_1_security_toolkit/ 2>/dev/null

# Config (if exists)
cp -r $BASE_DIR/config product_1_security_toolkit/ 2>/dev/null

# Add commercial license
echo "COMMERCIAL LICENSE

This toolkit is licensed for commercial use.

You may:
- Use for client projects
- Modify and customize
- Create derivative works
- Use in commercial services

© 2025 All Rights Reserved" > product_1_security_toolkit/LICENSE.txt

# Zip it
zip -r Security_Automation_Toolkit.zip product_1_security_toolkit/
echo "✅ Product 1 packaged: Security_Automation_Toolkit.zip"
echo ""

# ============================================
# PRODUCT 2: Upwork Freelancing System
# ============================================
echo "📦 Product 2: Upwork Freelancing System..."

mkdir -p product_2_upwork_system

# Upwork docs
cp $BASE_DIR/UPWORK_*.md product_2_upwork_system/ 2>/dev/null
cp $BASE_DIR/UPWORK_*.html product_2_upwork_system/ 2>/dev/null

# Templates
cp $BASE_DIR/POLYMORPHIC_UPWORK_TEMPLATES.md product_2_upwork_system/ 2>/dev/null
cp $BASE_DIR/YOUR_FIRST_WINNING_PROPOSAL.md product_2_upwork_system/ 2>/dev/null
cp $BASE_DIR/COPY_PASTE_TEMPLATES.md product_2_upwork_system/ 2>/dev/null

# Business guides
cp $BASE_DIR/BUSINESS_EXECUTION_PLAYBOOK.md product_2_upwork_system/ 2>/dev/null
cp $BASE_DIR/PSYCHOLOGICAL_LEVERAGE_PLAYBOOK.md product_2_upwork_system/ 2>/dev/null

# Tools
cp $BASE_DIR/CLIENT_OUTREACH_GENERATOR.py product_2_upwork_system/ 2>/dev/null
cp $BASE_DIR/RESPONSE_TEMPLATES_IF_CLIENT_MESSAGES.md product_2_upwork_system/ 2>/dev/null

# Start guide
echo "# Upwork Freelancing System - Quick Start

1. Read UPWORK_FAST_DEPLOY.md first
2. Use UPWORK_EMERGENCY_PROPOSALS.md for applications
3. Customize templates as needed
4. Follow BUSINESS_EXECUTION_PLAYBOOK.md

© 2025 All Rights Reserved" > product_2_upwork_system/START_HERE.md

zip -r Upwork_Freelancing_System.zip product_2_upwork_system/
echo "✅ Product 2 packaged: Upwork_Freelancing_System.zip"
echo ""

# ============================================
# PRODUCT 3: Bug Bounty Starter Pack
# ============================================
echo "📦 Product 3: Bug Bounty Starter Pack..."

mkdir -p product_3_bug_bounty_pack

# Core guides
cp $BASE_DIR/START_SAFE_BOUNTY_HUNTING_NOW.md product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/BUG_BOUNTY_LAUNCH_PLAN.md product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/ADVANCED_HUNTING_STRATEGY.md product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/SOPHISTICATED_METHODOLOGY.md product_3_bug_bounty_pack/ 2>/dev/null

# Legal & submission
cp $BASE_DIR/LEGAL_CHECKLIST_BEFORE_EVERY_SCAN.md product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/SUBMIT_NOW.md product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/INSTANT_SUBMISSION_GUIDE.md product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/submission_template.md product_3_bug_bounty_pack/ 2>/dev/null

# Programs
cp $BASE_DIR/bug_bounty_programs.json product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/bug_bounty_program_tracker.md product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/BEGINNER_*.md product_3_bug_bounty_pack/ 2>/dev/null

# Tools
cp $BASE_DIR/BUG_HUNT_TONIGHT.py product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/quick_bug_hunter.py product_3_bug_bounty_pack/ 2>/dev/null

# OPSEC
cp $BASE_DIR/ANONYMOUS_BUG_BOUNTY_GUIDE.md product_3_bug_bounty_pack/ 2>/dev/null
cp $BASE_DIR/OPSEC_*.md product_3_bug_bounty_pack/ 2>/dev/null

# Hunt guides
cp $BASE_DIR/HUNT_*.md product_3_bug_bounty_pack/ 2>/dev/null

zip -r Bug_Bounty_Starter_Pack.zip product_3_bug_bounty_pack/
echo "✅ Product 3 packaged: Bug_Bounty_Starter_Pack.zip"
echo ""

# ============================================
# PRODUCT 4: Divergent Thinking System
# ============================================
echo "📦 Product 4: Divergent Thinking System..."

mkdir -p product_4_divergent_thinking

# Core system
cp $BASE_DIR/DIVERGENT_THINKING_ENGINE.py product_4_divergent_thinking/ 2>/dev/null
cp $BASE_DIR/DIVERGENT_THINKING_INTEGRATION.py product_4_divergent_thinking/ 2>/dev/null
cp $BASE_DIR/DIVERGENT_THINKING_*.md product_4_divergent_thinking/ 2>/dev/null

# Copyright
cp $BASE_DIR/DIVERGENT_THINKING_COPYRIGHT.py product_4_divergent_thinking/ 2>/dev/null
cp $BASE_DIR/DIVERGENT_COPYRIGHT_CONFIRMATION.md product_4_divergent_thinking/ 2>/dev/null

zip -r Divergent_Thinking_System.zip product_4_divergent_thinking/
echo "✅ Product 4 packaged: Divergent_Thinking_System.zip"
echo ""

# ============================================
# PRODUCT 5: Complete Business Bundle
# ============================================
echo "📦 Product 5: Complete Business Bundle..."

mkdir -p product_5_business_bundle

# Business docs
cp $BASE_DIR/BUSINESS_*.md product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/BUSINESS_*.html product_5_business_bundle/ 2>/dev/null

# Money guides
cp $BASE_DIR/MAKE_MONEY_*.md product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/MAKE_MONEY_*.sh product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/EARN_MONEY_*.md product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/GET_PAID_*.py product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/MONEY_*.md product_5_business_bundle/ 2>/dev/null

# Strategy
cp $BASE_DIR/SYSTEMS_MINDSET_FRAMEWORK.md product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/SUPERIOR_BUSINESS_MODEL.md product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/EXECUTION_SUMMARY.md product_5_business_bundle/ 2>/dev/null

# Dashboards
cp $BASE_DIR/*DASHBOARD*.html product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/MONEY_*.html product_5_business_bundle/ 2>/dev/null

# ROI
cp $BASE_DIR/ROI_*.md product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/QUICKEST_PATH_*.md product_5_business_bundle/ 2>/dev/null
cp $BASE_DIR/QUICKEST_PATH_*.html product_5_business_bundle/ 2>/dev/null

zip -r Complete_Business_Bundle.zip product_5_business_bundle/
echo "✅ Product 5 packaged: Complete_Business_Bundle.zip"
echo ""

# ============================================
# SUMMARY
# ============================================
echo "════════════════════════════════════════════════════════"
echo "✅ ALL 5 PRODUCTS PACKAGED!"
echo "════════════════════════════════════════════════════════"
echo ""
echo "📦 Your products:"
ls -lh *.zip
echo ""
echo "💰 Revenue Potential:"
echo "  1. Security Toolkit ($299-999)     → $1,495-19,980/mo"
echo "  2. Upwork System ($49-149)         → $490-7,450/mo"
echo "  3. Bug Bounty Pack ($97-197)       → $970-5,910/mo"
echo "  4. Divergent Thinking ($197-497)   → $591-7,455/mo"
echo "  5. Business Bundle ($49-99)        → $980-4,950/mo"
echo ""
echo "  TOTAL POTENTIAL: $4,526-45,745/month"
echo ""
echo "🚀 Next Steps:"
echo "  1. Go to: https://gumroad.com"
echo "  2. Create new product for each ZIP"
echo "  3. Upload ZIPs"
echo "  4. Copy/paste descriptions (in previous message)"
echo "  5. Set prices"
echo "  6. Publish"
echo ""
echo "⏰ Time to upload all 5: ~20 minutes"
echo ""
echo "════════════════════════════════════════════════════════"
