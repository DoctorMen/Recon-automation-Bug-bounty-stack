#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# First Dollar Plan CLI - Quick Commands

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

case "$1" in
    dashboard)
        python3 scripts/automate_first_dollar.py --action dashboard
        ;;
    
    proposal)
        if [ -z "$2" ]; then
            echo "Usage: $0 proposal CLIENT_NAME [PRICE] [DESCRIPTION]"
            exit 1
        fi
        python3 scripts/automate_first_dollar.py --action proposal --client "$2" --price "${3:-300}" --description "${4:-}"
        ;;
    
    batch)
        python3 scripts/automate_first_dollar.py --action batch --jobs-file "${2:-}"
        ;;
    
    won)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 won CLIENT_NAME AMOUNT [DOMAIN]"
            exit 1
        fi
        python3 scripts/automate_first_dollar.py --action won --client "$2" --amount "$3" --domain "${4:-}"
        ;;
    
    scan)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 scan CLIENT_NAME DOMAIN"
            exit 1
        fi
        python3 scripts/automate_first_dollar.py --action scan --client "$2" --domain "$3"
        ;;
    
    deliver)
        if [ -z "$2" ]; then
            echo "Usage: $0 deliver CLIENT_NAME"
            exit 1
        fi
        python3 scripts/automate_first_dollar.py --action deliver --client "$2"
        ;;
    
    workflow)
        if [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
            echo "Usage: $0 workflow CLIENT_NAME DOMAIN AMOUNT"
            exit 1
        fi
        python3 scripts/quick_client_workflow.py --client "$2" --domain "$3" --amount "$4"
        ;;
    
    portfolio)
        python3 scripts/generate_portfolio_samples.py
        ;;
    
    check-profile)
        python3 scripts/automate_first_dollar.py --action check-profile
        ;;
    
    *)
        echo "🚀 First Dollar Plan CLI"
        echo ""
        echo "Usage: $0 COMMAND [ARGS]"
        echo ""
        echo "Commands:"
        echo "  dashboard              Show automation dashboard"
        echo "  proposal CLIENT [PRICE] [DESC]  Generate proposal"
        echo "  batch [JOBS_FILE]      Generate batch proposals"
        echo "  won CLIENT AMOUNT [DOMAIN]  Track project won"
        echo "  scan CLIENT DOMAIN     Run scan"
        echo "  deliver CLIENT         Mark as delivered"
        echo "  workflow CLIENT DOMAIN AMOUNT  Complete workflow"
        echo "  portfolio              Generate portfolio samples"
        echo "  check-profile          Check profile setup"
        echo ""
        echo "Examples:"
        echo "  $0 proposal 'Acme Corp' 300 'Urgent security scan needed'"
        echo "  $0 workflow 'Acme Corp' acme.com 300"
        echo "  $0 dashboard"
        ;;
esac

