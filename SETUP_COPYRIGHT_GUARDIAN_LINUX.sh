#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Setup Auto Copyright Guardian to run automatically on Linux

echo "========================================"
echo "SETUP AUTO COPYRIGHT GUARDIAN"
echo "========================================"
echo ""
echo "This will set up automated copyright protection"
echo "to run every 10 minutes in the background."
echo ""
echo "Options:"
echo "1. Run manually (recommended for testing)"
echo "2. Setup systemd service (auto-start)"
echo "3. Setup cron job (simpler alternative)"
echo "4. Run once and exit"
echo ""
read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        echo ""
        echo "Starting manually..."
        ./START_COPYRIGHT_GUARDIAN.sh
        ;;
    
    2)
        echo ""
        echo "Setting up systemd service..."
        echo ""
        
        # Copy service file
        sudo cp copyright-guardian.service /etc/systemd/system/
        
        # Reload systemd
        sudo systemctl daemon-reload
        
        # Enable service
        sudo systemctl enable copyright-guardian
        
        # Start service
        sudo systemctl start copyright-guardian
        
        echo ""
        echo "✅ Service installed and started!"
        echo ""
        echo "Commands:"
        echo "- Status:  sudo systemctl status copyright-guardian"
        echo "- Stop:    sudo systemctl stop copyright-guardian"
        echo "- Restart: sudo systemctl restart copyright-guardian"
        echo "- Logs:    sudo journalctl -u copyright-guardian -f"
        echo ""
        ;;
    
    3)
        echo ""
        echo "Setting up cron job..."
        echo ""
        
        # Add cron job
        CRON_JOB="*/10 * * * * cd $(pwd) && /usr/bin/python3 AUTO_COPYRIGHT_GUARDIAN.py >> .auto_copyright_log.txt 2>&1"
        
        # Check if already exists
        if crontab -l 2>/dev/null | grep -q "AUTO_COPYRIGHT_GUARDIAN.py"; then
            echo "⚠️  Cron job already exists"
        else
            (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
            echo "✅ Cron job added!"
        fi
        
        echo ""
        echo "The guardian will run every 10 minutes."
        echo ""
        echo "Commands:"
        echo "- View cron: crontab -l"
        echo "- Edit cron: crontab -e"
        echo "- View log:  tail -f .auto_copyright_log.txt"
        echo ""
        ;;
    
    4)
        echo ""
        echo "Running single scan..."
        python3 AUTO_COPYRIGHT_GUARDIAN.py
        echo ""
        echo "Scan complete. Run this again anytime to update copyrights."
        ;;
    
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac
