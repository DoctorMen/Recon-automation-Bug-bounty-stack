#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
DASHBOARD CONNECTOR
Connects real Upwork data to 3D ParallelProfit™ Dashboard

This updates the dashboard with real metrics from the Upwork Integration Engine.

Author: DoctorMen
Status: Production Ready
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Fix encoding for Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

class DashboardConnector:
    """
    Connects backend data to frontend dashboard
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.data_file = self.base_dir / "output" / "upwork_data" / "metrics.json"
        self.dashboard_file = self.base_dir / "output" / "dashboard_data.json"
    
    def load_real_metrics(self):
        """Load real metrics from Upwork engine"""
        if self.data_file.exists():
            with open(self.data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            return {
                "jobs_discovered": 0,
                "proposals_generated": 0,
                "applications_sent": 0,
                "jobs_won": 0,
                "revenue_earned": 0,
                "win_rate": 0.0
            }
    
    def update_dashboard(self):
        """Update dashboard with real data"""
        metrics = self.load_real_metrics()
        
        dashboard_data = {
            "metrics": metrics,
            "last_updated": datetime.now().isoformat(),
            "status": "live",
            "data_source": "real"
        }
        
        # Save for dashboard to read
        with open(self.dashboard_file, 'w', encoding='utf-8') as f:
            json.dump(dashboard_data, f, indent=2)
        
        print("✅ Dashboard updated with real data")
        print(f"📊 Jobs: {metrics['jobs_discovered']}")
        print(f"✍️ Proposals: {metrics['proposals_generated']}")
        print(f"💰 Revenue: ${metrics['revenue_earned']}")
        print(f"📈 Win Rate: {metrics['win_rate']:.1f}%")
        
        return dashboard_data
    
    def inject_into_html(self, html_file: Path):
        """Inject real data into HTML dashboard"""
        if not html_file.exists():
            print(f"❌ Dashboard file not found: {html_file}")
            return
        
        # Read dashboard HTML
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Load real metrics
        metrics = self.load_real_metrics()
        
        # Create JavaScript to inject
        js_injection = f"""
<script>
// REAL DATA INJECTION
const REAL_METRICS = {{
    jobsDiscovered: {metrics['jobs_discovered']},
    proposalsGenerated: {metrics['proposals_generated']},
    applicationsSent: {metrics['applications_sent']},
    jobsWon: {metrics['jobs_won']},
    revenueEarned: {metrics['revenue_earned']},
    winRate: {metrics['win_rate']},
    lastUpdated: '{datetime.now().isoformat()}',
    dataSource: 'real'
}};

// Update dashboard on load
window.addEventListener('DOMContentLoaded', function() {{
    console.log('🔥 Loading REAL data:', REAL_METRICS);
    
    // Update metrics display
    if (typeof updateMetrics === 'function') {{
        updateMetrics(REAL_METRICS);
    }}
}});
</script>
"""
        
        # Inject before closing </body> tag
        if '</body>' in html_content:
            html_content = html_content.replace('</body>', js_injection + '\n</body>')
        else:
            html_content += js_injection
        
        # Save updated HTML
        output_file = html_file.parent / f"{html_file.stem}_LIVE{html_file.suffix}"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Created live dashboard: {output_file}")
        return output_file


def main():
    """Main entry point"""
    print("""
================================================================================
                    DASHBOARD CONNECTOR
            Connecting Real Data to 3D Dashboard
================================================================================
    """)
    
    connector = DashboardConnector()
    
    # Update dashboard data
    data = connector.update_dashboard()
    
    # Try to inject into HTML dashboards
    base_dir = Path(__file__).parent.parent
    dashboards = [
        base_dir / "3D_PARALLEL_MONEY_MAP.html",
        base_dir / "PARALLELPROFIT_BLEEDING_EDGE.html",
        base_dir / "04_PRODUCT_DEMOS" / "3D_PARALLEL_MONEY_MAP.html"
    ]
    
    for dashboard in dashboards:
        if dashboard.exists():
            print(f"\n📊 Injecting data into: {dashboard.name}")
            connector.inject_into_html(dashboard)
    
    print("\n" + "="*80)
    print("✅ DASHBOARD CONNECTOR COMPLETE")
    print("="*80)
    print("\nYour 3D dashboard now shows REAL data!")
    print("Open the *_LIVE.html files to see live metrics")


if __name__ == "__main__":
    main()
