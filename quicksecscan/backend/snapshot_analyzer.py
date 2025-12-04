#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
QuickSecScan - Snapshot Analyzer
Self-improving system: analyzes past scans, identifies patterns, tunes detection
"""
import os
import json
import boto3
from datetime import datetime, timedelta
from collections import Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

S3_BUCKET = os.getenv("S3_BUCKET", "quicksecscan-reports")
s3_client = boto3.client('s3')

class SnapshotAnalyzer:
    """Analyze scan snapshots to improve detection and reduce false positives"""
    
    def __init__(self, lookback_days=30):
        self.lookback_days = lookback_days
        self.snapshots = []
    
    def load_snapshots(self, domain=None):
        """Load recent snapshots from S3"""
        prefix = f"snapshots/{domain}/" if domain else "snapshots/"
        cutoff_date = datetime.utcnow() - timedelta(days=self.lookback_days)
        
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
            for obj in page.get('Contents', []):
                # Filter by date
                if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                    continue
                
                # Download and parse snapshot
                response = s3_client.get_object(Bucket=S3_BUCKET, Key=obj['Key'])
                snapshot = json.loads(response['Body'].read())
                self.snapshots.append(snapshot)
        
        logger.info(f"Loaded {len(self.snapshots)} snapshots for analysis")
        return self.snapshots
    
    def analyze_false_positive_patterns(self):
        """Identify findings that are consistently false positives"""
        # Track findings that appear frequently but are never acted upon
        all_findings = []
        for snapshot in self.snapshots:
            all_findings.extend(snapshot.get('findings', []))
        
        # Count by finding name
        finding_names = Counter([f['name'] for f in all_findings])
        
        # High-frequency, low-value findings (likely FPs or noise)
        common_findings = finding_names.most_common(20)
        logger.info(f"Most common findings: {common_findings}")
        
        # TODO: Implement feedback loop to suppress these in future scans
        return common_findings
    
    def analyze_domain_patterns(self):
        """Identify common vulnerabilities by domain type"""
        # Group by TLD, tech stack, etc.
        by_tld = {}
        for snapshot in self.snapshots:
            domain = snapshot.get('domain', '')
            tld = domain.split('.')[-1] if '.' in domain else 'unknown'
            
            if tld not in by_tld:
                by_tld[tld] = {'count': 0, 'avg_findings': 0, 'severities': Counter()}
            
            by_tld[tld]['count'] += 1
            by_tld[tld]['avg_findings'] += snapshot.get('findings_count', 0)
            
            for severity, count in snapshot.get('findings_by_severity', {}).items():
                by_tld[tld]['severities'][severity] += count
        
        # Calculate averages
        for tld, data in by_tld.items():
            data['avg_findings'] /= data['count']
        
        logger.info(f"Domain patterns by TLD: {by_tld}")
        return by_tld
    
    def generate_tuning_recommendations(self):
        """Generate recommendations for scan tuning"""
        recommendations = []
        
        # Analyze false positives
        common_findings = self.analyze_false_positive_patterns()
        if common_findings:
            top_5 = [name for name, count in common_findings[:5]]
            recommendations.append({
                'type': 'suppress_noisy_templates',
                'action': f"Consider suppressing Nuclei templates for: {', '.join(top_5)}",
                'reason': 'High frequency, likely low value'
            })
        
        # Analyze domain patterns
        domain_patterns = self.analyze_domain_patterns()
        high_risk_tlds = [tld for tld, data in domain_patterns.items() if data['avg_findings'] > 10]
        if high_risk_tlds:
            recommendations.append({
                'type': 'increase_scan_depth',
                'action': f"Increase scan depth for TLDs: {', '.join(high_risk_tlds)}",
                'reason': 'Higher average finding count suggests more vulnerabilities'
            })
        
        logger.info(f"Generated {len(recommendations)} tuning recommendations")
        return recommendations
    
    def apply_improvements(self):
        """Apply improvements to scan configuration"""
        recommendations = self.generate_tuning_recommendations()
        
        # Save recommendations to file for manual review
        output_file = f"tuning_recommendations_{datetime.utcnow().strftime('%Y%m%d')}.json"
        with open(output_file, 'w') as f:
            json.dump(recommendations, f, indent=2)
        
        logger.info(f"Recommendations saved to {output_file}")
        
        # TODO: Auto-apply low-risk recommendations (e.g., template suppression)
        return recommendations

def run_weekly_analysis():
    """Run weekly snapshot analysis (cron job)"""
    analyzer = SnapshotAnalyzer(lookback_days=7)
    analyzer.load_snapshots()
    recommendations = analyzer.apply_improvements()
    
    # Email summary to monitoring inbox
    # TODO: Implement email summary
    logger.info(f"Weekly analysis complete. {len(recommendations)} recommendations.")

if __name__ == "__main__":
    run_weekly_analysis()

