import json
import os

def generate_report(finding):
    os.makedirs(f"programs/{finding['program']}/findings/{finding['id']}", exist_ok=True)
    
    # Evidence storage
    with open(f"programs/{finding['program']}/findings/{finding['id']}/evidence.json", "w") as f:
        json.dump(finding["evidence"], f)
    
    # Markdown report
    report = f"""## {finding['title']}
**Severity**: {finding['severity']}
**URL**: {finding['url']}

### Proof of Concept
```bash
{finding['curl_command']}
```

### Recommended Fix
{finding['remediation']}
"""
    with open(f"programs/{finding['program']}/findings/{finding['id']}/report.md", "w") as f:
        f.write(report)
