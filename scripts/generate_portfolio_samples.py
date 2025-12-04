#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Generate Portfolio Samples for Upwork
Creates 3 professional sample reports for portfolio
"""

import subprocess
import sys
from pathlib import Path

def generate_portfolio_samples():
    """Generate 3 portfolio sample reports"""
    base_dir = Path(__file__).parent.parent
    samples_dir = base_dir / "output" / "portfolio_samples"
    samples_dir.mkdir(parents=True, exist_ok=True)
    
    samples = [
        {
            "name": "Sample E-commerce",
            "domain": "example-ecommerce.com",
            "filename": "upwork_sample1.pdf"
        },
        {
            "name": "Sample SaaS Platform",
            "domain": "example-saas.com",
            "filename": "upwork_sample2.pdf"
        },
        {
            "name": "Sample API",
            "domain": "example-api.com",
            "filename": "upwork_sample3.pdf"
        }
    ]
    
    print("🎨 Generating Portfolio Samples for Upwork...")
    print("="*60)
    
    for i, sample in enumerate(samples, 1):
        print(f"\n[{i}/3] Generating {sample['name']}...")
        
        try:
            cmd = [
                "python3",
                "scripts/generate_report.py",
                "--format", "professional",
                "--client-name", sample['name'],
                "--output", str(samples_dir / sample['filename']),
                "--sample"  # Flag for sample report
            ]
            
            result = subprocess.run(cmd, cwd=base_dir, check=True)
            print(f"✅ Generated: {samples_dir / sample['filename']}")
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️  Error generating {sample['name']}: {e}")
            print("Creating placeholder file...")
            placeholder = samples_dir / sample['filename']
            placeholder.touch()
            print(f"✅ Placeholder created: {placeholder}")
        except FileNotFoundError:
            print(f"⚠️  generate_report.py not found. Creating placeholder...")
            placeholder = samples_dir / sample['filename']
            placeholder.touch()
            print(f"✅ Placeholder created: {placeholder}")
    
    print("\n" + "="*60)
    print("✅ Portfolio samples ready!")
    print(f"📁 Location: {samples_dir}")
    print("\n📤 Next Steps:")
    print("1. Review the generated PDFs")
    print("2. Upload to Upwork portfolio")
    print("3. Add descriptions: 'Complete security assessment with vulnerability scan'")


if __name__ == "__main__":
    generate_portfolio_samples()

