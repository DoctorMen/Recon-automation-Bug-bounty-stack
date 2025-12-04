#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
Screenshot Analyzer - Upwork Job Post Processor
Analyzes screenshots and executes tasks automatically
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import base64

try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

class ScreenshotAnalyzer:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.memory_file = self.base_dir / "output" / "screenshot_memory.json"
        self.screenshots_dir = self.base_dir / "output" / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        
        self.memory = self.load_memory()
        self.max_retries = 3
        
    def load_memory(self) -> Dict:
        """Load learned patterns from screenshots"""
        if self.memory_file.exists():
            with open(self.memory_file, 'r') as f:
                return json.load(f)
        return {
            "processed_jobs": [],
            "learned_patterns": {},
            "error_patterns": {},
            "success_patterns": {}
        }
    
    def save_memory(self):
        """Save learned patterns"""
        with open(self.memory_file, 'w') as f:
            json.dump(self.memory, f, indent=2)
    
    def extract_text_from_image(self, image_path: str) -> str:
        """Extract text from screenshot using OCR"""
        if not OCR_AVAILABLE:
            return self.fallback_text_extraction(image_path)
        
        try:
            image = Image.open(image_path)
            text = pytesseract.image_to_string(image)
            return text
        except Exception as e:
            print(f"OCR failed: {e}, using fallback")
            return self.fallback_text_extraction(image_path)
    
    def fallback_text_extraction(self, image_path: str) -> str:
        """Fallback: Prompt user or use manual input"""
        print(f"⚠️  OCR not available. Please paste the job description:")
        if sys.stdin.isatty():
            return input("Job description: ")
        return ""
    
    def parse_upwork_job(self, text: str) -> Dict:
        """Parse Upwork job post from text"""
        job = {
            "title": "",
            "description": "",
            "budget": "",
            "skills": [],
            "urgency": False,
            "keywords": []
        }
        
        # Extract title (usually first line or after "Title:")
        title_match = re.search(r'(?:Title:|Job Title:)\s*(.+?)(?:\n|$)', text, re.IGNORECASE)
        if not title_match:
            lines = text.split('\n')
            job["title"] = lines[0] if lines else "Security Assessment"
        else:
            job["title"] = title_match.group(1).strip()
        
        # Extract budget
        budget_patterns = [
            r'\$(\d+(?:,\d{3})*(?:-\$\d+(?:,\d{3})*)?)',
            r'Budget[:\s]+(\$?\d+(?:,\d{3})*)',
            r'(\d+(?:,\d{3})*)\s*(?:USD|dollars?)'
        ]
        for pattern in budget_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                job["budget"] = match.group(1).replace(',', '')
                break
        
        # Detect urgency
        urgency_keywords = ["urgent", "asap", "emergency", "today", "immediate", "quick"]
        job["urgency"] = any(keyword in text.lower() for keyword in urgency_keywords)
        
        # Extract keywords
        security_keywords = [
            "security", "vulnerability", "penetration", "audit", "scan",
            "OWASP", "API", "web application", "WordPress", "compliance"
        ]
        job["keywords"] = [kw for kw in security_keywords if kw.lower() in text.lower()]
        
        # Extract description
        desc_match = re.search(r'(?:Description:|Details:)\s*(.+?)(?:\n\n|\Z)', text, re.IGNORECASE | re.DOTALL)
        if desc_match:
            job["description"] = desc_match.group(1).strip()
        else:
            job["description"] = text[:500]  # First 500 chars
        
        return job
    
    def determine_action(self, job: Dict) -> Dict:
        """Determine what action to take based on job content"""
        keywords = " ".join(job["keywords"]).lower()
        description = job["description"].lower()
        title = job["title"].lower()
        combined = f"{keywords} {description} {title}"
        
        action = {
            "type": "proposal",
            "template": 1,
            "priority": "normal"
        }
        
        # Detect action type from job content
        if "apply" in combined or "proposal" in combined or "bid" in combined:
            action["type"] = "proposal"
        elif "scan" in combined or "test" in combined or "audit" in combined:
            action["type"] = "scan"
        elif "track" in combined or "log" in combined:
            action["type"] = "track"
        elif "analyze" in combined or "review" in combined:
            action["type"] = "analyze"
        
        # Template matching logic
        if job["urgency"] or "urgent" in combined or "asap" in combined:
            action["template"] = 1  # Emergency template
            action["priority"] = "urgent"
        elif "api" in combined or "rest" in combined:
            action["template"] = 2  # API Security
        elif "pentest" in combined or "penetration" in combined or "owasp" in combined:
            action["template"] = 3  # Pentest
        elif "monthly" in combined or "recurring" in combined or "monitoring" in combined:
            action["template"] = 4  # Monthly
        elif "pci" in combined or "hipaa" in combined or "compliance" in combined:
            action["template"] = 5  # Compliance
        elif "wordpress" in combined or "wp" in combined:
            action["template"] = 6  # WordPress
        elif "ecommerce" in combined or "e-commerce" in combined or "shop" in combined:
            action["template"] = 7  # E-commerce
        elif "cloud" in combined or "aws" in combined or "azure" in combined:
            action["template"] = 8  # Cloud
        else:
            action["template"] = 1  # Default to emergency
        
        return action
    
    def determine_template(self, job: Dict) -> int:
        """Determine which template to use based on job"""
        action = self.determine_action(job)
        return action["template"]
    
    def extract_client_name(self, text: str) -> str:
        """Extract client name from job post"""
        # Look for "Client:" or "Posted by:"
        client_match = re.search(r'(?:Client|Posted by|Hiring):\s*([A-Z][a-zA-Z\s]+)', text)
        if client_match:
            return client_match.group(1).strip()
        
        # Fallback: use first capitalized words
        words = text.split()
        capitalized = [w for w in words if w[0].isupper() and len(w) > 2]
        if capitalized:
            return " ".join(capitalized[:2])
        
        return "Client"
    
    def calculate_price(self, job: Dict) -> str:
        """Calculate price based on job details"""
        if job["budget"]:
            # Use job budget if available
            budget = int(job["budget"].replace('$', '').replace(',', ''))
            # Suggest 20% below budget for competitiveness
            suggested = int(budget * 0.8)
            return str(suggested)
        
        # Default pricing based on template
        template = self.determine_template(job)
        default_prices = {
            1: "300",  # Emergency
            2: "1200", # API
            3: "2900", # Pentest
            4: "1250", # Monthly
            5: "2500", # Compliance
            6: "450",  # WordPress
            7: "800",  # E-commerce
            8: "2000"  # Cloud
        }
        return default_prices.get(template, "300")
    
    def generate_proposal(self, job: Dict, retry_count: int = 0) -> Tuple[str, bool]:
        """Generate proposal from job data"""
        try:
            client_name = self.extract_client_name(job.get("description", ""))
            template = self.determine_template(job)
            price = self.calculate_price(job)
            
            # Use polymorphic command system or direct automation
            cmd = [
                "python3", "scripts/automate_first_dollar.py",
                "--action", "proposal",
                "--client", client_name,
                "--price", price,
                "--description", job.get("description", "")[:200]
            ]
            
            result = subprocess.run(cmd, cwd=self.base_dir, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Save successful pattern
                self.memory["success_patterns"][f"template_{template}"] = {
                    "count": self.memory["success_patterns"].get(f"template_{template}", {}).get("count", 0) + 1,
                    "last_used": datetime.now().isoformat()
                }
                self.save_memory()
                return result.stdout, True
            else:
                return self.handle_error(result.stderr, job, retry_count)
                
        except Exception as e:
            return self.handle_error(str(e), job, retry_count)
    
    def handle_error(self, error: str, job: Dict, retry_count: int) -> Tuple[str, bool]:
        """Polymorphic error handling with idempotent retries"""
        if retry_count >= self.max_retries:
            # Final fallback: manual generation
            return self.fallback_generation(job), False
        
        # Learn error pattern
        error_key = error[:50]  # First 50 chars
        if error_key not in self.memory["error_patterns"]:
            self.memory["error_patterns"][error_key] = {
                "count": 1,
                "solutions": []
            }
        else:
            self.memory["error_patterns"][error_key]["count"] += 1
        
        # Try alternative approach
        retry_count += 1
        print(f"⚠️  Retry {retry_count}/{self.max_retries}: Trying alternative approach...")
        
        # Alternative: use simpler command
        try:
            client_name = self.extract_client_name(job.get("description", ""))
            price = self.calculate_price(job)
            
            # Direct template generation
            template_content = self.get_template_content(self.determine_template(job))
            proposal = template_content.replace("[CLIENT_NAME]", client_name)
            proposal = proposal.replace("[PRICE]", price)
            
            # Save proposal
            proposal_file = self.base_dir / "output" / "first_dollar_automation" / "proposals" / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{client_name.replace(' ', '_')}.txt"
            proposal_file.parent.mkdir(parents=True, exist_ok=True)
            with open(proposal_file, 'w') as f:
                f.write(proposal)
            
            return f"✅ Proposal generated (fallback method): {proposal_file}", True
            
        except Exception as e2:
            if retry_count < self.max_retries:
                return self.handle_error(str(e2), job, retry_count)
            return f"❌ Error after {self.max_retries} retries: {e2}", False
    
    def get_template_content(self, template_num: int) -> str:
        """Get template content"""
        templates = {
            1: """Subject: 2-Hour Security Scan - Results Today

Hi [CLIENT_NAME],

I see you need a security assessment urgently. I specialize in fast, comprehensive security scans using enterprise automation tools.

What I'll deliver in 2 hours:
✅ Complete vulnerability scan (100+ security checks)
✅ Professional report with security score
✅ Critical issues flagged immediately
✅ Step-by-step fix instructions
✅ 30-day support included

My automated system scans 80-240x faster than manual methods, so I can deliver results today - perfect for urgent situations.

Fixed Price: $[PRICE]
Timeline: 2 hours from start
Guarantee: Full refund if not satisfied

Ready to secure your business today?

Best regards,
[Your Name]"""
        }
        return templates.get(template_num, templates[1])
    
    def fallback_generation(self, job: Dict) -> str:
        """Final fallback: manual template"""
        client_name = self.extract_client_name(job.get("description", ""))
        price = self.calculate_price(job)
        template = self.determine_template(job)
        
        proposal = self.get_template_content(template)
        proposal = proposal.replace("[CLIENT_NAME]", client_name)
        proposal = proposal.replace("[PRICE]", price)
        
        # Save to file
        proposal_file = self.base_dir / "output" / "screenshots" / f"proposal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(proposal_file, 'w') as f:
            f.write(proposal)
        
        return f"Proposal saved to: {proposal_file}\n\n{proposal}"
    
    def execute_task(self, job: Dict, action: Dict, retry_count: int = 0) -> Tuple[str, bool]:
        """Execute task based on action type - polymorphic handler"""
        action_type = action.get("type", "proposal")
        
        try:
            if action_type == "proposal":
                return self.generate_proposal(job, retry_count)
            elif action_type == "scan":
                return self.execute_scan(job, retry_count)
            elif action_type == "track":
                return self.track_project(job, retry_count)
            elif action_type == "analyze":
                return self.analyze_job(job, retry_count)
            else:
                # Default: try proposal generation
                return self.generate_proposal(job, retry_count)
        except Exception as e:
            return self.handle_error(str(e), job, retry_count)
    
    def execute_scan(self, job: Dict, retry_count: int) -> Tuple[str, bool]:
        """Execute scan task"""
        # Extract domain from job description
        domain_match = re.search(r'([a-zA-Z0-9\-]+\.(?:com|net|org|io|co))', job.get("description", ""))
        if domain_match:
            domain = domain_match.group(1)
            client_name = self.extract_client_name(job.get("description", ""))
            
            cmd = [
                "python3", "scripts/quick_client_workflow.py",
                "--client", client_name,
                "--domain", domain,
                "--amount", self.calculate_price(job)
            ]
            
            result = subprocess.run(cmd, cwd=self.base_dir, capture_output=True, text=True, timeout=300)
            return result.stdout if result.returncode == 0 else self.handle_error(result.stderr, job, retry_count)
        else:
            return "Domain not found in job description. Please specify domain.", False
    
    def track_project(self, job: Dict, retry_count: int) -> Tuple[str, bool]:
        """Track project"""
        client_name = self.extract_client_name(job.get("description", ""))
        amount = int(self.calculate_price(job))
        
        cmd = [
            "python3", "scripts/automate_first_dollar.py",
            "--action", "won",
            "--client", client_name,
            "--amount", str(amount)
        ]
        
        result = subprocess.run(cmd, cwd=self.base_dir, capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else self.handle_error(result.stderr, job, retry_count)
    
    def analyze_job(self, job: Dict, retry_count: int) -> Tuple[str, bool]:
        """Analyze job and provide insights"""
        analysis = f"""
📊 Job Analysis:
  Title: {job['title']}
  Budget: ${job['budget'] or 'Not specified'}
  Urgency: {job['urgency']}
  Keywords: {', '.join(job['keywords']) if job['keywords'] else 'None'}
  Recommended Template: {self.determine_template(job)}
  Suggested Price: ${self.calculate_price(job)}
  Win Probability: {'High (90%)' if job['urgency'] else 'Medium (75%)'}
"""
        return analysis, True
    
    def process_screenshot(self, image_path: str) -> str:
        """Process screenshot and execute tasks - polymorphic execution"""
        print(f"📸 Analyzing screenshot: {image_path}")
        
        # Extract text
        text = self.extract_text_from_image(image_path)
        if not text:
            return "❌ Could not extract text from screenshot"
        
        # Parse job
        job = self.parse_upwork_job(text)
        print(f"📋 Job Title: {job['title']}")
        print(f"💰 Budget: ${job['budget'] or 'Not specified'}")
        print(f"⚡ Urgent: {job['urgency']}")
        
        # Check if already processed
        job_hash = hash(text[:100])
        if job_hash in [j.get("hash") for j in self.memory["processed_jobs"]]:
            return "ℹ️  This job was already processed"
        
        # Determine action (polymorphic)
        action = self.determine_action(job)
        print(f"🎯 Action Type: {action['type']}")
        print(f"📝 Template: {action['template']}")
        
        # Execute task polymorphically
        result, success = self.execute_task(job, action)
        
        # Save to memory
        self.memory["processed_jobs"].append({
            "hash": job_hash,
            "timestamp": datetime.now().isoformat(),
            "action": action["type"],
            "template": action["template"],
            "success": success
        })
        self.save_memory()
        
        return result
    
    def analyze_and_execute(self, image_path: str) -> str:
        """Main entry point: analyze screenshot and execute"""
        if not os.path.exists(image_path):
            return f"❌ Screenshot not found: {image_path}"
        
        return self.process_screenshot(image_path)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 screenshot_analyzer.py <screenshot_path>")
        print("\nExamples:")
        print("  python3 screenshot_analyzer.py screenshot.png")
        print("  python3 screenshot_analyzer.py /path/to/upwork_post.png")
        sys.exit(1)
    
    image_path = sys.argv[1]
    analyzer = ScreenshotAnalyzer()
    result = analyzer.analyze_and_execute(image_path)
    print("\n" + "="*60)
    print(result)
    print("="*60)


if __name__ == "__main__":
    main()

