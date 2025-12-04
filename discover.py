import yaml
import json
import os
import subprocess
from datetime import datetime

# Set PATH for Go tools
os.environ['PATH'] = os.environ.get('PATH', '') + ':/usr/local/go/bin:' + os.path.expanduser('~/go/bin')

# Stage 0: Load catalog
with open("programs/catalog.yml") as f:
    catalog = yaml.safe_load(f)

# Stage 1: Autonomous discovery
run_id = datetime.now().strftime("%Y%m%d_%H%M")
os.makedirs(f"runs/{run_id}", exist_ok=True)

discovery_data = []
for program in catalog:
    domains = " ".join(program["domains"])
    
    # Subdomain discovery pipeline
    subfinder_cmd = f"subfinder -d {domains} -silent | dnsx -silent"
    httpx_cmd = f"httpx -status-code -title -tech-detect -json -o runs/{run_id}/discovery.jsonl"
    
    process = subprocess.Popen(subfinder_cmd, shell=True, stdout=subprocess.PIPE)
    httpx_process = subprocess.Popen(httpx_cmd, shell=True, stdin=process.stdout)
    httpx_process.communicate()

# Stage 2: Scoring & Shortlisting
SCORE_WEIGHTS = {"admin_panels": 10, "graphql": 8, "old_tech": 7, "auth_flows": 6}

shortlist = []
with open(f"runs/{run_id}/discovery.jsonl") as f:
    for line in f:
        data = json.loads(line)
        score = 0
        
        # Scoring logic
        if "/admin" in data["url"]: score += SCORE_WEIGHTS["admin_panels"]
        if "graphql" in data["url"]: score += SCORE_WEIGHTS["graphql"]
        if "struts" in data.get("technologies", ""): score += SCORE_WEIGHTS["old_tech"]
        if "login" in data["url"]: score += SCORE_WEIGHTS["auth_flows"]
        
        shortlist.append({"url": data["url"], "score": score})

# Top 5 targets
shortlist = sorted(shortlist, key=lambda x: x["score"], reverse=True)[:5]

# Human gate
print("SHORTLISTED TARGETS:")
for i, target in enumerate(shortlist):
    print(f"{i+1}. {target['url']} (Score: {target['score']})")

selection = input("Select targets (e.g., 1,3,4) or type 'skip': ")

if selection != "skip":
    selected_indices = [int(x.strip()) - 1 for x in selection.split(',')]
    selected_targets = [shortlist[i] for i in selected_indices]
    
    print(f"\nRunning guided hunting on {len(selected_targets)} target(s)...")
    
    # Stage 3: Guided hunting
    for target in selected_targets:
        url = target['url']
        target_dir = f"runs/{run_id}/targets/{url.replace('://', '_').replace('/', '_')}"
        os.makedirs(target_dir, exist_ok=True)
        
        print(f"\nScanning {url}...")
        
        # Run nuclei with allowlisted templates
        nuclei_cmd = f"/home/ubuntu/go/bin/nuclei -u {url} -t /home/ubuntu/nuclei-templates/http/ -j -o {target_dir}/nuclei.json"
        subprocess.run(nuclei_cmd, shell=True)
        
        # Run katana for content discovery (depth=1)
        katana_cmd = f"/home/ubuntu/go/bin/katana -u {url} -d 1 -j -o {target_dir}/katana.json"
        subprocess.run(katana_cmd, shell=True)
        
        print(f"Results saved to {target_dir}")
else:
    print("Skipping guided hunting.")
