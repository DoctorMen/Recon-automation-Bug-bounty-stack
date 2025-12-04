import requests
import json

map_url = "https://app.euler.finance/_next/static/chunks/2350-2c8c0ada11de8f05.js.map"
response = requests.get(map_url, verify=False)
data = response.json()

sources = data.get('sources', [])
sources_content = data.get('sourcesContent', [])

target_file = "../../packages/wagmi-evc/src/actions/simulateEVCBatchCall.ts"

for i, source in enumerate(sources):
    if target_file in source:
        content = sources_content[i]
        lines = content.split('\n')
        for j, line in enumerate(lines):
            if "TODO" in line and "swaps" in line:
                print(f"FOUND TODO at line {j+1}:")
                print("---------------------------------------------------")
                # Print context (10 lines before and after)
                start = max(0, j - 10)
                end = min(len(lines), j + 10)
                for k in range(start, end):
                    prefix = ">> " if k == j else "   "
                    print(f"{prefix}{k+1}: {lines[k]}")
                print("---------------------------------------------------")
