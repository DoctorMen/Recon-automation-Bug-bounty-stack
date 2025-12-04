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
        print(f"FOUND FILE: {source}")
        print("---------------------------------------------------")
        print(sources_content[i])
        print("---------------------------------------------------")
