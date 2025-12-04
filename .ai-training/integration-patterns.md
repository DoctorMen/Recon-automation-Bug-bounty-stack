<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Integration Patterns

## CLI Integration
```python
import subprocess
result = subprocess.run(['python3', 'run_pipeline.py'], capture_output=True)
```

## API Wrapper
```python
from fastapi import FastAPI
app = FastAPI()

@app.post('/scan')
def scan(domain: str):
    with open('targets.txt', 'w') as f:
        f.write(domain)
    subprocess.Popen(['python3', 'run_pipeline.py'])
    return {'status': 'started'}
```

## Discord Bot
```python
@bot.command()
async def scan(ctx, domain):
    with open('targets.txt', 'w') as f:
        f.write(domain)
    subprocess.Popen(['python3', 'run_pipeline.py'])
    await ctx.send(f'Scanning {domain}...')
```

## File Monitoring
```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class ResultsHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith('triage.json'):
            # Process new findings
            pass
```
