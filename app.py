from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import Optional
import uvicorn
import os
import requests
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

app = FastAPI(title="Recon Automation API", description="API for remote scanning requests", version="1.0")

# API Key authentication
API_KEY_NAME = "api_key"
API_KEY = "your-secure-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_api_key(api_key_header: str = Depends(api_key_header)):
    if api_key_header != API_KEY:
        raise HTTPException(status_code=403, detail="Could not validate credentials")
    return api_key_header

# Pydantic model for scan request
class ScanRequest(BaseModel):
    target: str
    scan_type: Optional[str] = "basic"

# Webhook URL (set this in your environment)
WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'https://your-webhook-url.com')

# Function to send webhook notification
def send_webhook_notification(message: str):
    if WEBHOOK_URL:
        payload = {'text': message}
        try:
            response = requests.post(WEBHOOK_URL, json=payload)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error sending webhook: {e}")

# Database setup
DATABASE_URL = "sqlite:///./scans.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Scan model
class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    scan_type = Column(String)
    status = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

# Create the database tables
Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
async def root():
    return {"message": "Welcome to the Recon Automation API!"}

@app.post("/scan")
async def start_scan(request: ScanRequest, api_key: str = Depends(get_api_key), db: Session = Depends(get_db)):
    # Placeholder logic for starting a scan
    new_scan = Scan(target=request.target, scan_type=request.scan_type, status="Started")
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    send_webhook_notification(f"Scan started for target: {request.target}")
    return {"status": "Scan started", "target": request.target, "scan_type": request.scan_type}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
