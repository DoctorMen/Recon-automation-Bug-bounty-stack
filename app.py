from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn
import os
import requests
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import datetime

# Custom CSS for professional Swagger UI branding
custom_swagger_css = """
/* Top Bar Styling */
.topbar-wrapper img {
    content: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGRlZnM+CjxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZDEiIHgxPSIwJSIgeTE9IjAlIiB4Mj0iMTAwJSIgeTI9IjEwMCUiPgo8c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMzY0MkY1O3N0b3Atb3BhY2l0eToxIiAvPgo8c3RvcCBvZmZzZXQ9IjEwMCUiIHN0eWxlPSJzdG9wLWNvbG9yOiM5MzMzRUE7c3RvcC1vcGFjaXR5OjEiIC8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPHJlY3Qgd2lkdGg9IjQwIiBoZWlnaHQ9IjQwIiByeD0iOCIgZmlsbD0idXJsKCNncmFkMSkiLz4KPHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEyIDJMMTMuMDkgOC4yNkwyMCA5TDEzLjA5IDE1Ljc0TDEyIDIyTDEwLjkxIDE1Ljc0TDQgOUwxMC45MSA4LjI2TDEyIDJaIiBmaWxsPSJ3aGl0ZSIvPgo8L3N2Zz4KPC9zdmc+');
    height: 40px;
    width: 40px;
}

/* Header styling */
.swagger-ui .topbar {
    background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%);
    border-bottom: none;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.swagger-ui .topbar-wrapper .link {
    color: white !important;
    font-weight: 600;
    font-size: 18px;
}

/* Info section styling */
.swagger-ui .info {
    margin: 20px 0;
    background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%);
    border-radius: 12px;
    padding: 30px;
    color: white;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
}

.swagger-ui .info .title {
    color: white !important;
    font-size: 32px;
    font-weight: 700;
    margin-bottom: 10px;
}

.swagger-ui .info .description {
    color: rgba(255,255,255,0.9) !important;
    font-size: 16px;
    line-height: 1.6;
}

.swagger-ui .info .version {
    color: rgba(255,255,255,0.8) !important;
    font-weight: 500;
}

/* Button styling */
.swagger-ui .btn {
    background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%);
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 12px 24px;
    transition: all 0.3s ease;
    box-shadow: 0 2px 8px rgba(54, 66, 245, 0.3);
}

.swagger-ui .btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 16px rgba(54, 66, 245, 0.4);
}

.swagger-ui .btn.authorize {
    background: linear-gradient(135deg, #10B981 0%, #059669 100%);
}

.swagger-ui .btn.authorize:hover {
    box-shadow: 0 4px 16px rgba(16, 185, 129, 0.4);
}

/* Scheme container styling */
.swagger-ui .scheme-container {
    background: white;
    border-radius: 12px;
    padding: 20px;
    margin: 20px 0;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
}

/* Operation styling */
.swagger-ui .opblock {
    border-radius: 8px;
    border: 1px solid #e5e7eb;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    margin-bottom: 10px;
}

.swagger-ui .opblock.opblock-post {
    border-color: #3642F5;
    background: linear-gradient(135deg, rgba(54, 66, 245, 0.05) 0%, rgba(147, 51, 234, 0.05) 100%);
}

.swagger-ui .opblock.opblock-post .opblock-summary-method {
    background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%);
    color: white;
    border-radius: 6px 0 0 6px;
}

.swagger-ui .opblock.opblock-get {
    border-color: #10B981;
    background: rgba(16, 185, 129, 0.05);
}

.swagger-ui .opblock.opblock-get .opblock-summary-method {
    background: #10B981;
    color: white;
    border-radius: 6px 0 0 6px;
}

/* Parameter styling */
.swagger-ui .parameter__name {
    font-weight: 600;
    color: #374151;
}

.swagger-ui .parameter__type {
    color: #6B7280;
    font-weight: 500;
}

/* Response styling */
.swagger-ui .highlight-code {
    background: #f8fafc;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 16px;
}

/* Tab styling */
.swagger-ui .tab li {
    border-radius: 6px 6px 0 0;
    font-weight: 500;
}

.swagger-ui .tab li.active {
    background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%);
    color: white;
}

.swagger-ui .tab li.active:after {
    background: linear-gradient(135deg, #9333EA 0%, #3642F5 100%);
}

/* Model styling */
.swagger-ui .model-box {
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 16px;
}

.swagger-ui .model .property {
    color: #374151;
}

/* Try it out styling */
.swagger-ui .execute-wrapper {
    background: linear-gradient(135deg, rgba(54, 66, 245, 0.1) 0%, rgba(147, 51, 234, 0.1) 100%);
    border-radius: 8px;
    padding: 16px;
    margin-top: 16px;
}

/* Loading styling */
.swagger-ui .loading-container {
    background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%);
    border-radius: 8px;
}

/* Error styling */
.swagger-ui .errors-wrapper {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(220, 38, 38, 0.1) 100%);
    border: 1px solid #ef4444;
    border-radius: 8px;
    padding: 16px;
}

/* Footer styling */
.swagger-ui .swagger-ui .footer {
    background: #f8fafc;
    border-top: 1px solid #e5e7eb;
    padding: 20px;
    text-align: center;
    color: #6B7280;
}

/* Custom scrollbar */
.swagger-ui ::-webkit-scrollbar {
    width: 8px;
}

.swagger-ui ::-webkit-scrollbar-track {
    background: #f1f5f9;
    border-radius: 4px;
}

.swagger-ui ::-webkit-scrollbar-thumb {
    background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%);
    border-radius: 4px;
}

.swagger-ui ::-webkit-scrollbar-thumb:hover {
    background: linear-gradient(135deg, #2d35db 0%, #7c2dc9 100%);
}
"""

app = FastAPI(
    title="Recon Automation API",
    description="""
    ## 🚀 Professional Security Scanning API
    
    **Recon Automation Platform** provides enterprise-grade vulnerability scanning and security assessment capabilities.
    
    ### 📋 Key Features:
    - **🔍 Automated Reconnaissance**: Comprehensive target scanning
    - **🛡️ Vulnerability Detection**: Advanced security analysis
    - **📊 Real-time Analytics**: Live scan monitoring and reporting
    - **🔐 API Authentication**: Secure key-based access control
    - **⚡ High Performance**: Optimized for rapid scanning
    
    ### 🎯 Use Cases:
    - **Bug Bounty Programs**: Streamline vulnerability discovery
    - **Security Audits**: Automated compliance checking
    - **Penetration Testing**: Professional security assessments
    - **DevSecOps**: Integrate security into CI/CD pipelines
    
    ### 📞 Support:
    - **Documentation**: [Executive Dashboard](https://doctormen.github.io/Recon-automation-Bug-bounty-stack/dashboard.html)
    - **API Status**: [Live Monitoring](https://doctormen.github.io/Recon-automation-Bug-bounty-stack/dashboard.html)
    - **Contact**: support@reconautomation.com
    
    ---
    *Built with FastAPI, SQLAlchemy, and deployed on Heroku*
    """,
    version="2.0.0",
    swagger_ui_parameters={
        "deepLinking": True,
        "displayRequestDuration": True,
        "docExpansion": "list",
        "operationsSorter": "method",
        "filter": True,
        "showExtensions": True,
        "showCommonExtensions": True,
        "tryItOutEnabled": True,
        "customCssUrl": "/static/swagger-custom.css",
        "customSiteTitle": "Recon Automation API | Professional Security Scanning Platform"
    }
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Custom docs route with inline CSS
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <title>Recon Automation API | Professional Security Scanning Platform</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui.css" />
    <style>
        /* Top Bar Styling */
        .topbar-wrapper img {
            content: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGRlZnM+CjxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZDEiIHgxPSIwJSIgeTE9IjAlIiB4Mj0iMTAwJSIgeTI9IjEwMCUiPgo8c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMzY0MkY1O3N0b3Atb3BhY2l0eToxIiAvPgo8c3RvcCBvZmZzZXQ9IjEwMCUiIHN0eWxlPSJzdG9wLWNvbG9yOiM5MzMzRUE7c3RvcC1vcGFjaXR5OjEiIC8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPHJlY3Qgd2lkdGg9IjQwIiBoZWlnaHQ9IjQwIiByeD0iOCIgZmlsbD0idXJsKCNncmFkMSkiLz4KPHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEyIDJMMTMuMDkgOC4yNkwyMCA5TDEzLjA5IDE1Ljc0TDEyIDIyTDEwLjkxIDE1Ljc0TDQgOUwxMC45MSA4LjI2TDEyIDJaIiBmaWxsPSJ3aGl0ZSIvPgo8L3N2Zz4KPC9zdmc+');
            height: 40px;
            width: 40px;
        }

        /* Header styling */
        .swagger-ui .topbar {
            background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%) !important;
            border-bottom: none !important;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1) !important;
        }

        .swagger-ui .topbar-wrapper .link {
            color: white !important;
            font-weight: 600 !important;
            font-size: 18px !important;
        }

        /* Info section styling */
        .swagger-ui .info {
            margin: 20px 0 !important;
            background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%) !important;
            border-radius: 12px !important;
            padding: 30px !important;
            color: white !important;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1) !important;
        }

        .swagger-ui .info .title {
            color: white !important;
            font-size: 32px !important;
            font-weight: 700 !important;
            margin-bottom: 10px !important;
        }

        .swagger-ui .info .description {
            color: rgba(255,255,255,0.9) !important;
            font-size: 16px !important;
            line-height: 1.6 !important;
        }

        /* Button styling */
        .swagger-ui .btn {
            background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%) !important;
            border: none !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
            padding: 12px 24px !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 2px 8px rgba(54, 66, 245, 0.3) !important;
        }

        .swagger-ui .btn:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 4px 16px rgba(54, 66, 245, 0.4) !important;
        }

        .swagger-ui .btn.authorize {
            background: linear-gradient(135deg, #10B981 0%, #059669 100%) !important;
        }

        /* Operation styling */
        .swagger-ui .opblock.opblock-post {
            border-color: #3642F5 !important;
            background: linear-gradient(135deg, rgba(54, 66, 245, 0.05) 0%, rgba(147, 51, 234, 0.05) 100%) !important;
        }

        .swagger-ui .opblock.opblock-post .opblock-summary-method {
            background: linear-gradient(135deg, #3642F5 0%, #9333EA 100%) !important;
            color: white !important;
            border-radius: 6px 0 0 6px !important;
        }

        .swagger-ui .opblock.opblock-get {
            border-color: #10B981 !important;
            background: rgba(16, 185, 129, 0.05) !important;
        }

        .swagger-ui .opblock.opblock-get .opblock-summary-method {
            background: #10B981 !important;
            color: white !important;
            border-radius: 6px 0 0 6px !important;
        }

        /* Try it out styling */
        .swagger-ui .execute-wrapper {
            background: linear-gradient(135deg, rgba(54, 66, 245, 0.1) 0%, rgba(147, 51, 234, 0.1) 100%) !important;
            border-radius: 8px !important;
            padding: 16px !important;
            margin-top: 16px !important;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                tryItOutEnabled: true
            });
        };
    </script>
</body>
</html>
    """)

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

# Create the database tables (check if exists first)
try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print(f"Database tables may already exist: {e}")

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
