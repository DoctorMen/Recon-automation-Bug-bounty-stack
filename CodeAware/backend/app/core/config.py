#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Configuration settings for CodeAware API
"""
from pydantic_settings import BaseSettings
from typing import List, Optional
import secrets


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    PROJECT_NAME: str = "CodeAware"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # API
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
    ]
    
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://codeaware:codeaware@localhost:5432/codeaware"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    
    # GitHub Integration
    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[str] = None
    
    # GitLab Integration
    GITLAB_CLIENT_ID: Optional[str] = None
    GITLAB_CLIENT_SECRET: Optional[str] = None
    
    # Analysis Settings
    MAX_FILE_SIZE_MB: int = 10
    MAX_REPO_SIZE_MB: int = 500
    ANALYSIS_TIMEOUT_SECONDS: int = 300
    
    # ML Models
    MODEL_PATH: str = "models/"
    
    # Subscription Tiers
    TIER_INDIVIDUAL_MONTHLY_SCANS: int = 10
    TIER_PROFESSIONAL_MONTHLY_SCANS: int = 50
    TIER_TEAM_MONTHLY_SCANS: int = -1  # Unlimited
    
    # Email (optional)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAIL_FROM: str = "noreply@codeaware.io"
    
    # Sentry (optional)
    SENTRY_DSN: Optional[str] = None
    
    # Stripe (payment processing)
    STRIPE_SECRET_KEY: Optional[str] = None
    STRIPE_PUBLIC_KEY: Optional[str] = None
    STRIPE_WEBHOOK_SECRET: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()




