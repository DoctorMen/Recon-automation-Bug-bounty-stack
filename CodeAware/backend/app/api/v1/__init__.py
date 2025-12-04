#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
API v1 Router
"""
from fastapi import APIRouter

from app.api.v1.endpoints import auth, users, repositories, analyses, subscriptions

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(repositories.router, prefix="/repositories", tags=["repositories"])
api_router.include_router(analyses.router, prefix="/analyses", tags=["analyses"])
api_router.include_router(subscriptions.router, prefix="/subscriptions", tags=["subscriptions"])




