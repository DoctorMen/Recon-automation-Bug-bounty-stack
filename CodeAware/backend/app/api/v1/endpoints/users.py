#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
User management endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.core.security import get_current_user_id
from app.db.session import get_db
from app.models.user import User

router = APIRouter()


class UserProfile(BaseModel):
    id: int
    email: str
    username: str
    full_name: str
    subscription_tier: str
    is_verified: bool
    github_username: str = None
    gitlab_username: str = None
    
    class Config:
        from_attributes = True


@router.get("/me", response_model=UserProfile)
async def get_current_user(
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Get current user profile"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user




