#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Repository management endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import List
from datetime import datetime

from app.core.security import get_current_user_id
from app.db.session import get_db
from app.models.repository import Repository

router = APIRouter()


class RepositoryCreate(BaseModel):
    name: str
    full_name: str
    description: str = ""
    provider: str
    provider_url: str
    default_branch: str = "main"
    language: str = ""


class RepositoryResponse(BaseModel):
    id: int
    name: str
    full_name: str
    description: str
    provider: str
    default_branch: str
    language: str
    created_at: datetime
    last_analyzed_at: datetime = None
    
    class Config:
        from_attributes = True


@router.post("/", response_model=RepositoryResponse, status_code=status.HTTP_201_CREATED)
async def create_repository(
    repo_data: RepositoryCreate,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Add a repository"""
    # Check if repository already exists
    result = await db.execute(
        select(Repository).where(
            Repository.owner_id == user_id,
            Repository.full_name == repo_data.full_name
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Repository already added"
        )
    
    repository = Repository(
        owner_id=user_id,
        **repo_data.model_dump()
    )
    
    db.add(repository)
    await db.commit()
    await db.refresh(repository)
    
    return repository


@router.get("/", response_model=List[RepositoryResponse])
async def list_repositories(
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """List user's repositories"""
    result = await db.execute(
        select(Repository).where(Repository.owner_id == user_id)
    )
    repositories = result.scalars().all()
    
    return repositories


@router.get("/{repository_id}", response_model=RepositoryResponse)
async def get_repository(
    repository_id: int,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Get repository details"""
    result = await db.execute(
        select(Repository).where(
            Repository.id == repository_id,
            Repository.owner_id == user_id
        )
    )
    repository = result.scalar_one_or_none()
    
    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    return repository




