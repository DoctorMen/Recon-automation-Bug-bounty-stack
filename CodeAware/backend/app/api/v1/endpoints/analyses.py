#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Code Analysis endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import List, Optional
import tempfile
import shutil
import git
from datetime import datetime

from app.core.security import get_current_user_id
from app.db.session import get_db
from app.models.analysis import Analysis, AnalysisStatus
from app.models.repository import Repository
from app.services.code_analyzer import CodeAnalyzer
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


class AnalysisRequest(BaseModel):
    repository_id: int
    branch: Optional[str] = "main"


class AnalysisResponse(BaseModel):
    id: int
    repository_id: int
    status: str
    quality_score: Optional[float]
    security_score: Optional[float]
    maintainability_score: Optional[float]
    scalability_score: Optional[float]
    overall_score: Optional[float]
    actual_skill_level: Optional[float]
    awareness_gap: Optional[float]
    dunning_kruger_score: Optional[float]
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class DetailedAnalysisResponse(AnalysisResponse):
    total_files: Optional[int]
    total_lines: Optional[int]
    average_complexity: Optional[float]
    issues_detail: Optional[dict]
    learning_recommendations: Optional[list]


async def run_analysis_task(analysis_id: int, repo_path: str, db: AsyncSession):
    """Background task to run code analysis"""
    try:
        # Update status to running
        result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
        analysis = result.scalar_one()
        analysis.status = AnalysisStatus.RUNNING
        await db.commit()
        
        # Run analysis
        start_time = datetime.utcnow()
        analyzer = CodeAnalyzer(repo_path)
        result = analyzer.analyze()
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Update analysis with results
        analysis.status = AnalysisStatus.COMPLETED
        analysis.quality_score = result.quality_score
        analysis.security_score = result.security_score
        analysis.maintainability_score = result.maintainability_score
        analysis.scalability_score = result.scalability_score
        analysis.overall_score = result.overall_score
        analysis.actual_skill_level = result.actual_skill_level
        analysis.awareness_gap = result.awareness_gap
        analysis.dunning_kruger_score = result.dunning_kruger_score
        analysis.total_files = result.total_files
        analysis.total_lines = result.total_lines
        analysis.code_lines = result.code_lines
        analysis.comment_lines = result.comment_lines
        analysis.blank_lines = result.blank_lines
        analysis.average_complexity = result.average_complexity
        analysis.max_complexity = result.max_complexity
        analysis.complex_functions_count = result.complex_functions_count
        analysis.critical_issues = result.critical_issues
        analysis.high_issues = result.high_issues
        analysis.medium_issues = result.medium_issues
        analysis.low_issues = result.low_issues
        analysis.info_issues = result.info_issues
        analysis.security_vulnerabilities = result.security_vulnerabilities
        analysis.issues_detail = [
            {
                'severity': issue.severity,
                'category': issue.category,
                'message': issue.message,
                'file_path': issue.file_path,
                'line_number': issue.line_number,
                'code_snippet': issue.code_snippet,
                'recommendation': issue.recommendation
            }
            for issue in result.issues
        ]
        analysis.learning_recommendations = result.learning_recommendations
        analysis.analysis_duration = duration
        analysis.completed_at = datetime.utcnow()
        
        await db.commit()
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
        analysis = result.scalar_one()
        analysis.status = AnalysisStatus.FAILED
        analysis.error_message = str(e)
        await db.commit()
    
    finally:
        # Cleanup temp directory
        try:
            shutil.rmtree(repo_path)
        except:
            pass


@router.post("/", response_model=AnalysisResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_analysis(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Start a new code analysis"""
    # Get repository
    result = await db.execute(
        select(Repository).where(
            Repository.id == request.repository_id,
            Repository.owner_id == user_id
        )
    )
    repository = result.scalar_one_or_none()
    
    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    # Create analysis record
    analysis = Analysis(
        user_id=user_id,
        repository_id=repository.id,
        branch=request.branch or repository.default_branch,
        status=AnalysisStatus.PENDING
    )
    
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)
    
    # Clone repository to temp directory
    temp_dir = tempfile.mkdtemp()
    try:
        repo = git.Repo.clone_from(repository.provider_url, temp_dir, branch=request.branch)
        analysis.commit_sha = repo.head.commit.hexsha
        await db.commit()
        
        # Start background analysis
        background_tasks.add_task(run_analysis_task, analysis.id, temp_dir, db)
        
    except Exception as e:
        logger.error(f"Failed to clone repository: {e}")
        shutil.rmtree(temp_dir)
        analysis.status = AnalysisStatus.FAILED
        analysis.error_message = f"Failed to clone repository: {str(e)}"
        await db.commit()
    
    return analysis


@router.get("/{analysis_id}", response_model=DetailedAnalysisResponse)
async def get_analysis(
    analysis_id: int,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Get analysis results"""
    result = await db.execute(
        select(Analysis).where(
            Analysis.id == analysis_id,
            Analysis.user_id == user_id
        )
    )
    analysis = result.scalar_one_or_none()
    
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found"
        )
    
    return analysis


@router.get("/", response_model=List[AnalysisResponse])
async def list_analyses(
    skip: int = 0,
    limit: int = 20,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """List user's analyses"""
    result = await db.execute(
        select(Analysis)
        .where(Analysis.user_id == user_id)
        .order_by(desc(Analysis.created_at))
        .offset(skip)
        .limit(limit)
    )
    analyses = result.scalars().all()
    
    return analyses




