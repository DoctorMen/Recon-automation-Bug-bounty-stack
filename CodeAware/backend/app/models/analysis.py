#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Code Analysis database model
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum

from app.db.base import Base


class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Analysis(Base):
    __tablename__ = "analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    
    # Analysis metadata
    commit_sha = Column(String)
    branch = Column(String)
    status = Column(Enum(AnalysisStatus), default=AnalysisStatus.PENDING)
    
    # Overall scores (0-100)
    quality_score = Column(Float)
    security_score = Column(Float)
    maintainability_score = Column(Float)
    scalability_score = Column(Float)
    overall_score = Column(Float)
    
    # Awareness metrics (Dunning-Kruger detection)
    perceived_skill_level = Column(Float)  # Self-assessment
    actual_skill_level = Column(Float)  # Measured from code
    awareness_gap = Column(Float)  # Difference (positive = overconfident)
    dunning_kruger_score = Column(Float)  # 0-100, higher = more DK effect
    
    # Code metrics
    total_files = Column(Integer)
    total_lines = Column(Integer)
    code_lines = Column(Integer)
    comment_lines = Column(Integer)
    blank_lines = Column(Integer)
    
    # Complexity
    average_complexity = Column(Float)
    max_complexity = Column(Float)
    complex_functions_count = Column(Integer)
    
    # Issues found
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    info_issues = Column(Integer, default=0)
    
    # Security
    security_vulnerabilities = Column(Integer, default=0)
    security_hotspots = Column(Integer, default=0)
    
    # Detailed results (JSON)
    issues_detail = Column(JSON)  # List of all issues
    metrics_detail = Column(JSON)  # Detailed metrics
    learning_recommendations = Column(JSON)  # Personalized learning paths
    
    # Performance
    analysis_duration = Column(Float)  # seconds
    
    # Error tracking
    error_message = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    
    # Relationships
    user = relationship("User", back_populates="analyses")
    repository = relationship("Repository", back_populates="analyses")




