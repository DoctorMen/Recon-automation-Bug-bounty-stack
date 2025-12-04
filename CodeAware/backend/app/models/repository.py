#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Repository database model
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.db.base import Base


class Repository(Base):
    __tablename__ = "repositories"
    
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    name = Column(String, nullable=False)
    full_name = Column(String, nullable=False)  # e.g., "username/repo"
    description = Column(Text)
    
    # Git provider
    provider = Column(String)  # github, gitlab, bitbucket
    provider_id = Column(String)
    provider_url = Column(String)
    
    # Repository info
    default_branch = Column(String, default="main")
    language = Column(String)
    is_private = Column(Boolean, default=False)
    
    # Analysis settings
    auto_analyze = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_analyzed_at = Column(DateTime(timezone=True))
    
    # Relationships
    owner = relationship("User", back_populates="repositories")
    analyses = relationship("Analysis", back_populates="repository")




