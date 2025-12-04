#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
User database model
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum

from app.db.base import Base


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"
    ENTERPRISE_ADMIN = "enterprise_admin"


class SubscriptionTier(str, enum.Enum):
    FREE = "free"
    INDIVIDUAL = "individual"
    PROFESSIONAL = "professional"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    
    role = Column(Enum(UserRole), default=UserRole.USER)
    subscription_tier = Column(Enum(SubscriptionTier), default=SubscriptionTier.FREE)
    
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # API access
    api_key = Column(String, unique=True, index=True)
    
    # GitHub integration
    github_username = Column(String)
    github_access_token = Column(String)
    
    # GitLab integration
    gitlab_username = Column(String)
    gitlab_access_token = Column(String)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login_at = Column(DateTime(timezone=True))
    
    # Relationships
    repositories = relationship("Repository", back_populates="owner")
    analyses = relationship("Analysis", back_populates="user")
    subscription = relationship("Subscription", back_populates="user", uselist=False)




