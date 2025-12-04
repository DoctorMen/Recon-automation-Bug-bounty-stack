#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Base class for database models
"""
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# Import all models here for Alembic
from app.models.user import User
from app.models.repository import Repository
from app.models.analysis import Analysis
from app.models.subscription import Subscription




