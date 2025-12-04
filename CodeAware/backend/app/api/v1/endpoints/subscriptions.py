#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Subscription management endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from datetime import datetime, timedelta

from app.core.security import get_current_user_id
from app.db.session import get_db
from app.models.subscription import Subscription, BillingPeriod, SubscriptionStatus
from app.models.user import User, SubscriptionTier

router = APIRouter()


class SubscriptionCreate(BaseModel):
    tier: str
    billing_period: str = "monthly"


class SubscriptionResponse(BaseModel):
    id: int
    tier: str
    status: str
    billing_period: str
    amount: float
    monthly_scan_limit: int
    scans_used_this_month: int
    current_period_end: datetime = None
    
    class Config:
        from_attributes = True


class PricingPlan(BaseModel):
    tier: str
    name: str
    monthly_price: float
    yearly_price: float
    scan_limit: int
    features: list


@router.get("/pricing", response_model=list[PricingPlan])
async def get_pricing():
    """Get pricing plans"""
    return [
        {
            "tier": "individual",
            "name": "Individual Developer",
            "monthly_price": 29.0,
            "yearly_price": 290.0,
            "scan_limit": 10,
            "features": [
                "10 repository scans per month",
                "Basic code quality analysis",
                "Personal awareness dashboard",
                "Community support",
                "Email reports"
            ]
        },
        {
            "tier": "professional",
            "name": "Professional",
            "monthly_price": 99.0,
            "yearly_price": 990.0,
            "scan_limit": 50,
            "features": [
                "50 repository scans per month",
                "Advanced security scanning",
                "Custom learning paths",
                "Priority email support",
                "API access",
                "Detailed metrics"
            ]
        },
        {
            "tier": "team",
            "name": "Team",
            "monthly_price": 499.0,
            "yearly_price": 4990.0,
            "scan_limit": -1,
            "features": [
                "Unlimited repository scans",
                "Team awareness dashboard",
                "Admin controls",
                "GitHub/GitLab integrations",
                "Dedicated support",
                "Custom rules and policies",
                "Up to 10 team members"
            ]
        },
        {
            "tier": "enterprise",
            "name": "Enterprise",
            "monthly_price": 2999.0,
            "yearly_price": 29990.0,
            "scan_limit": -1,
            "features": [
                "Everything in Team",
                "On-premise deployment option",
                "SSO/SAML integration",
                "SLA guarantees",
                "Executive reporting",
                "Custom integrations",
                "Dedicated success manager",
                "Unlimited team members"
            ]
        }
    ]


@router.post("/", response_model=SubscriptionResponse, status_code=status.HTTP_201_CREATED)
async def create_subscription(
    sub_data: SubscriptionCreate,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Create or upgrade subscription"""
    # Check if subscription exists
    result = await db.execute(select(Subscription).where(Subscription.user_id == user_id))
    existing_sub = result.scalar_one_or_none()
    
    if existing_sub:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Subscription already exists. Use PATCH to update."
        )
    
    # Pricing
    pricing = {
        "individual": {"monthly": 29.0, "yearly": 290.0, "limit": 10},
        "professional": {"monthly": 99.0, "yearly": 990.0, "limit": 50},
        "team": {"monthly": 499.0, "yearly": 4990.0, "limit": -1},
        "enterprise": {"monthly": 2999.0, "yearly": 29990.0, "limit": -1}
    }
    
    if sub_data.tier not in pricing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid subscription tier"
        )
    
    tier_pricing = pricing[sub_data.tier]
    amount = tier_pricing[sub_data.billing_period]
    
    # Create subscription
    subscription = Subscription(
        user_id=user_id,
        tier=sub_data.tier,
        billing_period=BillingPeriod(sub_data.billing_period),
        status=SubscriptionStatus.TRIALING,
        amount=amount,
        monthly_scan_limit=tier_pricing["limit"],
        trial_ends_at=datetime.utcnow() + timedelta(days=14),
        current_period_start=datetime.utcnow(),
        current_period_end=datetime.utcnow() + timedelta(days=30)
    )
    
    db.add(subscription)
    
    # Update user tier
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one()
    user.subscription_tier = SubscriptionTier(sub_data.tier)
    
    await db.commit()
    await db.refresh(subscription)
    
    return subscription


@router.get("/me", response_model=SubscriptionResponse)
async def get_my_subscription(
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's subscription"""
    result = await db.execute(select(Subscription).where(Subscription.user_id == user_id))
    subscription = result.scalar_one_or_none()
    
    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active subscription"
        )
    
    return subscription




