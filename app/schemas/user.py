from typing import Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, EmailStr, ConfigDict, Field


# ================================
# User Schemas
# ================================


class UserRead(BaseModel):
    """Schema for getting user details without password hash"""
    id: UUID
    username: str
    email: EmailStr
    created_at: datetime


    model_config = ConfigDict(from_attributes=True)

# --------------------------
# Schema for authentication token response
# --------------------------

class Token(BaseModel):
    """Schema for authentication token response"""
    access_token: str
    token_type: str = "bearer"
    user: UserRead

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "bearer",
                "user": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "username": "mikehegar",
                    "email": "mike.hegar@example.com",
                    "is_active": True,
                    "created_at": "2025-01-01T00:00:00",
                },
            }
        }
    )


class TokenData(BaseModel):
    """Schema for JWT token payload"""
    user_id: Optional[UUID] = None

# --------------------------
# Schema for user login
# --------------------------
class UserLogin(BaseModel):
    """Schema for user login"""
    username: str
    password: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "mikehegar123",
                "password": "SecurePass123",
            }
        }
    )
