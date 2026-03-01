"""
Pydantic schemas for authentication API
Request and response models for user authentication endpoints
"""

from pydantic import BaseModel, EmailStr, Field, field_serializer, field_validator
from typing import Optional, Any
from datetime import datetime


# ============================================================================
# REQUEST SCHEMAS
# ============================================================================

class UserCreate(BaseModel):
    """
    Schema for creating a new user (admin only)
    """
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password (min 8 characters)")
    first_name: str = Field(..., min_length=1, max_length=100, description="First name")
    last_name: str = Field(..., min_length=1, max_length=100, description="Last name")
    phone_number: Optional[str] = Field(None, max_length=20, description="Phone number (optional)")
    role: str = Field(default="user", description="User role: 'admin' or 'user'")
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "email": "john@company.com",
                "password": "SecurePass123!",
                "first_name": "John",
                "last_name": "Doe",
                "phone_number": "+1234567890",
                "role": "user"
            }
        }


class LoginRequest(BaseModel):
    """
    Schema for login request
    """
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "admin",
                "password": "admin123"
            }
        }


class UserUpdate(BaseModel):
    """
    Schema for updating user information
    """
    email: Optional[EmailStr] = None
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    phone_number: Optional[str] = Field(None, max_length=20)
    is_active: Optional[bool] = None
    role: Optional[str] = Field(None, pattern='^(admin|user)$')
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "newemail@company.com",
                "first_name": "John",
                "last_name": "Smith",
                "phone_number": "+1234567890",
                "is_active": True,
                "role": "user"
            }
        }


class ChangePasswordRequest(BaseModel):
    """
    Schema for changing user password
    """
    old_password: str = Field(..., description="Current password for verification")
    new_password: str = Field(..., min_length=8, description="New password (min 8 characters)")

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v, info):
        """Ensure new password is different from old password"""
        if 'old_password' in info.data and v == info.data['old_password']:
            raise ValueError('New password must be different from old password')
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "old_password": "OldPass123!",
                "new_password": "NewSecurePass456!"
            }
        }


# ============================================================================
# RESPONSE SCHEMAS
# ============================================================================

class UserResponse(BaseModel):
    """
    Schema for user data in responses (excluding sensitive data)
    """
    user_id: str
    username: str
    email: str
    first_name: str
    last_name: str
    phone_number: Optional[str]
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    
    @field_validator('user_id', mode='before')
    @classmethod
    def validate_user_id(cls, value: Any) -> str:
        """Convert UUID to string if needed during validation"""
        if value is None:
            return None
        return str(value)
    
    @field_serializer('user_id')
    def serialize_user_id(self, value):
        """Convert UUID to string if needed during serialization"""
        return str(value) if value else None
    
    class Config:
        from_attributes = True  # Allows conversion from ORM models
        json_schema_extra = {
            "example": {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "john_doe",
                "email": "john@company.com",
                "first_name": "John",
                "last_name": "Doe",
                "phone_number": "+1234567890",
                "role": "user",
                "is_active": True,
                "created_at": "2026-02-20T10:30:00",
                "last_login": "2026-02-20T15:45:00"
            }
        }


class Token(BaseModel):
    """
    Schema for JWT token response
    """
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "user": {
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "username": "admin",
                    "email": "admin@ranscanai.com",
                    "first_name": "Admin",
                    "last_name": "User",
                    "phone_number": None,
                    "role": "admin",
                    "is_active": True,
                    "created_at": "2026-02-20T10:00:00",
                    "last_login": "2026-02-20T15:45:00"
                }
            }
        }


class MessageResponse(BaseModel):
    """
    Generic message response
    """
    message: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "User created successfully"
            }
        }


class ErrorResponse(BaseModel):
    """
    Error response schema
    """
    detail: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "detail": "Invalid credentials"
            }
        }
