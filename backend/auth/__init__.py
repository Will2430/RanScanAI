"""
Authentication module for RanScanAI
Includes password hashing, JWT tokens, API routes, and schemas
"""

from .utils import hash_password, verify_password, create_access_token, decode_access_token
from .routes import router as auth_router, get_current_user, get_current_admin
from .schemas import (
    UserCreate, LoginRequest, UserResponse, Token,
    MessageResponse, ErrorResponse, UserUpdate
)

__all__ = [
    # Utility functions
    'hash_password',
    'verify_password', 
    'create_access_token',
    'decode_access_token',
    # Dependencies
    'get_current_user',
    'get_current_admin',
    # Router
    'auth_router',
    # Schemas
    'UserCreate',
    'LoginRequest',
    'UserResponse',
    'Token',
    'MessageResponse',
    'ErrorResponse',
    'UserUpdate',
]
