"""
Authentication routes for RanScanAI
Handles user authentication, authorization, and user management
"""

from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from typing import Optional, List
from datetime import datetime
import logging
import uuid

from db_manager import get_session, User
from .utils import hash_password, verify_password, create_access_token, decode_access_token
from .schemas import (
    UserCreate, LoginRequest, UserResponse, Token, 
    MessageResponse, ErrorResponse, UserUpdate
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# Security scheme for protected routes
security = HTTPBearer()


# ============================================================================
# DEPENDENCY FUNCTIONS
# ============================================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_session)
) -> User:
    """
    Dependency to get current authenticated user from JWT token
    Raises 401 if token is invalid or user not found
    """
    token = credentials.credentials
    
    # Decode token
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database
    result = await db.execute(
        select(User).where(User.username == username)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    return user


async def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to ensure current user is an admin
    Raises 403 if user is not admin
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@router.post("/login", response_model=Token, responses={
    401: {"model": ErrorResponse, "description": "Invalid credentials"},
    403: {"model": ErrorResponse, "description": "Account inactive"}
})
async def login(
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_session)
):
    """
    Login endpoint for both admin and users
    
    Returns JWT token and user information
    """
    # Get user from database
    result = await db.execute(
        select(User).where(User.username == login_data.username)
    )
    user = result.scalar_one_or_none()
    
    # Check if user exists and password is correct
    if not user or not verify_password(login_data.password, user.password_hash):
        logger.warning(f"Failed login attempt for username: {login_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Check if account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Please contact administrator."
        )
    
    # Note: last_login update disabled due to SQLAlchemy greenlet issues
    # Can be updated via separate background task or admin endpoint if needed
    
    # Create JWT token
    token_data = {
        "sub": user.username,
        "role": user.role,
        "user_id": str(user.user_id)  # Convert UUID to string for JSON serialization
    }
    access_token = create_access_token(data=token_data)
    
    logger.info(f"User logged in: {user.username} (role: {user.role})")
    
    # Convert user_id to string for response
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.get("/me", response_model=UserResponse, responses={
    401: {"model": ErrorResponse, "description": "Not authenticated"}
})
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Get current authenticated user information
    
    Requires valid JWT token in Authorization header
    """
    return UserResponse.model_validate(current_user)


# ============================================================================
# ADMIN ENDPOINTS - USER MANAGEMENT
# ============================================================================

@router.post("/admin/create-user", response_model=UserResponse, 
             status_code=status.HTTP_201_CREATED,
             responses={
                 403: {"model": ErrorResponse, "description": "Admin privileges required"},
                 409: {"model": ErrorResponse, "description": "User already exists"}
             })
async def create_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_session),
    admin: User = Depends(get_current_admin)
):
    """
    Create a new user account (Admin only)
    
    Only administrators can create user accounts. The newly created user
    will be able to login immediately with the provided credentials.
    """
    # Check if username already exists
    result = await db.execute(
        select(User).where(User.username == user_data.username)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{user_data.username}' already exists"
        )
    
    # Check if email already exists
    result = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Email '{user_data.email}' already exists"
        )
    
    # Validate role
    if user_data.role not in ["admin", "user"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role must be either 'admin' or 'user'"
        )
    
    # Hash password
    password_hash = hash_password(user_data.password)
    
    # Create new user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=password_hash,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        phone_number=user_data.phone_number,
        role=user_data.role,
        is_active=True
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    logger.info(f"Admin '{admin.username}' created new user: {new_user.username} (role: {new_user.role})")
    
    return UserResponse.model_validate(new_user)


@router.get("/admin/users", response_model=List[UserResponse],
            responses={
                403: {"model": ErrorResponse, "description": "Admin privileges required"}
            })
async def list_users(
    skip: int = 0,
    limit: int = 100,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_session),
    admin: User = Depends(get_current_admin)
):
    """
    List all users (Admin only)
    
    Query parameters:
    - skip: Number of records to skip (pagination)
    - limit: Maximum number of records to return
    - role: Filter by role ('admin' or 'user')
    - is_active: Filter by active status (true/false)
    """
    query = select(User)
    
    # Apply filters
    if role:
        query = query.where(User.role == role)
    if is_active is not None:
        query = query.where(User.is_active == is_active)
    
    # Apply pagination
    query = query.offset(skip).limit(limit).order_by(User.created_at.desc())
    
    result = await db.execute(query)
    users = result.scalars().all()
    
    return [UserResponse.model_validate(user) for user in users]


@router.get("/admin/users/{user_id}", response_model=UserResponse,
            responses={
                403: {"model": ErrorResponse, "description": "Admin privileges required"},
                404: {"model": ErrorResponse, "description": "User not found"}
            })
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_session),
    admin: User = Depends(get_current_admin)
):
    """
    Get specific user by ID (Admin only)
    """
    # Convert string to UUID
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID format: {user_id}"
        )
    
    result = await db.execute(
        select(User).where(User.user_id == user_uuid)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    return UserResponse.model_validate(user)


@router.patch("/admin/users/{user_id}", response_model=UserResponse,
              responses={
                  403: {"model": ErrorResponse, "description": "Admin privileges required"},
                  404: {"model": ErrorResponse, "description": "User not found"}
              })
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_session),
    admin: User = Depends(get_current_admin)
):
    """
    Update user information (Admin only)
    
    Can update email, name, phone number, and active status
    """
    # Convert string to UUID
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID format: {user_id}"
        )
    
    result = await db.execute(
        select(User).where(User.user_id == user_uuid)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Update fields if provided
    if user_update.email is not None:
        # Check if email already exists for another user
        result = await db.execute(
            select(User).where(User.email == user_update.email, User.user_id != user_uuid)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Email '{user_update.email}' already exists"
            )
        user.email = user_update.email
    
    if user_update.first_name is not None:
        user.first_name = user_update.first_name
    if user_update.last_name is not None:
        user.last_name = user_update.last_name
    if user_update.phone_number is not None:
        user.phone_number = user_update.phone_number
    if user_update.is_active is not None:
        user.is_active = user_update.is_active
    
    user.updated_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(user)
    
    logger.info(f"Admin '{admin.username}' updated user: {user.username}")
    
    return UserResponse.model_validate(user)


@router.delete("/admin/users/{user_id}", response_model=MessageResponse,
               responses={
                   403: {"model": ErrorResponse, "description": "Admin privileges required"},
                   404: {"model": ErrorResponse, "description": "User not found"}
               })
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_session),
    admin: User = Depends(get_current_admin)
):
    """
    Delete user (Admin only)
    
    Note: This permanently deletes the user from the database.
    Consider deactivating instead using PATCH /admin/users/{user_id}
    """
    # Convert string to UUID
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID format: {user_id}"
        )
    
    result = await db.execute(
        select(User).where(User.user_id == user_uuid)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Prevent admin from deleting themselves
    if user.user_id == admin.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    username = user.username
    await db.delete(user)
    await db.commit()
    
    logger.warning(f"Admin '{admin.username}' deleted user: {username}")
    
    return MessageResponse(message=f"User '{username}' deleted successfully")
