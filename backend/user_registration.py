"""
RanScanAI User Registration and Management API
Handles user registration, management, and authentication
"""

from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from datetime import datetime
import logging
import hashlib
import secrets
from typing import Optional, List
from uuid import UUID

# Configure logging
logger = logging.getLogger(__name__)

# Initialize router
router = APIRouter(prefix="/api", tags=["auth"])

# ============================================================================
# Pydantic Models
# ============================================================================

class UserRegisterRequest(BaseModel):
    """User registration request model"""
    first_name: str
    last_name: str
    email: EmailStr
    username: str
    password: str
    phone_number: Optional[str] = None
    role: str = "developer"
    company_id: Optional[str] = None
    department: Optional[str] = None

    @validator('first_name')
    def validate_first_name(cls, v):
        if not v or len(v) < 2 or len(v) > 50:
            raise ValueError('First name must be 2-50 characters')
        if not v.replace('-', '').replace("'", '').replace(' ', '').isalpha():
            raise ValueError('First name can only contain letters, spaces, hyphens, and apostrophes')
        return v.strip()

    @validator('last_name')
    def validate_last_name(cls, v):
        if not v or len(v) < 2 or len(v) > 50:
            raise ValueError('Last name must be 2-50 characters')
        if not v.replace('-', '').replace("'", '').replace(' ', '').isalpha():
            raise ValueError('Last name can only contain letters, spaces, hyphens, and apostrophes')
        return v.strip()

    @validator('username')
    def validate_username(cls, v):
        if not v or len(v) < 3 or len(v) > 20:
            raise ValueError('Username must be 3-20 characters')
        if not v.replace('_', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v.strip()

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in '!@#$%^&*()_+-=[]{};\':"|,.<>?\/' for c in v)
        
        if not (has_upper and has_lower and has_digit and has_special):
            raise ValueError(
                'Password must contain uppercase, lowercase, number, and special character'
            )
        return v

    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ['analyst', 'operator', 'manager', 'developer', 'viewer']
        if v not in allowed_roles:
            raise ValueError(f'Role must be one of: {", ".join(allowed_roles)}')
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "email": "john.doe@company.com",
                "username": "john_doe123",
                "password": "SecurePass@123",
                "phone_number": "+1 (555) 123-4567",
                "role": "analyst",
                "company_id": "550e8400-e29b-41d4-a716-446655440000",
                "department": "Cybersecurity"
            }
        }


class UserResponse(BaseModel):
    """User response model (without sensitive data)"""
    user_id: UUID
    username: str
    email: str
    first_name: str
    last_name: str
    phone_number: Optional[str]
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class RegistrationResponse(BaseModel):
    """Registration response model"""
    success: bool
    message: str
    user: Optional[UserResponse] = None
    error: Optional[str] = None


class CompanyResponse(BaseModel):
    """Company response model"""
    company_id: UUID
    company_name: str
    company_industry: Optional[str]
    company_size: Optional[str]

    class Config:
        from_attributes = True


class CompaniesListResponse(BaseModel):
    """Companies list response"""
    companies: List[CompanyResponse]


# ============================================================================
# Database Models (ORM)
# ============================================================================

# Note: Import from db_manager
from backend.db_manager import Base, AsyncSessionLocal, get_session_maker
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Text, DateTime, Boolean, UUID as SQLAUUID
import uuid as python_uuid

class User(Base):
    """User model for database"""
    __tablename__ = "users"
    
    user_id: Mapped[SQLAUUID] = mapped_column(
        SQLAUUID(as_uuid=True), 
        primary_key=True, 
        default=python_uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))
    phone_number: Mapped[Optional[str]] = mapped_column(String(20), unique=True, nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    role: Mapped[str] = mapped_column(String(50), default='developer')
    company_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Company(Base):
    """Company model"""
    __tablename__ = "companies"
    
    company_id: Mapped[SQLAUUID] = mapped_column(
        SQLAUUID(as_uuid=True), 
        primary_key=True, 
        default=python_uuid.uuid4
    )
    company_name: Mapped[str] = mapped_column(String(255))
    company_industry: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    company_size: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)


# ============================================================================
# Helper Functions
# ============================================================================

def hash_password(password: str) -> str:
    """Hash password using SHA-256 with salt"""
    salt = secrets.token_hex(32)  # 64-character salt
    password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${password_hash}"


def verify_password(password: str, hash_str: str) -> bool:
    """Verify password against hash"""
    try:
        salt, password_hash = hash_str.split('$')
        computed_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        return computed_hash == password_hash
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def get_db_session() -> AsyncSession:
    """Dependency to get database session"""
    session_maker = get_session_maker()
    return session_maker()


# ============================================================================
# API Endpoints
# ============================================================================

@router.post("/auth/register", response_model=RegistrationResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    request: UserRegisterRequest,
    session: AsyncSession = Depends(get_db_session)
):
    """
    Register a new user
    
    Required admin authentication token in Authorization header
    
    Args:
        request: User registration data
        session: Database session
    
    Returns:
        RegistrationResponse with user details
    """
    logger.info(f"Registering new user: {request.username} ({request.email})")
    
    try:
        # Check if username already exists
        stmt = select(User).where(User.username == request.username)
        existing_user = await session.execute(stmt)
        if existing_user.scalar_one_or_none():
            logger.warning(f"Registration failed: Username '{request.username}' already exists")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )

        # Check if email already exists
        stmt = select(User).where(User.email == request.email.lower())
        existing_email = await session.execute(stmt)
        if existing_email.scalar_one_or_none():
            logger.warning(f"Registration failed: Email '{request.email}' already exists")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered"
            )

        # Hash password
        password_hash = hash_password(request.password)

        # Create new user
        new_user = User(
            user_id=python_uuid.uuid4(),
            username=request.username,
            email=request.email.lower(),
            first_name=request.first_name,
            last_name=request.last_name,
            phone_number=request.phone_number or None,
            password_hash=password_hash,
            role=request.role,
            company_id=request.company_id,
            department=request.department or None,
            is_active=True
        )

        # Add to session and commit
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)

        logger.info(f"✓ User registered successfully: {new_user.username} (ID: {new_user.user_id})")

        # Convert to response model
        user_response = UserResponse(
            user_id=new_user.user_id,
            username=new_user.username,
            email=new_user.email,
            first_name=new_user.first_name,
            last_name=new_user.last_name,
            phone_number=new_user.phone_number,
            role=new_user.role,
            is_active=new_user.is_active,
            created_at=new_user.created_at
        )

        return RegistrationResponse(
            success=True,
            message=f"User '{request.username}' registered successfully",
            user=user_response
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again later."
        )


@router.get("/companies", response_model=CompaniesListResponse)
async def get_companies(session: AsyncSession = Depends(get_db_session)):
    """
    Get all active companies for dropdown
    
    Returns:
        List of companies
    """
    try:
        stmt = select(Company).limit(1000)
        result = await session.execute(stmt)
        companies = result.scalars().all()

        return CompaniesListResponse(companies=companies)

    except Exception as e:
        logger.error(f"Error fetching companies: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch companies"
        )


@router.get("/users", response_model=List[UserResponse])
async def get_users(
    company_id: Optional[str] = None,
    role: Optional[str] = None,
    session: AsyncSession = Depends(get_db_session)
):
    """
    Get users with optional filtering
    
    Args:
        company_id: Filter by company
        role: Filter by role
        session: Database session
    
    Returns:
        List of users
    """
    try:
        stmt = select(User)
        
        if company_id:
            stmt = stmt.where(User.company_id == company_id)
        
        if role:
            stmt = stmt.where(User.role == role)
        
        stmt = stmt.order_by(User.created_at.desc()).limit(1000)
        
        result = await session.execute(stmt)
        users = result.scalars().all()

        return [
            UserResponse(
                user_id=user.user_id,
                username=user.username,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name,
                phone_number=user.phone_number,
                role=user.role,
                is_active=user.is_active,
                created_at=user.created_at
            )
            for user in users
        ]

    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users"
        )


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, session: AsyncSession = Depends(get_db_session)):
    """
    Get user by ID
    
    Args:
        user_id: User ID
        session: Database session
    
    Returns:
        User details
    """
    try:
        stmt = select(User).where(User.user_id == python_uuid.UUID(user_id))
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        return UserResponse(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            phone_number=user.phone_number,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at
        )

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    except Exception as e:
        logger.error(f"Error fetching user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user"
        )
