# Authentication Module

This folder contains all authentication-related code for RanScanAI.

## Structure

```
auth/
├── __init__.py       # Package initialization, exports main components
├── utils.py          # Password hashing and JWT token utilities
├── routes.py         # FastAPI authentication endpoints
└── schemas.py        # Pydantic request/response models
```

## Components

### utils.py
Core authentication utilities:
- `hash_password()` - Hash passwords with bcrypt (12 rounds)
- `verify_password()` - Verify password against hash
- `create_access_token()` - Generate JWT tokens (24-hour expiration)
- `decode_access_token()` - Decode and validate JWT tokens

### routes.py
FastAPI router with 7 endpoints:
- `POST /api/auth/login` - Login (public)
- `GET /api/auth/me` - Get current user (authenticated)
- `POST /api/auth/admin/create-user` - Create user (admin only)
- `GET /api/auth/admin/users` - List users (admin only)
- `GET /api/auth/admin/users/{user_id}` - Get user by ID (admin only)
- `PATCH /api/auth/admin/users/{user_id}` - Update user (admin only)
- `DELETE /api/auth/admin/users/{user_id}` - Delete user (admin only)

### schemas.py
Pydantic models for validation and serialization:
- `UserCreate` - Create user request
- `LoginRequest` - Login credentials
- `UserUpdate` - Update user request
- `UserResponse` - User data response
- `Token` - JWT token response
- `MessageResponse` - Generic message
- `ErrorResponse` - Error details

## Usage

### In main.py:
```python
from auth import auth_router

app.include_router(auth_router)
```

### In other modules:
```python
from auth import hash_password, verify_password, create_access_token
from auth import UserCreate, UserResponse, Token

# Use the functions
hashed = hash_password("password123")
is_valid = verify_password("password123", hashed)
token = create_access_token({"sub": "username", "role": "admin"})
```

## Configuration

Set environment variables in `.env`:
```
JWT_SECRET_KEY=your-secret-key-change-in-production
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname?ssl=require
```

## Testing

Helper scripts in `backend/` folder:
- `setup_admin.py` - Create/check admin user in database
- `test_auth.py` - Test authentication endpoints
- `debug_login.py` - Debug login and password verification
- `test_db_connection.py` - Test database connectivity

## Documentation

See `/docs/AUTH_API_DOCUMENTATION.md` for complete API documentation with examples.
