# RanScanAI Authentication System - Installation & Setup Guide

## Overview

This guide will help you set up and run the complete authentication system for RanScanAI.

## Prerequisites

- Python 3.8+
- PostgreSQL database
- Git

## Installation Steps

### 1. Install Required Python Packages

```bash
cd c:\Users\User\RanScanAI\backend
pip install -r requirements.txt
```

This will install all dependencies including authentication libraries:
- bcrypt (password hashing)
- python-jose (JWT tokens)
- passlib (password utilities)
- email-validator (email validation)

### 2. Configure Environment Variables

Create or update `.env` file in the backend directory:

```env
# Database Configuration
DATABASE_URL=postgresql+asyncpg://username:password@host:5432/ranscanai

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-change-this-in-production-123456789
```

**Important**: Generate a secure secret key for production:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Initialize Database

Run the SQL initialization script:

```bash
psql -h your-host -U your-user -d ranscanai -f c:\Users\User\RanScanAI\db-init\init-db.sql
```

Or if using Azure PostgreSQL or other cloud database, run the SQL script using your database management tool.

### 4. Verify Installation

Check that all required files exist:

```
RanScanAI/
├── backend/
│   ├── main.py (updated with auth routes)
│   ├── auth.py (password hashing & JWT)
│   ├── auth_routes.py (API endpoints)
│   ├── schemas.py (Pydantic models)
│   └── db_manager.py (updated with User model)
└── docs/
    └── AUTH_API_DOCUMENTATION.md
```

### 5. Start the Backend Server

```bash
cd c:\Users\User\RanScanAI\backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 6. Test the Authentication System

#### Test Login (Admin):
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

You should receive a response with an access token.

#### Test Create User (Admin Only):
```bash
# First, copy the access_token from the login response above
curl -X POST http://localhost:8000/api/auth/admin/create-user \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@company.com",
    "password": "TestPass123!",
    "first_name": "Test",
    "last_name": "User",
    "role": "user"
  }'
```

## File Descriptions

### Backend Files

#### `auth.py`
- Password hashing with bcrypt (12 rounds)
- JWT token generation and validation
- Token expiration: 24 hours (configurable)

#### `auth_routes.py`
- **Public Routes**:
  - `POST /api/auth/login` - Login for admin and users
  - `GET /api/auth/me` - Get current user info
  
- **Admin Routes**:
  - `POST /api/auth/admin/create-user` - Create new user
  - `GET /api/auth/admin/users` - List all users (with filters)
  - `GET /api/auth/admin/users/{id}` - Get specific user
  - `PATCH /api/auth/admin/users/{id}` - Update user
  - `DELETE /api/auth/admin/users/{id}` - Delete user

#### `schemas.py`
- `UserCreate` - Request model for creating users
- `LoginRequest` - Login credentials
- `UserResponse` - User data in responses
- `Token` - JWT token response
- `UserUpdate` - Update user fields
- `MessageResponse` - Generic messages
- `ErrorResponse` - Error messages

#### `db_manager.py`
- Added `User` model with:
  - Authentication fields (username, email, password_hash)
  - User information (first_name, last_name, phone_number)
  - Role and status (role, is_active)
  - Timestamps (created_at, updated_at, last_login)

## Database Schema

### users Table (Modified for Authentication)

```sql
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone_number TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_login TIMESTAMP WITH TIME ZONE
);
```

### Default Admin Account

- **Username**: `admin`
- **Password**: `admin123` (hash stored in database)
- **Email**: `admin@ranscanai.com`
- **Role**: `admin`

**⚠️ Security Note**: Change the default admin password after first login!

## API Testing

### Using Postman/Insomnia:

1. **Login**:
   - Method: POST
   - URL: `http://localhost:8000/api/auth/login`
   - Body (JSON):
   ```json
   {
     "username": "admin",
     "password": "admin123"
   }
   ```

2. **Create User** (copy token from login response):
   - Method: POST
   - URL: `http://localhost:8000/api/auth/admin/create-user`
   - Headers: `Authorization: Bearer <your_token>`
   - Body (JSON):
   ```json
   {
     "username": "john_doe",
     "email": "john@company.com",
     "password": "SecurePass123!",
     "first_name": "John",
     "last_name": "Doe",
     "role": "user"
   }
   ```

3. **Get User Info**:
   - Method: GET
   - URL: `http://localhost:8000/api/auth/me`
   - Headers: `Authorization: Bearer <your_token>`

## Frontend Integration

See [AUTH_API_DOCUMENTATION.md](./AUTH_API_DOCUMENTATION.md) for:
- Complete API endpoint documentation
- Request/response examples
- React authentication context example
- Protected route implementation
- Error handling patterns

## Troubleshooting

### Issue: "Module not found" errors

**Solution**: Install missing dependencies:
```bash
pip install -r requirements.txt
```

If you still have issues, install authentication packages individually:
```bash
pip install bcrypt python-jose passlib python-multipart email-validator
```

### Issue: Database connection fails

**Solution**: 
1. Verify DATABASE_URL in `.env` file
2. Check PostgreSQL is running
3. Verify database credentials
4. Test connection: `psql -h host -U user -d database`

### Issue: JWT token invalid

**Solution**:
1. Verify JWT_SECRET_KEY is set in `.env`
2. Check token hasn't expired (24 hour default)
3. Ensure token is sent as `Bearer <token>` in Authorization header

### Issue: Cannot create users (403 Forbidden)

**Solution**: 
1. Verify you're logged in as admin role
2. Check admin token is valid and not expired
3. Confirm admin user exists in database

### Issue: Password hash verification fails

**Solution**:
1. Ensure bcrypt is installed: `pip install bcrypt`
2. Check password meets minimum requirements (8 characters)
3. Verify password_hash is stored correctly in database

## Security Recommendations

### For Production Deployment:

1. **Change Default Admin Password**:
   ```sql
   UPDATE users 
   SET password_hash = '<new_bcrypt_hash>' 
   WHERE username = 'admin';
   ```

2. **Generate Secure JWT Secret**:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. **Use HTTPS Only**: Configure your web server (nginx/Apache) with SSL/TLS

4. **Restrict CORS**: Update `main.py` to allow only your frontend domain:
   ```python
   allow_origins=["https://yourdomain.com"]
   ```

5. **Set Strong Password Policy**: Consider adding password complexity requirements

6. **Enable Rate Limiting**: Add rate limiting middleware to prevent brute force attacks

7. **Implement Token Refresh**: Add refresh token mechanism for better security

8. **Use Environment Variables**: Never commit secrets to version control

## Next Steps

1. **Frontend Development**: 
   - Use the API documentation to build login/signup forms
   - Implement protected routes
   - Add user management dashboard for admins

2. **Testing**:
   - Write unit tests for authentication functions
   - Add integration tests for API endpoints
   - Test role-based access control

3. **Enhancements**:
   - Email verification for new accounts
   - Password reset functionality
   - Two-factor authentication (2FA)
   - Session management and logout
   - Audit logging for user actions

## Support

For questions or issues:
- Check the API documentation: [AUTH_API_DOCUMENTATION.md](./AUTH_API_DOCUMENTATION.md)
- Review backend logs for detailed error messages
- Verify all environment variables are correctly configured
