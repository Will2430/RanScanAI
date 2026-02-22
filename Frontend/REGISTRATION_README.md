# RanScanAI User Registration System

## Overview

This document describes the complete user registration system for RanScanAI, including the frontend registration page, backend API endpoints, and database schema.

## Project Structure

```
Frontend/
├── registration.html            # Main registration form page
├── registration_styles.css      # Styling for registration page
└── registration_script.js       # Form validation and submission logic

Backend/
├── user_registration.py         # Registration API endpoints
└── main.py                      # Main FastAPI app (needs router integration)

Database/
├── init-db.sql                  # Initial database schema
└── user_registration_schema.sql # User registration specific schema
```

---

## Frontend Components

### 1. registration.html
The main registration page featuring:
- **Personal Information Section**: First name, last name, email, phone
- **Account Information Section**: Username, password, role selection
- **Company Information Section**: Company assignment and department
- **Form Validation**: Real-time client-side validation
- **Error Handling**: Inline error messages for each field
- **Loading State**: Visual feedback during submission

**Key Features:**
- Responsive design (desktop, tablet, mobile)
- Accessibility compliant
- Progressive enhancement
- Clear visual hierarchy

### 2. registration_styles.css
Professional styling including:
- Modern color scheme with CSS variables
- Smooth animations and transitions
- Form field styling and error states
- Password strength indicator
- Alert/message components
- Responsive breakpoints (768px, 600px)
- Print-friendly styles

### 3. registration_script.js
Frontend logic handling:
- Form validation (email format, password strength, username uniqueness patterns)
- Real-time field validation
- Password strength meter
- API communication
- Error and success message display
- Loading states

**Validation Rules:**
```javascript
- First/Last Name: 2-50 characters, letters only
- Username: 3-20 characters, alphanumeric + underscore
- Email: Valid email format
- Password: 8+ characters, uppercase, lowercase, number, special char
- Phone: Optional, format validation included
- Role: Required, predefined roles
- Company: Required from dropdown
```

---

## Backend API Endpoints

### Base URL
```
http://localhost:8000/api
```

### 1. Register User
**Endpoint:** `POST /auth/register`

**Request Headers:**
```
Content-Type: application/json
Authorization: Bearer {admin_token}
```

**Request Body:**
```json
{
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
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "User 'john_doe123' registered successfully",
  "user": {
    "user_id": "550e8400-e29b-41d4-a716-446655440001",
    "username": "john_doe123",
    "email": "john.doe@company.com",
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+1 (555) 123-4567",
    "role": "analyst",
    "is_active": true,
    "created_at": "2026-02-22T10:30:00Z"
  }
}
```

**Error Responses:**
```json
{
  "detail": "Username already exists"
}
```

### 2. Get Companies
**Endpoint:** `GET /companies`

**Response:**
```json
{
  "companies": [
    {
      "company_id": "550e8400-e29b-41d4-a716-446655440000",
      "company_name": "TechCorp Inc",
      "company_industry": "Technology",
      "company_size": "500-1000"
    }
  ]
}
```

### 3. Get Users
**Endpoint:** `GET /users?company_id=xxx&role=analyst`

**Query Parameters:**
- `company_id` (optional): Filter by company
- `role` (optional): Filter by role

**Response:**
```json
[
  {
    "user_id": "550e8400-e29b-41d4-a716-446655440001",
    "username": "john_doe123",
    "email": "john.doe@company.com",
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+1 (555) 123-4567",
    "role": "analyst",
    "is_active": true,
    "created_at": "2026-02-22T10:30:00Z"
  }
]
```

### 4. Get User by ID
**Endpoint:** `GET /users/{user_id}`

**Response:** Same as Get Users single user format

---

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone_number TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN DEFAULT true,
    role TEXT DEFAULT 'developer',
    company_id UUID REFERENCES Companies(company_id),
    department TEXT,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);
```

### Indexes Created
- `idx_users_company_id`: For company filtering
- `idx_users_role`: For role-based queries
- `idx_users_is_active`: For active user queries
- `idx_users_created_at`: For sorting

### Additional Tables (user_registration_schema.sql)
- `user_roles`: Role definitions and permissions
- `user_audit_log`: Track user actions
- `user_sessions`: Session management
- `user_preferences`: User settings
- `user_activity`: User activity logging
- `password_reset_tokens`: Password recovery

---

## Installation & Setup

### Step 1: Database Setup
Run the SQL scripts to set up tables:
```bash
# Using psql
psql -h YOUR_HOST -U YOUR_USER -d YOUR_DB -f db-init/init-db.sql
psql -h YOUR_HOST -U YOUR_USER -d YOUR_DB -f db-init/user_registration_schema.sql
```

### Step 2: Backend Integration
Update `backend/main.py` to include registration router:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.user_registration import router as auth_router

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include registration router
app.include_router(auth_router)

# ... rest of your app ...
```

### Step 3: Environment Configuration
Create `.env` file in backend directory:
```
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/ranscanai
JWT_SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
```

### Step 4: Python Dependencies
Ensure requirements.txt includes:
```
fastapi==0.128.0
sqlalchemy==2.0.0
pydantic==2.0.0
pydantic[email]==2.0.0
python-dotenv==1.0.0
asyncpg==0.31.0
```

### Step 5: Run Application
```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 6: Serve Frontend
Serve the Frontend folder with your web server:
```bash
# Using Python
python -m http.server 8080 --directory Frontend

# Or using Node.js http-server
npx http-server Frontend -p 8080
```

---

## Usage

### For Admin Users
1. Navigate to: `http://localhost:8080/registration.html`
2. Fill in user details
3. Select user role and company
4. Click "Register User"
5. Confirmation message appears
6. User can immediately start using the system

### User Roles
- **Analyst**: Full scan and reporting capabilities
- **Operator**: Operational tasks and monitoring
- **Manager**: User management and oversight
- **Developer**: Development and testing access
- **Viewer**: Read-only access
- **Admin**: Full system access

---

## Field Validations

### Frontend Validations
- Real-time as user types
- Regex pattern matching
- Format verification
- Duplicate checking patterns

### Backend Validations
- Pydantic model validation
- Database constraint checking
- Unique constraint enforcement
- Password strength verification

---

## Security Features

1. **Password Security**
   - SHA-256 with salt
   - Strength requirements enforced
   - Hashed storage, never plain text

2. **Authentication**
   - JWT token-based (ready for integration)
   - Authorization headers
   - Admin-only registration

3. **Data Protection**
   - HTTPS ready
   - CORS configured
   - Input sanitization
   - SQL injection prevention (SQLAlchemy ORM)

4. **Audit Logging**
   - User registration logged
   - Timestamps recorded
   - Action tracking available

---

## Troubleshooting

### Issue: "Companies dropdown empty"
- Verify Companies table has records
- Check database connection
- Review browser console for API errors

### Issue: "Email already registered"
- Check if user email exists in database
- Use unique email for new registration

### Issue: "Password strength indicator not showing"
- Ensure JavaScript enabled
- Check browser console for errors
- Verify registration_script.js loaded

### Issue: "Database connection failed"
- Verify DATABASE_URL in .env
- Check PostgreSQL service running
- Verify credentials and permissions

---

## Future Enhancements

1. **Multi-factor Authentication (MFA)**
2. **LDAP/Active Directory Integration**
3. **Bulk user import (CSV)**
4. **User profile management**
5. **Role-based access control (RBAC)**
6. **Email verification workflow**
7. **SSO integration**
8. **Advanced audit logging**

---

## API Documentation

For interactive API documentation:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## Support

For issues or questions:
1. Check console logs for errors
2. Verify database connectivity
3. Review validation messages
4. Check backend logs for API errors

---

## License

© 2026 RanScanAI. All rights reserved.
