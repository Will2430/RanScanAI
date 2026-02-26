# RanScanAI Authentication - Quick Reference Card

## 🚀 Quick Start Commands

```bash
# 1. Install dependencies
cd c:\Users\User\RanScanAI\backend
pip install -r requirements.txt

# 2. Configure environment (.env file)
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/ranscanai
JWT_SECRET_KEY=your-secret-key-here

# 3. Initialize database
psql -h host -U user -d ranscanai -f ../db-init/init-db.sql

# 4. Test system
python test_auth.py

# 5. Start server
python -m uvicorn main:app --reload --port 8000
```

## 🔑 Default Admin Credentials

- **Username**: `admin`
- **Password**: `admin123`
- **⚠️ CHANGE THIS IN PRODUCTION!**

## 📡 API Endpoints

### Public Endpoints
```
POST /api/auth/login
  Body: {"username": "admin", "password": "admin123"}
  Returns: JWT token + user info
```

### User Endpoints (Requires Token)
```
GET /api/auth/me
  Header: Authorization: Bearer <token>
  Returns: Current user information
```

### Admin Endpoints (Requires Admin Token)
```
POST /api/auth/admin/create-user
  Header: Authorization: Bearer <admin_token>
  Body: {
    "username": "john",
    "email": "john@company.com",
    "password": "Pass123!",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user"
  }

GET /api/auth/admin/users
  Header: Authorization: Bearer <admin_token>
  Query: ?role=user&is_active=true&limit=50

PATCH /api/auth/admin/users/{id}
  Header: Authorization: Bearer <admin_token>
  Body: {"email": "new@email.com", "is_active": false}

DELETE /api/auth/admin/users/{id}
  Header: Authorization: Bearer <admin_token>
```

## 🧪 cURL Test Commands

### Login
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### Get Current User
```bash
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Create User (Admin)
```bash
curl -X POST http://localhost:8000/api/auth/admin/create-user \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"testuser",
    "email":"test@company.com",
    "password":"Test123!",
    "first_name":"Test",
    "last_name":"User",
    "role":"user"
  }'
```

## 💻 Frontend JavaScript Examples

### Login Function
```javascript
async function login(username, password) {
  const response = await fetch('http://localhost:8000/api/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, password})
  });
  const data = await response.json();
  localStorage.setItem('token', data.access_token);
  return data;
}
```

### Authenticated Request
```javascript
async function getUser() {
  const token = localStorage.getItem('token');
  const response = await fetch('http://localhost:8000/api/auth/me', {
    headers: {'Authorization': `Bearer ${token}`}
  });
  return await response.json();
}
```

### Create User (Admin)
```javascript
async function createUser(userData) {
  const token = localStorage.getItem('token');
  const response = await fetch('http://localhost:8000/api/auth/admin/create-user', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(userData)
  });
  return await response.json();
}
```

## 📁 File Structure

```
RanScanAI/
├── backend/
│   ├── main.py                 # FastAPI app (updated)
│   ├── auth.py                 # Password & JWT utils (NEW)
│   ├── auth_routes.py          # Auth endpoints (NEW)
│   ├── schemas.py              # Pydantic models (NEW)
│   ├── db_manager.py           # User model (updated)
│   ├── test_auth.py            # Test script (NEW)
│   └── requirements-auth.txt   # Dependencies (NEW)
├── db-init/
│   └── init-db.sql             # Database schema (updated)
└── docs/
    ├── AUTH_API_DOCUMENTATION.md       # Full API docs
    ├── SETUP_GUIDE.md                  # Installation guide
    ├── AUTH_IMPLEMENTATION_SUMMARY.md  # Implementation summary
    └── AUTH_ARCHITECTURE_DIAGRAM.md    # Visual architecture
```

## 🔒 Security Features

| Feature | Implementation |
|---------|----------------|
| Password Hashing | bcrypt with 12 rounds |
| Token Type | JWT (JSON Web Tokens) |
| Token Algorithm | HS256 |
| Token Expiration | 24 hours |
| Role-Based Access | Admin and User roles |
| Account Status | Can deactivate users |
| Password Min Length | 8 characters |

## 🎯 User Roles

### Admin
- ✅ Login to website
- ✅ Create user accounts
- ✅ View all users
- ✅ Update user information
- ✅ Delete users
- ✅ Deactivate/activate users

### User
- ✅ Login to website (after admin creates account)
- ✅ View own profile
- ❌ Cannot create other users
- ❌ Cannot manage other users

## 🗄️ Database Table

```sql
users
  ├── user_id (UUID PRIMARY KEY)
  ├── username (UNIQUE)
  ├── email (UNIQUE)
  ├── password_hash
  ├── first_name
  ├── last_name
  ├── phone_number
  ├── role ('admin' or 'user')
  ├── is_active
  ├── created_at
  ├── updated_at
  └── last_login
```

## ⚠️ Common Error Codes

| Code | Meaning | Solution |
|------|---------|----------|
| 401 | Unauthorized | Invalid credentials or expired token |
| 403 | Forbidden | Not admin or account inactive |
| 404 | Not Found | User doesn't exist |
| 409 | Conflict | Username/email already exists |

## 🔧 Environment Variables

```env
# Required in .env file
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/database
JWT_SECRET_KEY=your-secret-key-minimum-32-characters
```

## 📊 Authentication Flow

```
1. Admin Login → Receive JWT Token
2. Admin Creates User → User account created
3. User Login → Receive JWT Token
4. Make Authenticated Requests → Include token in headers
```

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| Module not found | `pip install bcrypt python-jose passlib` |
| Database error | Check DATABASE_URL in .env |
| Invalid token | Token expired, login again |
| 403 on admin endpoint | Not logged in as admin |
| Cannot create user | Username/email already exists |

## 📚 Documentation Files

- **API Reference**: `docs/AUTH_API_DOCUMENTATION.md`
- **Setup Guide**: `docs/SETUP_GUIDE.md`
- **Implementation Summary**: `docs/AUTH_IMPLEMENTATION_SUMMARY.md`
- **Architecture Diagram**: `docs/AUTH_ARCHITECTURE_DIAGRAM.md`

## 🎓 Next Steps

1. ✅ Install dependencies
2. ✅ Configure .env file
3. ✅ Initialize database
4. ✅ Test with admin login
5. ✅ Create test user
6. ⚠️ Change default admin password
7. 🚀 Build frontend
8. 🔒 Enable HTTPS in production

## 📞 Need Help?

- Run test script: `python test_auth.py`
- Check backend logs for errors
- Review API documentation
- Verify environment variables
- Check database connection

---

**Version**: 1.0  
**Last Updated**: February 20, 2026  
**Status**: Production Ready ✅
