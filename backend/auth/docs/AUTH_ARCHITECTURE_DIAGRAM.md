# RanScanAI Authentication System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           FRONTEND (React/Vue/etc)                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐             │
│  │ Login Page   │    │ Dashboard    │    │ Admin Panel  │             │
│  │              │    │              │    │              │             │
│  │ - Username   │    │ - User Info  │    │ - Create User│             │
│  │ - Password   │    │ - Protected  │    │ - List Users │             │
│  │ - Submit     │    │   Content    │    │ - Edit User  │             │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘             │
│         │                   │                   │                      │
│         └───────────────────┴───────────────────┘                      │
│                             │                                           │
│                    ┌────────▼────────┐                                 │
│                    │ Authentication  │                                 │
│                    │     Context     │                                 │
│                    │                 │                                 │
│                    │ - Store Token   │                                 │
│                    │ - Store User    │                                 │
│                    │ - Auth State    │                                 │
│                    └────────┬────────┘                                 │
│                             │                                           │
└─────────────────────────────┼───────────────────────────────────────────┘
                              │
                              │ HTTP Requests (JWT in headers)
                              │
┌─────────────────────────────▼───────────────────────────────────────────┐
│                      BACKEND (FastAPI)                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                        main.py                                     │ │
│  │  ┌─────────────────────────────────────────────────────────────┐  │ │
│  │  │  FastAPI App                                                 │  │ │
│  │  │  - CORS Middleware                                          │  │ │
│  │  │  - Include Auth Router                                      │  │ │
│  │  └─────────────────────────────────────────────────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                │                                         │
│                                ▼                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                    auth_routes.py                                  │ │
│  │                                                                    │ │
│  │  PUBLIC ENDPOINTS:                                                │ │
│  │  ┌────────────────────────────────────────────────────────────┐  │ │
│  │  │ POST /api/auth/login                                       │  │ │
│  │  │  - Validate credentials                                    │  │ │
│  │  │  - Generate JWT token ──────────┐                         │  │ │
│  │  │  - Return token + user info     │                         │  │ │
│  │  └────────────────────────────────────────────────────────────┘  │ │
│  │                                      │                            │ │
│  │  USER ENDPOINTS (Requires JWT):     │                            │ │
│  │  ┌────────────────────────────────────────────────────────────┐  │ │
│  │  │ GET /api/auth/me                │                          │  │ │
│  │  │  - Decode JWT token ◄───────────┘                          │  │ │
│  │  │  - Get user from DB                                        │  │ │
│  │  │  - Return user info                                        │  │ │
│  │  └────────────────────────────────────────────────────────────┘  │ │
│  │                                                                    │ │
│  │  ADMIN ENDPOINTS (Requires Admin JWT):                            │ │
│  │  ┌────────────────────────────────────────────────────────────┐  │ │
│  │  │ POST /api/auth/admin/create-user                          │  │ │
│  │  │  - Verify admin role                                       │  │ │
│  │  │  - Hash password ────────────┐                            │  │ │
│  │  │  - Create user in DB         │                            │  │ │
│  │  │                               │                            │  │ │
│  │  │ GET /api/auth/admin/users     │                            │  │ │
│  │  │  - Verify admin role          │                            │  │ │
│  │  │  - List all users             │                            │  │ │
│  │  │                               │                            │  │ │
│  │  │ PATCH /api/auth/admin/users/{id}                           │  │ │
│  │  │ DELETE /api/auth/admin/users/{id}                          │  │ │
│  │  └────────────────────────────────────────────────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                    │                           │                        │
│                    ▼                           ▼                        │
│  ┌─────────────────────────┐    ┌──────────────────────────────┐      │
│  │      auth.py            │    │       schemas.py             │      │
│  ├─────────────────────────┤    ├──────────────────────────────┤      │
│  │ hash_password()         │    │ UserCreate                   │      │
│  │ verify_password()       │    │ LoginRequest                 │      │
│  │ create_access_token()   │    │ UserResponse                 │      │
│  │ decode_access_token()   │    │ Token                        │      │
│  │                         │    │ UserUpdate                   │      │
│  │ Uses: bcrypt (12 rounds)│    │ MessageResponse              │      │
│  │       JWT (HS256)       │    │ ErrorResponse                │      │
│  └─────────────────────────┘    └──────────────────────────────┘      │
│                    │                                                    │
│                    ▼                                                    │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                    db_manager.py                                   │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │  SQLAlchemy ORM Models:                                           │ │
│  │                                                                    │ │
│  │  class User(Base):                                                │ │
│  │    __tablename__ = "users"                                        │ │
│  │    - user_id (UUID), username, email                              │ │
│  │    - password_hash (bcrypt)                                       │ │
│  │    - first_name, last_name, phone_number                          │ │
│  │    - role (admin/user)                                            │ │
│  │    - is_active                                                    │ │
│  │    - created_at, updated_at, last_login                           │ │
│  │                                                                    │ │
│  │  Functions:                                                        │ │
│  │  - get_session() - DB session dependency                          │ │
│  │  - init_db() - Initialize database                                │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                  │                                      │
└──────────────────────────────────┼──────────────────────────────────────┘
                                   │
                                   │ SQLAlchemy (AsyncPG)
                                   │
┌──────────────────────────────────▼──────────────────────────────────────┐
│                        PostgreSQL DATABASE                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                      users table                                   │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │ user_id (UUID PRIMARY KEY)                                        │ │
│  │ username (VARCHAR UNIQUE)                                         │ │
│  │ email (VARCHAR UNIQUE)                                            │ │
│  │ password_hash (VARCHAR) ← bcrypt hash                             │ │
│  │ first_name, last_name (VARCHAR)                                   │ │
│  │ phone_number (VARCHAR)                                            │ │
│  │ role (VARCHAR) ← 'admin' or 'user'                                │ │
│  │ is_active (BOOLEAN)                                               │ │
│  │ created_at, updated_at, last_login (TIMESTAMP)                    │ │
│  │                                                                    │ │
│  │ Indexes:                                                           │ │
│  │  - idx_users_username                                             │ │
│  │  - idx_users_email                                                │ │
│  │  - idx_users_role                                                 │ │
│  │  - idx_users_is_active                                            │ │
│  │                                                                    │ │
│  │ Default Data:                                                      │ │
│  │  username: admin                                                  │ │
│  │  password: admin123 (hashed)                                      │ │
│  │  role: admin                                                      │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════
                           AUTHENTICATION FLOW
═══════════════════════════════════════════════════════════════════════════

ADMIN LOGIN & CREATE USER:
─────────────────────────────────────────────────────────────────────────

  1. Admin Login
     ┌─────────┐
     │ Frontend│ POST /api/auth/login
     │         ├──────────────────────────────┐
     │ Enter:  │ {"username": "admin",        │
     │ - admin │  "password": "admin123"}     │
     │ - pass  │                              ▼
     └─────────┘                        ┌──────────┐
                                        │  Backend │
                                        │          │
                                        │ 1. Query │ SELECT * FROM users
                                        │    DB    │ WHERE username = 'admin'
                                        │          │        │
                                        │ 2. Verify│◄───────┘
                                        │    Pass  │ bcrypt.checkpw()
                                        │          │
                                        │ 3. Create│ jwt.encode({
                                        │    Token │   "sub": "admin",
                                        │          │   "role": "admin",
                                        │          │   "user_id": 1
                                        └────┬─────┘ })
                                             │
     ┌─────────┐                             │
     │ Frontend│◄────────────────────────────┘
     │         │ {"access_token": "eyJ...",
     │ Store:  │  "user": {...}}
     │ - Token │
     │ - User  │
     └─────────┘


  2. Admin Creates User
     ┌─────────┐
     │ Frontend│ POST /api/auth/admin/create-user
     │         ├────────────────────────────────────┐
     │ Form:   │ Header: Bearer eyJ...              │
     │ - user  │ Body: {"username": "john",         │
     │ - email │        "password": "pass123",      │
     │ - pass  │        "email": "j@c.com",         │
     │ - name  │        "first_name": "John",       │
     └─────────┘        "last_name": "Doe"}         ▼
                                              ┌──────────┐
                                              │  Backend │
                                              │          │
                                              │ 1. Decode│ jwt.decode(token)
                                              │    Token │ → role = "admin" ✓
                                              │          │
                                              │ 2. Check │ SELECT ... WHERE
                                              │    Exists│ username = 'john'
                                              │          │ → NOT EXISTS ✓
                                              │          │
                                              │ 3. Hash  │ bcrypt.hashpw()
                                              │    Pass  │ → $2b$12$...
                                              │          │
                                              │ 4. Insert│ INSERT INTO
                                              │    User  │ users ...
                                              └────┬─────┘
                                                   │
     ┌─────────┐                                   │
     │ Frontend│◄──────────────────────────────────┘
     │         │ {"id": 2,
     │ Display │  "username": "john",
     │ Success │  "role": "user",
     └─────────┘  "is_active": true}


  3. User Login
     ┌─────────┐
     │ Frontend│ POST /api/auth/login
     │         ├──────────────────────────────┐
     │ Enter:  │ {"username": "john",         │
     │ - john  │  "password": "pass123"}      │
     │ - pass  │                              ▼
     └─────────┘                        ┌──────────┐
                                        │  Backend │
                                        │          │
                                        │ 1. Query │ SELECT * FROM users
                                        │    DB    │ WHERE username = 'john'
                                        │          │        │
                                        │ 2. Verify│◄───────┘
                                        │    Pass  │ bcrypt.checkpw()
                                        │          │
                                        │ 3. Create│ jwt.encode({
                                        │    Token │   "sub": "john",
                                        │          │   "role": "user",
                                        │          │   "user_id": 2
                                        └────┬─────┘ })
                                             │
     ┌─────────┐                             │
     │ Frontend│◄────────────────────────────┘
     │         │ {"access_token": "eyJ...",
     │ Access  │  "user": {...}}
     │ Content │
     └─────────┘


═══════════════════════════════════════════════════════════════════════════
                         SECURITY LAYERS
═══════════════════════════════════════════════════════════════════════════

  Layer 1: PASSWORD HASHING
  ┌────────────────────────────────────────────────────┐
  │ Plain Password → bcrypt (12 rounds) → Hash Stored  │
  │                                                     │
  │ "admin123" → $2b$12$LQv3c1yqBWVHxkd0LHAkCO...     │
  │                                                     │
  │ Benefits:                                           │
  │ ✓ One-way encryption                               │
  │ ✓ Salt included automatically                      │
  │ ✓ Slow computation (prevents brute force)          │
  └────────────────────────────────────────────────────┘

  Layer 2: JWT TOKENS
  ┌────────────────────────────────────────────────────┐
  │ Header.Payload.Signature                           │
  │                                                     │
  │ Payload: {"sub": "admin",                          │
  │          "role": "admin",                          │
  │          "user_id": 1,                             │
  │          "exp": 1708467600}                        │
  │                                                     │
  │ Signed with: JWT_SECRET_KEY (HS256)                │
  │                                                     │
  │ Benefits:                                           │
  │ ✓ Stateless authentication                         │
  │ ✓ Tamper-proof                                     │
  │ ✓ Auto-expiration (24 hours)                       │
  └────────────────────────────────────────────────────┘

  Layer 3: ROLE-BASED ACCESS
  ┌────────────────────────────────────────────────────┐
  │ Middleware checks:                                 │
  │                                                     │
  │ 1. Token valid?                                    │
  │ 2. User exists in DB?                              │
  │ 3. User is_active?                                 │
  │ 4. Required role? (admin for /admin/* endpoints)   │
  │                                                     │
  │ Benefits:                                           │
  │ ✓ Granular access control                          │
  │ ✓ Easy to extend with more roles                   │
  │ ✓ Can deactivate users without deletion            │
  └────────────────────────────────────────────────────┘
```
