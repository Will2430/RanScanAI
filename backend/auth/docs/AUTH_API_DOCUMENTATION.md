# RanScanAI Authentication API Documentation

## Overview

This document provides complete API documentation for the RanScanAI authentication system. The system supports two user roles:
- **Admin**: System provider who can create and manage user accounts
- **User**: Regular users who can login after being created by an admin

**Authentication Method**: JWT (JSON Web Tokens) with bcrypt password hashing

**Base URL**: `http://localhost:8000/api/auth` (adjust for your deployment)

---

## Table of Contents

1. [Authentication Flow](#authentication-flow)
2. [Public Endpoints](#public-endpoints)
3. [User Endpoints](#user-endpoints)
4. [Admin Endpoints](#admin-endpoints)
5. [Error Handling](#error-handling)
6. [Frontend Integration Examples](#frontend-integration-examples)

---

## Authentication Flow

### For Admin:
1. Admin logs in with credentials → receives JWT token
2. Admin creates user accounts
3. Admin can view/manage all users

### For Regular Users:
1. Admin creates user account
2. User logs in with credentials → receives JWT token
3. User can access protected resources

---

## Public Endpoints

### 1. Login

**Endpoint**: `POST /api/auth/login`

**Description**: Login for both admin and users. Returns JWT token and user information.

**Request Body**:
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsInVzZXJfaWQiOjEsImV4cCI6MTcwODQ2NzYwMH0.X7Y8Z9...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@ranscanai.com",
    "first_name": "Admin",
    "last_name": "User",
    "phone_number": null,
    "role": "admin",
    "is_active": true,
    "created_at": "2026-02-20T10:00:00Z",
    "last_login": "2026-02-20T15:45:00Z"
  }
}
```

**Error Responses**:

401 Unauthorized:
```json
{
  "detail": "Invalid username or password"
}
```

403 Forbidden:
```json
{
  "detail": "Account is inactive. Please contact administrator."
}
```

**Frontend Example (JavaScript)**:
```javascript
async function login(username, password) {
  const response = await fetch('http://localhost:8000/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, password })
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail);
  }
  
  const data = await response.json();
  // Store token in localStorage or state management
  localStorage.setItem('access_token', data.access_token);
  localStorage.setItem('user', JSON.stringify(data.user));
  
  return data;
}
```

---

## User Endpoints

### 2. Get Current User Info

**Endpoint**: `GET /api/auth/me`

**Description**: Get information about the currently authenticated user.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "id": 2,
  "username": "john_doe",
  "email": "john@company.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "role": "user",
  "is_active": true,
  "created_at": "2026-02-20T11:00:00Z",
  "last_login": "2026-02-20T16:00:00Z"
}
```

**Error Response** (401 Unauthorized):
```json
{
  "detail": "Invalid or expired token"
}
```

**Frontend Example (JavaScript)**:
```javascript
async function getCurrentUser() {
  const token = localStorage.getItem('access_token');
  
  const response = await fetch('http://localhost:8000/api/auth/me', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (!response.ok) {
    // Token expired or invalid
    localStorage.removeItem('access_token');
    window.location.href = '/login';
    return null;
  }
  
  return await response.json();
}
```

---

## Admin Endpoints

### 3. Create User (Admin Only)

**Endpoint**: `POST /api/auth/admin/create-user`

**Description**: Create a new user account. Only administrators can create users.

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Request Body**:
```json
{
  "username": "john_doe",
  "email": "john@company.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "role": "user"
}
```

**Field Requirements**:
- `username`: 3-50 characters, unique
- `email`: Valid email format, unique
- `password`: Minimum 8 characters
- `first_name`: Required, 1-100 characters
- `last_name`: Required, 1-100 characters
- `phone_number`: Optional, max 20 characters
- `role`: Either "admin" or "user" (default: "user")

**Response** (201 Created):
```json
{
  "id": 2,
  "username": "john_doe",
  "email": "john@company.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "role": "user",
  "is_active": true,
  "created_at": "2026-02-20T12:00:00Z",
  "last_login": null
}
```

**Error Responses**:

403 Forbidden (Not admin):
```json
{
  "detail": "Admin privileges required"
}
```

409 Conflict (Username exists):
```json
{
  "detail": "Username 'john_doe' already exists"
}
```

409 Conflict (Email exists):
```json
{
  "detail": "Email 'john@company.com' already exists"
}
```

**Frontend Example (JavaScript)**:
```javascript
async function createUser(userData) {
  const token = localStorage.getItem('access_token');
  
  const response = await fetch('http://localhost:8000/api/auth/admin/create-user', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(userData)
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail);
  }
  
  return await response.json();
}
```

---

### 4. List Users (Admin Only)

**Endpoint**: `GET /api/auth/admin/users`

**Description**: Get list of all users with optional filtering.

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Query Parameters**:
- `skip`: Number of records to skip (pagination) - default: 0
- `limit`: Maximum records to return - default: 100
- `role`: Filter by role ("admin" or "user")
- `is_active`: Filter by active status (true/false)

**Example Request**:
```
GET /api/auth/admin/users?role=user&is_active=true&limit=50
```

**Response** (200 OK):
```json
[
  {
    "id": 2,
    "username": "john_doe",
    "email": "john@company.com",
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+1234567890",
    "role": "user",
    "is_active": true,
    "created_at": "2026-02-20T12:00:00Z",
    "last_login": "2026-02-20T14:30:00Z"
  },
  {
    "id": 3,
    "username": "jane_smith",
    "email": "jane@company.com",
    "first_name": "Jane",
    "last_name": "Smith",
    "phone_number": "+9876543210",
    "role": "user",
    "is_active": true,
    "created_at": "2026-02-20T13:00:00Z",
    "last_login": null
  }
]
```

**Frontend Example (JavaScript)**:
```javascript
async function listUsers(filters = {}) {
  const token = localStorage.getItem('access_token');
  const params = new URLSearchParams(filters);
  
  const response = await fetch(`http://localhost:8000/api/auth/admin/users?${params}`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (!response.ok) {
    throw new Error('Failed to fetch users');
  }
  
  return await response.json();
}
```

---

### 5. Get User by ID (Admin Only)

**Endpoint**: `GET /api/auth/admin/users/{user_id}`

**Description**: Get detailed information about a specific user.

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Example Request**:
```
GET /api/auth/admin/users/2
```

**Response** (200 OK):
```json
{
  "id": 2,
  "username": "john_doe",
  "email": "john@company.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "role": "user",
  "is_active": true,
  "created_at": "2026-02-20T12:00:00Z",
  "last_login": "2026-02-20T14:30:00Z"
}
```

**Error Response** (404 Not Found):
```json
{
  "detail": "User with ID 999 not found"
}
```

---

### 6. Update User (Admin Only)

**Endpoint**: `PATCH /api/auth/admin/users/{user_id}`

**Description**: Update user information.

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Request Body** (all fields optional):
```json
{
  "email": "newemail@company.com",
  "first_name": "John",
  "last_name": "Smith",
  "phone_number": "+1234567890",
  "is_active": false
}
```

**Response** (200 OK):
```json
{
  "id": 2,
  "username": "john_doe",
  "email": "newemail@company.com",
  "first_name": "John",
  "last_name": "Smith",
  "phone_number": "+1234567890",
  "role": "user",
  "is_active": false,
  "created_at": "2026-02-20T12:00:00Z",
  "last_login": "2026-02-20T14:30:00Z"
}
```

**Frontend Example (JavaScript)**:
```javascript
async function updateUser(userId, updates) {
  const token = localStorage.getItem('access_token');
  
  const response = await fetch(`http://localhost:8000/api/auth/admin/users/${userId}`, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(updates)
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail);
  }
  
  return await response.json();
}
```

---

### 7. Delete User (Admin Only)

**Endpoint**: `DELETE /api/auth/admin/users/{user_id}`

**Description**: Permanently delete a user account.

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Example Request**:
```
DELETE /api/auth/admin/users/2
```

**Response** (200 OK):
```json
{
  "message": "User 'john_doe' deleted successfully"
}
```

**Error Responses**:

400 Bad Request (Trying to delete self):
```json
{
  "detail": "Cannot delete your own account"
}
```

404 Not Found:
```json
{
  "detail": "User with ID 999 not found"
}
```

**Frontend Example (JavaScript)**:
```javascript
async function deleteUser(userId) {
  const token = localStorage.getItem('access_token');
  
  const confirmed = confirm('Are you sure you want to delete this user? This action cannot be undone.');
  if (!confirmed) return;
  
  const response = await fetch(`http://localhost:8000/api/auth/admin/users/${userId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail);
  }
  
  return await response.json();
}
```

---

## Error Handling

### Common HTTP Status Codes

- **200 OK**: Successful request
- **201 Created**: Resource created successfully
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Authentication required or token invalid
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource already exists (duplicate username/email)

### Error Response Format

All errors follow this format:
```json
{
  "detail": "Human-readable error message"
}
```

---

## Frontend Integration Examples

### Complete React Authentication Context

```javascript
import React, { createContext, useState, useContext, useEffect } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('access_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      fetchCurrentUser();
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchCurrentUser = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/auth/me', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
      } else {
        logout();
      }
    } catch (error) {
      console.error('Failed to fetch user:', error);
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = async (username, password) => {
    const response = await fetch('http://localhost:8000/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail);
    }

    const data = await response.json();
    setToken(data.access_token);
    setUser(data.user);
    localStorage.setItem('access_token', data.access_token);
    
    return data;
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('access_token');
  };

  const isAdmin = () => user?.role === 'admin';

  return (
    <AuthContext.Provider value={{ user, token, login, logout, isAdmin, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
```

### Protected Route Component

```javascript
import { Navigate } from 'react-router-dom';
import { useAuth } from './AuthContext';

export const ProtectedRoute = ({ children, adminOnly = false }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return <Navigate to="/login" />;
  }

  if (adminOnly && user.role !== 'admin') {
    return <Navigate to="/unauthorized" />;
  }

  return children;
};
```

### Login Component Example

```javascript
import { useState } from 'react';
import { useAuth } from './AuthContext';
import { useNavigate } from 'react-router-dom';

export const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    try {
      await login(username, password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>RanScanAI Login</h2>
      {error && <div className="error">{error}</div>}
      
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        required
      />
      
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required
      />
      
      <button type="submit">Login</button>
    </form>
  );
};
```

---

## Security Best Practices

### Frontend:
1. **Store tokens securely**: Use httpOnly cookies for production (not localStorage)
2. **Token expiration**: Implement token refresh mechanism
3. **HTTPS only**: Always use HTTPS in production
4. **Input validation**: Validate all user inputs before sending to API
5. **Error messages**: Don't expose sensitive information in error messages

### Backend (Already Implemented):
1. **Password hashing**: bcrypt with 12 rounds
2. **JWT tokens**: Signed with secret key
3. **Token expiration**: 24 hours (configurable)
4. **Role-based access**: Admin and user roles
5. **Password requirements**: Minimum 8 characters

---

## Default Credentials

**Admin Account** (created automatically in database):
- **Username**: `admin`
- **Password**: `admin123`

**⚠️ IMPORTANT**: Change the default admin password immediately after first login!

---

## Testing with cURL

### Login:
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### Get Current User:
```bash
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### Create User:
```bash
curl -X POST http://localhost:8000/api/auth/admin/create-user \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@company.com",
    "password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user"
  }'
```

---

## Need Help?

For additional support or questions:
- Check backend logs for detailed error information
- Verify JWT token is correctly formatted and not expired
- Ensure DATABASE_URL and JWT_SECRET_KEY are properly configured in .env file
