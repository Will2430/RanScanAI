# User-Specific Scan History Implementation Guide

## 🎯 What Was Implemented

Added user authentication and user-specific scan history tracking to RanScanAI:
- ✅ Users can only see their own scan history
- ✅ Admins can see all users' scan history
- ✅ Each scan is now linked to the user who performed it
- ✅ Authentication required for all scanning operations

---

## 📋 Changes Made

### **1. Database Model Changes** ([db_manager.py](db_manager.py))

#### Added to `ScanHistory` table:
```python
# User relationship - links scan to the user who performed it
user_id: Mapped[uuid.UUID] = mapped_column(
    PGUUID(as_uuid=True),
    ForeignKey("users.user_id", ondelete="CASCADE"),
    nullable=False,
    index=True
)
user: Mapped["User"] = relationship("User", back_populates="scans")
```

#### Added to `User` model:
```python
# Relationship: user's scan history
scans: Mapped[list["ScanHistory"]] = relationship(
    "ScanHistory",
    back_populates="user",
    cascade="all, delete-orphan"
)
```

#### Updated Functions:
- `save_scan_history()` - Now requires `user_id` parameter
- `get_scan_history()` - Added optional `user_id` filter

### **2. Authentication Module** ([auth/__init__.py](auth/__init__.py))

Exported authentication dependencies:
```python
from .routes import get_current_user, get_current_admin
```

### **3. API Endpoints** ([main.py](main.py))

#### Updated Scan Endpoints (Now Require Authentication):
- `POST /scan` - Scan local file (requires login, saves user_id)
- `POST /scan-upload` - Scan uploaded file (requires login, saves user_id)

#### New Scan History Endpoints:
- `GET /scan-history` - Get current user's scan history
  - Parameters: `limit` (default 100), `malicious_only` (default false)
  - Returns: List of user's scans with timestamps, file info, results

- `GET /admin/scan-history` - Get all users' scan history (admin only)
  - Parameters: `limit` (default 100), `malicious_only` (default false)
  - Returns: List of all scans from all users

#### New Response Model:
```python
class ScanHistoryResponse(BaseModel):
    id: int
    timestamp: str
    file_name: str
    file_path: str
    is_malicious: bool
    confidence: float
    prediction_label: str
    model_type: str
    scan_time_ms: float
```

---

## 🗄️ Database Migration Required

Since you've added a new column (`user_id`) to an existing table, you need to update your database:

### **Option 1: Fresh Database (Easiest if no important data)**

```python
# Run this in Python console or create migration script
from db_manager import Base, get_engine
import asyncio

async def recreate_tables():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)  # Drop all tables
        await conn.run_sync(Base.metadata.create_all)  # Recreate with new schema
    print("✅ Database schema recreated!")

asyncio.run(recreate_tables())
```

### **Option 2: SQL Migration (Keep existing data)**

Run this SQL directly on your Azure PostgreSQL database:

```sql
-- Add user_id column to scan_history table
ALTER TABLE scan_history 
ADD COLUMN user_id UUID NOT NULL DEFAULT 'YOUR_ADMIN_USER_ID_HERE';

-- Add foreign key constraint
ALTER TABLE scan_history
ADD CONSTRAINT fk_scan_history_user
FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE;

-- Create index for performance
CREATE INDEX idx_scan_history_user_id ON scan_history(user_id);
```

**Note:** Replace `'YOUR_ADMIN_USER_ID_HERE'` with an actual admin user UUID from your `users` table.

To get an admin user ID:
```sql
SELECT user_id FROM users WHERE role = 'admin' LIMIT 1;
```

---

## 🎨 Frontend Integration

### **Step 1: Add Authorization Header to Scan Requests**

Update your frontend to include JWT token when scanning:

```javascript
// Example: Update scan request
const token = localStorage.getItem('access_token');

const response = await fetch('http://localhost:8000/scan', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`  // ✨ Add this
  },
  body: JSON.stringify({
    file_path: filePath,
    enable_vt: true
  })
});
```

### **Step 2: Fetch Scan History**

Add a new component to display scan history:

```javascript
// Fetch user's scan history
async function fetchScanHistory() {
  const token = localStorage.getItem('access_token');
  
  const response = await fetch('http://localhost:8000/scan-history?limit=50', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  const scans = await response.json();
  return scans;
}

// For admin - fetch all scans
async function fetchAllScans() {
  const token = localStorage.getItem('access_token');
  
  const response = await fetch('http://localhost:8000/admin/scan-history?limit=100', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  const scans = await response.json();
  return scans;
}
```

### **Step 3: Display Scan History**

Example React component:

```jsx
import React, { useState, useEffect } from 'react';

function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    fetchScanHistory().then(data => {
      setScans(data);
      setLoading(false);
    });
  }, []);
  
  if (loading) return <div>Loading scan history...</div>;
  
  return (
    <div>
      <h2>My Scan History</h2>
      <table>
        <thead>
          <tr>
            <th>Date</th>
            <th>File Name</th>
            <th>Result</th>
            <th>Confidence</th>
            <th>Model</th>
          </tr>
        </thead>
        <tbody>
          {scans.map(scan => (
            <tr key={scan.id}>
              <td>{new Date(scan.timestamp).toLocaleString()}</td>
              <td>{scan.file_name}</td>
              <td className={scan.is_malicious ? 'danger' : 'safe'}>
                {scan.prediction_label}
              </td>
              <td>{(scan.confidence * 100).toFixed(1)}%</td>
              <td>{scan.model_type}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

---

## 🔐 Security Benefits

1. **Audit Trail**: Every scan is now tracked to a specific user
2. **Privacy**: Users can only see their own scans (unless admin)
3. **Accountability**: Admins can monitor all scanning activity
4. **Access Control**: Unauthenticated users cannot perform scans

---

## 📊 Testing the Implementation

### **1. Test Authentication on Scan Endpoint**

```bash
# Without token - should fail with 401
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"file_path": "test.exe", "enable_vt": false}'

# With token - should succeed
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"file_path": "test.exe", "enable_vt": false}'
```

### **2. Test Scan History Endpoints**

```bash
# Get current user's scans
curl -X GET "http://localhost:8000/scan-history?limit=10" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Get all scans (admin only)
curl -X GET "http://localhost:8000/admin/scan-history?limit=10" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN_HERE"
```

### **3. Verify Database Records**

```sql
-- Check scan records with user_id
SELECT 
  sh.id,
  sh.file_name,
  sh.is_malicious,
  u.username,
  u.role
FROM scan_history sh
JOIN users u ON sh.user_id = u.user_id
ORDER BY sh.timestamp DESC
LIMIT 10;
```

---

## 📝 API Endpoint Summary

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/scan` | POST | Required | Scan local file |
| `/scan-upload` | POST | Required | Scan uploaded file |
| `/scan-history` | GET | Required (User) | Get my scans |
| `/admin/scan-history` | GET | Required (Admin) | Get all scans |
| `/api/auth/login` | POST | Public | Login to get token |
| `/api/auth/me` | GET | Required | Get current user info |

---

## 🚀 Next Steps

1. **Run Database Migration** (see section above)
2. **Restart Backend Server**: `python main.py`
3. **Update Frontend**: Add Authorization headers to scan requests
4. **Create Scan History UI**: Display user's past scans
5. **Test Everything**: Verify scans are saved with user_id

---

## 💡 Optional Enhancements

Consider adding:
- **Pagination**: For large scan histories
- **Date Filtering**: Filter scans by date range
- **Export Feature**: Download scan history as CSV/PDF
- **Scan Statistics**: Charts showing malware detection rates per user
- **Real-time Updates**: WebSocket for live scan status
- **File Re-scan**: Button to re-scan files from history

---

## ⚠️ Important Notes

1. **Breaking Change**: All scan endpoints now require authentication
2. **Existing Scans**: Old scans without user_id will need migration (see SQL above)
3. **Frontend Update**: Must update to include Authorization headers
4. **Token Expiry**: JWT tokens expire after 24 hours - implement refresh logic

---

## 📞 Need Help?

If you encounter issues:
1. Check database connection in `.env` file
2. Verify admin user exists: `python setup_admin.py`
3. Check server logs for authentication errors
4. Test endpoints with Postman before frontend integration

**Status**: ✅ Backend implementation complete - ready for database migration and frontend integration!
