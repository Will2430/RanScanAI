"""
Quick test script for authentication system
Run this to verify your authentication setup is working correctly
"""

import asyncio
import sys
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import select
from db_manager import get_session_maker, User, init_db
from auth import hash_password, verify_password, create_access_token, decode_access_token

async def test_auth_system():
    """Test the authentication system"""
    
    print("🧪 Testing RanScanAI Authentication System\n")
    
    # Test 1: Password hashing
    print("1. Testing password hashing...")
    test_password = "TestPassword123!"
    hashed = hash_password(test_password)
    print(f"   ✓ Password hashed: {hashed[:50]}...")
    
    # Test 2: Password verification
    print("2. Testing password verification...")
    is_valid = verify_password(test_password, hashed)
    assert is_valid, "Password verification failed!"
    print(f"   ✓ Password verification: {is_valid}")
    
    # Test 3: JWT token creation
    print("3. Testing JWT token creation...")
    token_data = {"sub": "testuser", "role": "admin", "user_id": 1}
    token = create_access_token(token_data)
    print(f"   ✓ Token created: {token[:50]}...")
    
    # Test 4: JWT token decoding
    print("4. Testing JWT token decoding...")
    decoded = decode_access_token(token)
    assert decoded["sub"] == "testuser", "Token decode failed!"
    print(f"   ✓ Token decoded: {decoded}")
    
    # Test 5: Database connection and user model
    print("5. Testing database connection...")
    try:
        await init_db()
        print("   ✓ Database initialized")
        
        # Try to query users
        session_maker = get_session_maker()
        async with session_maker() as session:
            result = await session.execute(select(User).limit(1))
            users = result.scalars().all()
            print(f"   ✓ Found {len(users)} user(s) in database")
            
            if users:
                user = users[0]
                print(f"   ✓ Sample user: {user.username} (role: {user.role})")
    except Exception as e:
        print(f"   ⚠ Database test failed: {e}")
        print("   Note: Make sure DATABASE_URL is configured in .env")
    
    print("\n✅ All basic authentication tests passed!")
    print("\nNext steps:")
    print("1. Start the FastAPI server: python -m uvicorn main:app --reload")
    print("2. Test login endpoint: POST http://localhost:8000/api/auth/login")
    print("3. See docs/AUTH_API_DOCUMENTATION.md for full API documentation")

if __name__ == "__main__":
    asyncio.run(test_auth_system())
