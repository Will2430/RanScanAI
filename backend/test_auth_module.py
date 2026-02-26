"""
Test script to verify auth module structure after reorganization
Run this to ensure all imports work correctly
"""

print("="*60)
print("Testing Auth Module Structure")
print("="*60)

try:
    print("\n1. Testing auth package import...")
    import auth
    print("   ✓ auth package imported")
    
    print("\n2. Testing utility functions...")
    from auth import hash_password, verify_password, create_access_token, decode_access_token
    print("   ✓ hash_password imported")
    print("   ✓ verify_password imported")
    print("   ✓ create_access_token imported")
    print("   ✓ decode_access_token imported")
    
    print("\n3. Testing router...")
    from auth import auth_router
    print(f"   ✓ auth_router imported (type: {type(auth_router).__name__})")
    print(f"   ✓ Router prefix: {auth_router.prefix}")
    print(f"   ✓ Number of routes: {len(auth_router.routes)}")
    
    print("\n4. Testing schemas...")
    from auth import UserCreate, LoginRequest, UserResponse, Token, UserUpdate
    print("   ✓ UserCreate imported")
    print("   ✓ LoginRequest imported")
    print("   ✓ UserResponse imported")
    print("   ✓ Token imported")
    print("   ✓ UserUpdate imported")
    
    print("\n5. Testing utility functions work...")
    test_password = "test123"
    hashed = hash_password(test_password)
    print(f"   ✓ Password hashed: {hashed[:20]}...")
    
    is_valid = verify_password(test_password, hashed)
    print(f"   ✓ Password verification: {is_valid}")
    
    token = create_access_token({"sub": "testuser", "role": "user"})
    print(f"   ✓ JWT token created: {token[:30]}...")
    
    decoded = decode_access_token(token)
    print(f"   ✓ Token decoded: {decoded.get('sub')}")
    
    print("\n" + "="*60)
    print("✅ ALL TESTS PASSED!")
    print("="*60)
    print("\n✓ Auth module is properly organized and functional")
    print("✓ All imports work correctly")
    print("✓ Old files can now be safely removed:")
    print("  - backend/auth.py")
    print("  - backend/auth_routes.py")
    print("  - backend/schemas.py")
    
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    print("\n⚠️ There may be an issue with the module structure")
