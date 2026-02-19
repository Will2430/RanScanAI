"""
Test script to verify model_service database logging integration
"""
import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

async def test_db_integration():
    print("Testing model_service database integration...")
    print()
    
    # Test 1: Import modules
    print("1. Testing module imports...")
    try:
        from db_manager import init_db, get_session_maker
        from terminal_logger import LoggingCapture
        print("   ✓ Database modules imported successfully")
    except ImportError as e:
        print(f"   ✗ Import failed: {e}")
        return False
    
    # Test 2: Initialize database
    print("\n2. Testing database initialization...")
    try:
        await init_db()
        print("   ✓ Database tables created/verified")
    except Exception as e:
        print(f"   ✗ Database init failed: {e}")
        return False
    
    # Test 3: Test logging capture
    print("\n3. Testing logging capture...")
    try:
        import logging
        logger = logging.getLogger(__name__)
        
        with LoggingCapture(__name__) as capture:
            logger.info("Test log message 1")
            logger.info("Test log message 2")
        
        output = capture.get_output()
        if "Test log message 1" in output['stdout']:
            print("   ✓ Logging capture working")
        else:
            print("   ✗ Logging capture failed")
            return False
    except Exception as e:
        print(f"   ✗ Logging test failed: {e}")
        return False
    
    # Test 4: Test database write
    print("\n4. Testing database write...")
    try:
        from db_manager import save_terminal_log
        
        async with get_session_maker()() as session:
            await save_terminal_log(
                session=session,
                command="test_command",
                command_type="test",
                stdout="Test output",
                stderr="",
                execution_time_ms=100.0,
                scan_result={"test": True}
            )
        
        print("   ✓ Database write successful")
    except Exception as e:
        print(f"   ✗ Database write failed: {e}")
        return False
    
    # Test 5: Test database read
    print("\n5. Testing database read...")
    try:
        from sqlalchemy import select, desc
        from db_manager import TerminalLog
        
        async with get_session_maker()() as session:
            stmt = select(TerminalLog).order_by(desc(TerminalLog.timestamp)).limit(1)
            result = await session.execute(stmt)
            log = result.scalar()
            
            if log and log.command == "test_command":
                print(f"    Database read successful (latest: {log.command})")
            else:
                print("    Database read failed")
                return False
    except Exception as e:
        print(f"    Database read failed: {e}")
        return False
    
    print("\n" + "="*60)
    print("✅ All tests passed! model_service database integration ready")
    print("="*60)
    print("\nNext steps:")
    print("1. Start model_service: python model_service.py")
    print("2. Test scan endpoint: Upload a file to /predict/staged")
    print("3. Check logs: GET http://127.0.0.1:8001/logs/scans")
    print()
    
    return True

if __name__ == "__main__":
    success = asyncio.run(test_db_integration())
    sys.exit(0 if success else 1)
