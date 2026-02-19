"""
Quick test script to verify Azure PostgreSQL connection
"""
import asyncio
import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

# Load .env file
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

async def test_connection():
    print("Testing Azure PostgreSQL connection...")
    print(f"Host: {os.getenv('DB_HOST')}")
    print(f"Database: {os.getenv('POSTGRES_DB')}")
    print(f"User: {os.getenv('POSTGRES_USER')}")
    print()
    
    try:
        # Create engine
        engine = create_async_engine(DATABASE_URL, echo=False)
        
        # Test connection
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT version()"))
            version = result.scalar()
            
            print("✓ Connection successful!")
            print(f"PostgreSQL version: {version[:80]}")
            print()
            
            # List databases
            result = await conn.execute(text("SELECT datname FROM pg_database WHERE datistemplate = false"))
            databases = [row[0] for row in result]
            print(f"Available databases: {', '.join(databases)}")
            
        await engine.dispose()
        
    except Exception as e:
        print(f"✗ Connection failed!")
        print(f"Error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = asyncio.run(test_connection())
    exit(0 if success else 1)
