# Terminal Output to Azure PostgreSQL - Architecture Example

## Overview
This example shows how to capture terminal/command output from your backend operations (model scans, VT checks, etc.) and save them to Azure PostgreSQL for auditing, analytics, and monitoring.

## File Hierarchy Integration

```
Iteration_1/backend/
├── main.py                    # Main FastAPI app (adds /logs endpoints)
├── db_manager.py              # NEW: Database connection & ORM models
├── terminal_logger.py         # NEW: Captures & formats terminal output
├── requirements.txt           # Add: asyncpg, sqlalchemy[asyncio]
└── .env                       # Contains DATABASE_URL
```

## Component Breakdown

### 1. Database Schema (db_manager.py)
```python
"""
Database manager for Azure PostgreSQL
Handles connections, models, and CRUD operations for terminal logs
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Text, DateTime, Integer, Boolean, JSON
from datetime import datetime
from typing import Optional, Dict, Any
import os

# Azure PostgreSQL connection URL from environment
# Format: postgresql+asyncpg://user:password@host:5432/database?ssl=require
DATABASE_URL = os.getenv("DATABASE_URL")

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=True,  # Log SQL queries (disable in production)
    pool_size=5,
    max_overflow=10
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Base model
class Base(DeclarativeBase):
    pass


# Database Models
class TerminalLog(Base):
    """Stores terminal command outputs and scan results"""
    __tablename__ = "terminal_logs"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Command info
    command: Mapped[str] = mapped_column(String(500))  # e.g., "scan_file"
    command_type: Mapped[str] = mapped_column(String(50))  # e.g., "malware_scan", "vt_check"
    
    # Output data
    stdout: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stderr: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int] = mapped_column(Integer, default=0)
    
    # Execution metadata
    execution_time_ms: Mapped[float] = mapped_column(default=0.0)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Structured data (JSON)
    scan_result: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    # Example: {"is_malicious": true, "confidence": 0.95, "file_path": "..."}
    
    # Context
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class ScanHistory(Base):
    """Dedicated table for malware scan history"""
    __tablename__ = "scan_history"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # File info
    file_path: Mapped[str] = mapped_column(String(1000))
    file_name: Mapped[str] = mapped_column(String(255))
    file_size: Mapped[int] = mapped_column(Integer)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    
    # Scan results
    is_malicious: Mapped[bool] = mapped_column(Boolean)
    confidence: Mapped[float] = mapped_column()
    prediction_label: Mapped[str] = mapped_column(String(50))
    model_type: Mapped[str] = mapped_column(String(50))  # "CNN" or "Traditional ML"
    
    # Performance
    scan_time_ms: Mapped[float] = mapped_column()
    features_analyzed: Mapped[int] = mapped_column(Integer)
    
    # VT enrichment (if available)
    vt_detection_ratio: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    vt_data: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)


# Database operations
async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:
    """Dependency for FastAPI to get DB session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


# CRUD operations
async def save_terminal_log(
    session: AsyncSession,
    command: str,
    command_type: str,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    execution_time_ms: float = 0.0,
    scan_result: Optional[Dict[str, Any]] = None,
    file_path: Optional[str] = None
):
    """Save a terminal log entry"""
    log_entry = TerminalLog(
        command=command,
        command_type=command_type,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        execution_time_ms=execution_time_ms,
        success=(exit_code == 0),
        scan_result=scan_result,
        file_path=file_path
    )
    session.add(log_entry)
    await session.commit()
    return log_entry


async def save_scan_history(
    session: AsyncSession,
    file_path: str,
    result: Dict[str, Any],
    model_type: str = "Traditional ML"
):
    """Save a scan result to history"""
    from pathlib import Path
    
    scan_entry = ScanHistory(
        file_path=file_path,
        file_name=Path(file_path).name,
        file_size=result.get('file_size', 0),
        file_hash=result.get('file_hash'),
        is_malicious=result['is_malicious'],
        confidence=result['confidence'],
        prediction_label=result['prediction_label'],
        model_type=model_type,
        scan_time_ms=result['scan_time_ms'],
        features_analyzed=result.get('features_count', 0),
        vt_detection_ratio=result.get('vt_detection_ratio'),
        vt_data=result.get('vt_data')
    )
    session.add(scan_entry)
    await session.commit()
    return scan_entry
```

### 2. Terminal Output Capture (terminal_logger.py)
```python
"""
Captures and formats terminal output for database logging
Integrates with existing logging system
"""
import logging
import io
import sys
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class TerminalCapture:
    """Context manager to capture stdout/stderr"""
    
    def __init__(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = datetime.utcnow()
        self.stdout_redirect = redirect_stdout(self.stdout)
        self.stderr_redirect = redirect_stderr(self.stderr)
        self.stdout_redirect.__enter__()
        self.stderr_redirect.__enter__()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = datetime.utcnow()
        self.stdout_redirect.__exit__(exc_type, exc_val, exc_tb)
        self.stderr_redirect.__exit__(exc_type, exc_val, exc_tb)
    
    def get_output(self) -> Dict[str, Any]:
        """Get captured output and metadata"""
        execution_time = (self.end_time - self.start_time).total_seconds() * 1000
        return {
            'stdout': self.stdout.getvalue(),
            'stderr': self.stderr.getvalue(),
            'execution_time_ms': execution_time,
            'exit_code': 0 if not self.stderr.getvalue() else 1
        }


class LoggingCapture:
    """Captures logging output instead of terminal output"""
    
    def __init__(self, logger_name: str = __name__):
        self.logger_name = logger_name
        self.handler = None
        self.stream = io.StringIO()
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = datetime.utcnow()
        # Create string stream handler
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        self.handler.setFormatter(formatter)
        
        # Add to logger
        target_logger = logging.getLogger(self.logger_name)
        target_logger.addHandler(self.handler)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = datetime.utcnow()
        # Remove handler
        target_logger = logging.getLogger(self.logger_name)
        target_logger.removeHandler(self.handler)
    
    def get_output(self) -> Dict[str, Any]:
        """Get captured logs"""
        execution_time = (self.end_time - self.start_time).total_seconds() * 1000
        return {
            'stdout': self.stream.getvalue(),
            'stderr': '',
            'execution_time_ms': execution_time,
            'exit_code': 0
        }


def format_scan_output(result: Dict[str, Any]) -> str:
    """Format scan result for logging"""
    lines = [
        f"Scan Result: {result['prediction_label']}",
        f"Confidence: {result['confidence']:.2%}",
        f"Scan Time: {result['scan_time_ms']:.2f}ms",
        f"Features: {result.get('features_count', 'N/A')}"
    ]
    
    if result.get('vt_detection_ratio'):
        lines.append(f"VT Detection: {result['vt_detection_ratio']}")
    
    return "\n".join(lines)
```

### 3. Integration in main.py

```python
# Add these imports at the top of main.py
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends
from db_manager import (
    init_db, get_session, 
    save_terminal_log, save_scan_history
)
from terminal_logger import LoggingCapture, format_scan_output

# Add to startup event
@app.on_event("startup")
async def startup_event():
    """Initialize ML model and services on startup"""
    global detector, cnn_detector, vt_enricher
    
    logger.info("🚀 Starting SecureGuard Backend...")
    
    # Initialize database (ADD THIS)
    try:
        logger.info("Initializing database connection...")
        await init_db()
        logger.info("✓ Database ready")
    except Exception as e:
        logger.warning(f"Database initialization failed: {e}")
        logger.warning("Continuing without database logging...")
    
    # ... rest of existing startup code ...


# Modify scan endpoint to log to database
@app.post("/scan", response_model=ScanResponse)
async def scan_file(
    request: ScanRequest,
    db: AsyncSession = Depends(get_session)  # ADD THIS
):
    """Scan a file with database logging"""
    active_detector = cnn_detector or detector
    
    if not active_detector:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    try:
        # Validate file
        if not Path(request.file_path).exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        logger.info(f"Scanning file: {request.file_path}")
        
        # Capture logging output during scan
        with LoggingCapture(__name__) as capture:
            # Perform ML scan
            result = active_detector.scan_file(request.file_path)
        
        # Get captured output
        output = capture.get_output()
        
        # VT enrichment (existing code)
        vt_data = result.get('vt_detection_ratio') if cnn_detector else None
        if detector and result['is_malicious'] and request.enable_vt and vt_enricher:
            logger.info("Enriching with VirusTotal...")
            vt_enrichment = vt_enricher.check_file(request.file_path)
            vt_data = vt_enrichment.get('detection') if vt_enrichment else None
        
        # Save to database (ASYNC)
        try:
            # Save terminal log
            await save_terminal_log(
                session=db,
                command=f"scan_file: {Path(request.file_path).name}",
                command_type="malware_scan",
                stdout=output['stdout'] + "\n" + format_scan_output(result),
                stderr=output['stderr'],
                execution_time_ms=result['scan_time_ms'],
                scan_result=result,
                file_path=request.file_path
            )
            
            # Save scan history
            await save_scan_history(
                session=db,
                file_path=request.file_path,
                result=result,
                model_type="CNN" if cnn_detector else "Traditional ML"
            )
            
            logger.info("✓ Scan logged to database")
        except Exception as db_error:
            logger.error(f"Failed to log to database: {db_error}")
            # Don't fail the scan if logging fails
        
        # Build response (existing code)
        features_count = result.get('file_size', 0) if cnn_detector else result.get('features_count', 0)
        response = ScanResponse(
            is_malicious=result['is_malicious'],
            confidence=result['confidence'],
            prediction_label=result['prediction_label'],
            scan_time_ms=result['scan_time_ms'],
            features_analyzed=features_count,
            vt_data=vt_data
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# NEW: Endpoint to query logs
@app.get("/logs/recent")
async def get_recent_logs(
    limit: int = 50,
    db: AsyncSession = Depends(get_session)
):
    """Get recent terminal logs"""
    from sqlalchemy import select, desc
    from db_manager import TerminalLog
    
    stmt = select(TerminalLog).order_by(desc(TerminalLog.timestamp)).limit(limit)
    result = await db.execute(stmt)
    logs = result.scalars().all()
    
    return {
        "total": len(logs),
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "command": log.command,
                "type": log.command_type,
                "execution_time_ms": log.execution_time_ms,
                "success": log.success,
                "scan_result": log.scan_result
            }
            for log in logs
        ]
    }


@app.get("/logs/scans")
async def get_scan_history(
    limit: int = 100,
    malicious_only: bool = False,
    db: AsyncSession = Depends(get_session)
):
    """Get scan history with filtering"""
    from sqlalchemy import select, desc
    from db_manager import ScanHistory
    
    stmt = select(ScanHistory).order_by(desc(ScanHistory.timestamp))
    
    if malicious_only:
        stmt = stmt.where(ScanHistory.is_malicious == True)
    
    stmt = stmt.limit(limit)
    
    result = await db.execute(stmt)
    scans = result.scalars().all()
    
    return {
        "total": len(scans),
        "scans": [
            {
                "id": scan.id,
                "timestamp": scan.timestamp.isoformat(),
                "file_name": scan.file_name,
                "is_malicious": scan.is_malicious,
                "confidence": scan.confidence,
                "model_type": scan.model_type,
                "scan_time_ms": scan.scan_time_ms,
                "vt_detection": scan.vt_detection_ratio
            }
            for scan in scans
        ]
    }
```

### 4. Environment Setup (.env)

```bash
# Azure PostgreSQL Connection
# Get this from Azure Portal -> PostgreSQL -> Connection Strings
DATABASE_URL=postgresql+asyncpg://username:password@servername.postgres.database.azure.com:5432/databasename?ssl=require

# Alternative: Individual components
POSTGRES_USER=your_username@servername
POSTGRES_PASSWORD=your_password
DB_HOST=servername.postgres.database.azure.com
DB_PORT=5432
POSTGRES_DB=secureguard_db

# Existing settings
USE_CNN_MODEL=true
CNN_MODEL_SERVICE_URL=http://127.0.0.1:8001
```

### 5. Dependencies (requirements.txt)

```txt
# Existing dependencies...
fastapi
uvicorn
pydantic

# Add these for database:
sqlalchemy[asyncio]>=2.0.0
asyncpg>=0.29.0
python-dotenv
```

## How It Works

### Execution Flow:
```
1. Browser Extension → POST /scan → main.py
                                       ↓
2. main.py captures logger output → scan_file()
                                       ↓
3. MalwareDetector/CNNClient → logs to console
                                       ↓
4. LoggingCapture → grabs all logs
                                       ↓
5. save_terminal_log() → Azure PostgreSQL
   save_scan_history()
                                       ↓
6. Return ScanResponse → Browser Extension
```

### Database Tables Created:
- `terminal_logs` - All command outputs, stdout/stderr
- `scan_history` - Malware scan results only (optimized queries)

## Usage Examples

### Query recent scans:
```bash
GET http://localhost:8000/logs/scans?limit=50&malicious_only=true
```

### Get all terminal logs:
```bash
GET http://localhost:8000/logs/recent?limit=100
```

### Direct SQL queries in Azure:
```sql
-- Get scans from last 24 hours
SELECT * FROM scan_history 
WHERE timestamp > NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC;

-- Find high-confidence malware detections
SELECT file_name, confidence, model_type, vt_detection_ratio
FROM scan_history
WHERE is_malicious = true AND confidence > 0.9
ORDER BY confidence DESC;

-- Terminal output analytics
SELECT command_type, 
       COUNT(*) as total_runs,
       AVG(execution_time_ms) as avg_time,
       SUM(CASE WHEN success = true THEN 1 ELSE 0 END) as successes
FROM terminal_logs
GROUP BY command_type;
```

## Notes

- **Async/Await**: Uses SQLAlchemy 2.0 async for non-blocking DB operations
- **Separation of Concerns**: DB logic in `db_manager.py`, not cluttering `main.py`
- **Graceful Degradation**: If DB fails, scans still work (logged locally)
- **SSL Required**: Azure PostgreSQL requires SSL connection
- **Connection Pooling**: Configured with pool_size=5 for performance

## Next Steps (Not Implemented)

1. Create `db_manager.py` with the code above
2. Create `terminal_logger.py` with capture classes
3. Update `main.py` with async DB dependencies
4. Add `DATABASE_URL` to `.env`
5. Install new dependencies: `pip install sqlalchemy[asyncio] asyncpg`
6. Test with: `python -m pytest` or manual scan
