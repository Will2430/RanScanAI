"""
Database manager for Azure PostgreSQL - EXAMPLE IMPLEMENTATION
Copy this to Iteration_1/backend/db_manager.py when ready

Handles connections, ORM models, and CRUD operations for terminal logs
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Text, DateTime, Integer, Boolean, JSON
from datetime import datetime
from typing import Optional, Dict, Any
import os
import logging

logger = logging.getLogger(__name__)

# Azure PostgreSQL connection URL from environment
# Format: postgresql+asyncpg://user:password@host:5432/database?ssl=require
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    logger.warning("DATABASE_URL not set - database features disabled")
    DATABASE_URL = "postgresql+asyncpg://localhost/dummy"  # Fallback

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True to log SQL queries (useful for debugging)
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True  # Verify connections before using
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


# ============================================================================
# DATABASE MODELS
# ============================================================================

class TerminalLog(Base):
    """
    Stores terminal command outputs and scan results
    Use for: Audit logs, debugging, monitoring system health
    """
    __tablename__ = "terminal_logs"
    
    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    # Command information
    command: Mapped[str] = mapped_column(String(500))  # e.g., "scan_file: malware.exe"
    command_type: Mapped[str] = mapped_column(String(50), index=True)  # e.g., "malware_scan", "vt_check"
    
    # Output data (captured from terminal/logs)
    stdout: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stderr: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int] = mapped_column(Integer, default=0)
    
    # Execution metadata
    execution_time_ms: Mapped[float] = mapped_column(default=0.0)
    success: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    
    # Structured data (JSON) - stores full scan result
    scan_result: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    # Example: {"is_malicious": true, "confidence": 0.95, "features_count": 78}
    
    # Context
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<TerminalLog {self.id}: {self.command_type} at {self.timestamp}>"


class ScanHistory(Base):
    """
    Dedicated table for malware scan history
    Optimized for querying scan results, analytics, and reporting
    """
    __tablename__ = "scan_history"
    
    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    # File information
    file_path: Mapped[str] = mapped_column(String(1000))
    file_name: Mapped[str] = mapped_column(String(255), index=True)
    file_size: Mapped[int] = mapped_column(Integer)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    
    # Scan results
    is_malicious: Mapped[bool] = mapped_column(Boolean, index=True)
    confidence: Mapped[float] = mapped_column()
    prediction_label: Mapped[str] = mapped_column(String(50))  # "MALWARE" or "BENIGN"
    model_type: Mapped[str] = mapped_column(String(50))  # "CNN" or "Traditional ML"
    
    # Performance metrics
    scan_time_ms: Mapped[float] = mapped_column()
    features_analyzed: Mapped[int] = mapped_column(Integer)
    
    # VirusTotal enrichment (if available)
    vt_detection_ratio: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    # Example: "45/70" means 45 out of 70 engines detected it
    vt_data: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    
    def __repr__(self):
        return f"<ScanHistory {self.id}: {self.file_name} - {'MALWARE' if self.is_malicious else 'BENIGN'}>"


# ============================================================================
# DATABASE OPERATIONS
# ============================================================================

async def init_db():
    """
    Initialize database tables
    Creates all tables defined in Base metadata
    Call this during app startup
    """
    try:
        async with engine.begin() as conn:
            # Create tables if they don't exist
            await conn.run_sync(Base.metadata.create_all)
        logger.info("✓ Database tables initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def get_session() -> AsyncSession:
    """
    Dependency for FastAPI to get DB session
    Use with: db: AsyncSession = Depends(get_session)
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


# ============================================================================
# CRUD OPERATIONS
# ============================================================================

async def save_terminal_log(
    session: AsyncSession,
    command: str,
    command_type: str,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    execution_time_ms: float = 0.0,
    scan_result: Optional[Dict[str, Any]] = None,
    file_path: Optional[str] = None,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None
) -> TerminalLog:
    """
    Save a terminal log entry to database
    
    Args:
        session: Database session
        command: Command executed (e.g., "scan_file: malware.exe")
        command_type: Type of command (e.g., "malware_scan", "vt_check")
        stdout: Standard output captured
        stderr: Standard error captured
        exit_code: Exit code (0 = success)
        execution_time_ms: Execution time in milliseconds
        scan_result: Full scan result as dict (stored as JSON)
        file_path: Path to file being processed
        user_id: Optional user identifier
        session_id: Optional session identifier
    
    Returns:
        Created TerminalLog object
    """
    log_entry = TerminalLog(
        command=command,
        command_type=command_type,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        execution_time_ms=execution_time_ms,
        success=(exit_code == 0 and not stderr),
        scan_result=scan_result,
        file_path=file_path,
        user_id=user_id,
        session_id=session_id
    )
    
    session.add(log_entry)
    await session.commit()
    await session.refresh(log_entry)  # Get the ID
    
    logger.debug(f"Saved terminal log: {log_entry.id}")
    return log_entry


async def save_scan_history(
    session: AsyncSession,
    file_path: str,
    result: Dict[str, Any],
    model_type: str = "Traditional ML",
    file_hash: Optional[str] = None
) -> ScanHistory:
    """
    Save a malware scan result to history
    
    Args:
        session: Database session
        file_path: Full path to scanned file
        result: Scan result dict with keys:
            - is_malicious (bool)
            - confidence (float)
            - prediction_label (str)
            - scan_time_ms (float)
            - features_count or file_size (int)
            - vt_detection_ratio (optional str)
            - vt_data (optional dict)
        model_type: "CNN" or "Traditional ML"
        file_hash: Optional SHA256 hash of file
    
    Returns:
        Created ScanHistory object
    """
    from pathlib import Path
    
    scan_entry = ScanHistory(
        file_path=file_path,
        file_name=Path(file_path).name,
        file_size=result.get('file_size', result.get('features_count', 0)),
        file_hash=file_hash,
        is_malicious=result['is_malicious'],
        confidence=result['confidence'],
        prediction_label=result['prediction_label'],
        model_type=model_type,
        scan_time_ms=result['scan_time_ms'],
        features_analyzed=result.get('features_count', result.get('file_size', 0)),
        vt_detection_ratio=result.get('vt_detection_ratio'),
        vt_data=result.get('vt_data')
    )
    
    session.add(scan_entry)
    await session.commit()
    await session.refresh(scan_entry)
    
    logger.debug(f"Saved scan history: {scan_entry.id}")
    return scan_entry


async def get_recent_logs(
    session: AsyncSession,
    limit: int = 50,
    command_type: Optional[str] = None,
    success_only: bool = False
) -> list[TerminalLog]:
    """
    Get recent terminal logs
    
    Args:
        session: Database session
        limit: Maximum number of logs to return
        command_type: Filter by command type (optional)
        success_only: Only return successful operations
    
    Returns:
        List of TerminalLog objects
    """
    from sqlalchemy import select, desc
    
    stmt = select(TerminalLog).order_by(desc(TerminalLog.timestamp)).limit(limit)
    
    if command_type:
        stmt = stmt.where(TerminalLog.command_type == command_type)
    
    if success_only:
        stmt = stmt.where(TerminalLog.success == True)
    
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_scan_history(
    session: AsyncSession,
    limit: int = 100,
    malicious_only: bool = False,
    file_hash: Optional[str] = None
) -> list[ScanHistory]:
    """
    Get scan history with filtering
    
    Args:
        session: Database session
        limit: Maximum number of scans to return
        malicious_only: Only return malware detections
        file_hash: Filter by specific file hash
    
    Returns:
        List of ScanHistory objects
    """
    from sqlalchemy import select, desc
    
    stmt = select(ScanHistory).order_by(desc(ScanHistory.timestamp)).limit(limit)
    
    if malicious_only:
        stmt = stmt.where(ScanHistory.is_malicious == True)
    
    if file_hash:
        stmt = stmt.where(ScanHistory.file_hash == file_hash)
    
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_scan_stats(session: AsyncSession) -> Dict[str, Any]:
    """
    Get aggregate statistics from scan history
    
    Returns:
        Dictionary with stats:
        - total_scans
        - malware_detected
        - detection_rate
        - avg_scan_time_ms
        - avg_confidence
    """
    from sqlalchemy import select, func
    
    # Total scans
    total_scans = await session.scalar(select(func.count(ScanHistory.id)))
    
    # Malware detected
    malware_count = await session.scalar(
        select(func.count(ScanHistory.id)).where(ScanHistory.is_malicious == True)
    )
    
    # Average scan time
    avg_scan_time = await session.scalar(
        select(func.avg(ScanHistory.scan_time_ms))
    )
    
    # Average confidence for malware detections
    avg_confidence = await session.scalar(
        select(func.avg(ScanHistory.confidence)).where(ScanHistory.is_malicious == True)
    )
    
    return {
        "total_scans": total_scans or 0,
        "malware_detected": malware_count or 0,
        "detection_rate": (malware_count / total_scans * 100) if total_scans else 0,
        "avg_scan_time_ms": float(avg_scan_time) if avg_scan_time else 0,
        "avg_confidence": float(avg_confidence) if avg_confidence else 0
    }
