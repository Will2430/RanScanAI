"""
Database manager for Azure PostgreSQL
Handles connections, ORM models, and CRUD operations for terminal logs
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, selectinload
from datetime import datetime
from sqlalchemy import String, Text, DateTime, Integer, Boolean, JSON, ForeignKey,text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path
import os
import logging
import uuid
import json

# Load environment variables from .env file in same directory as this file
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / '.env'
    load_dotenv(dotenv_path=env_path)  # Load .env from backend directory
    if env_path.exists():
        logging.getLogger(__name__).debug(f"Loaded .env from {env_path}")
except ImportError:
    pass  # dotenv not required

logger = logging.getLogger(__name__)

# Azure PostgreSQL connection URL from environment
# Format: postgresql+asyncpg://user:password@host:5432/database?ssl=require
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    logger.warning("DATABASE_URL not set - database features disabled")
    DATABASE_URL = "postgresql+asyncpg://localhost/dummy"  # Fallback

# Create async engine
engine = None
AsyncSessionLocal = None

def get_engine():
    global engine
    if engine is None:
        engine = create_async_engine(
                DATABASE_URL,
                echo=False,  # Set to True to log SQL queries (useful for debugging)
                pool_size=5,
                max_overflow=10,
                pool_pre_ping=True  # Verify connections before using
        )
    return engine

def get_session_maker():
    """Get session maker with lazy engine initialization"""
    global AsyncSessionLocal
    if AsyncSessionLocal is None:
        AsyncSessionLocal = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False
        )
    return AsyncSessionLocal

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

    # FK to parent scan (nullable — non-scan logs like health checks have no scan)
    scan_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scan_history.id", ondelete="SET NULL"), nullable=True, index=True)
    scan: Mapped[Optional["ScanHistory"]] = relationship("ScanHistory", back_populates="terminal_logs")

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
    
    # User relationship - links scan to the user who performed it
    user_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, index=True)
    user: Mapped["User"] = relationship("User", back_populates="scans")
    
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

    # Admin review (for uncertain samples)
    admin_review: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    admin_decision_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships to child tables (one scan → many related records)
    terminal_logs: Mapped[list["TerminalLog"]] = relationship("TerminalLog", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    uncertain_samples: Mapped[list["UncertainSampleQueue"]] = relationship("UncertainSampleQueue", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    feedback_samples: Mapped[list["FeedbackSamples"]] = relationship("FeedbackSamples", back_populates="scan", passive_deletes=True)
    behavioral_patterns: Mapped[list["BehavioralPatterns"]] = relationship("BehavioralPatterns", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)

    def __repr__(self):
        return f"<ScanHistory {self.id}: {self.file_name} - {'MALWARE' if self.is_malicious else 'BENIGN'}>"


class UncertainSampleQueue(Base):
    """
    Queue for samples with uncertain predictions awaiting VT verification
    Stores actual file copies for later upload to VirusTotal
    """
    __tablename__ = "uncertain_sample_queue"
    
    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # File information
    file_hash: Mapped[str] = mapped_column(String(64), index=True, unique=True)  # SHA256
    file_name: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(String(1000))
    file_size: Mapped[int] = mapped_column(Integer)
    file_storage_path: Mapped[str] = mapped_column(String(500))  # Path to queued file copy
    
    # ML prediction results
    ml_prediction: Mapped[int] = mapped_column(Integer)  # 0=malicious, 1=benign
    ml_confidence: Mapped[float] = mapped_column()  # Confidence in chosen label
    ml_raw_score: Mapped[float] = mapped_column()  # Raw probability of malicious class
    prediction_label: Mapped[str] = mapped_column(String(50))  # "MALICIOUS" or "CLEAN"
    
    # Behavioral enrichment info
    behavioral_enriched: Mapped[bool] = mapped_column(Boolean, default=False)
    behavioral_source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    
    # Features (serialized JSON for retraining)
    features_json: Mapped[str] = mapped_column(Text)  # Serialized feature vector
    # Raw API call sequence captured from vm_complete_analyzer (for CNN retraining)
    api_sequence_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # VT tracking
    vt_queried: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    vt_query_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    vt_scan_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    vt_result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Full VT results
    vt_attempts: Mapped[int] = mapped_column(Integer, default=0)
    
    # Status: PENDING, UPLOADING, SCANNING, VALIDATED, FAILED
    status: Mapped[str] = mapped_column(String(20), default="PENDING", index=True)

    # Admin-assigned ground-truth label (set when admin reviews via ✓ Safe / ✗ Malware
    # or via bulk-approve).  Uses training convention: 0=benign, 1=malicious.
    # NULL means no label has been assigned yet — export will skip this entry.
    admin_label: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # FK to parent scan
    scan_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scan_history.id", ondelete="SET NULL"), nullable=True, index=True)
    scan: Mapped[Optional["ScanHistory"]] = relationship("ScanHistory", back_populates="uncertain_samples")

    def __repr__(self):
        return f"<UncertainSampleQueue {self.id}: {self.file_hash[:8]}... - {self.status}>"


class User(Base):
    """
    User authentication table for admin and user roles
    Admin can create users, both admin and users can login
    """
    __tablename__ = "users"
    
    # Primary key (using UUID type to match database)
    user_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Authentication
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)  # bcrypt hash
    
    # User information
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    phone_number: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    
    # Role and status
    role: Mapped[str] = mapped_column(String(20), default="user", index=True)  # "admin" or "user"
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationship: user's scan history
    scans: Mapped[list["ScanHistory"]] = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.user_id}: {self.username} ({self.role})>"


class FeedbackSamples(Base):
    """
    Stores validated mismatches between ML and VT for model retraining
    Replaces the CSV-based feedback collector with database storage
    """
    __tablename__ = "feedback_samples"
    
    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    # File information
    file_hash: Mapped[str] = mapped_column(String(64), index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    file_size: Mapped[int] = mapped_column(Integer)
    
    # ML prediction
    ml_prediction: Mapped[int] = mapped_column(Integer)  # 0=malicious, 1=benign
    ml_confidence: Mapped[float] = mapped_column()
    ml_verdict: Mapped[str] = mapped_column(String(20))  # "Malicious" or "Benign"
    ml_raw_score: Mapped[float] = mapped_column()
    
    # VT results
    vt_detections: Mapped[int] = mapped_column(Integer)
    vt_total_engines: Mapped[int] = mapped_column(Integer)
    vt_detection_ratio: Mapped[str] = mapped_column(String(20))  # "45/70"
    vt_family: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    vt_threat_label: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    vt_malicious: Mapped[bool] = mapped_column(Boolean, index=True)
    
    # Mismatch classification
    mismatch_type: Mapped[str] = mapped_column(String(20), index=True)  # FALSE_POSITIVE or FALSE_NEGATIVE
    severity: Mapped[str] = mapped_column(String(10), index=True)  # HIGH, MEDIUM, LOW
    
    # Processing status
    needs_review: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    processed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    processed_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Features for retraining (serialized JSON)
    features_json: Mapped[str] = mapped_column(Text)

    # FK to parent scan (nullable — feedback can be created from VT async job without a live scan)
    scan_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scan_history.id", ondelete="SET NULL"), nullable=True, index=True)
    scan: Mapped[Optional["ScanHistory"]] = relationship("ScanHistory", back_populates="feedback_samples")

    def __repr__(self):
        return f"<FeedbackSamples {self.id}: {self.mismatch_type} - {self.severity}>"


class BehavioralPatterns(Base):
    """
    Stores ransomware/malware behavioral patterns detected during sandbox analysis.
    One row per scan — each boolean column represents a detected pattern.
    """
    __tablename__ = "behavioral_patterns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    # Link back to the scan that produced these patterns
    file_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    detection_method: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Pattern flags (all from vm_complete_analyzer detect_patterns)
    mass_file_encryption: Mapped[bool] = mapped_column(Boolean, default=False)
    shadow_copy_deletion: Mapped[bool] = mapped_column(Boolean, default=False)
    registry_persistence: Mapped[bool] = mapped_column(Boolean, default=False)
    network_c2_communication: Mapped[bool] = mapped_column(Boolean, default=False)
    ransom_note_creation: Mapped[bool] = mapped_column(Boolean, default=False)
    mass_file_deletion: Mapped[bool] = mapped_column(Boolean, default=False)
    suspicious_process_creation: Mapped[bool] = mapped_column(Boolean, default=False)
    api_encrypt_rename_sequence: Mapped[bool] = mapped_column(Boolean, default=False)

    # Aggregate
    total_patterns_detected: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[Optional[float]] = mapped_column(nullable=True)

    # Full patterns dict for future-proofing
    raw_patterns: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)

    # FK to parent scan
    scan_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scan_history.id", ondelete="SET NULL"), nullable=True, index=True)
    scan: Mapped[Optional["ScanHistory"]] = relationship("ScanHistory", back_populates="behavioral_patterns")

    def __repr__(self):
        return f"<BehavioralPatterns {self.id}: {self.file_name} - {self.total_patterns_detected} patterns>"


class ModelTrainingHistory(Base):
    """
    Tracks model training versions and performance metrics.
    Seeded from cnn_fixed_metadata_20260301_180706.json on first init.
    Updated by the retrain trigger endpoint after each retraining run.
    """
    __tablename__ = "model_training_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trained_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    version: Mapped[str] = mapped_column(String(50), default="1.0")
    model_type: Mapped[str] = mapped_column(String(50))          # "1D CNN"
    model_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    dataset: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Performance metrics
    accuracy: Mapped[float] = mapped_column()
    precision: Mapped[Optional[float]] = mapped_column(nullable=True)
    recall: Mapped[Optional[float]] = mapped_column(nullable=True)
    f1_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    fnr: Mapped[Optional[float]] = mapped_column(nullable=True)
    auc: Mapped[Optional[float]] = mapped_column(nullable=True)

    # Architecture info
    n_features: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    vocab_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    total_samples: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Retraining cycle metadata
    samples_added: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)    # new samples used in this cycle
    accuracy_delta: Mapped[Optional[float]] = mapped_column(nullable=True)          # accuracy vs previous version

    # Active-version flag — at most one CNN row and one XGBoost row should be True
    # at any time.  set_active_model() enforces this invariant.
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", index=True)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self):
        return f"<ModelTrainingHistory {self.id}: v{self.version} acc={self.accuracy:.4f}>"


async def init_db():
    """
    Initialize database tables
    Creates all tables defined in Base metadata
    Call this during app startup
    """
    try:
        # Get engine (creates it if needed)
        eng = get_engine()
        async with eng.begin() as conn:
            # Create tables if they don't exist
            await conn.run_sync(Base.metadata.create_all)
        logger.info("✓ Database tables initialized")

        # Seed ModelTrainingHistory from JSON metadata if table is empty
        await _seed_model_training_history()

    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def _seed_model_training_history():
    """
    Seed ModelTrainingHistory from ALL cnn_fixed_metadata_*.json and
    xgboost_metadata_*.json files in the models directory.

    CNN versions are labelled v1.0, v1.1 … sorted oldest→newest.
    XGBoost versions are labelled vXGB-1.0, vXGB-1.1 … (separate series).
    accuracy_delta is calculated relative to the previous version within
    each model-type series.
    Skips seeding if the table already contains rows (use 'reseed' CLI to force).
    """
    from sqlalchemy import select, func
    import glob
    SessionLocal = get_session_maker()
    try:
        async with SessionLocal() as session:
            count = await session.scalar(select(func.count(ModelTrainingHistory.id)))
            if count and count > 0:
                logger.info("[SEED] model_training_history already has rows — skipping seed")
                return
            await _do_seed(session)
    except Exception as e:
        logger.warning(f"[SEED] Could not seed model training history: {e}")


async def _do_seed(session: AsyncSession):
    """Insert all metadata rows.  Called by _seed_model_training_history and reseed CLI."""
    import glob
    models_dir = Path(__file__).parent.parent / "models"

    def _ts(filename: str) -> str:
        """Extract the YYYYMMDD_HHMMSS timestamp from a metadata filename."""
        stem = Path(filename).stem  # e.g. cnn_fixed_metadata_20260225_183744
        parts = stem.split("_")
        # last two parts are date + time  e.g. ["cnn","fixed","metadata","20260225","183744"]
        return "_".join(parts[-2:])

    def _parse_ts(ts: str) -> datetime:
        try:
            return datetime.strptime(ts, "%Y%m%d_%H%M%S")
        except Exception:
            return datetime.utcnow()

    # ── Collect CNN metadata files ───────────────────────────────────────────
    cnn_files = sorted(
        glob.glob(str(models_dir / "cnn_fixed_metadata_*.json")),
        key=lambda p: _ts(p)
    )

    # ── Collect XGBoost metadata files ──────────────────────────────────────
    xgb_files = sorted(
        glob.glob(str(models_dir / "xgboost_metadata_*.json")),
        key=lambda p: _ts(p)
    )

    if not cnn_files and not xgb_files:
        logger.warning("[SEED] No metadata JSON files found in models dir — skipping seed")
        return

    rows: list[ModelTrainingHistory] = []

    # ── Build CNN rows ────────────────────────────────────────────────────────
    prev_acc: Optional[float] = None
    for idx, fpath in enumerate(cnn_files):
        with open(fpath) as f:
            meta = json.load(f)

        ts = _ts(fpath)
        trained_at = _parse_ts(ts)
        version = f"1.{idx}"

        # Match .keras file by timestamp
        keras_path = models_dir / f"best_fixed_cnn_{ts}.keras"
        model_path = str(keras_path) if keras_path.exists() else None

        accuracy = float(meta.get("accuracy", 0.0))
        delta = round(accuracy - prev_acc, 6) if prev_acc is not None else 0.0
        prev_acc = accuracy

        rows.append(ModelTrainingHistory(
            version=version,
            model_type=meta.get("model_type", "1D CNN"),
            model_path=model_path,
            dataset="MelbehaveD-v1 + Kaggle API Calls",
            accuracy=accuracy,
            precision=meta.get("precision"),
            recall=meta.get("recall"),
            f1_score=meta.get("f1_score"),
            fnr=meta.get("fnr"),
            auc=meta.get("auc"),
            n_features=meta.get("n_features"),
            vocab_size=meta.get("vocab_size"),
            total_samples=meta.get("total_samples", 80000),
            samples_added=0,
            accuracy_delta=delta,
            notes=f"Seeded from {Path(fpath).name}",
            trained_at=trained_at,
        ))

    # ── Build XGBoost rows ────────────────────────────────────────────────────
    prev_acc = None
    for idx, fpath in enumerate(xgb_files):
        with open(fpath) as f:
            meta = json.load(f)

        ts = _ts(fpath)
        trained_at = _parse_ts(ts)
        version = f"vXGB-1.{idx}"

        pkl_path = models_dir / f"xgboost_zenodo_{ts}.pkl"
        model_path = str(pkl_path) if pkl_path.exists() else None

        # XGBoost metadata nests performance metrics
        perf = meta.get("performance", {})
        accuracy = float(perf.get("accuracy", meta.get("accuracy", 0.0)))
        delta = round(accuracy - prev_acc, 6) if prev_acc is not None else 0.0
        prev_acc = accuracy

        rows.append(ModelTrainingHistory(
            version=version,
            model_type=meta.get("model_type", "XGBClassifier"),
            model_path=model_path,
            dataset="Zenodo",
            accuracy=accuracy,
            precision=meta.get("precision"),        # usually absent in XGB meta
            recall=meta.get("recall"),
            f1_score=meta.get("f1_score"),
            fnr=meta.get("fnr"),
            auc=float(perf.get("roc_auc", meta.get("auc", 0.0))) or None,
            n_features=meta.get("n_features"),
            vocab_size=None,
            total_samples=meta.get("n_samples"),
            samples_added=0,
            accuracy_delta=delta,
            notes=f"Seeded from {Path(fpath).name}",
            trained_at=trained_at,
        ))

    # Insert all rows sorted by trained_at so IDs are chronological
    rows.sort(key=lambda r: r.trained_at)
    for row in rows:
        session.add(row)
    await session.commit()
    logger.info(f"✓ ModelTrainingHistory seeded with {len(rows)} version(s) "
                f"({len(cnn_files)} CNN + {len(xgb_files)} XGBoost)")


async def get_session() -> AsyncSession:
    """
    Dependency for FastAPI to get DB session
    Use with: db: AsyncSession = Depends(get_session)
    """
    session_maker = get_session_maker()
    async with session_maker() as session:
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
    session_id: Optional[str] = None,
    scan_id: Optional[int] = None,
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
        session_id=session_id,
        scan_id=scan_id,
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
    user_id: uuid.UUID,  # ✨ NEW: Required user_id
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
        user_id: UUID of the user performing the scan
        model_type: "CNN" or "Traditional ML"
        file_hash: Optional SHA256 hash of file
    
    Returns:
        Created ScanHistory object
    """
    from pathlib import Path
    
    scan_entry = ScanHistory(
        user_id=user_id,  # ✨ NEW: Set user_id
        file_path=file_path,
        file_name=Path(file_path).name,
        file_size=result.get('file_size') or result.get('features_count') or 0,
        file_hash=file_hash,
        is_malicious=result['is_malicious'],
        confidence=result['confidence'],
        prediction_label=result['prediction_label'],
        model_type=model_type,
        scan_time_ms=result['scan_time_ms'],
        features_analyzed=result.get('features_count') or result.get('file_size') or 0,
        vt_detection_ratio=result.get('vt_detection_ratio'),
        vt_data=result.get('vt_data')
    )
    
    session.add(scan_entry)
    await session.commit()
    await session.refresh(scan_entry)
    
    logger.debug(f"Saved scan history: {scan_entry.id} for user: {user_id}")
    return scan_entry

async def save_behavioral_patterns(
    session: AsyncSession,
    patterns: Dict[str, bool],
    file_name: Optional[str] = None,
    file_hash: Optional[str] = None,
    detection_method: Optional[str] = None,
    risk_score: Optional[float] = None,
    scan_id: Optional[int] = None,
) -> "BehavioralPatterns":
    """
    Save sandbox behavioral pattern flags to the database.

    Args:
        session: Async DB session
        patterns: Dict of pattern_name -> bool from vm_complete_analyzer.detect_patterns()
        file_name: Original filename scanned
        file_hash: SHA-256 of scanned file
        detection_method: e.g. 'soft_voting_xgb_cnn'
        risk_score: Optional risk score from analyzer

    Returns:
        Persisted BehavioralPatterns ORM row
    """
    # Support both new rich-dict format {'detected': bool, 'confidence': ..., 'evidence': [...]} 
    # and legacy plain-bool format for backward compatibility.
    def _pb(key): 
        v = patterns.get(key, False)
        return bool(v.get('detected', False)) if isinstance(v, dict) else bool(v)

    total = sum(1 for k in patterns if _pb(k))
    row = BehavioralPatterns(
        file_name=file_name,
        file_hash=file_hash,
        detection_method=detection_method,
        mass_file_encryption=_pb('mass_file_encryption'),
        shadow_copy_deletion=_pb('shadow_copy_deletion'),
        registry_persistence=_pb('registry_persistence'),
        network_c2_communication=_pb('network_c2_communication'),
        ransom_note_creation=_pb('ransom_note_creation'),
        mass_file_deletion=_pb('mass_file_deletion'),
        suspicious_process_creation=_pb('suspicious_process_creation'),
        api_encrypt_rename_sequence=_pb('api_encrypt_rename_sequence'),
        total_patterns_detected=total,
        risk_score=risk_score,
        # Round-trip through json to produce a plain Python dict — asyncpg's JSON codec
        # cannot handle nested dicts that haven't been through stdlib json serialization.
        raw_patterns=json.loads(json.dumps(patterns, default=str)),
        scan_id=scan_id,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row

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
    user_id: Optional[uuid.UUID] = None,  # ✨ NEW: Filter by user_id
    malicious_only: bool = False,
    file_hash: Optional[str] = None
) -> list[ScanHistory]:
    """
    Get scan history with filtering
    
    Args:
        session: Database session
        limit: Maximum number of scans to return
        user_id: Filter by specific user (optional - for admin viewing all scans, pass None)
        malicious_only: Only return malware detections
        file_hash: Filter by specific file hash
    
    Returns:
        List of ScanHistory objects
    """
    from sqlalchemy import select, desc
    
    stmt = select(ScanHistory).order_by(desc(ScanHistory.timestamp)).limit(limit)
    
    if user_id:  # ✨ NEW: Filter by user_id if provided
        stmt = stmt.where(ScanHistory.user_id == user_id)
    
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


# ============================================================================
# ADAPTIVE LEARNING - UNCERTAINTY QUEUE OPERATIONS
# ============================================================================

async def queue_uncertain_sample(
    session: AsyncSession,
    file_hash: str,
    file_name: str,
    file_path: str,
    file_size: int,
    file_storage_path: str,
    ml_prediction: int,
    ml_confidence: float,
    ml_raw_score: float,
    prediction_label: str,
    features_json: str,
    behavioral_enriched: bool = False,
    behavioral_source: Optional[str] = None,
    scan_id: Optional[int] = None,
    api_sequence_json: Optional[str] = None,
) -> UncertainSampleQueue:
    """
    Queue an uncertain sample for later VT upload
    
    Args:
        session: Database session
        file_hash: SHA256 hash of file
        file_name: Original filename
        file_path: Original file path
        file_size: File size in bytes
        file_storage_path: Path to stored file copy
        ml_prediction: 0=malicious, 1=benign
        ml_confidence: Confidence in prediction
        ml_raw_score: Raw probability of malicious class
        prediction_label: \"MALICIOUS\" or \"CLEAN\"
        features_json: Serialized feature vector
        behavioral_enriched: Whether behavioral features included
        behavioral_source: Source of behavioral data
    
    Returns:
        Created UncertainSampleQueue object
    """
    # Check if already queued (avoid duplicates)
    from sqlalchemy import select
    existing = await session.scalar(
        select(UncertainSampleQueue).where(UncertainSampleQueue.file_hash == file_hash)
    )
    
    if existing:
        logger.debug(f"Sample already queued: {file_hash[:8]}...")
        return existing
    
    queue_entry = UncertainSampleQueue(
        file_hash=file_hash,
        file_name=file_name,
        file_path=file_path,
        file_size=file_size,
        file_storage_path=file_storage_path,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        ml_raw_score=ml_raw_score,
        prediction_label=prediction_label,
        behavioral_enriched=behavioral_enriched,
        behavioral_source=behavioral_source,
        features_json=features_json,
        api_sequence_json=api_sequence_json,
        status="PENDING",
        scan_id=scan_id,
    )
    
    session.add(queue_entry)
    await session.commit()
    await session.refresh(queue_entry)
    
    logger.debug(f"Queued uncertain sample: {queue_entry.id}")
    return queue_entry


async def get_pending_vt_uploads(
    session: AsyncSession,
    limit: int = 400,
    max_attempts: int = 3
) -> list[UncertainSampleQueue]:
    """
    Get samples pending VT upload
    
    Args:
        session: Database session
        limit: Maximum samples to return
        max_attempts: Max retry attempts before giving up
    
    Returns:
        List of UncertainSampleQueue objects
    """
    from sqlalchemy import select
    
    stmt = (
        select(UncertainSampleQueue)
        .where(UncertainSampleQueue.status == "PENDING")
        .where(UncertainSampleQueue.vt_attempts < max_attempts)
        .order_by(UncertainSampleQueue.created_at.asc())
        .limit(limit)
    )
    
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def update_vt_upload_status(
    session: AsyncSession,
    queue_id: int,
    status: str,
    vt_scan_id: Optional[str] = None
):
    """
    Update VT upload status
    
    Args:
        session: Database session
        queue_id: Queue entry ID
        status: New status (UPLOADING, SCANNING, VALIDATED, FAILED)
        vt_scan_id: VT scan ID if available
    """
    from sqlalchemy import select, update
    
    stmt = (
        update(UncertainSampleQueue)
        .where(UncertainSampleQueue.id == queue_id)
        .values(
            status=status,
            vt_scan_id=vt_scan_id,
            updated_at=datetime.utcnow()
        )
    )
    
    await session.execute(stmt)
    await session.commit()
    logger.debug(f"Updated queue {queue_id} status: {status}")


async def update_vt_result(
    session: AsyncSession,
    queue_id: int,
    status: str,
    vt_result_json: str,
    vt_queried: bool = True
):
    """
    Update queue entry with VT scan results
    
    Args:
        session: Database session
        queue_id: Queue entry ID
        status: Final status (VALIDATED, FAILED)
        vt_result_json: Serialized VT results
        vt_queried: Mark as queried
    """
    from sqlalchemy import update
    
    stmt = (
        update(UncertainSampleQueue)
        .where(UncertainSampleQueue.id == queue_id)
        .values(
            status=status,
            vt_result_json=vt_result_json,
            vt_queried=vt_queried,
            vt_query_date=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
    )
    
    await session.execute(stmt)
    await session.commit()
    logger.debug(f"Updated queue {queue_id} with VT results")


async def increment_vt_attempts(session: AsyncSession, queue_id: int):
    """
    Increment VT attempt counter for failed uploads
    
    Args:
        session: Database session
        queue_id: Queue entry ID
    """
    from sqlalchemy import select, update
    
    stmt = (
        update(UncertainSampleQueue)
        .where(UncertainSampleQueue.id == queue_id)
        .values(
            vt_attempts=UncertainSampleQueue.vt_attempts + 1,
            updated_at=datetime.utcnow()
        )
    )
    
    await session.execute(stmt)
    await session.commit()
    logger.debug(f"Incremented VT attempts for queue {queue_id}")


async def get_queue_statistics(session: AsyncSession) -> Dict[str, Any]:
    """
    Get uncertainty queue statistics
    
    Returns:
        Dictionary with queue stats
    """
    from sqlalchemy import select, func
    
    total_queued = await session.scalar(select(func.count(UncertainSampleQueue.id)))
    
    pending = await session.scalar(
        select(func.count(UncertainSampleQueue.id))
        .where(UncertainSampleQueue.status == "PENDING")
    )
    
    validated = await session.scalar(
        select(func.count(UncertainSampleQueue.id))
        .where(UncertainSampleQueue.status == "VALIDATED")
    )
    
    failed = await session.scalar(
        select(func.count(UncertainSampleQueue.id))
        .where(UncertainSampleQueue.status == "FAILED")
    )
    
    avg_confidence = await session.scalar(
        select(func.avg(UncertainSampleQueue.ml_confidence))
    )
    
    return {
        "total_queued": total_queued or 0,
        "pending_vt": pending or 0,
        "validated": validated or 0,
        "failed": failed or 0,
        "avg_confidence": float(avg_confidence) if avg_confidence else 0
    }


async def cleanup_old_queue_entries(session: AsyncSession, days: int = 7):
    """
    Delete queue entries older than specified days
    
    Args:
        session: Database session
        days: Delete entries older than this many days
    """
    from sqlalchemy import delete
    from datetime import timedelta
    
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    stmt = delete(UncertainSampleQueue).where(
        UncertainSampleQueue.created_at < cutoff_date
    )
    
    result = await session.execute(stmt)
    await session.commit()
    
    deleted_count = result.rowcount
    logger.info(f"Cleaned up {deleted_count} old queue entries (>{days} days)")
    return deleted_count


# ============================================================================
# ADAPTIVE LEARNING - FEEDBACK SAMPLES OPERATIONS
# ============================================================================

async def insert_feedback_sample(
    session: AsyncSession,
    file_hash: str,
    file_name: str,
    file_size: int,
    ml_prediction: int,
    ml_confidence: float,
    ml_raw_score: float,
    vt_detections: int,
    vt_total_engines: int,
    vt_malicious: bool,
    vt_scans: Dict[str, Any],
    mismatch_type: str,
    severity: str,
    features_json: str
) -> FeedbackSamples:
    """
    Insert feedback sample for retraining
    
    Args:
        session: Database session
        file_hash: SHA256 hash
        file_name: Original filename
        file_size: File size
        ml_prediction: 0=malicious, 1=benign
        ml_confidence: ML confidence
        ml_raw_score: Raw ML score
        vt_detections: Number of AV detections
        vt_total_engines: Total AV engines
        vt_malicious: VT verdict (bool)
        vt_scans: Full VT scan results
        mismatch_type: FALSE_POSITIVE or FALSE_NEGATIVE
        severity: HIGH, MEDIUM, LOW
        features_json: Serialized features
    
    Returns:
        Created FeedbackSamples object
    """
    ml_verdict = "Malicious" if ml_prediction == 0 else "Benign"
    
    # Extract VT family/label from scans
    vt_family = "Unknown"
    vt_threat_label = "Unknown"
    
    # Try to get most common family name from detections
    if vt_scans:
        families = []
        for av_name, av_result in vt_scans.items():
            if isinstance(av_result, dict) and av_result.get('category') in ['malicious', 'suspicious']:
                result_str = av_result.get('result', '')
                if result_str:
                    families.append(result_str)
        
        if families:
            # Use most common family name
            from collections import Counter
            vt_family = Counter(families).most_common(1)[0][0]
            vt_threat_label = vt_family
    
    feedback_entry = FeedbackSamples(
        file_hash=file_hash,
        file_name=file_name,
        file_size=file_size,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        ml_verdict=ml_verdict,
        ml_raw_score=ml_raw_score,
        vt_detections=vt_detections,
        vt_total_engines=vt_total_engines,
        vt_detection_ratio=f"{vt_detections}/{vt_total_engines}",
        vt_family=vt_family,
        vt_threat_label=vt_threat_label,
        vt_malicious=vt_malicious,
        mismatch_type=mismatch_type,
        severity=severity,
        needs_review=True,
        processed=False,
        features_json=features_json,
        notes=f"{mismatch_type}: ML={ml_verdict}, VT={vt_detections}/{vt_total_engines}"
    )
    
    session.add(feedback_entry)
    await session.commit()
    await session.refresh(feedback_entry)
    
    logger.info(f"Logged feedback: {mismatch_type} for {file_hash[:8]}...")
    return feedback_entry


async def get_feedback_samples(
    session: AsyncSession,
    processed: bool = False,
    limit: Optional[int] = None
) -> list[FeedbackSamples]:
    """
    Get feedback samples for retraining
    
    Args:
        session: Database session
        processed: Get processed (True) or unprocessed (False) samples
        limit: Maximum samples to return
    
    Returns:
        List of FeedbackSamples objects
    """
    from sqlalchemy import select
    
    stmt = (
        select(FeedbackSamples)
        .where(FeedbackSamples.processed == processed)
        .where(FeedbackSamples.needs_review == True)
        .order_by(FeedbackSamples.timestamp.desc())
    )
    
    if limit:
        stmt = stmt.limit(limit)
    
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def mark_feedback_processed(
    session: AsyncSession,
    feedback_ids: list[int]
):
    """
    Mark feedback samples as processed after retraining
    
    Args:
        session: Database session
        feedback_ids: List of feedback sample IDs to mark as processed
    """
    from sqlalchemy import update
    
    stmt = (
        update(FeedbackSamples)
        .where(FeedbackSamples.id.in_(feedback_ids))
        .values(
            processed=True,
            processed_date=datetime.utcnow()
        )
    )
    
    await session.execute(stmt)
    await session.commit()
    logger.info(f"Marked {len(feedback_ids)} feedback samples as processed")


async def get_feedback_statistics(session: AsyncSession) -> Dict[str, Any]:
    """
    Get feedback sample statistics
    
    Returns:
        Dictionary with feedback stats
    """
    from sqlalchemy import select, func
    
    total_feedback = await session.scalar(select(func.count(FeedbackSamples.id)))
    
    pending = await session.scalar(
        select(func.count(FeedbackSamples.id))
        .where(FeedbackSamples.processed == False)
        .where(FeedbackSamples.needs_review == True)
    )
    
    false_positives = await session.scalar(
        select(func.count(FeedbackSamples.id))
        .where(FeedbackSamples.mismatch_type == "FALSE_POSITIVE")
    )
    
    false_negatives = await session.scalar(
        select(func.count(FeedbackSamples.id))
        .where(FeedbackSamples.mismatch_type == "FALSE_NEGATIVE")
    )
    
    high_severity = await session.scalar(
        select(func.count(FeedbackSamples.id))
        .where(FeedbackSamples.severity == "HIGH")
    )
    
    return {
        "total_feedback": total_feedback or 0,
        "pending_review": pending or 0,
        "false_positives": false_positives or 0,
        "false_negatives": false_negatives or 0,
        "high_severity": high_severity or 0,
        "ready_for_retraining": (pending or 0) >= 100
    }


# ============================================================================
# RETRAIN CENTER CRUD OPERATIONS
# ============================================================================

async def get_uncertain_samples_with_vt_status(
    session: AsyncSession,
    limit: int = 200,
) -> list[dict]:
    """
    Return uncertain scan_history rows (confidence 0.3–0.7, admin_review=False)
    with the associated uncertain_sample_queue VT status via LEFT JOIN.
    """
    from sqlalchemy import select, and_

    stmt = (
        select(
            ScanHistory,
            UncertainSampleQueue.status.label("vt_status"),
            UncertainSampleQueue.vt_query_date.label("vt_query_date"),
            UncertainSampleQueue.id.label("queue_id"),
        )
        .outerjoin(
            UncertainSampleQueue,
            UncertainSampleQueue.scan_id == ScanHistory.id,
        )
        .options(selectinload(ScanHistory.user))
        .where(
            and_(
                ScanHistory.confidence >= 0.3,
                ScanHistory.confidence <= 0.7,
                ScanHistory.admin_review == False,  # noqa: E712
            )
        )
        .order_by(ScanHistory.confidence.asc())
        .limit(limit)
    )

    result = await session.execute(stmt)
    rows = result.all()  # list of Row(ScanHistory, vt_status, vt_query_date, queue_id)
    return rows


async def bulk_approve_uncertain_samples(
    session: AsyncSession,
    scan_ids: list[int],
) -> int:
    """
    Mark a list of scan_history rows as admin_review=True and derive an admin_label
    for each linked uncertain_sample_queue entry from scan_history.is_malicious.
    For entries the admin already individually reviewed the label is preserved.
    Returns the number of scan_history rows updated.
    """
    from sqlalchemy import select, update

    if not scan_ids:
        return 0

    # Fetch scan rows so we can read is_malicious per entry
    fetch_stmt = select(ScanHistory).where(ScanHistory.id.in_(scan_ids))
    result = await session.execute(fetch_stmt)
    scans = result.scalars().all()

    now = datetime.utcnow()
    for sh in scans:
        sh.admin_review = True
        sh.admin_decision_date = now

        # Derive label in training convention (0=benign, 1=malicious)
        lbl = 1 if sh.is_malicious else 0
        # Only set admin_label if it hasn't been explicitly assigned via individual review
        usq_stmt = (
            update(UncertainSampleQueue)
            .where(UncertainSampleQueue.scan_id == sh.id)
            .where(UncertainSampleQueue.admin_label == None)  # noqa: E711
            .values(admin_label=lbl)
        )
        await session.execute(usq_stmt)

    await session.commit()
    return len(scans)


async def get_approved_for_retrain(session: AsyncSession) -> list[dict]:
    """
    Return uncertain_sample_queue entries whose linked scan_history row
    has admin_review=True, joined with scan metadata.
    """
    from sqlalchemy import select

    stmt = (
        select(
            UncertainSampleQueue,
            ScanHistory.file_name.label("sh_file_name"),
            ScanHistory.confidence.label("sh_confidence"),
            UncertainSampleQueue.admin_label.label("usq_admin_label"),
            ScanHistory.admin_decision_date.label("sh_admin_decision_date"),
        )
        .join(ScanHistory, UncertainSampleQueue.scan_id == ScanHistory.id)
        .where(ScanHistory.admin_review == True)  # noqa: E712
        .order_by(UncertainSampleQueue.created_at.desc())
    )

    result = await session.execute(stmt)
    return result.all()


async def get_latest_model_metadata(session: AsyncSession) -> Optional[ModelTrainingHistory]:
    """Return the most recently trained model row from model_training_history."""
    from sqlalchemy import select

    stmt = (
        select(ModelTrainingHistory)
        .order_by(ModelTrainingHistory.trained_at.desc())
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def insert_model_training_record(
    session: AsyncSession,
    version: str,
    model_type: str,
    accuracy: float,
    total_samples: int,
    model_path: Optional[str] = None,
    dataset: Optional[str] = None,
    precision: Optional[float] = None,
    recall: Optional[float] = None,
    f1_score: Optional[float] = None,
    fpr: Optional[float] = None,
    auc: Optional[float] = None,
    n_features: Optional[int] = None,
    vocab_size: Optional[int] = None,
    notes: Optional[str] = None,
    samples_added: Optional[int] = None,
    accuracy_delta: Optional[float] = None,
) -> ModelTrainingHistory:
    """Insert a new model training record after a successful retraining run."""
    row = ModelTrainingHistory(
        version=version,
        model_type=model_type,
        model_path=model_path,
        dataset=dataset,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        fpr=fpr,
        auc=auc,
        n_features=n_features,
        vocab_size=vocab_size,
        total_samples=total_samples,
        samples_added=samples_added,
        accuracy_delta=accuracy_delta,
        notes=notes,
        trained_at=datetime.utcnow(),
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def flush_uncertain_queue(
    session: AsyncSession,
    queue_ids: Optional[list[int]] = None,
) -> int:
    """
    Reset admin_review=False (and admin_decision_date=None) on scan_history rows
    linked to uncertain_sample_queue entries — does NOT delete queue rows.
    This allows the admin to re-approve samples without re-scanning.

    Args:
        session: DB session
        queue_ids: Specific queue entry IDs to reset. If None/empty, resets ALL.

    Returns:
        Number of scan_history rows reset.
    """
    from sqlalchemy import select, update

    # Find the queue rows to determine which scan_ids to reset
    if queue_ids:
        rows_stmt = select(UncertainSampleQueue.scan_id).where(
            UncertainSampleQueue.id.in_(queue_ids)
        )
    else:
        rows_stmt = select(UncertainSampleQueue.scan_id)

    result = await session.execute(rows_stmt)
    linked_scan_ids = [r for (r,) in result.all() if r is not None]

    if not linked_scan_ids:
        return 0

    # Reset admin_review on linked scan_history rows only
    reset_stmt = (
        update(ScanHistory)
        .where(ScanHistory.id.in_(linked_scan_ids))
        .values(admin_review=False, admin_decision_date=None)
    )
    res = await session.execute(reset_stmt)
    await session.commit()
    count = res.rowcount
    logger.info(f"Flushed (reset admin_review) on {count} scan_history rows")
    return count


async def backfill_uncertain_queue_from_history(
    session: AsyncSession,
    confidence_low: float = 0.3,
    confidence_high: float = 0.7,
) -> int:
    """
    Populate uncertain_sample_queue from existing scan_history rows whose
    confidence falls within [confidence_low, confidence_high] and that are
    not already present in the queue (matched by scan_id or file_hash).

    Useful for seeding the queue from historical scans for demo/testing.
    Fields not available in scan_history (features_json, file_storage_path)
    are filled with safe placeholder values.

    Args:
        session: DB session
        confidence_low: Lower bound (inclusive), default 0.3
        confidence_high: Upper bound (inclusive), default 0.7

    Returns:
        Number of new queue rows inserted.
    """
    from sqlalchemy import select, and_

    # Fetch candidate scan_history rows
    stmt = (
        select(ScanHistory)
        .where(
            and_(
                ScanHistory.confidence >= confidence_low,
                ScanHistory.confidence <= confidence_high,
                ScanHistory.file_hash.isnot(None),
            )
        )
        .order_by(ScanHistory.timestamp.desc())
    )
    result = await session.execute(stmt)
    candidates = result.scalars().all()

    if not candidates:
        logger.info("[BACKFILL] No scan_history rows found in confidence range")
        return 0

    # Fetch existing queue scan_ids and file_hashes to avoid duplicates
    existing_scan_ids_res = await session.execute(select(UncertainSampleQueue.scan_id))
    existing_scan_ids = {r for (r,) in existing_scan_ids_res.all() if r is not None}

    existing_hashes_res = await session.execute(select(UncertainSampleQueue.file_hash))
    existing_hashes = {r for (r,) in existing_hashes_res.all()}

    inserted = 0
    for sh in candidates:
        # Skip if already queued by scan_id or file_hash
        if sh.id in existing_scan_ids or sh.file_hash in existing_hashes:
            continue

        ml_prediction = 0 if sh.is_malicious else 1
        # Approximate raw score: confidence toward the predicted class
        ml_raw_score = sh.confidence if sh.is_malicious else (1.0 - sh.confidence)
        label = "MALICIOUS" if sh.is_malicious else "CLEAN"

        entry = UncertainSampleQueue(
            file_hash=sh.file_hash,
            file_name=sh.file_name,
            file_path=sh.file_path,
            file_size=sh.file_size,
            file_storage_path=sh.file_path,   # placeholder — original path
            ml_prediction=ml_prediction,
            ml_confidence=sh.confidence,
            ml_raw_score=ml_raw_score,
            prediction_label=label,
            behavioral_enriched=False,
            features_json="[]",               # not available from history
            status="PENDING",
            scan_id=sh.id,
        )
        session.add(entry)
        existing_hashes.add(sh.file_hash)     # prevent duplicates within this batch
        existing_scan_ids.add(sh.id)
        inserted += 1

    if inserted:
        await session.commit()
    logger.info(f"[BACKFILL] Inserted {inserted} entries into uncertain_sample_queue")
    return inserted


# ============================================================================
# ACTIVE-MODEL SELECTION
# ============================================================================

async def get_active_models(session: AsyncSession) -> dict:
    """
    Return the currently active CNN and XGBoost model rows.

    Returns:
        {
          "cnn":     ModelTrainingHistory | None,
          "xgboost": ModelTrainingHistory | None,
        }
    """
    from sqlalchemy import select

    stmt = select(ModelTrainingHistory).where(ModelTrainingHistory.is_active == True)  # noqa: E712
    result = await session.execute(stmt)
    rows = result.scalars().all()

    out = {"cnn": None, "xgboost": None}
    for row in rows:
        mt = (row.model_type or "").lower()
        if "cnn" in mt or "1d" in mt:
            out["cnn"] = row
        elif "xgb" in mt or "xgboost" in mt or "gradient" in mt:
            out["xgboost"] = row
    return out


async def set_active_model(session: AsyncSession, record_id: int) -> ModelTrainingHistory:
    """
    Mark a model_training_history row as the active version for its model family.

    For whichever family the chosen row belongs to (CNN or XGBoost), ALL existing
    active flags for that family are cleared first, then the chosen row is set.

    Returns the updated row.
    Raises ValueError if record_id is not found.
    """
    from sqlalchemy import select, update

    # Fetch the target row
    stmt = select(ModelTrainingHistory).where(ModelTrainingHistory.id == record_id)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        raise ValueError(f"ModelTrainingHistory id={record_id} not found")

    # Determine family
    mt = (row.model_type or "").lower()
    if "cnn" in mt or "1d" in mt:
        family_filter = ModelTrainingHistory.model_type.ilike("%CNN%")
    else:
        # XGBoost / GradientBoosting
        family_filter = ModelTrainingHistory.model_type.ilike("%XGB%")

    # Unset all active flags for this family
    await session.execute(
        update(ModelTrainingHistory)
        .where(family_filter)
        .values(is_active=False)
    )

    # Set the chosen row active
    row.is_active = True
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def get_all_model_versions(session: AsyncSession) -> list[ModelTrainingHistory]:
    """Return all ModelTrainingHistory rows ordered oldest → newest (for version chart)."""
    from sqlalchemy import select

    result = await session.execute(
        select(ModelTrainingHistory).order_by(ModelTrainingHistory.trained_at.asc())
    )
    return list(result.scalars().all())


async def export_approved_samples_for_retraining(
    session: AsyncSession,
    xgb_feature_names: Optional[list[str]] = None,
    output_dir: Optional[str] = None,
) -> dict:
    """
    Export approved uncertain_sample_queue entries to flat files for retraining:

    - augment_cnn.json  : list of {api_sequence: [...], label: 0|1}  (0=benign, 1=malicious)
    - augment_xgb.csv   : CSV with feature columns + label (0=benign, 1=malicious)

    Only entries with admin_review=True on the linked scan_history are exported.
    Entries missing api_sequence_json are skipped for the CNN export;
    entries where features_json == '[]' are skipped for the XGBoost export.

    Returns:
        {cnn_rows, xgb_rows, cnn_path, xgb_path, output_dir}
    """
    import csv
    from sqlalchemy import select

    out_dir = Path(output_dir) if output_dir else (
        Path(__file__).parent / "training_script" / "augment_data"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    # Fetch approved queue entries
    stmt = (
        select(UncertainSampleQueue)
        .join(ScanHistory, UncertainSampleQueue.scan_id == ScanHistory.id)
        .where(ScanHistory.admin_review == True)  # noqa: E712
    )
    result = await session.execute(stmt)
    entries = result.scalars().all()

    cnn_rows: list[dict] = []
    xgb_rows: list[dict] = []

    for e in entries:
        # Use the admin-assigned ground-truth label (training convention: 0=benign, 1=malicious).
        # Skip entries that were never explicitly labelled — training on the model's own
        # uncertain prediction would introduce noise.
        if e.admin_label is None:
            continue
        label = e.admin_label

        # ── CNN export ────────────────────────────────────────────────────
        if e.api_sequence_json:
            try:
                seq = json.loads(e.api_sequence_json)
                if isinstance(seq, list) and seq:
                    cnn_rows.append({"api_sequence": seq, "label": label})
            except Exception:
                pass

        # ── XGBoost export ────────────────────────────────────────────────
        if e.features_json and e.features_json != "[]":
            try:
                feat_vals = json.loads(e.features_json)
                if isinstance(feat_vals, list) and feat_vals:
                    if xgb_feature_names and len(xgb_feature_names) == len(feat_vals):
                        row = dict(zip(xgb_feature_names, feat_vals))
                    else:
                        row = {f"f{i}": v for i, v in enumerate(feat_vals)}
                    row["label"] = label
                    xgb_rows.append(row)
            except Exception:
                pass

    # Write CNN JSON
    cnn_path = out_dir / "augment_cnn.json"
    with open(cnn_path, "w") as f:
        json.dump(cnn_rows, f)

    # Write XGBoost CSV
    xgb_path = out_dir / "augment_xgb.csv"
    if xgb_rows:
        fieldnames = list(xgb_rows[0].keys())
        with open(xgb_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(xgb_rows)
    else:
        xgb_path.write_text("")

    logger.info(
        f"[EXPORT] Wrote {len(cnn_rows)} CNN rows → {cnn_path.name} | "
        f"{len(xgb_rows)} XGBoost rows → {xgb_path.name}"
    )
    return {
        "cnn_rows": len(cnn_rows),
        "xgb_rows": len(xgb_rows),
        "cnn_path": str(cnn_path),
        "xgb_path": str(xgb_path),
        "output_dir": str(out_dir),
    }


# ============================================================================
# CLI ENTRY POINT
# Usage:
#   python db_manager.py init       — create tables + seed model metadata
#   python db_manager.py backfill   — populate uncertain_sample_queue from scan_history
#   python db_manager.py reseed     — drop + re-insert all model_training_history rows
# ============================================================================

if __name__ == "__main__":
    import asyncio
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"

    if cmd == "init":
        asyncio.run(init_db())

    elif cmd == "backfill":
        async def _backfill():
            sm = get_session_maker()
            async with sm() as session:
                n = await backfill_uncertain_queue_from_history(session)
                print(f"Backfill complete — {n} rows inserted into uncertain_sample_queue.")
        asyncio.run(_backfill())

    elif cmd == "reseed":
        async def _reseed():
            from sqlalchemy import delete
            # Ensure tables exist first
            eng = get_engine()
            async with eng.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            sm = get_session_maker()
            async with sm() as session:
                # Clear existing rows
                await session.execute(delete(ModelTrainingHistory))
                await session.commit()
                print("Cleared existing model_training_history rows.")

                await _do_seed(session)
                # Count result
                from sqlalchemy import select, func
                n = await session.scalar(select(func.count(ModelTrainingHistory.id)))
                print(f"Reseed complete — {n} version(s) in model_training_history.")
        asyncio.run(_reseed())

    else:
        print("Usage: python db_manager.py [init|backfill|reseed]")
        print("  init      — create all tables and seed model_training_history")
        print("  backfill  — copy scan_history rows (confidence 0.3–0.7) into uncertain_sample_queue")
        print("  reseed    — drop and re-insert all model_training_history from metadata JSON files")
