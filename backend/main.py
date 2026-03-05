"""
RanScanAI Backend - Privacy-First Malware Detection API
FastAPI server for local malware scanning with ML model
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import uvicorn
import logging
import asyncio
import uuid
import json
from pathlib import Path
from typing import Optional, Dict, Any
import os
import sys
import httpx

# Load environment variables from .env file (optional)
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file if it exists
except ImportError:
    pass  # dotenv not installed, will use system env vars only

# Configure logging FIRST
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add parent and workspace root directories to path for imports
workspace_root = Path(__file__).parent.parent.parent  # K/
sys.path.insert(0, str(workspace_root))  # For migration_package imports
sys.path.insert(0, str(Path(__file__).parent.parent))  # For Iteration_1/ imports

# Import model modules
from ml_model import MalwareDetector

# CNN client is optional (only if you have CNN service running)
CNNModelClient = None
try:
    from cnn_client import CNNModelClient
    logger.info("✓ CNN client module imported successfully")
except ImportError as e:
    logger.debug(f"Could not import from migration_package.cnn_client: {e}")

from vt_integration import VirusTotalEnricher

# Import authentication router
try:
    logger.info("Attempting to import auth_routes...")
    from auth import auth_router, get_current_user, get_current_admin
    logger.info(f"✓ Auth routes imported successfully (router type: {type(auth_router)})")
except ImportError as e:
    logger.error(f"❌ Auth routes import failed (ImportError): {e}")
    logger.warning("Auth routes not available - authentication disabled")
    import traceback
    traceback.print_exc()
    auth_router = None
    get_current_user = None
    get_current_admin = None
except Exception as e:
    logger.error(f"❌ Unexpected error importing auth routes: {e}")
    import traceback
    traceback.print_exc()
    auth_router = None
    get_current_user = None
    get_current_admin = None

# Import detection routes
try:
    from detection_routes import router as detection_router
    logger.info("✓ Detection routes imported successfully")
except ImportError as e:
    logger.warning(f"Detection routes import failed: {e}")
    detection_router = None
except Exception as e:
    logger.warning(f"Unexpected error importing detection routes: {e}")
    detection_router = None

# Import report routes
try:
    from report_routes import router as report_router
    logger.info("✓ Report routes imported successfully")
except ImportError as e:
    logger.warning(f"Report routes import failed: {e}")
    report_router = None
except Exception as e:
    logger.warning(f"Unexpected error importing report routes: {e}")
    report_router = None

# Import retrain routes
try:
    from retrain_routes import router as retrain_router
    logger.info("✓ Retrain routes imported successfully")
except ImportError as e:
    logger.warning(f"Retrain routes import failed: {e}")
    retrain_router = None
except Exception as e:
    logger.warning(f"Unexpected error importing retrain routes: {e}")
    retrain_router = None

# Configuration
# Toggle between Traditional ML and CNN model
USE_CNN_MODEL = os.getenv("USE_CNN_MODEL", "false").lower() == "true"  # Set to "true" to enable CNN
CNN_MODEL_SERVICE_URL = os.getenv("CNN_MODEL_SERVICE_URL", "http://100.73.153.23:8001")

# OR override directly (uncomment to use):
USE_CNN_MODEL = True  # Change this to True to use CNN model

# Initialize FastAPI app
app = FastAPI(
    title="SecureGuard API",
    description="Privacy-first malware detection with hybrid AI analysis",
    version="1.0.0"
)

# Configure CORS for browser extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to extension ID
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include authentication routes
if auth_router:
    app.include_router(auth_router)
    logger.info("✓ Authentication routes registered")
else:
    logger.warning("⚠️ Authentication routes NOT registered - auth_router is None")

# Include detection routes
if detection_router:
    app.include_router(detection_router)
    logger.info("✓ Detection routes registered at /api/detections")
else:
    logger.warning("⚠️ Detection routes NOT registered")

# Include report routes
if report_router:
    app.include_router(report_router)
    logger.info("✓ Report routes registered at /api/reports")
else:
    logger.warning("⚠️ Report routes NOT registered")

# Include retrain routes
if retrain_router:
    app.include_router(retrain_router)
    logger.info("✓ Retrain routes registered at /api/retrain")
else:
    logger.warning("⚠️ Retrain routes NOT registered")

# Global instances
detector: Optional[MalwareDetector] = None
cnn_detector: Optional[CNNModelClient] = None  # Now using HTTP client
vt_enricher: Optional[VirusTotalEnricher] = None

# In-memory job store: job_id → asyncio.Queue
# Each queue carries {type, msg/data} dicts consumed by the SSE stream endpoint
scan_jobs: dict[str, asyncio.Queue] = {}

# DB availability — mirrors db_manager import success
DB_AVAILABLE = False
try:
    from db_manager import get_session, save_scan_history, get_scan_history, User
    from sqlalchemy.ext.asyncio import AsyncSession
    DB_AVAILABLE = True
    logger.info("✓ DB modules available in main.py")
except ImportError as e:
    logger.warning(f"DB modules not available in main.py: {e}")
    AsyncSession = None
# Database dependency helper
async def get_db_session() -> Optional[AsyncSession]:
    """
    Optional database session dependency
    Returns session if DB_AVAILABLE, None otherwise
    """
    if DB_AVAILABLE:
        async for session in get_session():
            yield session
    else:
        yield None

class ScanRequest(BaseModel):
    """Request model for file scanning"""
    file_path: str
    download_id: Optional[int] = None
    enable_vt: bool = True


class ScanResponse(BaseModel):
    """Response model for scan results"""
    is_malicious: bool
    confidence: float
    prediction_label: str
    scan_time_ms: float
    features_analyzed: int
    vt_data: Optional[Dict[str, Any]] = None
    privacy_note: str = "Scan performed locally - no data uploaded"


class ScanHistoryResponse(BaseModel):
    """Response model for scan history records"""
    id: int
    timestamp: str
    file_name: str
    file_path: str
    is_malicious: bool
    confidence: float
    prediction_label: str
    model_type: str
    scan_time_ms: float
    
    class Config:
        from_attributes = True  # For Pydantic v2 ORM compatibility


class ScanHistoryListResponse(BaseModel):
    """Response model for scan history list with count"""
    count: int
    scans: list[ScanHistoryResponse]


@app.on_event("startup")
async def startup_event():
    """Initialize ML model and services on startup"""
    global detector, cnn_detector, vt_enricher
    
    logger.info("🚀 Starting SecureGuard Backend...")
    
    try:
        # Choose model based on configuration
        if USE_CNN_MODEL and CNNModelClient is not None:
            logger.info("Connecting to CNN model service...")
            try:
                # Connect to model service (runs in Python 3.10 with TensorFlow)
                cnn_detector = CNNModelClient(service_url=CNN_MODEL_SERVICE_URL)
                logger.info(f"✓ Connected to CNN model service at {CNN_MODEL_SERVICE_URL}")
                logger.info(f"  Model type: 1D CNN (via HTTP)")
            except Exception as e:
                logger.warning(f"Failed to connect to CNN service: {e}")
                logger.info("Falling back to traditional ML model...")
                detector = MalwareDetector()
                logger.info(f"✓ Traditional ML model loaded ({detector.model_size_mb:.2f} MB)")
        else:
            # Initialize traditional ML detector
            if USE_CNN_MODEL and CNNModelClient is None:
                logger.warning("CNN client not available - using traditional model")
            logger.info("Loading traditional ML model...")
            detector = MalwareDetector()
            logger.info(f"✓ Model loaded successfully ({detector.model_size_mb:.2f} MB)")
        
        # Note: VT enrichment is now handled by model_service in staged analysis
        # Only initialize local VT enricher if using traditional ML model
        if detector and not cnn_detector:
            logger.info("Initializing VirusTotal enricher...")
            try:
                vt_enricher = VirusTotalEnricher()
                logger.info("✓ VirusTotal enricher ready")
            except Exception as e:
                logger.warning(f"VT enricher not available: {e}")
        
        logger.info("✅ SecureGuard Backend ready!")
        logger.info(f"   Model type: {'CNN' if cnn_detector else 'Traditional ML'}")
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "SecureGuard API",
        "version": "1.0.0",
        "status": "running",
        "message": "Privacy-first malware detection"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    active_detector = cnn_detector or detector
    return {
        "status": "healthy",
        "model_loaded": active_detector is not None,
        "model_type": "CNN" if cnn_detector else "Traditional ML",
        "model_accuracy": detector.model_accuracy if detector else None,
        "vt_available": vt_enricher is not None
    }


@app.post("/scan", response_model=ScanResponse)
async def scan_file(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),  # ✨ NEW: Require authentication
    db: AsyncSession = Depends(get_session)  # ✨ NEW: Database session
):
    """
    Scan a file for malware using local ML model (Authentication Required)
    
    Args:
        request: ScanRequest with file path and options
        current_user: Authenticated user (injected by dependency)
        db: Database session
        
    Returns:
        ScanResponse with detection results
    """
    # Use CNN model if available, otherwise fall back to traditional
    active_detector = cnn_detector or detector
    
    if not active_detector:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    try:
        # Validate file exists
        if not Path(request.file_path).exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        logger.info(f"Scanning file: {request.file_path} (User: {current_user.username})")
        
        # Perform ML scan
        # For CNN: uses staged analysis (PE static + VT enrichment if uncertain)
        # For traditional ML: uses local model only
        result = active_detector.scan_file(request.file_path)
        
        # VT data is already included in result for CNN staged analysis
        vt_data = result.get('vt_detection_ratio') if cnn_detector else None
        
        # For traditional ML, optionally enrich with VirusTotal
        if detector and result['is_malicious'] and request.enable_vt and vt_enricher:
            logger.info("File flagged as malicious - enriching with VirusTotal...")
            vt_enrichment = vt_enricher.check_file(request.file_path)
            vt_data = vt_enrichment.get('detection') if vt_enrichment else None
        
        # Get features count (different for CNN vs traditional)
        features_count = result.get('file_size', 0) if cnn_detector else result.get('features_count', 0)
        
        # ✨ NEW: Save scan to database with user_id
        model_type = "CNN" if cnn_detector else "Traditional ML"
        await save_scan_history(
            session=db,
            file_path=request.file_path,
            result=result,
            user_id=current_user.user_id,  # Link scan to user
            model_type=model_type
        )
        
        response = ScanResponse(
            is_malicious=result['is_malicious'],
            confidence=result['confidence'],
            prediction_label=result['prediction_label'],
            scan_time_ms=result['scan_time_ms'],
            features_analyzed=features_count,
            vt_data=vt_data
        )
        
        logger.info(f"Scan complete: {response.prediction_label} ({response.confidence:.2%})")
        return response
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan-history", response_model=ScanHistoryListResponse)
async def get_my_scan_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
    limit: int = 100,
    malicious_only: bool = False
):
    """
    Get scan history for the current authenticated user
    
    Args:
        current_user: Authenticated user
        db: Database session  
        limit: Maximum number of records to return
        malicious_only: Only return malicious detections
        
    Returns:
        Scan history records with count for the current user
    """
    try:
        scans = await get_scan_history(
            session=db,
            limit=limit,
            user_id=current_user.user_id,  # Filter by current user
            malicious_only=malicious_only
        )
        
        # Convert to response format
        scan_list = [
            ScanHistoryResponse(
                id=scan.id,
                timestamp=scan.timestamp.isoformat(),
                file_name=scan.file_name,
                file_path=scan.file_path,
                is_malicious=scan.is_malicious,
                confidence=scan.confidence,
                prediction_label=scan.prediction_label,
                model_type=scan.model_type,
                scan_time_ms=scan.scan_time_ms
            )
            for scan in scans
        ]
        
        return ScanHistoryListResponse(
            count=len(scan_list),
            scans=scan_list
        )
    except Exception as e:
        logger.error(f"Failed to fetch scan history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/scan-history", response_model=ScanHistoryListResponse)
async def get_all_scan_history(
    current_admin: User = Depends(get_current_admin),  # Only admins
    db: AsyncSession = Depends(get_session),
    limit: int = 100,
    malicious_only: bool = False
):
    """
    Get scan history for all users (Admin only)
    
    Args:
        current_admin: Authenticated admin user
        db: Database session
        limit: Maximum number of records to return
        malicious_only: Only return malicious detections
        
    Returns:
        Scan history records with count for all users
    """
    try:
        scans = await get_scan_history(
            session=db,
            limit=limit,
            user_id=None,  # No filter - get all users' scans
            malicious_only=malicious_only
        )
        
        # Convert to response format
        scan_list = [
            ScanHistoryResponse(
                id=scan.id,
                timestamp=scan.timestamp.isoformat(),
                file_name=scan.file_name,
                file_path=scan.file_path,
                is_malicious=scan.is_malicious,
                confidence=scan.confidence,
                prediction_label=scan.prediction_label,
                model_type=scan.model_type,
                scan_time_ms=scan.scan_time_ms
            )
            for scan in scans
        ]
        
        return ScanHistoryListResponse(
            count=len(scan_list),
            scans=scan_list
        )
    except Exception as e:
        logger.error(f"Failed to fetch scan history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan-upload", response_model=ScanResponse)
async def scan_uploaded_file(
    file: UploadFile = File(...),
    enable_vt: bool = True,
    current_user: User = Depends(get_current_user),  # ✨ NEW: Require authentication
    db: AsyncSession = Depends(get_session)  # ✨ NEW: Database session
):
    """
    Scan an uploaded file for malware (Authentication Required)
    
    Args:
        file: Uploaded file from browser
        enable_vt: Enable VirusTotal enrichment for threats
        current_user: Authenticated user (injected by dependency)
        db: Database session
        
    Returns:
        ScanResponse with detection results
    """
    # Use CNN model if available, otherwise fall back to traditional
    active_detector = cnn_detector or detector
    
    if not active_detector:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    temp_path = None
    try:
        # Save uploaded file temporarily (use absolute path)
        temp_dir = Path(__file__).parent / "temp_scans"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        temp_path = temp_dir / file.filename
        
        # Write file
        with open(temp_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        logger.info(f"Scanning uploaded file: {file.filename} ({len(content)} bytes) (User: {current_user.username})")
        
        # Perform scan
        # For CNN: uses staged analysis (PE static + VT enrichment if uncertain)
        # For traditional ML: uses local model only
        result = active_detector.scan_file(str(temp_path))
        
        # VT data is already included in result for CNN staged analysis
        vt_data = result.get('vt_detection_ratio') if cnn_detector else None
        
        # For traditional ML, optionally enrich with VirusTotal
        if detector and result['is_malicious'] and enable_vt and vt_enricher:
            logger.info("File flagged as malicious - enriching with VirusTotal...")
            vt_enrichment = vt_enricher.check_file(str(temp_path))
            vt_data = vt_enrichment.get('detection') if vt_enrichment else None
        
        # ✨ NEW: Save scan to database with user_id
        model_type = "CNN" if cnn_detector else "Traditional ML"
        await save_scan_history(
            session=db,
            file_path=str(temp_path),
            result=result,
            user_id=current_user.user_id,  # Link scan to user
            model_type=model_type
        )
        
        # Clean up temp file
        if temp_path and temp_path.exists():
            temp_path.unlink()
        
        # Get features count (different for CNN vs traditional)
        features_count = result.get('file_size', 0) if cnn_detector else result.get('features_count', 0)
        
        response = ScanResponse(
            is_malicious=result['is_malicious'],
            confidence=result['confidence'],
            prediction_label=result['prediction_label'],
            scan_time_ms=result['scan_time_ms'],
            features_analyzed=features_count,
            vt_data=vt_data
        )
        
        logger.info(f"Upload scan complete: {response.prediction_label} ({response.confidence:.2%})")
        return response
        
    except Exception as e:
        logger.error(f"Upload scan failed: {e}")
        # Clean up on error
        if temp_path and temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/staged")
async def proxy_predict_staged(
    file: UploadFile = File(...),
    run_sandbox: bool = True,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session)
):
    """
    Gateway proxy for /predict/staged on model_service (port 8001).
    Authenticates the user, spawns a background task, and returns a job_id
    immediately. The client should connect to GET /scan/{job_id}/stream for
    live progress and the final result via SSE.
    """
    job_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    scan_jobs[job_id] = queue

    file_bytes = await file.read()
    filename = file.filename or "uploaded_file"
    user_id = str(current_user.user_id)

    async def run_scan():
        try:
            await queue.put({"type": "log", "msg": f"🔍 Submitting '{filename}' to model service..."})

            async with httpx.AsyncClient(timeout=660.0) as client:
                async with client.stream(
                    "POST",
                    f"{CNN_MODEL_SERVICE_URL}/predict/staged",
                    params={"run_sandbox": str(run_sandbox).lower(), "user_id": user_id},
                    files={"file": (filename, file_bytes, "application/octet-stream")},
                ) as response:
                    if response.status_code != 200:
                        body = await response.aread()
                        await queue.put({"type": "error", "msg": body.decode(), "status": response.status_code})
                        return
                    async for line in response.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        raw = line[5:].strip()
                        if not raw:
                            continue
                        try:
                            msg = json.loads(raw)
                        except Exception:
                            continue
                        await queue.put(msg)
                        if msg.get("type") in ("result", "error"):
                            break

        except Exception as e:
            await queue.put({"type": "error", "msg": str(e), "status": 500})
        finally:
            # Keep queue alive briefly so the SSE consumer can drain the last message
            await asyncio.sleep(30)
            scan_jobs.pop(job_id, None)

    asyncio.create_task(run_scan())
    return {"job_id": job_id}


@app.get("/scan/{job_id}/stream")
async def stream_scan_result(
    job_id: str,
    token: Optional[str] = None,  # JWT passed as query param — EventSource can't set headers
):
    """
    SSE stream for a running scan job. Connect after POST /predict/staged returns a job_id.

    Usage (JavaScript):
        const es = new EventSource(`/scan/${jobId}/stream?token=${localStorage.getItem('access_token')}`);
        es.onmessage = (e) => {
            const msg = JSON.parse(e.data);
            if (msg.type === 'log')    appendLog(msg.msg);
            if (msg.type === 'result') { showResult(msg.data); es.close(); }
            if (msg.type === 'error')  { showError(msg.msg);   es.close(); }
        };

    Event types:
        {"type": "log",    "msg": "..."}             — progress line
        {"type": "result", "data": {...}}             — final prediction JSON
        {"type": "error",  "msg": "...", "status": N} — on failure
    """
    # Validate JWT supplied as query param (EventSource cannot send Authorization header)
    from auth.utils import decode_access_token
    payload = decode_access_token(token or "")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or missing token")

    queue = scan_jobs.get(job_id)
    if queue is None:
        raise HTTPException(status_code=404, detail="Job not found or already expired")

    async def event_generator():
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=60.0)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg["type"] in ("result", "error"):
                    break
            except asyncio.TimeoutError:
                # SSE comment — keeps the connection alive without triggering onmessage
                yield ": heartbeat\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ==============================================================================
# MODEL VERSION MANAGEMENT  (admin only)
# Lets admin choose which CNN / XGBoost version is currently loaded in
# model_service.  Reads/writes model_training_history.is_active, then
# tells model_service to hot-reload via POST http://localhost:8001/reload-model.
# ==============================================================================

CNN_SERVICE_URL_BASE = os.getenv("CNN_MODEL_SERVICE_URL", "http://127.0.0.1:8001")


@app.get("/api/models/versions")
async def list_model_versions(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Return all model_training_history rows grouped by model family.

    Response shape:
    {
      "cnn":     [{id, version, accuracy, model_path, trained_at, is_active, ...}, ...],
      "xgboost": [...],
    }
    """
    from db_manager import get_all_model_versions

    rows = await get_all_model_versions(db)

    def _row_dict(r):
        return {
            "id":            r.id,
            "version":       r.version,
            "model_type":    r.model_type,
            "accuracy":      r.accuracy,
            "precision":     r.precision,
            "recall":        r.recall,
            "f1_score":      r.f1_score,
            "auc":           r.auc,
            "n_features":    r.n_features,
            "total_samples": r.total_samples,
            "samples_added": r.samples_added,
            "accuracy_delta":r.accuracy_delta,
            "model_path":    r.model_path,
            "dataset":       r.dataset,
            "notes":         r.notes,
            "is_active":     r.is_active,
            "trained_at":    r.trained_at.isoformat() if r.trained_at else None,
        }

    cnn_rows = []
    xgb_rows = []
    for r in rows:
        mt = (r.model_type or "").lower()
        if "cnn" in mt or "1d" in mt:
            cnn_rows.append(_row_dict(r))
        else:
            xgb_rows.append(_row_dict(r))

    return {"cnn": cnn_rows, "xgboost": xgb_rows}


@app.get("/api/models/active")
async def get_active_model_versions(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Return the currently active CNN and XGBoost model versions (is_active=True).
    """
    from db_manager import get_active_models

    active = await get_active_models(db)

    def _row_dict(r):
        if r is None:
            return None
        return {
            "id":         r.id,
            "version":    r.version,
            "model_type": r.model_type,
            "accuracy":   r.accuracy,
            "model_path": r.model_path,
            "is_active":  r.is_active,
            "trained_at": r.trained_at.isoformat() if r.trained_at else None,
        }

    return {
        "cnn":     _row_dict(active.get("cnn")),
        "xgboost": _row_dict(active.get("xgboost")),
    }


@app.post("/api/models/set-active")
async def set_active_model_version(
    record_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Mark a model_training_history row as the active version for its model family,
    then hot-reload model_service so it immediately picks up the change.

    Body: ?record_id=<int>   (query-param; no body required)
    """
    import httpx
    from db_manager import set_active_model

    try:
        row = await set_active_model(db, record_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    # Ask model_service to reload from the new active selection
    reload_ok = False
    reload_msg = ""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{CNN_SERVICE_URL_BASE}/reload-model")
        reload_ok  = resp.status_code == 200
        reload_msg = resp.json().get("message", "") if reload_ok else f"HTTP {resp.status_code}"
    except Exception as exc:
        reload_msg = f"model_service unreachable: {exc}"
        logger.warning(f"[set-active] Could not trigger model_service reload: {exc}")

    return {
        "status":      "ok",
        "activated":   {"id": row.id, "version": row.version, "model_type": row.model_type},
        "reload_ok":   reload_ok,
        "reload_msg":  reload_msg,
    }


# ==============================================================================
# DATABASE LOG QUERY ENDPOINTS
# ==============================================================================

@app.get("/logs/recent")
async def get_recent_logs(
    limit: int = 50,
    command_type: Optional[str] = None,
    db: Optional[AsyncSession] = Depends(get_db_session)
):
    """
    Get recent terminal logs from model service
    
    Query params:
    - limit: Max number of logs (default: 50)
    - command_type: Filter by type (e.g., "malware_scan")
    """
    if not DB_AVAILABLE or db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    from sqlalchemy import select, desc
    from db_manager import TerminalLog
    
    stmt = select(TerminalLog).order_by(desc(TerminalLog.timestamp)).limit(limit)
    
    if command_type:
        stmt = stmt.where(TerminalLog.command_type == command_type)
    
    result = await db.execute(stmt)
    logs = result.scalars().all()
    
    return {
        "total": len(logs),
        "service": "model_service",
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
    db: Optional[AsyncSession] = Depends(get_db_session)
):
    """
    Get scan history with filtering
    
    Query params:
    - limit: Max number of scans (default: 100)
    - malicious_only: Only return malware detections (default: false)
    """
    if not DB_AVAILABLE or db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
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
        "service": "model_service",
        "scans": [
            {
                "id": scan.id,
                "timestamp": scan.timestamp.isoformat(),
                "file_name": scan.file_name,
                "is_malicious": scan.is_malicious,
                "confidence": scan.confidence,
                "prediction_label": scan.prediction_label,
                "model_type": scan.model_type,
                "scan_time_ms": scan.scan_time_ms,
                "vt_detection": scan.vt_detection_ratio
            }
            for scan in scans
        ]
    }


@app.get("/logs/scans/{scan_id}")
async def get_scan_detail(
    scan_id: int,
    include: Optional[str] = None,
    db: Optional[AsyncSession] = Depends(get_db_session)
):
    """
    Get a single scan record by ID with optional related table data.

    Path params:
    - scan_id: ID of the scan record

    Query params:
    - include: Comma-separated list of related tables to include alongside the scan.
               Valid values: terminal_logs, behavioral_patterns, uncertain_samples, feedback_samples
               Example: ?include=behavioral_patterns,terminal_logs
    """
    if not DB_AVAILABLE or db is None:
        raise HTTPException(status_code=503, detail="Database not available")

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from db_manager import ScanHistory

    VALID_INCLUDES = {
        "terminal_logs",
        "behavioral_patterns",
        "uncertain_samples",
        "feedback_samples",
    }

    requested: set[str] = set()
    if include:
        requested = {s.strip().lower() for s in include.split(",")} & VALID_INCLUDES

    stmt = select(ScanHistory).where(ScanHistory.id == scan_id)

    # Only join the relationships the caller actually asked for
    rel_map = {
        "terminal_logs":      ScanHistory.terminal_logs,
        "behavioral_patterns": ScanHistory.behavioral_patterns,
        "uncertain_samples":  ScanHistory.uncertain_samples,
        "feedback_samples":   ScanHistory.feedback_samples,
    }
    for key in requested:
        stmt = stmt.options(selectinload(rel_map[key]))

    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    response: dict = {
        "id": scan.id,
        "timestamp": scan.timestamp.isoformat(),
        "file_name": scan.file_name,
        "file_hash": scan.file_hash,
        "is_malicious": scan.is_malicious,
        "confidence": scan.confidence,
        "prediction_label": scan.prediction_label,
        "model_type": scan.model_type,
        "scan_time_ms": scan.scan_time_ms,
        "vt_detection": scan.vt_detection_ratio,
        "included_tables": sorted(requested),
    }

    if "terminal_logs" in requested:
        response["terminal_logs"] = [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "command": log.command,
                "command_type": log.command_type,
                "execution_time_ms": log.execution_time_ms,
                "success": log.success,
                "stdout": log.stdout,
                "stderr": log.stderr,
                "scan_result": log.scan_result,
            }
            for log in scan.terminal_logs
        ]

    if "behavioral_patterns" in requested:
        response["behavioral_patterns"] = [
            {
                "id": bp.id,
                "timestamp": bp.timestamp.isoformat(),
                "detection_method": bp.detection_method,
                "total_patterns_detected": bp.total_patterns_detected,
                "risk_score": bp.risk_score,
                "mass_file_encryption": bp.mass_file_encryption,
                "shadow_copy_deletion": bp.shadow_copy_deletion,
                "registry_persistence": bp.registry_persistence,
                "network_c2_communication": bp.network_c2_communication,
                "ransom_note_creation": bp.ransom_note_creation,
                "mass_file_deletion": bp.mass_file_deletion,
                "suspicious_process_creation": bp.suspicious_process_creation,
                "api_encrypt_rename_sequence": bp.api_encrypt_rename_sequence,
                "raw_patterns": bp.raw_patterns,
            }
            for bp in scan.behavioral_patterns
        ]

    if "uncertain_samples" in requested:
        response["uncertain_samples"] = [
            {
                "id": s.id,
                "created_at": s.created_at.isoformat(),
                "file_hash": s.file_hash,
                "file_name": s.file_name,
                "ml_prediction": s.ml_prediction,
                "ml_confidence": s.ml_confidence,
                "ml_raw_score": s.ml_raw_score,
                "prediction_label": s.prediction_label,
                "behavioral_enriched": s.behavioral_enriched,
                "behavioral_source": s.behavioral_source,
                "status": s.status,
                "vt_queried": s.vt_queried,
                "vt_attempts": s.vt_attempts,
            }
            for s in scan.uncertain_samples
        ]

    if "feedback_samples" in requested:
        response["feedback_samples"] = [
            {
                "id": s.id,
                "timestamp": s.timestamp.isoformat(),
                "file_hash": s.file_hash,
                "file_name": s.file_name,
                "ml_verdict": s.ml_verdict,
                "ml_confidence": s.ml_confidence,
                "vt_detection_ratio": s.vt_detection_ratio,
                "vt_family": s.vt_family,
                "vt_threat_label": s.vt_threat_label,
                "mismatch_type": s.mismatch_type,
                "severity": s.severity,
                "needs_review": s.needs_review,
                "processed": s.processed,
            }
            for s in scan.feedback_samples
        ]

    return response


@app.get("/logs/stats")
async def get_log_statistics(db: Optional[AsyncSession] = Depends(get_db_session)):
    """Get aggregate statistics from scan history"""
    if not DB_AVAILABLE or db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    from db_manager import get_scan_stats
    
    stats = await get_scan_stats(db)
    
    return {
        "status": "success",
        "service": "model_service",
        "statistics": stats
    }


@app.get("/stats")
async def get_statistics():
    """Get model statistics and performance metrics"""
    active_detector = cnn_detector or detector
    
    if not active_detector:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    return active_detector.get_stats()


if __name__ == "__main__":
    # Run server
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,  # Disabled to reduce log noise - manually restart after code changes
        log_level="info"
    )
