"""
SecureGuard Backend - Privacy-First Malware Detection API
FastAPI server for local malware scanning with ML model
"""

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import os
import sys

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
    from auth import auth_router
    logger.info(f"✓ Auth routes imported successfully (router type: {type(auth_router)})")
except ImportError as e:
    logger.error(f"❌ Auth routes import failed (ImportError): {e}")
    logger.warning("Auth routes not available - authentication disabled")
    import traceback
    traceback.print_exc()
    auth_router = None
except Exception as e:
    logger.error(f"❌ Unexpected error importing auth routes: {e}")
    import traceback
    traceback.print_exc()
    auth_router = None

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

# Configuration
# Toggle between Traditional ML and CNN model
USE_CNN_MODEL = os.getenv("USE_CNN_MODEL", "false").lower() == "true"  # Set to "true" to enable CNN
CNN_MODEL_SERVICE_URL = os.getenv("CNN_MODEL_SERVICE_URL", "http://127.0.0.1:8001")

# OR override directly (uncomment to use):
USE_CNN_MODEL = True  # Change this to True to use CNN model
CNN_MODEL_SERVICE_URL = "http://127.0.0.1:8001"  # CNN service URL

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

# Global instances
detector: Optional[MalwareDetector] = None
cnn_detector: Optional[CNNModelClient] = None  # Now using HTTP client
vt_enricher: Optional[VirusTotalEnricher] = None


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
async def scan_file(request: ScanRequest):
    """
    Scan a file for malware using local ML model
    
    Args:
        request: ScanRequest with file path and options
        
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
        
        logger.info(f"Scanning file: {request.file_path}")
        
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


@app.post("/scan-upload", response_model=ScanResponse)
async def scan_uploaded_file(file: UploadFile = File(...), enable_vt: bool = True):
    """
    Scan an uploaded file for malware
    
    Args:
        file: Uploaded file from browser
        enable_vt: Enable VirusTotal enrichment for threats
        
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
        
        logger.info(f"Scanning uploaded file: {file.filename} ({len(content)} bytes)")
        
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
