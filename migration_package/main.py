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

# Configure logging FIRST
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add parent directory to path to import existing modules
sys.path.append(str(Path(__file__).parent.parent))

# Import model modules
try:
    from models.ml_model import MalwareDetector
except ImportError:
    from ml_model import MalwareDetector

# CNN client is optional (only if you have CNN service running)
CNNModelClient = None
try:
    from models.cnn_client import CNNModelClient
    logger.info("CNN client module found")
except ImportError:
    try:
        from cnn_client import CNNModelClient
        logger.info("CNN client module found (direct import)")
    except ImportError:
        logger.info("CNN client not available - traditional model only")

try:
    from backend.vt_integration import VirusTotalEnricher
except ImportError:
    from vt_integration import VirusTotalEnricher

# Configuration
USE_CNN_MODEL = os.getenv("USE_CNN_MODEL", "false").lower() == "true"
CNN_MODEL_SERVICE_URL = os.getenv("CNN_MODEL_SERVICE_URL", "http://127.0.0.1:8001")

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
        
        # Initialize VirusTotal enricher (optional)
        logger.info("Initializing VirusTotal enricher...")
        vt_enricher = VirusTotalEnricher()
        logger.info("✓ VirusTotal enricher ready")
        
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
        "vt_available": vt_enricher is not None and vt_enricher.is_configured()
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
        
        # Perform local ML scan
        result = active_detector.scan_file(request.file_path)
        
        # Enrich with VirusTotal if malicious and enabled
        vt_data = None
        if result['is_malicious'] and request.enable_vt and vt_enricher:
            logger.info("File flagged as malicious - enriching with VirusTotal...")
            vt_data = vt_enricher.check_file(request.file_path)
        
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
        result = active_detector.scan_file(str(temp_path))
        
        # Enrich with VirusTotal if malicious
        vt_data = None
        if result['is_malicious'] and enable_vt and vt_enricher:
            logger.info("File flagged as malicious - enriching with VirusTotal...")
            vt_data = vt_enricher.check_file(str(temp_path))
        
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
        reload=True,
        log_level="info"
    )
