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

# Add parent directory to path to import existing modules
sys.path.append(str(Path(__file__).parent.parent))

from backend.ml_model import MalwareDetector
from backend.vt_integration import VirusTotalEnricher

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
    global detector, vt_enricher
    
    logger.info("🚀 Starting SecureGuard Backend...")
    
    try:
        # Initialize ML detector
        logger.info("Loading ML model...")
        detector = MalwareDetector()
        logger.info(f"✓ Model loaded successfully ({detector.model_size_mb:.2f} MB)")
        
        # Initialize VirusTotal enricher (optional)
        logger.info("Initializing VirusTotal enricher...")
        vt_enricher = VirusTotalEnricher()
        logger.info("✓ VirusTotal enricher ready")
        
        logger.info("✅ SecureGuard Backend ready!")
        
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
    return {
        "status": "healthy",
        "model_loaded": detector is not None,
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
    if not detector:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    try:
        # Validate file exists
        if not Path(request.file_path).exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        logger.info(f"Scanning file: {request.file_path}")
        
        # Perform local ML scan
        result = detector.scan_file(request.file_path)
        
        # Enrich with VirusTotal if malicious and enabled
        vt_data = None
        if result['is_malicious'] and request.enable_vt and vt_enricher:
            logger.info("File flagged as malicious - enriching with VirusTotal...")
            vt_data = vt_enricher.check_file(request.file_path)
        
        response = ScanResponse(
            is_malicious=result['is_malicious'],
            confidence=result['confidence'],
            prediction_label=result['label'],
            scan_time_ms=result['scan_time_ms'],
            features_analyzed=result['features_count'],
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
    if not detector:
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
        result = detector.scan_file(str(temp_path))
        
        # Enrich with VirusTotal if malicious
        vt_data = None
        if result['is_malicious'] and enable_vt and vt_enricher:
            logger.info("File flagged as malicious - enriching with VirusTotal...")
            vt_data = vt_enricher.check_file(str(temp_path))
        
        # Clean up temp file
        if temp_path and temp_path.exists():
            temp_path.unlink()
        
        response = ScanResponse(
            is_malicious=result['is_malicious'],
            confidence=result['confidence'],
            prediction_label=result['prediction_label'],
            scan_time_ms=result['scan_time_ms'],
            features_analyzed=result['features_count'],
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
    if not detector:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    return detector.get_stats()


if __name__ == "__main__":
    # Run server
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
