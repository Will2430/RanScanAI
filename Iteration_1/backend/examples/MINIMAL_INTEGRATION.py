"""
MINIMAL INTEGRATION CODE FOR main.py
=====================================

Copy and paste these snippets into your main.py when ready to implement.
Don't run this file directly - it's a reference!
"""

# ==============================================================================
# STEP 1: ADD THESE IMPORTS AT THE TOP OF main.py (after existing imports)
# ==============================================================================

from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends
from db_manager import (
    init_db, 
    get_session, 
    save_terminal_log, 
    save_scan_history
)
from terminal_logger import LoggingCapture, format_scan_output


# ==============================================================================
# STEP 2: UPDATE startup_event() - ADD THIS SECTION
# ==============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize ML model and services on startup"""
    global detector, cnn_detector, vt_enricher
    
    logger.info("🚀 Starting SecureGuard Backend...")
    
    # ======= ADD THIS BLOCK =======
    # Initialize database connection
    try:
        logger.info("Initializing database connection...")
        await init_db()
        logger.info("✓ Database tables initialized")
    except Exception as e:
        logger.warning(f"Database initialization failed: {e}")
        logger.warning("⚠️  Continuing without database logging...")
    # ======= END ADD =======
    
    # ... rest of your existing startup code (model loading, etc.) ...
    try:
        if USE_CNN_MODEL and CNNModelClient is not None:
            logger.info("Connecting to CNN model service...")
            # ... existing CNN setup code ...
        else:
            logger.info("Loading traditional ML model...")
            # ... existing ML setup code ...
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise


# ==============================================================================
# STEP 3: UPDATE scan_file() endpoint - MODIFY SIGNATURE AND ADD LOGGING
# ==============================================================================

@app.post("/scan", response_model=ScanResponse)
async def scan_file(
    request: ScanRequest,
    db: AsyncSession = Depends(get_session)  # ← ADD THIS PARAMETER
):
    """
    Scan a file for malware using local ML model
    NOW WITH DATABASE LOGGING!
    """
    active_detector = cnn_detector or detector
    
    if not active_detector:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    try:
        # Validate file exists
        if not Path(request.file_path).exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        logger.info(f"Scanning file: {request.file_path}")
        
        # ======= REPLACE THIS SECTION =======
        # Old code:
        # result = active_detector.scan_file(request.file_path)
        
        # New code with logging capture:
        with LoggingCapture(__name__) as capture:
            # Perform ML scan (existing code)
            result = active_detector.scan_file(request.file_path)
        
        # Get captured output
        output = capture.get_output()
        # ======= END REPLACE =======
        
        # ... existing VT enrichment code (unchanged) ...
        vt_data = result.get('vt_detection_ratio') if cnn_detector else None
        if detector and result['is_malicious'] and request.enable_vt and vt_enricher:
            logger.info("File flagged as malicious - enriching with VirusTotal...")
            vt_enrichment = vt_enricher.check_file(request.file_path)
            vt_data = vt_enrichment.get('detection') if vt_enrichment else None
        
        # ======= ADD THIS BLOCK AFTER VT ENRICHMENT =======
        # Save to database (async, non-blocking)
        try:
            # Save detailed terminal log
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
            
            # Save scan history for analytics
            await save_scan_history(
                session=db,
                file_path=request.file_path,
                result=result,
                model_type="CNN" if cnn_detector else "Traditional ML"
            )
            
            logger.info("✓ Scan results logged to database")
            
        except Exception as db_error:
            # Don't fail the scan if database logging fails
            logger.error(f"Failed to log to database: {db_error}")
            # Continue - user still gets scan result
        # ======= END ADD =======
        
        # ... rest of existing response code (unchanged) ...
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


# ==============================================================================
# STEP 4: UPDATE scan_uploaded_file() endpoint - SAME CHANGES
# ==============================================================================

@app.post("/scan-upload", response_model=ScanResponse)
async def scan_uploaded_file(
    file: UploadFile = File(...), 
    enable_vt: bool = True,
    db: AsyncSession = Depends(get_session)  # ← ADD THIS PARAMETER
):
    """
    Scan an uploaded file for malware
    NOW WITH DATABASE LOGGING!
    """
    active_detector = cnn_detector or detector
    
    if not active_detector:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    temp_path = None
    try:
        # ... existing temp file save code (unchanged) ...
        temp_dir = Path(__file__).parent / "temp_scans"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / file.filename
        
        with open(temp_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        logger.info(f"Scanning uploaded file: {file.filename} ({len(content)} bytes)")
        
        # ======= REPLACE: Add logging capture =======
        with LoggingCapture(__name__) as capture:
            result = active_detector.scan_file(str(temp_path))
        
        output = capture.get_output()
        # ======= END REPLACE =======
        
        # ... existing VT enrichment code (unchanged) ...
        vt_data = result.get('vt_detection_ratio') if cnn_detector else None
        if detector and result['is_malicious'] and enable_vt and vt_enricher:
            logger.info("File flagged as malicious - enriching with VirusTotal...")
            vt_enrichment = vt_enricher.check_file(str(temp_path))
            vt_data = vt_enrichment.get('detection') if vt_enrichment else None
        
        # ======= ADD: Database logging =======
        try:
            await save_terminal_log(
                session=db,
                command=f"scan_upload: {file.filename}",
                command_type="malware_scan",
                stdout=output['stdout'] + "\n" + format_scan_output(result),
                stderr=output['stderr'],
                execution_time_ms=result['scan_time_ms'],
                scan_result=result,
                file_path=str(temp_path)
            )
            
            await save_scan_history(
                session=db,
                file_path=str(temp_path),
                result=result,
                model_type="CNN" if cnn_detector else "Traditional ML"
            )
            
            logger.info("✓ Upload scan logged to database")
            
        except Exception as db_error:
            logger.error(f"Failed to log to database: {db_error}")
        # ======= END ADD =======
        
        # ... rest of existing code (cleanup and response) ...
        if temp_path and temp_path.exists():
            temp_path.unlink()
        
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
        if temp_path and temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=500, detail=str(e))


# ==============================================================================
# STEP 5: ADD NEW ENDPOINTS FOR QUERYING LOGS (paste at end of main.py)
# ==============================================================================

@app.get("/logs/recent")
async def get_recent_logs(
    limit: int = 50,
    command_type: Optional[str] = None,
    db: AsyncSession = Depends(get_session)
):
    """
    Get recent terminal logs
    
    Query params:
    - limit: Max number of logs (default: 50)
    - command_type: Filter by type (e.g., "malware_scan")
    """
    from sqlalchemy import select, desc
    from db_manager import TerminalLog
    
    stmt = select(TerminalLog).order_by(desc(TerminalLog.timestamp)).limit(limit)
    
    if command_type:
        stmt = stmt.where(TerminalLog.command_type == command_type)
    
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
    """
    Get scan history with filtering
    
    Query params:
    - limit: Max number of scans (default: 100)
    - malicious_only: Only return malware detections (default: false)
    """
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
                "prediction_label": scan.prediction_label,
                "model_type": scan.model_type,
                "scan_time_ms": scan.scan_time_ms,
                "vt_detection": scan.vt_detection_ratio
            }
            for scan in scans
        ]
    }


@app.get("/logs/stats")
async def get_statistics(db: AsyncSession = Depends(get_session)):
    """Get aggregate statistics from scan history"""
    from db_manager import get_scan_stats
    
    stats = await get_scan_stats(db)
    
    return {
        "status": "success",
        "statistics": stats
    }


# ==============================================================================
# VERIFICATION CHECKLIST
# ==============================================================================
"""
After making these changes, verify:

1. Files created:
   ✓ Iteration_1/backend/db_manager.py (copied from examples/)
   ✓ Iteration_1/backend/terminal_logger.py (copied from examples/)

2. main.py updated:
   ✓ Imports added at top
   ✓ startup_event() has init_db() call
   ✓ scan_file() has db parameter and logging
   ✓ scan_uploaded_file() has db parameter and logging
   ✓ New endpoints added: /logs/recent, /logs/scans, /logs/stats

3. Environment configured:
   ✓ DATABASE_URL in .env file
   ✓ Dependencies installed: pip install sqlalchemy[asyncio] asyncpg

4. Database ready:
   ✓ Azure PostgreSQL created
   ✓ Firewall allows your IP
   ✓ Tables created (run init_db())

5. Test endpoints:
   ✓ POST /scan → saves to database
   ✓ GET /logs/scans → returns scan history
   ✓ GET /logs/recent → returns terminal logs
   ✓ GET /logs/stats → returns statistics
"""
