# Model Service Database Logging - Implementation Summary

## What Was Done

Database logging has been successfully integrated into `model_service.py` to capture detailed staging analysis logs and save them to Azure PostgreSQL.

## Files Modified/Created

### 1. **db_manager.py** (Copied from examples/)
- Database connection management
- ORM models: `TerminalLog`, `ScanHistory`
- CRUD operations
- ✅ Updated to load `.env` file automatically

### 2. **terminal_logger.py** (Copied from examples/)
- `LoggingCapture` - Captures Python logging output
- Output formatting utilities
- No changes needed

### 3. **model_service.py** (Modified)
- ✅ Added database imports at top
- ✅ Added `init_db()` to startup event
- ✅ Modified `/predict/staged` endpoint:
  - Added `db` parameter: `db: AsyncSession = Depends(get_session)`
  - Added logging capture before scan
  - Added database save before BOTH return statements (with/without enrichment)
  - Added error handling for log capture
- ✅ Added 3 new endpoints:
  - `GET /logs/recent` - Recent terminal logs
  - `GET /logs/scans` - Scan history with filtering
  - `GET /logs/stats` - Aggregate statistics

## What Gets Logged

### Terminal Logs Table
Every `/predict/staged` call saves:
- **Command**: `predict_staged: filename.exe`
- **Stdout**: All logger.info() messages including:
  - Stage 1: PE feature extraction results
  - Confidence thresholds (CONFIDENCE_LOW/HIGH)
  - Suspicious file indicators (packed, high entropy, etc.)
  - Stage 2: VT enrichment details
  - Behavioral data processing
  - Final verdict reasoning
- **Execution time**: Total scan duration
- **Scan result**: Full result dict as JSON

### Scan History Table
Optimized scan records with:
- File name, size
- is_malicious, confidence, prediction_label
- Model type: "GradientBoosting (Staged)" or "GradientBoosting (VT Enriched)"
- VT detection ratio (if available)
- Behavioral enrichment status

## Key Staging Messages Captured

The `/predict/staged` endpoint logs extensive detail:

```
Stage 1: Extracting PE features from malware.exe
Stage 1 result: raw_score=0.789, confidence=0.789 (MALICIOUS)
File flagged as suspicious (high_entropy 7.84) - forcing VT enrichment
Stage 2: Calling VirusTotal API for enrichment
✓ VT enriched: 45/70 detections
Top detections: Microsoft (Trojan:Win32/Generic), Kaspersky (HEUR:Trojan.Win32.Generic)
Merging 18 behavioral features with 71 PE features
Stage 2 result: raw_score=0.956, confidence=0.956 (MALICIOUS)
Final verdict: MALICIOUS (96% confidence) via pe_virustotal_api_enriched
```

All of this goes into the `stdout` field of `terminal_logs` table!

## Database Schema (Auto-created on startup)

```sql
-- Detailed audit trail
CREATE TABLE terminal_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    command VARCHAR(500),  -- e.g., "predict_staged: malware.exe"
    command_type VARCHAR(50),  -- "malware_scan"
    stdout TEXT,  -- All logging output!
    stderr TEXT,
    execution_time_ms FLOAT,
    success BOOLEAN,
    scan_result JSON,  -- Full result dict
    file_path VARCHAR(1000)
);

-- Optimized scan history
CREATE TABLE scan_history (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    file_name VARCHAR(255),
    file_size INTEGER,
    is_malicious BOOLEAN,
    confidence FLOAT,
    prediction_label VARCHAR(50),
    model_type VARCHAR(50),  -- "GradientBoosting (VT Enriched)"
    scan_time_ms FLOAT,
    features_analyzed INTEGER,
    vt_detection_ratio VARCHAR(20),  -- "45/70"
    vt_data JSON
);
```

## New API Endpoints (Model Service - Port 8001)

### GET http://127.0.0.1:8001/logs/recent?limit=50
Returns recent terminal logs with full staging output

### GET http://127.0.0.1:8001/logs/scans?malicious_only=true&limit=100
Returns scan history (optimized for analytics)

### GET http://127.0.0.1:8001/logs/stats
Returns aggregate statistics:
- Total scans
- Malware detected count
- Detection rate %
- Average scan time
- Average confidence

## Usage Example

1. **Start model service**:
   ```bash
   python model_service.py
   # Service runs on port 8001
   # Database tables auto-created on startup
   ```

2. **Upload a file for staged analysis**:
   ```bash
   curl -F "file=@malware.exe" http://127.0.0.1:8001/predict/staged
   # Logs saved to database automatically
   ```

3. **View detailed logs**:
   ```bash
   # Get recent scans
   curl http://127.0.0.1:8001/logs/recent
   
   # Get malware detections only
   curl http://127.0.0.1:8001/logs/scans?malicious_only=true
   
   # Get statistics
   curl http://127.0.0.1:8001/logs/stats
   ```

4. **Query from Azure Portal**:
   ```sql
   -- View latest staging analysis
   SELECT 
       timestamp,
       command,
       stdout,  -- Full staging output!
       scan_result->>'confidence' as confidence,
       scan_result->>'vt_detection_ratio' as vt_ratio
   FROM terminal_logs
   WHERE command_type = 'malware_scan'
   ORDER BY timestamp DESC
   LIMIT 10;
   
   -- Find all VT-enriched detections
   SELECT *
   FROM scan_history
   WHERE model_type LIKE '%VT%'
     AND is_malicious = true
   ORDER BY confidence DESC;
   ```

## Why This Is Better Than main.py

**model_service.py logs are more informative because:**

1. **Staging Logic Details**: Shows why VT was called (confidence thresholds, suspicious indicators)
2. **Behavioral Enrichment**: Logs VM behavioral data processing
3. **VT Integration**: Shows which AVs detected it and their verdicts
4. **Feature Merging**: Details of combining PE + behavioral features
5. **Decision Reasoning**: Clear explanation of final verdict

**main.py would only log:**
- "Scanning file: malware.exe"
- "Scan complete: MALICIOUS (95%)"

**model_service.py logs:**
- All of the above PLUS:
- PE feature extraction details
- Stage 1 prediction and confidence
- Why VT was triggered (threshold or suspicious file)
- VT API response details
- Behavioral data conversion
- Feature enrichment process
- Stage 2 re-prediction
- Final verdict reasoning

## Testing

Run the test suite:
```bash
cd Iteration_1/backend
python test_model_service_db.py
```

Expected output:
```
✅ All tests passed! model_service database integration ready

Next steps:
1. Start model_service: python model_service.py
2. Test scan endpoint: Upload a file to /predict/staged
3. Check logs: GET http://127.0.0.1:8001/logs/scans
```

## Database Configuration

Uses the same `.env` file:
```env
DATABASE_URL=postgresql+asyncpg://ranscan_william:williamRSC%40N321@ranscanai-server.postgres.database.azure.com:5432/ranscanai?ssl=require
```

Both `model_service.py` and `main.py` can use the same database since they share the same tables.

## Status

✅ **COMPLETE AND TESTED**

- Database tables created
- Logging capture working
- Database writes successful
- Query endpoints functional
- Ready for production use

The model_service logs are now stored in Azure PostgreSQL with full staging analysis details!
