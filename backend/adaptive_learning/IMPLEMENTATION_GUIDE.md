# Adaptive Learning System - Implementation Guide

## Overview

Database-driven adaptive learning pipeline that queues uncertain predictions for VirusTotal verification and triggers model retraining when enough mismatches are collected.

## Architecture

```
Scan Flow:
    File Upload → PE Static Analysis → Behavioral Scan → Prediction
        ↓ (if confidence < 85%)
    Queue to Database (with file copy saved)
        ↓ (return result immediately - no blocking)
    
Background Jobs (Schedulers):
    Daily (00:00):   VT Upload Scheduler uploads queued files to VT
        ↓
    VT scans with 70+ AV engines
        ↓
    Compare ML vs VT verdict → Log mismatches to FeedbackSamples
        ↓
    Weekly (02:00):  Retraining Scheduler checks if 100+ mismatches
        ↓
    If yes → Trigger model retraining (future implementation)
        ↓
    Weekly (03:00):  Cleanup Job deletes old files (>7 days)
```

## Components

### 1. Database Tables

**UncertainSampleQueue** (`uncertain_sample_queue`)
- Stores samples with confidence < 85%
- Includes file copy path for VT upload
- Tracks VT upload status (PENDING → UPLOADING → SCANNING → VALIDATED)
- Fields: file_hash, ml_prediction, ml_confidence, features_json, behavioral_enriched, vt_result_json, status

**FeedbackSamples** (`feedback_samples`)
- Stores validated ML vs VT mismatches
- Used for model retraining
- Fields: file_hash, ml_verdict, vt_detections, mismatch_type (FALSE_POSITIVE/FALSE_NEGATIVE), severity, features_json, processed

### 2. Modified Components

**model_service.py** (`/predict/staged` endpoint)
- Removed synchronous VT enrichment
- Added queuing logic for uncertain samples
- Calls `queue_uncertain_sample_with_file()` if confidence < 85%
- Saves file copy to `adaptive_learning/queued_files/{hash}.bin`

**vt_integration.py**
- Added `upload_file_for_scan()` - Upload file to VT, returns scan_id
- Added `get_scan_results()` - Poll for completed scan results with 70+ AV verdicts

**feedback_collector.py**
- Refactored from CSV to database (async/await)
- `log_mismatch_from_queue()` - Compare ML vs VT, insert to FeedbackSamples
- `get_statistics()` - Query database for feedback stats
- `should_retrain()` - Check if threshold met

### 3. New Schedulers

**vt_upload_scheduler.py** (Daily at 00:00)
- Gets pending samples from queue (status=PENDING)
- Uploads files to VT (batch size: 400/day)
- Waits for scan results (5 min timeout)
- Compares ML vs VT verdict
- Logs mismatches to FeedbackSamples
- Deletes uploaded files

**retraining_scheduler.py** (Weekly Sunday 02:00)
- Counts feedback samples (processed=False)
- If count >= 100 → Trigger retraining (TODO)
- Generates feedback report

**cleanup_queued_files.py** (Weekly Sunday 03:00)
- Deletes files older than 7 days from queued_files/
- Deletes old database entries

## Setup

### 1. Environment Variables

Copy `.env.example` to `.env`:

```bash
cp backend/.env.example backend/.env
```

Edit `.env`:
```env
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db?ssl=require
UNCERTAINTY_THRESHOLD=0.85
VT_BATCH_SIZE=400
MAX_VT_ATTEMPTS=3
RETRAINING_THRESHOLD=100
QUEUED_FILES_RETENTION_DAYS=7
```

### 2. Initialize Database

```bash
cd iteration_1/backend
python -c "import asyncio; from db_manager import init_db; asyncio.run(init_db())"
```

This creates the new tables:
- `uncertain_sample_queue`
- `feedback_samples`

### 3. Setup Schedulers (Windows)

Run as Administrator:

```powershell
cd iteration_1\backend\schedulers
.\setup_schedulers.ps1
```

This creates:
- **SecureGuard_VT_Upload** - Daily at 00:00
- **SecureGuard_Retraining_Check** - Weekly Sunday at 02:00
- **SecureGuard_Cleanup_Files** - Weekly Sunday at 03:00

### 4. Manual Testing

Test VT upload scheduler:
```bash
python backend/schedulers/vt_upload_scheduler.py
```

Test retraining scheduler:
```bash
python backend/schedulers/retraining_scheduler.py
```

Test cleanup:
```bash
python backend/schedulers/cleanup_queued_files.py
```

## Usage

### Scanning Files

Normal scan (with queuing):
```bash
curl -X POST http://localhost:8001/predict/staged \
  -F "file=@suspicious.exe" \
  -F "run_local_scan=true"
```

If confidence < 85%:
- File is queued to database
- File copy saved to `adaptive_learning/queued_files/{hash}.bin`
- Response includes prediction immediately (no VT blocking)

### Monitoring Queues

Check queue status:
```bash
curl http://localhost:8001/adaptive/queue/stats
```

Response:
```json
{
  "total_queued": 45,
  "pending_vt": 12,
  "validated": 30,
  "failed": 3,
  "avg_confidence": 0.67
}
```

Check feedback samples:
```bash
curl http://localhost:8001/adaptive/feedback/stats
```

Response:
```json
{
  "total_feedback": 23,
  "pending_review": 23,
  "false_positives": 8,
  "false_negatives": 15,
  "high_severity": 10,
  "ready_for_retraining": false
}
```

### Scheduler Logs

View logs:
```bash
# VT upload scheduler
cat adaptive_learning/vt_scheduler.log

# Retraining scheduler
cat adaptive_learning/retraining_scheduler.log

# Cleanup job
cat adaptive_learning/cleanup.log
```

## Data Flow

### 1. Scanning Phase

```python
# User uploads file
POST /predict/staged

# model_service.py processes:
1. PE static features extracted
2. Behavioral scan (vm_behavioral_monitor.py)
3. ML prediction with enriched features
4. If confidence < 85%:
   - Calculate file hash (SHA256)
   - Save file copy: adaptive_learning/queued_files/{hash}.bin
   - Insert to uncertain_sample_queue:
     * file_hash, file_name, file_size
     * ml_prediction, ml_confidence, ml_raw_score
     * features_json (for future retraining)
     * behavioral_enriched, behavioral_source
     * status = PENDING
5. Return prediction to user (immediate response)
```

### 2. VT Upload Phase (Daily)

```python
# vt_upload_scheduler.py runs at 00:00

1. Get pending samples from DB (limit 400)
2. For each sample:
   a. Load file from queued_files/{hash}.bin
   b. Upload to VT: vt.upload_file_for_scan()
   c. Wait for scan results (5 min timeout)
   d. Compare ML vs VT:
      - VT malicious if detections > 5
      - ML malicious if prediction == 0
      - If mismatch → feedback_collector.log_mismatch_from_queue()
   e. Update queue: status = VALIDATED, vt_result_json
   f. Delete file from queued_files/
3. Log summary: uploaded, scanned, mismatches
```

### 3. Feedback Collection

```python
# feedback_collector.log_mismatch_from_queue()

If ML != VT:
  - Classify mismatch:
    * FALSE_POSITIVE: ML=malicious, VT=clean
    * FALSE_NEGATIVE: ML=clean, VT=malicious
  - Classify severity:
    * HIGH: False negative with >30 VT detections
    * MEDIUM: Other false negatives or high-confidence false positives
    * LOW: Low-confidence false positives
  - Insert to feedback_samples:
    * file_hash, ml_verdict, ml_confidence
    * vt_detections,vt_total_engines, vt_malicious
    * mismatch_type, severity
    * features_json (for retraining)
    * needs_review=True, processed=False
```

### 4. Retraining Phase (Weekly)

```python
# retraining_scheduler.py runs Sunday 02:00

1. Count feedback samples where processed=False
2. If count >= 100:
   a. TODO: Call model_retrainer.py
   b. TODO: Train new model with feedback samples
   c. TODO: Validate new model performance
   d. TODO: Deploy if improved
   e. TODO: Mark samples as processed
3. Else:
   - Log progress: "45/100 samples (45%)"
```

### 5. Cleanup Phase (Weekly)

```python
# cleanup_queued_files.py runs Sunday 03:00

1. Delete files from queued_files/ older than 7 days
2. Delete DB entries from uncertain_sample_queue older than 7 days
3. Log summary: files deleted, DB entries deleted
```

## Database Queries

Check queue status:
```sql
SELECT status, COUNT(*) 
FROM uncertain_sample_queue 
GROUP BY status;
```

Check feedback ready for retraining:
```sql
SELECT COUNT(*) 
FROM feedback_samples 
WHERE processed = FALSE AND needs_review = TRUE;
```

View recent mismatches:
```sql
SELECT 
  timestamp,
  file_name,
  mismatch_type,
  severity,
  ml_verdict,
  vt_detection_ratio
FROM feedback_samples
WHERE processed = FALSE
ORDER BY timestamp DESC
LIMIT 10;
```

## Troubleshooting

### Issue: No samples being queued

**Check 1:** Verify UNCERTAINTY_THRESHOLD
```bash
echo $UNCERTAINTY_THRESHOLD  # Should be 0.85
```

**Check 2:** Scan files and check confidence
```bash
# If all predictions have confidence > 85%, nothing will be queued
```

**Check 3:** Verify database connection
```bash
python -c "from db_manager import AsyncSessionLocal; import asyncio; asyncio.run(list(AsyncSessionLocal())[0].execute('SELECT 1'))"
```

### Issue: VT scheduler failing

**Check 1:** Verify VT API key
```bash
cat backend/config_files/vt_config.json
```

**Check 2:** Check VT daily quota
```python
from vt_integration import VirusTotalEnricher
vt = VirusTotalEnricher()
print(vt.get_cache_stats())  # Check daily_requests_remaining
```

**Check 3:** Check file paths
```bash
ls adaptive_learning/queued_files/  # Files should exist
```

### Issue: Files not being uploaded

**Check 1:** Verify queue status in DB
```sql
SELECT status, COUNT(*) FROM uncertain_sample_queue GROUP BY status;
```

**Check 2:** Check vt_attempts
```sql
SELECT file_hash, vt_attempts, status 
FROM uncertain_sample_queue 
WHERE status = 'PENDING';
```

If vt_attempts >= 3, files are skipped. Manually reset:
```sql
UPDATE uncertain_sample_queue 
SET vt_attempts = 0 
WHERE vt_attempts >= 3;
```

## Future Enhancements

- [ ] Implement model_retrainer.py database integration
- [ ] Add email notifications when retraining threshold met
- [ ] Add web dashboard for monitoring queues
- [ ] Add retry mechanism for failed VT uploads
- [ ] Add support for other sandboxing services (Cuckoo, CAPE)
- [ ] Add A/B testing framework for model comparison
- [ ] Add automated hyperparameter tuning during retraining

## References

- **VT API Docs:** https://developers.virustotal.com/reference/overview
- **PostgreSQL Async:** https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- **Windows Task Scheduler:** https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page
