"""
VirusTotal Upload Scheduler
Runs daily to upload queued uncertain samples to VT for multi-AV scanning

Schedule: Daily at midnight (configurable via environment)
Rate limit: 400 files/day (80% of VT free tier 500/day quota)
"""

import asyncio
import logging
import sys
import os
import json
import time
from pathlib import Path
from datetime import datetime

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from db_manager import (
    get_session_maker,
    get_pending_vt_uploads,
    update_vt_upload_status,
    update_vt_result,
    increment_vt_attempts
)
from vt_integration import VirusTotalEnricher
from adaptive_learning.feedback_collector import FeedbackCollector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('adaptive_learning/vt_scheduler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


async def run_vt_upload_scheduler():
    """
    Daily scheduler: Upload queued files to VT for multi-AV scanning
    
    Process:
    1. Get pending samples from queue (status=PENDING)
    2. For each sample:
       - Upload file to VT
       - Wait for scan results
       - Compare ML vs VT verdict
       - Log mismatch if found
       - Update queue status
    3. Clean up uploaded files
    4. Log summary statistics
    """
    start_time = datetime.now()
    logger.info("="*70)
    logger.info(" VT UPLOAD SCHEDULER - DAILY RUN")
    logger.info(f"   Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*70)
    
    # Load configuration from environment
    batch_size = int(os.getenv('VT_BATCH_SIZE', 400))
    max_attempts = int(os.getenv('MAX_VT_ATTEMPTS', 3))
    
    logger.info(f"Configuration:")
    logger.info(f"  Batch size: {batch_size} files")
    logger.info(f"  Max attempts: {max_attempts}")
    
    # Statistics
    stats = {
        'pending': 0,
        'uploaded': 0,
        'scanned': 0,
        'mismatches': 0,
        'failed': 0,
        'not_found': 0,
        'already_processed': 0
    }
    
    try:
        # Get database session
        async with get_session_maker()() as db:
            # Get pending samples
            logger.info(f"\n Fetching pending VT uploads...")
            pending_samples = await get_pending_vt_uploads(
                db,
                limit=batch_size,
                max_attempts=max_attempts
            )
            
            stats['pending'] = len(pending_samples)
            logger.info(f" Found {len(pending_samples)} samples to process")
            
            if not pending_samples:
                logger.info(" No samples to process - queue is empty")
                return stats
            
            # Initialize VT enricher and feedback collector
            try:
                vt = VirusTotalEnricher()
                feedback_collector = FeedbackCollector()
                logger.info(" VT API and feedback collector initialized")
            except Exception as e:
                logger.error(f"Failed to initialize VT enricher: {e}")
                logger.error(" Cannot proceed without VT API access")
                return stats
            
            # Process each sample
            for idx, sample in enumerate(pending_samples, 1):
                try:
                    logger.info(f"\n[{idx}/{len(pending_samples)}] Processing: {sample.file_name}")
                    logger.info(f"  Hash: {sample.file_hash[:16]}...")
                    logger.info(f"  ML verdict: {sample.prediction_label} ({sample.ml_confidence:.1%})")
                    
                    # Check if file still exists
                    file_path = Path(sample.file_storage_path)
                    if not file_path.exists():
                        logger.warning(f"  File not found: {file_path}")
                        await update_vt_upload_status(db, sample.id, status='FAILED')
                        stats['not_found'] += 1
                        continue
                    
                    # Upload file to VT
                    logger.info(f"  Uploading to VT...")
                    await update_vt_upload_status(db, sample.id, status='UPLOADING')
                    
                    upload_result = vt.upload_file_for_scan(str(file_path))
                    
                    if not upload_result:
                        # Upload failed - increment attempts
                        logger.warning(f"  Upload failed")
                        await increment_vt_attempts(db, sample.id)
                        stats['failed'] += 1
                        time.sleep(15)  # Rate limiting
                        continue
                    
                    stats['uploaded'] += 1
                    scan_id = upload_result['scan_id']
                    logger.info(f"  ✓ Uploaded: {scan_id}")
                    
                    # Update status to SCANNING
                    await update_vt_upload_status(
                        db,
                        sample.id,
                        status='SCANNING',
                        vt_scan_id=scan_id
                    )
                    
                    # Wait for scan results (polls with timeout)
                    logger.info(f"  Waiting for scan results (max 5 minutes)...")
                    scan_results = vt.get_scan_results(scan_id, wait=True, max_wait_seconds=300)
                    
                    if not scan_results:
                        logger.warning(f"  Scan timeout - will retry later")
                        await increment_vt_attempts(db, sample.id)
                        stats['failed'] += 1
                        time.sleep(15)
                        continue
                    
                    stats['scanned'] += 1
                    vt_detections = scan_results['detections']
                    vt_total = scan_results['total_engines']
                    
                    logger.info(f"  ✓ Scan complete: {vt_detections}/{vt_total} detections")
                    
                    # Determine VT verdict (>5 detections = malicious)
                    vt_malicious = vt_detections > 5
                    ml_malicious = (sample.ml_prediction == 0)  # 0=malicious, 1=benign
                    
                    logger.info(f"  Verdict comparison:")
                    logger.info(f"    ML: {'MALICIOUS' if ml_malicious else 'CLEAN'}")
                    logger.info(f"    VT: {'MALICIOUS' if vt_malicious else 'CLEAN'}")
                    
                    # Check for mismatch
                    mismatch_type = None
                    if vt_malicious != ml_malicious:
                        # Log mismatch to feedback table
                        mismatch_type = await feedback_collector.log_mismatch_from_queue(
                            session=db,
                            queue_entry=sample,
                            vt_result=scan_results
                        )
                        
                        if mismatch_type:
                            stats['mismatches'] += 1
                            logger.warning(f"  MISMATCH: {mismatch_type}")
                    else:
                        logger.info(f"  Agreement - no mismatch")
                    
                    # Update queue with VT results
                    await update_vt_result(
                        db,
                        sample.id,
                        status='VALIDATED',
                        vt_result_json=json.dumps(scan_results),
                        vt_queried=True
                    )
                    
                    # Delete uploaded file from queue directory
                    try:
                        file_path.unlink()
                        logger.debug(f"   Deleted queued file: {file_path.name}")
                    except Exception as e:
                        logger.warning(f"    Failed to delete file: {e}")
                    
                    # Rate limiting (4 requests/minute = 15s between requests)
                    # Actually slower to respect VT free tier
                    logger.debug(f"  Rate limiting pause (15s)...")
                    time.sleep(15)
                    
                except Exception as e:
                    logger.error(f"   Error processing sample {sample.id}: {e}", exc_info=True)
                    await increment_vt_attempts(db, sample.id)
                    stats['failed'] += 1
                    continue
            
            await db.commit()
    
    except Exception as e:
        logger.error(f"Scheduler failed: {e}", exc_info=True)
        raise
    
    finally:
        # Log summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info("\n" + "="*70)
        logger.info("VT UPLOAD SCHEDULER SUMMARY")
        logger.info("="*70)
        logger.info(f"  Duration: {duration/60:.1f} minutes")
        logger.info(f"  Samples pending: {stats['pending']}")
        logger.info(f"  Files uploaded: {stats['uploaded']}")
        logger.info(f"  Scans completed: {stats['scanned']}")
        logger.info(f"  Mismatches found: {stats['mismatches']}")
        logger.info(f"  Failed uploads: {stats['failed']}")
        logger.info(f"  Files not found: {stats['not_found']}")
        logger.info("="*70)
        
    return stats


def main():
    """Main entry point"""
    try:
        stats = asyncio.run(run_vt_upload_scheduler())
        
        # Exit with appropriate code
        if stats['failed'] > 0:
            logger.warning(f"  Completed with {stats['failed']} failures")
            sys.exit(1)
        else:
            logger.info(" Scheduler completed successfully")
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.warning("\n  Scheduler interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f" Scheduler failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
