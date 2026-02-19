"""
Cleanup Job for Old Queued Files
Runs weekly to delete old queued files and database entries

Schedule: Weekly after retraining scheduler (configurable)
Retention: 7 days (configurable via environment)
"""

import asyncio
import logging
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from db_manager import get_session_maker, cleanup_old_queue_entries

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('adaptive_learning/cleanup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


async def cleanup_old_queued_files():
    """
    Delete queued files older than retention period
    Prevents disk space accumulation from failed/abandoned uploads
    
    Process:
    1. Delete old files from adaptive_learning/queued_files/
    2. Delete old database entries from uncertain_sample_queue
    3. Log cleanup statistics
    """
    start_time = datetime.now()
    logger.info("="*70)
    logger.info(" CLEANUP JOB - REMOVING OLD QUEUED FILES")
    logger.info(f"   Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*70)
    
    # Load configuration from environment
    retention_days = int(os.getenv('QUEUED_FILES_RETENTION_DAYS', 7))
    
    logger.info(f"Configuration:")
    logger.info(f"  Retention period: {retention_days} days")
    
    # Statistics
    stats = {
        'files_deleted': 0,
        'db_entries_deleted': 0,
        'errors': 0
    }
    
    try:
        # === STEP 1: Clean up filesystem ===
        queue_dir = Path(__file__).parent.parent.parent / 'adaptive_learning' / 'queued_files'
        
        if queue_dir.exists():
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            logger.info(f"\n Scanning directory: {queue_dir}")
            logger.info(f"   Cutoff date: {cutoff_date.strftime('%Y-%m-%d %H:%M:%S')}")
            
            for file_path in queue_dir.glob('*.bin'):
                try:
                    file_age = datetime.fromtimestamp(file_path.stat().st_mtime)
                    
                    if file_age < cutoff_date:
                        file_path.unlink()
                        stats['files_deleted'] += 1
                        logger.debug(f"   Deleted: {file_path.name} (age: {(datetime.now() - file_age).days} days)")
                except Exception as e:
                    logger.error(f"  ✗ Failed to delete {file_path.name}: {e}")
                    stats['errors'] += 1
            
            logger.info(f" Deleted {stats['files_deleted']} old files")
        else:
            logger.warning(f"  Queue directory not found: {queue_dir}")
        
        # === STEP 2: Clean up database ===
        async with get_session_maker()() as db:
            logger.info(f"\n  Cleaning database entries...")
            
            deleted_count = await cleanup_old_queue_entries(db, days=retention_days)
            stats['db_entries_deleted'] = deleted_count
            
            logger.info(f" Deleted {deleted_count} old database entries")
    
    except Exception as e:
        logger.error(f"Cleanup failed: {e}", exc_info=True)
        raise
    
    finally:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info("\n" + "="*70)
        logger.info("CLEANUP JOB SUMMARY")
        logger.info("="*70)
        logger.info(f"  Duration: {duration:.1f}s")
        logger.info(f"  Files deleted: {stats['files_deleted']}")
        logger.info(f"  DB entries deleted: {stats['db_entries_deleted']}")
        logger.info(f"  Errors: {stats['errors']}")
        logger.info("="*70)
    
    return stats


def main():
    """Main entry point"""
    try:
        stats = asyncio.run(cleanup_old_queued_files())
        
        if stats['errors'] > 0:
            logger.warning(f" Completed with {stats['errors']} errors")
            sys.exit(1)
        else:
            logger.info("Cleanup completed successfully")
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.warning("\n Cleanup interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Cleanup failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
