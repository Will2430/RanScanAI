"""
Model Retraining Scheduler
Runs weekly to check if enough feedback samples are available for retraining

Schedule: Weekly on Sunday at 2 AM (configurable via environment)
Threshold: 100 feedback samples (configurable via environment)
"""

import asyncio
import logging
import sys
import os
from pathlib import Path
from datetime import datetime

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from db_manager import get_session_maker
from adaptive_learning.feedback_collector import FeedbackCollector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('adaptive_learning/retraining_scheduler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


async def run_retraining_scheduler():
    """
    Weekly scheduler: Check if enough feedback samples for retraining
    
    Process:
    1. Count feedback samples (processed=False, needs_review=True)
    2. If count >= threshold:
       - Trigger model_retrainer.py (future implementation)
       - Mark samples as processed
       - Update model version tracking
    3. Log status
    """
    start_time = datetime.now()
    logger.info("="*70)
    logger.info(" MODEL RETRAINING SCHEDULER - WEEKLY CHECK")
    logger.info(f"   Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*70)
    
    # Load configuration from environment
    retraining_threshold = int(os.getenv('RETRAINING_THRESHOLD', 100))
    
    logger.info(f"Configuration:")
    logger.info(f"  Retraining threshold: {retraining_threshold} samples")
    
    try:
        # Get database session
        async with get_session_maker()() as db:
            # Initialize feedback collector
            feedback_collector = FeedbackCollector()
            
            # Get statistics
            stats = await feedback_collector.get_statistics(db)
            pending_count = stats['pending_review']
            
            logger.info(f"\nFeedback Statistics:")
            logger.info(f"  Total feedback samples: {stats['total_feedback']}")
            logger.info(f"  Pending review: {pending_count}")
            logger.info(f"  False positives: {stats['false_positives']}")
            logger.info(f"  False negatives: {stats['false_negatives']}")
            logger.info(f"  High severity: {stats['high_severity']}")
            
            # Check if threshold met
            should_retrain = await feedback_collector.should_retrain(db, threshold=retraining_threshold)
            
            if should_retrain:
                logger.info(f"\n RETRAINING THRESHOLD REACHED")
                logger.info(f"   {pending_count} samples ready for retraining (threshold: {retraining_threshold})")
                
                # TODO: Implement actual retraining trigger
                # For now, just log that retraining would be triggered
                logger.warning("\n MODEL RETRAINING NOT YET IMPLEMENTED")
                logger.warning("   Next steps:")
                logger.warning("   1. Implement model_retrainer.py database integration")
                logger.warning("   2. Call retrainer from this scheduler")
                logger.warning("   3. Mark samples as processed after successful retraining")
                logger.warning("   4. Update model version tracking")
                
                # Generate feedback report
                await feedback_collector.export_report(db)
                
                return {
                    'threshold_met': True,
                    'pending_samples': pending_count,
                    'retraining_triggered': False,  # Will be True after implementation
                    'status': 'ready_for_retraining'
                }
            else:
                logger.info(f"\n✓ Retraining threshold not met")
                logger.info(f"   Progress: {pending_count}/{retraining_threshold} samples ({pending_count/retraining_threshold*100:.1f}%)")
                logger.info(f"   Need {retraining_threshold - pending_count} more samples")
                
                return {
                    'threshold_met': False,
                    'pending_samples': pending_count,
                    'retraining_triggered': False,
                    'status': 'collecting_feedback'
                }
    
    except Exception as e:
        logger.error(f"Scheduler failed: {e}", exc_info=True)
        raise
    
    finally:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info("\n" + "="*70)
        logger.info(f"Scheduler completed in {duration:.1f}s")
        logger.info("="*70)


def main():
    """Main entry point"""
    try:
        result = asyncio.run(run_retraining_scheduler())
        
        if result['threshold_met']:
            logger.info(" Retraining check completed - threshold met")
            sys.exit(0)
        else:
            logger.info(" Retraining check completed - collecting more samples")
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.warning("\n Scheduler interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f" Scheduler failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
