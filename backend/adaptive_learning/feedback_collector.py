"""
Adaptive Learning System - Feedback Collector
Logs mismatches between ML predictions and VirusTotal consensus
for continuous model improvement

UPDATED: Now uses PostgreSQL database instead of CSV files
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class FeedbackCollector:
    """
    Collects samples where ML model disagrees with VirusTotal
    for future model retraining and improvement
    
    Database-driven implementation - replaces CSV approach
    """
    
    def __init__(self):
        """Initialize feedback collector (database-driven)"""
        logger.info("[ADAPTIVE] Feedback collector initialized (database mode)")
    
    async def log_mismatch_from_queue(
        self,
        session: AsyncSession,
        queue_entry,  # UncertainSampleQueue object
        vt_result: Dict[str, Any]
    ) -> Optional[str]:
        """
        Compare queued ML prediction with VT scan results
        Insert into FeedbackSamples if mismatch found
        
        Args:
            session: Database session
            queue_entry: Entry from UncertainSampleQueue table
            vt_result: VT scan results with all AV detections
            
        Returns:
            mismatch_type (FALSE_POSITIVE/FALSE_NEGATIVE) or None
        """
        # Import here to avoid circular dependency
        from db_manager import insert_feedback_sample
        
        # Determine VT verdict
        vt_detections = vt_result.get('detections', 0)
        vt_total = vt_result.get('total_engines', 70)
        vt_malicious = vt_detections > 5  # >5 detections = malicious
        
        # ML verdict (prediction: probability score where >0.5=malicious, closer to 1=malicious, closer to 0=benign)
        ml_malicious = (queue_entry.ml_prediction > 0.5)
        
        # Check mismatch
        if ml_malicious == vt_malicious:
            logger.debug(f"[ADAPTIVE] Agreement: ML={ml_malicious}, VT={vt_malicious}")
            return None  # No mismatch
        
        # Classify mismatch
        if ml_malicious and not vt_malicious:
            mismatch_type = "FALSE_POSITIVE"  # ML flagged clean file
            severity = "LOW" if queue_entry.ml_confidence < 0.7 else "MEDIUM"
        else:
            mismatch_type = "FALSE_NEGATIVE"  # ML missed malware
            severity = "HIGH" if vt_detections > 30 else "MEDIUM"
        
        # Insert into FeedbackSamples table
        await insert_feedback_sample(
            session=session,
            file_hash=queue_entry.file_hash,
            file_name=queue_entry.file_name,
            file_size=queue_entry.file_size,
            ml_prediction=queue_entry.ml_prediction,
            ml_confidence=queue_entry.ml_confidence,
            ml_raw_score=queue_entry.ml_raw_score,
            vt_detections=vt_detections,
            vt_total_engines=vt_total,
            vt_malicious=vt_malicious,
            vt_scans=vt_result.get('scans', {}),
            mismatch_type=mismatch_type,
            severity=severity,
            features_json=queue_entry.features_json
        )
        
        logger.warning(f"[ADAPTIVE] ⚠️  Logged {mismatch_type} for retraining: {queue_entry.file_hash[:8]}...")
        logger.warning(f"           ML: {'Malicious' if ml_malicious else 'Benign'} ({queue_entry.ml_confidence:.2%}) | VT: {vt_detections}/{vt_total} engines")
        
        return mismatch_type
    
    async def get_pending_samples_count(self, session: AsyncSession) -> int:
        """Get count of samples awaiting review"""
        from sqlalchemy import select, func
        from db_manager import FeedbackSamples
        
        count = await session.scalar(
            select(func.count(FeedbackSamples.id))
            .where(FeedbackSamples.needs_review == True)
            .where(FeedbackSamples.processed == False)
        )
        
        return count or 0
    
    async def get_statistics(self, session: AsyncSession) -> Dict[str, Any]:
        """Get statistics about collected feedback"""
        from db_manager import get_feedback_statistics
        
        stats = await get_feedback_statistics(session)
        
        logger.info(f"[ADAPTIVE] Feedback stats: {stats['total_feedback']} total, {stats['pending_review']} pending")
        
        return stats
    
    async def should_retrain(self, session: AsyncSession, threshold: int = 100) -> bool:
        """
        Check if we have enough new samples to trigger retraining
        
        Args:
            session: Database session
            threshold: Minimum samples needed to trigger retraining
            
        Returns:
            bool: True if should retrain
        """
        pending = await self.get_pending_samples_count(session)
        
        if pending >= threshold:
            logger.info(f"[ADAPTIVE] 🔄 Retraining threshold reached: {pending} samples pending (threshold: {threshold})")
            return True
        
        logger.debug(f"[ADAPTIVE] Retraining threshold not met: {pending}/{threshold} samples")
        return False
    
    async def get_samples_for_retraining(self, session: AsyncSession) -> list:
        """Get all unprocessed samples for retraining"""
        from db_manager import get_feedback_samples
        
        samples = await get_feedback_samples(session, processed=False)
        
        logger.info(f"[ADAPTIVE] Retrieved {len(samples)} samples for retraining")
        
        return samples
    
    async def mark_samples_processed(self, session: AsyncSession, feedback_ids: list[int]):
        """Mark samples as processed after retraining"""
        from db_manager import mark_feedback_processed
        
        await mark_feedback_processed(session, feedback_ids)
        
        logger.info(f"[ADAPTIVE] ✓ Marked {len(feedback_ids)} samples as processed")
    
    async def export_report(self, session: AsyncSession, output_file: str = "adaptive_learning/feedback_report.txt"):
        """Generate a human-readable report of feedback statistics"""
        stats = await self.get_statistics(session)
        
        report = f"""
ADAPTIVE LEARNING - FEEDBACK REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*70}

SUMMARY
-------
Total Samples Collected:    {stats['total_feedback']:,}
Pending Review:             {stats['pending_review']:,}

MISMATCH BREAKDOWN
------------------
False Positives (ML flagged clean files):  {stats['false_positives']:,}
False Negatives (ML missed malware):       {stats['false_negatives']:,}

SEVERITY DISTRIBUTION
---------------------
High Severity:    {stats['high_severity']:,}

RETRAINING STATUS
-----------------
Ready for retraining: {"YES" if stats['ready_for_retraining'] else "NO"}
Threshold: 100 samples
Current: {stats['pending_review']:,} samples

{'='*70}
"""
        
        from pathlib import Path
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(report)
        
        print(report)
        logger.info(f"[ADAPTIVE] Report saved to: {output_file}")


# Example usage (updated for async/await)
async def test_feedback_collector():
    """Test feedback collector with database"""
    from db_manager import get_session_maker
    
    logging.basicConfig(level=logging.INFO)
    
    # Initialize feedback collector
    collector = FeedbackCollector()
    
    # Use database session
    async with get_session_maker()() as session:
        # Get statistics
        stats = await collector.get_statistics(session)
        print(f"\nStatistics: {stats}")
        
        # Check if should retrain
        if await collector.should_retrain(session, threshold=1):  # Lower threshold for demo
            print("\n✓ Ready for retraining!")
        
        # Export report
        await collector.export_report(session)


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_feedback_collector())
