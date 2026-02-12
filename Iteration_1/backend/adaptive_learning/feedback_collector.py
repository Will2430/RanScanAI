"""
Adaptive Learning System - Feedback Collector
Logs mismatches between ML predictions and VirusTotal consensus
for continuous model improvement
"""

import pandas as pd
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional


class FeedbackCollector:
    """
    Collects samples where ML model disagrees with VirusTotal
    for future model retraining and improvement
    """
    
    def __init__(self, feedback_file: str = "adaptive_learning/retraining_queue.csv"):
        self.feedback_file = feedback_file
        self._ensure_directory_exists()
        self._init_feedback_file()
    
    def _ensure_directory_exists(self):
        """Create adaptive_learning directory if it doesn't exist"""
        os.makedirs(os.path.dirname(self.feedback_file), exist_ok=True)
    
    def _init_feedback_file(self):
        """Initialize feedback file with headers if it doesn't exist"""
        if not os.path.exists(self.feedback_file):
            df = pd.DataFrame(columns=[
                'timestamp', 'file_hash', 'file_name', 
                'ml_prediction', 'ml_confidence', 'ml_verdict',
                'vt_detections', 'vt_total_engines', 'vt_detection_ratio',
                'vt_family', 'vt_threat_label', 'vt_malicious',
                'mismatch_type', 'severity', 'needs_review',
                'features_json', 'processed', 'processed_date', 'notes'
            ])
            df.to_csv(self.feedback_file, index=False)
            print(f"[ADAPTIVE] Created feedback file: {self.feedback_file}")
    
    def log_mismatch(self, 
                     file_hash: str,
                     file_name: str,
                     ml_prediction: int, 
                     ml_confidence: float,
                     vt_result: Dict[str, Any],
                     features: Dict[str, Any]) -> bool:
        """
        Log a mismatch between ML prediction and VirusTotal consensus
        
        Args:
            file_hash: MD5/SHA-1/SHA-256 hash of file
            file_name: Original filename
            ml_prediction: 0=malicious, 1=benign
            ml_confidence: Model confidence (0-1)
            vt_result: VirusTotal API response
            features: Feature dictionary used for prediction
            
        Returns:
            bool: True if logged successfully
        """
        
        # Determine VT verdict
        if not vt_result.get('found'):
            print(f"[ADAPTIVE] Skipping - file not in VT database: {file_hash}")
            return False
        
        vt_detections = vt_result.get('detections', 0)
        vt_total = vt_result.get('total_engines', 70)
        
        # VT is considered malicious if >5 engines detect it
        vt_malicious = vt_detections > 5
        
        # Determine ML verdict
        ml_malicious = (ml_prediction == 0)
        ml_verdict = 'Malicious' if ml_malicious else 'Benign'
        
        # Check if there's a mismatch
        if ml_malicious == vt_malicious:
            # No mismatch - predictions agree
            return False
        
        # Classify mismatch type
        if ml_malicious and not vt_malicious:
            mismatch_type = "FALSE_POSITIVE"  # ML flagged clean file
            severity = "LOW" if ml_confidence < 0.7 else "MEDIUM"
        else:  # not ml_malicious and vt_malicious
            mismatch_type = "FALSE_NEGATIVE"  # ML missed malware
            severity = "HIGH" if vt_detections > 30 else "MEDIUM"
        
        # Prepare mismatch data
        mismatch_data = {
            'timestamp': datetime.now().isoformat(),
            'file_hash': file_hash,
            'file_name': file_name,
            'ml_prediction': ml_prediction,
            'ml_confidence': round(ml_confidence, 4),
            'ml_verdict': ml_verdict,
            'vt_detections': vt_detections,
            'vt_total_engines': vt_total,
            'vt_detection_ratio': f"{vt_detections}/{vt_total}",
            'vt_family': vt_result.get('family_name', 'Unknown'),
            'vt_threat_label': vt_result.get('threat_label', 'Unknown'),
            'vt_malicious': vt_malicious,
            'mismatch_type': mismatch_type,
            'severity': severity,
            'needs_review': True,
            'features_json': json.dumps(features),
            'processed': False,
            'processed_date': None,
            'notes': f"{mismatch_type}: ML={ml_verdict}, VT={vt_detections}/{vt_total}"
        }
        
        # Append to CSV
        df = pd.DataFrame([mismatch_data])
        
        if os.path.exists(self.feedback_file):
            df.to_csv(self.feedback_file, mode='a', header=False, index=False)
        else:
            df.to_csv(self.feedback_file, mode='w', header=True, index=False)
        
        print(f"[ADAPTIVE] ⚠️  Logged {mismatch_type} for retraining: {file_hash[:8]}...")
        print(f"           ML: {ml_verdict} ({ml_confidence:.2%}) | VT: {vt_detections}/{vt_total} engines")
        
        return True
    
    def get_pending_samples_count(self) -> int:
        """Get count of samples awaiting review"""
        if not os.path.exists(self.feedback_file):
            return 0
        
        df = pd.read_csv(self.feedback_file)
        return len(df[df['needs_review'] == True])
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about collected feedback"""
        if not os.path.exists(self.feedback_file):
            return {
                'total_samples': 0,
                'pending_review': 0,
                'false_positives': 0,
                'false_negatives': 0,
                'high_severity': 0
            }
        
        df = pd.read_csv(self.feedback_file)
        
        return {
            'total_samples': len(df),
            'pending_review': len(df[df['needs_review'] == True]),
            'processed': len(df[df['processed'] == True]),
            'false_positives': len(df[df['mismatch_type'] == 'FALSE_POSITIVE']),
            'false_negatives': len(df[df['mismatch_type'] == 'FALSE_NEGATIVE']),
            'high_severity': len(df[df['severity'] == 'HIGH']),
            'medium_severity': len(df[df['severity'] == 'MEDIUM']),
            'low_severity': len(df[df['severity'] == 'LOW'])
        }
    
    def should_retrain(self, threshold: int = 100) -> bool:
        """
        Check if we have enough new samples to trigger retraining
        
        Args:
            threshold: Minimum samples needed to trigger retraining
            
        Returns:
            bool: True if should retrain
        """
        pending = self.get_pending_samples_count()
        
        if pending >= threshold:
            print(f"[ADAPTIVE] 🔄 Retraining threshold reached: {pending} samples pending")
            return True
        
        return False
    
    def get_samples_for_retraining(self) -> pd.DataFrame:
        """Get all unprocessed samples for retraining"""
        if not os.path.exists(self.feedback_file):
            return pd.DataFrame()
        
        df = pd.read_csv(self.feedback_file)
        return df[df['needs_review'] == True].copy()
    
    def mark_samples_processed(self, sample_hashes: list):
        """Mark samples as processed after retraining"""
        if not os.path.exists(self.feedback_file):
            return
        
        df = pd.read_csv(self.feedback_file)
        
        for hash_val in sample_hashes:
            mask = df['file_hash'] == hash_val
            df.loc[mask, 'needs_review'] = False
            df.loc[mask, 'processed'] = True
            df.loc[mask, 'processed_date'] = datetime.now().isoformat()
        
        df.to_csv(self.feedback_file, index=False)
        print(f"[ADAPTIVE] ✓ Marked {len(sample_hashes)} samples as processed")
    
    def export_report(self, output_file: str = "adaptive_learning/feedback_report.txt"):
        """Generate a human-readable report of feedback statistics"""
        stats = self.get_statistics()
        
        report = f"""
ADAPTIVE LEARNING - FEEDBACK REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*70}

SUMMARY
-------
Total Samples Collected:    {stats['total_samples']:,}
Pending Review:             {stats['pending_review']:,}
Processed:                  {stats['processed']:,}

MISMATCH BREAKDOWN
------------------
False Positives (ML flagged clean files):  {stats['false_positives']:,}
False Negatives (ML missed malware):       {stats['false_negatives']:,}

SEVERITY DISTRIBUTION
---------------------
High Severity:    {stats['high_severity']:,}
Medium Severity:  {stats['medium_severity']:,}
Low Severity:     {stats['low_severity']:,}

RETRAINING STATUS
-----------------
Ready for retraining: {"YES" if self.should_retrain() else "NO"}
Threshold: 100 samples
Current: {stats['pending_review']:,} samples

{'='*70}
"""
        
        with open(output_file, 'w') as f:
            f.write(report)
        
        print(report)
        print(f"[ADAPTIVE] Report saved to: {output_file}")


# Example usage
if __name__ == "__main__":
    # Initialize feedback collector
    collector = FeedbackCollector()
    
    # Example: Log a false positive
    example_features = {
        'processes_malicious': 0,
        'files_malicious': 0,
        'registry_total': 15,
        'network_dns': 2,
        'confidence': 0.75
    }
    
    example_vt_result = {
        'found': True,
        'malicious': False,
        'detections': 2,
        'total_engines': 72,
        'family_name': 'Clean',
        'threat_label': 'clean'
    }
    
    # This would log a false positive (ML said malicious, VT said clean)
    collector.log_mismatch(
        file_hash='abc123def456',
        file_name='example.exe',
        ml_prediction=0,  # Malicious
        ml_confidence=0.75,
        vt_result=example_vt_result,
        features=example_features
    )
    
    # Get statistics
    stats = collector.get_statistics()
    print(f"\nStatistics: {stats}")
    
    # Check if should retrain
    if collector.should_retrain(threshold=1):  # Lower threshold for demo
        print("\n✓ Ready for retraining!")
    
    # Export report
    collector.export_report()
