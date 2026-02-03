# Adaptive Learning System

This folder contains the implementation of the adaptive learning framework for continuous model improvement.

## Overview

The adaptive learning system implements Objective #2 of the FYP:
> "Implement an adaptive learning framework that leverages VirusTotal threat intelligence to create a continuous feedback loop, enabling periodic model retraining with validated samples."

## Components

### 1. **feedback_collector.py**
Collects samples where the ML model disagrees with VirusTotal consensus.

**Features:**
- Logs mismatches (false positives and false negatives)
- Classifies severity (HIGH/MEDIUM/LOW)
- Stores features for retraining
- Generates statistics and reports

**Usage:**
```python
from feedback_collector import FeedbackCollector

collector = FeedbackCollector()

# Log a mismatch
collector.log_mismatch(
    file_hash='abc123...',
    file_name='suspicious.exe',
    ml_prediction=0,  # Malicious
    ml_confidence=0.85,
    vt_result={...},
    features={...}
)

# Check if ready for retraining
if collector.should_retrain(threshold=100):
    print("Ready to retrain!")
```

### 2. **model_retrainer.py**
Automated retraining script that runs periodically (weekly).

**Features:**
- Loads original + feedback samples
- Trains new model
- Validates performance
- Deploys if improved
- Backs up old models

**Usage:**
```python
from model_retrainer import ModelRetrainer

retrainer = ModelRetrainer()
success = retrainer.retrain_model(min_samples=50)
```

**Scheduled Execution (Windows):**
```powershell
# Run every Sunday at 2 AM
schtasks /create /tn "MalwareModelRetraining" /tr "C:\path\to\python.exe C:\path\to\model_retrainer.py" /sc weekly /d SUN /st 02:00
```

### 3. **model_version_manager.py**
Tracks model versions and performance evolution.

**Features:**
- Version numbering (v1.0, v1.1, v1.2...)
- Accuracy history tracking
- Sample count tracking
- Update logging

**Usage:**
```python
from model_version_manager import ModelVersionManager

version_mgr = ModelVersionManager()

# Update version after retraining
version_mgr.update_version(
    new_accuracy=0.9945,
    samples_added=128,
    fpr=0.0015,
    notes="Added new ransomware variants"
)

# Get current info
info = version_mgr.get_current_info()
# Returns: {'version': '1.3', 'accuracy': 0.9945, ...}

# Print summary
version_mgr.print_summary()
```

## Workflow

```
┌──────────────────────────────────────────────────────────────┐
│                    ADAPTIVE LEARNING CYCLE                    │
└──────────────────────────────────────────────────────────────┘

1. User scans file
      ↓
2. ML Model predicts (e.g., Malicious, 85% confidence)
      ↓
3. Query VirusTotal API
      ↓
4. Check for mismatch
      ↓
5. IF ML says Malicious but VT says Clean (or vice versa):
      ↓
      → feedback_collector.log_mismatch()
      → Store in retraining_queue.csv
      ↓
6. Weekly: Check if threshold reached (e.g., 100 samples)
      ↓
7. IF threshold reached:
      ↓
      → model_retrainer.retrain_model()
      → Combine original + new samples
      → Train new model
      → Validate performance
      ↓
8. IF new model >= old model accuracy:
      ↓
      → Backup old model
      → Deploy new model
      → model_version_manager.update_version()
      → Mark samples as processed
      ↓
9. Model v1.1 deployed!
```

## File Structure

```
adaptive_learning/
├── feedback_collector.py       # Mismatch logging
├── model_retrainer.py          # Automated retraining
├── model_version_manager.py    # Version tracking
├── README.md                   # This file
├── retraining_queue.csv        # Feedback samples (generated)
├── retraining_log.txt          # Retraining history (generated)
├── model_version.json          # Version info (generated)
├── feedback_report.txt         # Statistics (generated)
├── version_report.txt          # Version report (generated)
└── model_backups/              # Old model backups
    ├── model_v20260129_020000.pkl
    ├── model_v20260205_020000.pkl
    └── ...
```

## Data Flow

### Feedback Collection
```csv
# retraining_queue.csv
timestamp,file_hash,ml_prediction,ml_confidence,vt_detections,vt_total_engines,mismatch_type,severity,needs_review,features_json,processed
2026-01-29T10:30:00,abc123...,0,0.85,2,72,FALSE_POSITIVE,MEDIUM,True,{...},False
2026-01-29T11:45:00,def456...,1,0.92,45,72,FALSE_NEGATIVE,HIGH,True,{...},False
```

### Version History
```json
{
  "current_version": "1.3",
  "total_samples": 22103,
  "retraining_count": 3,
  "accuracy_history": [
    {
      "version": "1.0",
      "accuracy": 0.9933,
      "fpr": 0.0019,
      "date": "2026-01-15",
      "samples": 21752,
      "notes": "Baseline model"
    },
    {
      "version": "1.1",
      "accuracy": 0.9935,
      "fpr": 0.0018,
      "date": "2026-01-22",
      "samples": 21880,
      "samples_added": 128,
      "notes": "Added ransomware variants"
    },
    {
      "version": "1.2",
      "accuracy": 0.9941,
      "fpr": 0.0017,
      "date": "2026-01-29",
      "samples": 21967,
      "samples_added": 87,
      "notes": "Lockbit 3.0 integration"
    }
  ]
}
```

## Configuration

### Thresholds
Edit these in the code or via environment variables:

```python
# feedback_collector.py
RETRAINING_THRESHOLD = 100  # Min samples to trigger retraining

# model_retrainer.py
MIN_SAMPLES = 50           # Min valid samples after processing
ACCURACY_TOLERANCE = 0.01  # Allow 1% accuracy drop

# VT consensus
VT_MALICIOUS_THRESHOLD = 5  # >5 detections = malicious
```

## Monitoring

### Check Feedback Status
```python
from feedback_collector import FeedbackCollector

collector = FeedbackCollector()
stats = collector.get_statistics()

print(f"Pending samples: {stats['pending_review']}")
print(f"False positives: {stats['false_positives']}")
print(f"False negatives: {stats['false_negatives']}")
```

### View Version History
```python
from model_version_manager import ModelVersionManager

version_mgr = ModelVersionManager()
version_mgr.print_summary()
```

### Generate Reports
```python
collector.export_report()           # Feedback statistics
version_mgr.export_report()         # Version history
```

## Integration with Main System

In your main detection system (FastAPI backend):

```python
from virustotal_enrichment import VirusTotalAPI
from adaptive_learning.feedback_collector import FeedbackCollector

vt = VirusTotalAPI(api_key="your_key")
collector = FeedbackCollector()

# During file scanning
ml_result = model.predict(features)
vt_result = vt.lookup_hash(file_hash)

# Log mismatch if predictions disagree
if vt_result['found']:
    collector.log_mismatch(
        file_hash=file_hash,
        file_name=file_name,
        ml_prediction=ml_result['prediction'],
        ml_confidence=ml_result['confidence'],
        vt_result=vt_result,
        features=features
    )
```

## Testing

Run individual components for testing:

```bash
# Test feedback collector
python feedback_collector.py

# Test retrainer (with low threshold for demo)
python model_retrainer.py

# Test version manager
python model_version_manager.py
```

## Expected Results

After implementing adaptive learning, you should observe:

1. **Automatic Feedback Collection**: Mismatches logged to CSV
2. **Periodic Retraining**: Model updates weekly with new samples
3. **Version Tracking**: Clear history of model evolution
4. **Performance Improvement**: Gradual accuracy gains over time
5. **New Variant Detection**: Ability to detect emerging threats

### Example Evolution:
```
v1.0: 99.33% accuracy (baseline - 21,752 samples)
v1.1: 99.35% accuracy (+128 samples - WannaCry variants)
v1.2: 99.41% accuracy (+87 samples - Lockbit 3.0)
v1.3: 99.45% accuracy (+203 samples - Custom packers)
v1.4: 99.52% accuracy (+91 samples - BlackCat variants)
```

## For FYP Defense

**Key Points to Emphasize:**

1. **Automated Learning**: System learns from mistakes automatically
2. **VirusTotal Integration**: Uses collective intelligence as ground truth
3. **Version Control**: Full transparency of model evolution
4. **Quality Assurance**: Only deploys if performance maintained
5. **Scalability**: Can handle thousands of feedback samples

**Demonstration:**
- Show retraining_queue.csv with real mismatches
- Display version history showing improvements
- Run retrainer live to show automation
- Present accuracy trend graph

## Future Enhancements

- [ ] Email notifications when retraining completes
- [ ] Web dashboard for monitoring
- [ ] A/B testing framework for model comparison
- [ ] Automated hyperparameter tuning during retraining
- [ ] Integration with MITRE ATT&CK framework
- [ ] Confidence threshold adjustment based on FPR trends
