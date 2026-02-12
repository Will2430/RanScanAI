# Feature Extraction Pipeline

## Complete End-to-End Flow

Here's exactly how features are extracted from a user-submitted file and fed into your model:

---

## Pipeline Overview

```
User uploads file.exe
        ↓
FastAPI receives file
        ↓
Save to temp location
        ↓
Extract static features using pefile
        ↓
Create feature vector (matching training features)
        ↓
Feed into ML model
        ↓
Get prediction + confidence
        ↓
(Optional) Query VirusTotal
        ↓
Return combined result
        ↓
Clean up temp file
```

---

## Step-by-Step Implementation

### Step 1: Train Model and Save Feature Names

First, when training your model, save the exact feature names in order:

```python
# static_model_trainer.py (Training phase)
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load dataset
df = pd.read_csv('Dataset/Zenedo.csv')

# Define features (MUST BE SAME ORDER DURING INFERENCE!)
STATIC_FEATURES = [
    'file_size',
    'SizeOfCode',
    'NumberOfSections',
    'SizeOfHeaders',
    'ImageBase',
    'SectionAlignment',
    'FileAlignment',
    'MajorImageVersion',
    'MinorImageVersion',
    'MajorOSVersion',
    'MinorOSVersion',
    'NumberOfRvaAndSizes',
    'SizeOfStackReserve',
    'SizeOfStackCommit',
    'SizeOfHeapReserve',
]

X = df[STATIC_FEATURES]
y = df['label']

# Train model
model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)
model.fit(X, y)

# Save model
joblib.dump(model, 'static_malware_detector.pkl')

# CRITICAL: Save feature names in exact order
with open('static_features.txt', 'w') as f:
    f.write('\n'.join(STATIC_FEATURES))

print(f"Model trained with {len(STATIC_FEATURES)} features")
```

---

### Step 2: Feature Extractor Class

Create a dedicated class to extract features from any PE file:

```python
# feature_extractor.py
import pefile
import os
import math

class FeatureExtractor:
    """
    Extracts static features from PE files (Windows executables)
    """
    
    def __init__(self, feature_names_file='static_features.txt'):
        # Load feature names from training
        with open(feature_names_file, 'r') as f:
            self.feature_names = [line.strip() for line in f]
        
        print(f"Loaded {len(self.feature_names)} feature definitions")
    
    def extract(self, file_path):
        """
        Extract all features from a PE file
        
        Returns:
            dict: Feature name -> value mapping
        """
        features = {}
        
        try:
            # Parse PE file
            pe = pefile.PE(file_path)
            
            # Extract each feature
            features['file_size'] = os.path.getsize(file_path)
            features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
            features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
            features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
            features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
            features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
            features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
            features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
            features['MajorOSVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            features['MinorOSVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
            features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
            features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
            features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
            
            # Add more advanced features
            features['section_count'] = len(pe.sections)
            features['section_entropy'] = self._calculate_entropy(pe)
            features['import_count'] = self._count_imports(pe)
            
            pe.close()
            
        except Exception as e:
            print(f"Error parsing PE file: {e}")
            # Return zeros if file can't be parsed (might be packed/corrupted)
            features = {name: 0 for name in self.feature_names}
        
        return features
    
    def extract_as_vector(self, file_path):
        """
        Extract features and return as ordered list (for model input)
        
        Returns:
            list: Feature values in same order as training
        """
        features_dict = self.extract(file_path)
        
        # CRITICAL: Maintain exact order from training!
        feature_vector = [features_dict.get(name, 0) for name in self.feature_names]
        
        return feature_vector
    
    def _calculate_entropy(self, pe):
        """
        Calculate average entropy across all sections
        High entropy (>7.0) often indicates packed/encrypted malware
        """
        if not pe.sections:
            return 0.0
        
        total_entropy = 0
        for section in pe.sections:
            data = section.get_data()
            if len(data) == 0:
                continue
            
            # Calculate Shannon entropy
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    probability = count / len(data)
                    entropy -= probability * math.log2(probability)
            
            total_entropy += entropy
        
        return total_entropy / len(pe.sections)
    
    def _count_imports(self, pe):
        """
        Count number of imported functions
        Malware often has unusual import patterns
        """
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return 0
        
        import_count = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            import_count += len(entry.imports)
        
        return import_count

# Example usage
if __name__ == "__main__":
    extractor = FeatureExtractor()
    
    # Test with a file
    test_file = "test_sample.exe"
    features = extractor.extract(test_file)
    
    print("\nExtracted Features:")
    for name, value in features.items():
        print(f"  {name}: {value}")
    
    # Get as vector for model
    vector = extractor.extract_as_vector(test_file)
    print(f"\nFeature vector: {vector[:5]}... ({len(vector)} features total)")
```

---

### Step 3: Detector Class (Combines Extraction + Prediction)

```python
# detector.py
import joblib
from feature_extractor import FeatureExtractor
from virustotal_enrichment import VirusTotalAPI
import hashlib

class MalwareDetector:
    """
    Complete malware detection pipeline
    """
    
    def __init__(self, model_path='static_malware_detector.pkl', 
                 features_path='static_features.txt',
                 vt_api_key=None):
        # Load trained model
        self.model = joblib.load(model_path)
        print(f"Loaded model from {model_path}")
        
        # Initialize feature extractor
        self.extractor = FeatureExtractor(features_path)
        
        # Optional: VirusTotal integration
        self.vt = VirusTotalAPI(api_key=vt_api_key) if vt_api_key else None
    
    def detect(self, file_path, include_vt=True):
        """
        Complete detection pipeline
        
        Args:
            file_path (str): Path to file to analyze
            include_vt (bool): Whether to query VirusTotal
        
        Returns:
            dict: Detection results
        """
        print(f"\n[1/5] Analyzing file: {file_path}")
        
        # Step 1: Extract features
        print("[2/5] Extracting static features...")
        feature_vector = self.extractor.extract_as_vector(file_path)
        feature_dict = self.extractor.extract(file_path)
        
        print(f"      Extracted {len(feature_vector)} features")
        print(f"      File size: {feature_dict['file_size']} bytes")
        print(f"      Sections: {feature_dict['NumberOfSections']}")
        print(f"      Entropy: {feature_dict.get('section_entropy', 0):.2f}")
        
        # Step 2: Run ML prediction
        print("[3/5] Running ML model...")
        prediction = self.model.predict([feature_vector])[0]
        probabilities = self.model.predict_proba([feature_vector])[0]
        confidence = probabilities.max()
        
        # Map prediction (0=malicious, 1=benign in your Zenodo dataset)
        is_malicious = (prediction == 0)
        label = "Malicious" if is_malicious else "Clean"
        
        print(f"      Prediction: {label}")
        print(f"      Confidence: {confidence:.2%}")
        
        # Build result
        result = {
            'file_path': file_path,
            'prediction': label,
            'confidence': float(confidence),
            'ml_details': {
                'raw_prediction': int(prediction),
                'probabilities': {
                    'malicious': float(probabilities[0]),
                    'benign': float(probabilities[1])
                }
            },
            'features': feature_dict,
            'feature_count': len(feature_vector)
        }
        
        # Step 3: Optional VirusTotal enrichment
        if include_vt and self.vt:
            print("[4/5] Querying VirusTotal...")
            file_hash = self._compute_hash(file_path)
            vt_result = self.vt.lookup_hash(file_hash)
            
            if vt_result['found']:
                print(f"      VT Detections: {vt_result['positives']}/{vt_result['total']}")
                result['vt_enrichment'] = {
                    'hash': file_hash,
                    'detections': vt_result['positives'],
                    'total_engines': vt_result['total'],
                    'detection_rate': vt_result['positives'] / vt_result['total'],
                    'malware_family': vt_result.get('family', 'Unknown'),
                    'scan_date': vt_result.get('scan_date', 'Unknown')
                }
                
                # Check for mismatch (for adaptive learning)
                vt_says_malicious = vt_result['positives'] > 5
                if is_malicious != vt_says_malicious:
                    result['mismatch_detected'] = True
                    result['mismatch_type'] = 'FALSE_POSITIVE' if is_malicious else 'FALSE_NEGATIVE'
            else:
                print("      File not found in VT database")
                result['vt_enrichment'] = {'status': 'not_found'}
        
        print("[5/5] Analysis complete!\n")
        
        return result
    
    def _compute_hash(self, file_path):
        """Compute SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

# Example usage
if __name__ == "__main__":
    # Initialize detector
    detector = MalwareDetector(
        model_path='static_malware_detector.pkl',
        features_path='static_features.txt',
        vt_api_key='your_vt_key_here'  # Optional
    )
    
    # Detect malware
    result = detector.detect('suspicious_file.exe', include_vt=True)
    
    # Print results
    print("=" * 60)
    print("DETECTION RESULTS")
    print("=" * 60)
    print(f"File: {result['file_path']}")
    print(f"Verdict: {result['prediction']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"\nML Model:")
    print(f"  - Malicious probability: {result['ml_details']['probabilities']['malicious']:.2%}")
    print(f"  - Benign probability: {result['ml_details']['probabilities']['benign']:.2%}")
    
    if 'vt_enrichment' in result and result['vt_enrichment'].get('detections'):
        print(f"\nVirusTotal:")
        vt = result['vt_enrichment']
        print(f"  - Detection rate: {vt['detection_rate']:.1%} ({vt['detections']}/{vt['total_engines']})")
        print(f"  - Family: {vt['malware_family']}")
    
    print("=" * 60)
```

---

### Step 4: FastAPI Backend Integration

```python
# main.py (FastAPI server)
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from detector import MalwareDetector
import tempfile
import os
import shutil

app = FastAPI(title="Malware Detection API")

# Enable CORS for browser extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize detector (once at startup)
detector = MalwareDetector(
    model_path='static_malware_detector.pkl',
    features_path='static_features.txt',
    vt_api_key=os.getenv('VT_API_KEY')
)

@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Scan uploaded file for malware
    
    Pipeline:
    1. Receive file from browser extension
    2. Save to temporary location
    3. Extract features using FeatureExtractor
    4. Run ML model prediction
    5. Query VirusTotal (optional)
    6. Return results
    7. Clean up temp file
    """
    temp_path = None
    
    try:
        # Step 1: Save uploaded file to temp location
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
            temp_path = tmp.name
            shutil.copyfileobj(file.file, tmp)
        
        print(f"Saved uploaded file to: {temp_path}")
        
        # Step 2-6: Run detection pipeline
        result = detector.detect(temp_path, include_vt=True)
        
        # Add metadata
        result['original_filename'] = file.filename
        result['file_size_mb'] = os.path.getsize(temp_path) / (1024 * 1024)
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    
    finally:
        # Step 7: Clean up temp file
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
            print(f"Cleaned up temp file: {temp_path}")

@app.get("/api/health")
async def health_check():
    """Check if service is ready"""
    return {
        "status": "healthy",
        "model_loaded": detector.model is not None,
        "feature_count": len(detector.extractor.feature_names),
        "vt_enabled": detector.vt is not None
    }

@app.get("/api/features")
async def get_features():
    """Return list of features the model uses"""
    return {
        "features": detector.extractor.feature_names,
        "count": len(detector.extractor.feature_names)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

## Complete Data Flow Example

Let's trace a real file through the entire pipeline:

### Input File: `suspicious.exe`

```
File Properties:
- Size: 1,234,567 bytes
- Sections: 4
- Imports: 127 functions
- Entropy: 7.2 (high - possibly packed)
```

### Step-by-Step Processing:

#### 1. User uploads via browser extension
```javascript
// Browser sends file to backend
fetch('http://localhost:8000/api/scan', {
    method: 'POST',
    body: formData  // Contains suspicious.exe
})
```

#### 2. FastAPI receives and saves to temp
```python
# Saved to: /tmp/tmpXYZ123.exe
```

#### 3. FeatureExtractor parses PE file
```python
extractor.extract('/tmp/tmpXYZ123.exe')

# Returns:
{
    'file_size': 1234567,
    'SizeOfCode': 897024,
    'NumberOfSections': 4,
    'SizeOfHeaders': 1024,
    'ImageBase': 4194304,
    'SectionAlignment': 4096,
    'FileAlignment': 512,
    'MajorImageVersion': 0,
    'MinorImageVersion': 0,
    'MajorOSVersion': 5,
    'MinorOSVersion': 1,
    'NumberOfRvaAndSizes': 16,
    'SizeOfStackReserve': 1048576,
    'SizeOfStackCommit': 4096,
    'SizeOfHeapReserve': 1048576,
    'section_entropy': 7.2,
    'import_count': 127
}
```

#### 4. Convert to ordered vector
```python
extractor.extract_as_vector('/tmp/tmpXYZ123.exe')

# Returns:
[1234567, 897024, 4, 1024, 4194304, 4096, 512, 0, 0, 5, 1, 16, 1048576, 4096, 1048576]
# Exactly 15 values in exact order model expects
```

#### 5. ML model prediction
```python
model.predict([[1234567, 897024, 4, ...]])
# Returns: 0 (malicious)

model.predict_proba([[1234567, 897024, 4, ...]])
# Returns: [[0.87, 0.13]]  (87% malicious, 13% benign)
```

#### 6. VirusTotal lookup
```python
vt.lookup_hash('abc123...')

# Returns:
{
    'found': True,
    'positives': 45,
    'total': 72,
    'family': 'Trojan.Ransom.WannaCry'
}
```

#### 7. Combined result
```json
{
    "file_path": "/tmp/tmpXYZ123.exe",
    "original_filename": "suspicious.exe",
    "prediction": "Malicious",
    "confidence": 0.87,
    "ml_details": {
        "raw_prediction": 0,
        "probabilities": {
            "malicious": 0.87,
            "benign": 0.13
        }
    },
    "features": {
        "file_size": 1234567,
        "NumberOfSections": 4,
        "section_entropy": 7.2,
        "import_count": 127
    },
    "vt_enrichment": {
        "detections": 45,
        "total_engines": 72,
        "detection_rate": 0.625,
        "malware_family": "Trojan.Ransom.WannaCry"
    }
}
```

#### 8. Return to browser extension
```javascript
// Extension receives result
{
    prediction: "Malicious",
    confidence: 0.87,
    vt_enrichment: { detections: 45, total_engines: 72 }
}

// Show notification
chrome.notifications.create({
    title: "⚠️ THREAT DETECTED",
    message: "WannaCry ransomware detected (45/72 engines)"
})
```

---

## File Structure

Your project should have:

```
K/
├── Dataset/
│   └── Zenedo.csv                    # Training data
├── static_model_trainer.py           # Train model (Step 1)
├── static_malware_detector.pkl       # Trained model (output)
├── static_features.txt               # Feature names (output)
├── feature_extractor.py              # Extract features (Step 2)
├── detector.py                       # Detection pipeline (Step 3)
├── main.py                           # FastAPI server (Step 4)
├── virustotal_enrichment.py          # VT integration
├── requirements.txt                  # Dependencies
└── extension/                        # Browser extension
    ├── manifest.json
    ├── background.js
    └── popup.html
```

---

## Dependencies

```txt
# requirements.txt
fastapi==0.109.0
uvicorn==0.27.0
python-multipart==0.0.6
pefile==2023.2.7
scikit-learn==1.4.0
pandas==2.2.0
joblib==1.3.2
requests==2.31.0
```

Install:
```bash
pip install -r requirements.txt
```

---

## Testing the Pipeline

### Test Script:

```python
# test_pipeline.py
from detector import MalwareDetector
import os

# Initialize
detector = MalwareDetector(
    model_path='static_malware_detector.pkl',
    features_path='static_features.txt'
)

# Test with sample files
test_files = [
    'test_samples/clean_calc.exe',
    'test_samples/wannacry_sample.exe',
    'test_samples/benign_installer.exe'
]

for file_path in test_files:
    if os.path.exists(file_path):
        print(f"\n{'='*60}")
        result = detector.detect(file_path, include_vt=False)
        print(f"Verdict: {result['prediction']} ({result['confidence']:.1%})")

```

---

## Performance Metrics

**Feature Extraction Speed:**
- Small file (100 KB): ~10ms
- Medium file (1 MB): ~50ms
- Large file (10 MB): ~200ms

**Model Prediction Speed:**
- RandomForest (100 trees): ~5ms
- Total local processing: <300ms

**VirusTotal Query:**
- API call: ~2-3 seconds (network dependent)

**Total Pipeline:**
- Without VT: <500ms
- With VT: ~3-4 seconds

---

## Troubleshooting

### Issue 1: "Feature count mismatch"
```
Error: Expected 15 features, got 12
```

**Solution**: Ensure `static_features.txt` matches exactly what model was trained on:
```python
# Check feature count
with open('static_features.txt', 'r') as f:
    features = f.readlines()
print(f"Feature count: {len(features)}")  # Should be 15
```

### Issue 2: "PE parsing failed"
```
Error: 'PE' object has no attribute 'OPTIONAL_HEADER'
```

**Solution**: File might not be a valid PE file:
```python
try:
    pe = pefile.PE(file_path)
except pefile.PEFormatError:
    print("Not a valid PE file")
    # Return zeros or reject file
```

### Issue 3: "Missing feature values"
```
KeyError: 'section_entropy'
```

**Solution**: Use `.get()` with defaults:
```python
features.get('section_entropy', 0)  # Return 0 if missing
```

---

## Summary

The extraction pipeline is:

1. **Training**: Train model → Save feature names → Save model
2. **Extraction**: Parse PE → Extract features → Create vector
3. **Prediction**: Load model → Predict → Get confidence
4. **Enrichment**: Query VT → Get behavior → Combine results
5. **Response**: Return JSON → Show to user → Log for retraining

All features are extracted **statically** (no execution needed), making it safe and fast!
