# Feature Extraction Challenge & Solution

## The Problem

Your Zenodo model was trained on **72 features** across three categories:

### 1. Static Features (11% importance)
- PE header properties (e.g., `SizeOfCode`, `NumberOfSections`)
- File metadata (size, extension)
- Import table analysis
- **Can extract WITHOUT executing the file** ✓

### 2. Dynamic Features (81% importance) ⚠️
- API calls (e.g., `CreateProcess`, `RegSetValue`)
- Registry modifications
- File system operations
- Process creation patterns
- **REQUIRES executing the file to monitor behavior** ✗

### 3. Network Features (8% importance) ⚠️
- IP connections
- DNS requests
- HTTP/HTTPS patterns
- C2 communication indicators
- **REQUIRES executing the file + network monitoring** ✗

## The Challenge

**You cannot safely execute unknown files to extract dynamic/network features!**

Running potentially malicious files on user machines is:
- Dangerous (could infect the system)
- Slow (need to wait for behavioral patterns)
- Resource-intensive (requires sandboxing/isolation)

## Practical Solutions

### Solution 1: **Static-Only Model** (RECOMMENDED for FYP)

Train a separate model using ONLY static features that can be extracted safely:

```python
# static_model_trainer.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Load Zenodo dataset
df = pd.read_csv('Dataset/Zenedo.csv')

# Define STATIC-ONLY features
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
    # Add other PE header features available in Zenodo
]

X = df[STATIC_FEATURES]
y = df['label']

# Handle categorical features
from sklearn.preprocessing import LabelEncoder
categorical_cols = X.select_dtypes(include=['object']).columns
for col in categorical_cols:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col].astype(str))

X = X.fillna(0)

# Split and train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Evaluate
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)

print(f"Static-Only Model Performance:")
print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")

# Calculate FPR
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
fpr = fp / (fp + tn)
print(f"False Positive Rate: {fpr:.4f}")

# Save model
joblib.dump(model, 'static_malware_detector.pkl')
with open('static_features.txt', 'w') as f:
    f.write('\n'.join(STATIC_FEATURES))

print("\nModel saved: static_malware_detector.pkl")
print("Features saved: static_features.txt")
```

**Advantages:**
- ✓ Safe (no execution needed)
- ✓ Fast (<100ms)
- ✓ Works offline
- ✓ Feasible for FYP scope

**Trade-off:**
- Lower accuracy (expect ~95-97% instead of 99.33%)
- Misses behavioral patterns
- BUT: Still better than nothing + can use VT as backup

---

### Solution 2: **Hybrid Approach with VirusTotal**

Use static features for instant detection, then query VirusTotal for behavioral analysis:

```python
# hybrid_detector.py
import pefile
import joblib
import hashlib
from virustotal_enrichment import VirusTotalAPI

class HybridDetector:
    def __init__(self, model_path='static_malware_detector.pkl', vt_api_key=None):
        self.model = joblib.load(model_path)
        with open('static_features.txt', 'r') as f:
            self.feature_names = [line.strip() for line in f]
        self.vt = VirusTotalAPI(api_key=vt_api_key) if vt_api_key else None
    
    def extract_static_features(self, file_path):
        """Extract static features from PE file"""
        features = {}
        
        try:
            pe = pefile.PE(file_path)
            
            # Basic PE header info
            features['file_size'] = pe.OPTIONAL_HEADER.SizeOfImage
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
            
            # Add more features as needed
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            # Return zeros if parsing fails
            features = {name: 0 for name in self.feature_names}
        
        # Ensure all features are present
        feature_vector = [features.get(name, 0) for name in self.feature_names]
        return feature_vector
    
    def detect(self, file_path):
        """
        Two-tier detection:
        1. Static ML model (instant)
        2. VirusTotal lookup (optional, for behavioral context)
        """
        # Tier 1: Static detection
        static_features = self.extract_static_features(file_path)
        ml_prediction = self.model.predict([static_features])[0]
        ml_confidence = self.model.predict_proba([static_features])[0].max()
        
        result = {
            'detection_method': 'static_ml',
            'prediction': 'Malicious' if ml_prediction == 0 else 'Clean',
            'confidence': ml_confidence,
            'static_features': dict(zip(self.feature_names, static_features))
        }
        
        # Tier 2: VirusTotal enrichment (if available)
        if self.vt:
            file_hash = self._compute_hash(file_path)
            vt_result = self.vt.lookup_hash(file_hash)
            
            if vt_result['found']:
                result['vt_enrichment'] = {
                    'detections': vt_result['positives'],
                    'total_engines': vt_result['total'],
                    'malware_family': vt_result.get('family', 'Unknown'),
                    'behavior_summary': vt_result.get('behavior', {})  # VT provides behavioral analysis!
                }
        
        return result
    
    def _compute_hash(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

# Usage
detector = HybridDetector(vt_api_key='your_key_here')
result = detector.detect('suspicious_file.exe')

print(f"ML Prediction: {result['prediction']} ({result['confidence']:.2%})")
if 'vt_enrichment' in result:
    print(f"VT Detections: {result['vt_enrichment']['detections']}/{result['vt_enrichment']['total_engines']}")
    print(f"Family: {result['vt_enrichment']['malware_family']}")
```

**How VirusTotal Helps:**
- VT already executes files in sandboxes to collect dynamic behavior
- You can query VT's behavioral analysis results
- Provides approximation of dynamic features without executing locally

---

### Solution 3: **Future Enhancement - Lightweight Sandbox** (NOT for FYP scope)

For advanced implementation (beyond FYP):

```python
# sandbox_analyzer.py (CONCEPT ONLY)
import docker  # Requires Docker

class SandboxAnalyzer:
    """
    Run file in isolated Docker container to collect dynamic features.
    WARNING: Complex, resource-intensive, security risks!
    """
    def __init__(self):
        self.client = docker.from_env()
    
    def analyze(self, file_path, timeout=30):
        """
        1. Spin up isolated container
        2. Copy file into container
        3. Execute and monitor (API calls, registry, network)
        4. Extract dynamic features
        5. Destroy container
        """
        # This is VERY complex and beyond FYP scope
        # Requires: Process monitoring, API hooking, network capture
        # Security risks: Breakout attacks, resource exhaustion
        pass
```

**Why NOT recommended for FYP:**
- Extremely complex implementation
- Security risks (sandbox escapes)
- Resource-intensive (Docker/VMs)
- Slow (30+ seconds per file)
- Overkill for academic project

---

## Recommended Implementation for Your FYP

### **Three-Tier Detection System**

```
User uploads file.exe
        ↓
┌──────────────────────────────────────────────────┐
│ TIER 1: Static ML Model (INSTANT)               │
│ - Extract PE headers (safe, fast)               │
│ - Run RandomForest prediction                    │
│ - Result: 95-97% accuracy, <100ms               │
└──────────────────────────────────────────────────┘
        ↓
┌──────────────────────────────────────────────────┐
│ TIER 2: VirusTotal Lookup (3-5 seconds)         │
│ - Query VT database                              │
│ - Get behavioral analysis (dynamic features!)   │
│ - Get malware family + threat intel              │
└──────────────────────────────────────────────────┘
        ↓
┌──────────────────────────────────────────────────┐
│ TIER 3: Adaptive Learning                       │
│ - If ML disagrees with VT → log for retraining  │
│ - Weekly model updates                           │
│ - Continuous improvement                         │
└──────────────────────────────────────────────────┘
```

### User Experience:

```
[INSTANT] Static ML: "Suspicious (92% malicious)"
[Wait 3s] VirusTotal: "48/72 engines detected as Trojan.Ransom.WannaCry"
[Decision] Combined verdict: "MALICIOUS - High confidence"
```

---

## Feature List for Static-Only Model

Based on Zenodo dataset, these features can be extracted safely:

### PE Header Features (15 features)
```python
EXTRACTABLE_FEATURES = [
    # File basics
    'file_size',
    'file_extension',  # .exe, .dll, .scr
    
    # Optional header
    'SizeOfCode',
    'SizeOfInitializedData',
    'SizeOfUninitializedData',
    'AddressOfEntryPoint',
    'BaseOfCode',
    'ImageBase',
    'SectionAlignment',
    'FileAlignment',
    'MajorOperatingSystemVersion',
    'MinorOperatingSystemVersion',
    'MajorImageVersion',
    'MinorImageVersion',
    'MajorSubsystemVersion',
    'MinorSubsystemVersion',
    'SizeOfImage',
    'SizeOfHeaders',
    'CheckSum',
    'Subsystem',
    'DllCharacteristics',
    'SizeOfStackReserve',
    'SizeOfStackCommit',
    'SizeOfHeapReserve',
    'SizeOfHeapCommit',
    'NumberOfRvaAndSizes',
    
    # File header
    'Machine',
    'NumberOfSections',
    'TimeDateStamp',
    'Characteristics',
    
    # Section info
    'section_count',
    'section_entropy',  # Detect packed/encrypted files
    
    # Import table
    'import_count',
    'imported_dll_count',
]
```

### Expected Performance:
- **Accuracy**: ~95-97% (vs 99.33% with dynamic features)
- **FPR**: ~1-2% (vs 0.19% with dynamic features)
- **Speed**: <100ms (vs 30+ seconds for sandbox)
- **Feasibility**: ✓✓✓ Perfect for FYP

---

## Implementation Steps

1. **Train static-only model** (use code above)
2. **Create feature extractor** using `pefile` library
3. **Integrate with browser extension** (FastAPI endpoint)
4. **Add VT enrichment** for behavioral context
5. **Document limitations** (dynamic features not extracted locally)

---

## For FYP Defense

**Acknowledge the limitation honestly:**

> "While our model was originally designed with dynamic behavioral features, we recognize the challenge of safely extracting these features from unknown files in a production environment. Therefore, we implemented a **static-only model** for instant local detection, supplemented by VirusTotal's sandbox analysis for behavioral insights. This hybrid approach balances security, speed, and accuracy while keeping the system practical for real-world deployment."

**Strengths:**
- ✓ Safe (no local execution)
- ✓ Fast (instant results)
- ✓ Privacy-preserving (local analysis)
- ✓ Scalable (lightweight)

**Future Work:**
- Integrate lightweight sandbox (Cuckoo, CAPE)
- Cloud-based dynamic analysis service
- Behavioral simulation using static analysis (control flow graphs, API dependencies)

---

## Conclusion

**For your FYP, use the Static-Only + VirusTotal hybrid approach.**

This solves the feature extraction problem while staying within reasonable scope for an academic project. You demonstrate understanding of the challenge and provide a practical, deployable solution.
