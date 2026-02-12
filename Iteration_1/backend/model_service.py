"""
CNN Model Serving API
Runs in Python 3.10 conda environment with TensorFlow support
Serves the trained Zenodo CNN model via REST API
"""

from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import logging
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from typing import Optional, Dict, Any
import time
import sys
import tempfile
import subprocess
import json
from testing_code.dynamic_path_config.path_config import get_test_folder

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add model_code to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'model_code'))

try:
    from pe_feature_extractor import PEFeatureExtractor
    from vt_integration import VirusTotalEnricher
    PE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"PE/VT modules not available: {e}")
    PE_AVAILABLE = False

# Import behavioral data converter
try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "testing_code" / "activity_monitor"))
    from host_analyze_vm_data import convert_vm_data_to_vt_format
    BEHAVIORAL_CONVERTER_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Behavioral data converter not available: {e}")
    BEHAVIORAL_CONVERTER_AVAILABLE = False
    
    # Fallback implementation
    def convert_vm_data_to_vt_format(vm_data: dict) -> dict:
        """Fallback converter if import fails"""
        files = vm_data.get('files', {})
        registry = vm_data.get('registry', {})
        network = vm_data.get('network', {})
        processes = vm_data.get('processes', {})
        
        return {
            'behavior': {
                'files': {
                    'malicious': files.get('malicious', 0),
                    'suspicious': files.get('suspicious', 0)
                },
                'registry': {
                    'write': registry.get('write', 0),
                    'delete': registry.get('delete', 0)
                },
                'network': {'connections': network.get('connections', 0)},
                'processes': {'total': processes.get('total', 0)},
                'dlls': len(vm_data.get('dlls', [])),
                'apis': vm_data.get('apis', 0)
            },
            'tags': [],
            'source': 'vm_behavioral_monitor'
        }

# Behavioral monitoring script location
VM_MONITOR_SCRIPT = Path(__file__).parent.parent.parent / "testing_code" / "activity_monitor" / "vm_behavioral_monitor.py"
VM_MONITOR_AVAILABLE = VM_MONITOR_SCRIPT.exists()
TEST_FOLDER = get_test_folder()

if VM_MONITOR_AVAILABLE:
    logger.info(f"✓ Behavioral monitor available: {VM_MONITOR_SCRIPT}")
else:
    logger.warning(f"✗ Behavioral monitor not found: {VM_MONITOR_SCRIPT}")


def run_behavioral_scan_local(file_path: str, timeout: int = 15) -> Optional[dict]:
    """
    Run vm_behavioral_monitor.py as subprocess (LOCAL TESTING ONLY)
    
    For demo/testing - NOT for production!
    Production would call Cuckoo Sandbox API instead.
    
    Args:
        file_path: Path to executable to analyze
        timeout: Max execution time in seconds (default 15s)
        
    Returns:
        Dict containing behavioral data or None if failed
    """
    if not VM_MONITOR_AVAILABLE:
        logger.error("Behavioral monitor script not available")
        return None
    
    # Ensure test folder exists
    TEST_FOLDER.mkdir(parents=True, exist_ok=True)
    
    try:
        logger.info(f"🔍 Running LOCAL behavioral scan on {Path(file_path).name}")
        logger.info(f"   Monitor: {VM_MONITOR_SCRIPT.name}")
        logger.info(f"   Watch dir: {TEST_FOLDER}")
        logger.info(f"   Timeout: {timeout}s")
        
        # Run the monitor script as subprocess WITHOUT capturing output
        # (capturing can cause deadlock if script prints too much)
        import os
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'  # Immediate output flushing
        
        # Redirect output to DEVNULL to suppress prints (we only care about the JSON file)
        result = subprocess.run(
            [
                sys.executable,  # Use same Python as model service
                str(VM_MONITOR_SCRIPT),
                str(file_path),
                str(TEST_FOLDER)
            ],
            stdout=subprocess.DEVNULL,  # Don't capture stdout (prevents deadlock)
            stderr=subprocess.PIPE,     # Only capture errors
            text=True,
            timeout=timeout,
            cwd=str(VM_MONITOR_SCRIPT.parent),  # Run from Testing_Code directory
            env=env
        )
        
        # Log output for debugging
        logger.info(f"✓ Monitor process completed (exit code: {result.returncode})")
        if result.returncode != 0:
            logger.warning(f"Monitor exited with non-zero code: {result.returncode}")
        if result.stderr:
            logger.warning(f"Monitor stderr:\n{result.stderr}")
        
        # Load the generated behavioral_data.json
        behavioral_json = VM_MONITOR_SCRIPT.parent / "behavioral_data.json"
        
        if behavioral_json.exists():
            with open(behavioral_json, 'r') as f:
                behavioral_data = json.load(f)
            
            logger.info(f"✅ Behavioral scan complete:")
            logger.info(f"   Files created: {len(behavioral_data.get('files', {}).get('created', []))}")
            logger.info(f"   Files deleted: {len(behavioral_data.get('files', {}).get('deleted', []))}")
            logger.info(f"   Files suspicious: {behavioral_data.get('files', {}).get('suspicious', 0)}")
            logger.info(f"   Registry writes: {behavioral_data.get('registry', {}).get('write', 0)}")
            logger.info(f"   DLLs loaded: {len(behavioral_data.get('dlls', []))}")
            logger.info(f"   Execution time: {behavioral_data.get('execution_time', 0):.1f}s")
            
            return behavioral_data
        else:
            logger.warning("No behavioral data file generated")
            return None
            
    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️  Behavioral scan timed out after {timeout}s (process killed)")
        logger.info("Attempting to load partial behavioral data...")
        # Try to load partial results
        behavioral_json = VM_MONITOR_SCRIPT.parent / "behavioral_data.json"
        if behavioral_json.exists():
            logger.info("✓ Partial behavioral data found")
            with open(behavioral_json, 'r') as f:
                return json.load(f)
        else:
            logger.warning("✗ No behavioral data file found after timeout")
        return None
        
    except Exception as e:
        logger.error(f"Behavioral scan failed: {e}", exc_info=True)
        return None


app = FastAPI(
    title="SecureGuard Gradient Boosting Model Service",
    description="Gradient Boosting model serving for malware detection with clean features (no data leakage)",
    version="2.0.0"
)

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model instance
model = None
scaler = None
model_metadata = {}
pe_extractor = None
vt_enricher = None
model_feature_names = []  # Features the model expects

# Feature extraction config
N_FEATURES = 71  # PE extractor produces 71 features (53 static + 18 behavioral)

# Staged analysis thresholds
# ADJUSTED: Model trained on Zenodo may be overconfident on real PE features
# Triggering VT more aggressively to validate predictions
CONFIDENCE_LOW = 0.15   # Below this = CLEAN (very conservative)
CONFIDENCE_HIGH = 0.85  # Above this = MALICIOUS (only if very confident)
# Between LOW and HIGH = call VT for enrichment (wider range = more VT calls)

# Known signatures
SIGNATURES = {
    'eicar': b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
    'eicar_alt': b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'
}


class PredictRequest(BaseModel):
    """Request model for prediction"""
    file_bytes_base64: Optional[str] = None
    features: Optional[list] = None


class PredictResponse(BaseModel):
    """Response model for prediction"""
    is_malicious: bool
    confidence: float
    prediction_label: str
    raw_score: float
    detection_method: str
    scan_time_ms: float
    signature_type: Optional[str] = None
    vt_enriched: bool = False
    vt_detection_ratio: Optional[str] = None
    pe_features_extracted: bool = False
    suspicious_indicators: Optional[str] = None  # Why file was flagged as suspicious
    vt_detections: Optional[Dict[str, str]] = None  # Which AVs detected it and their verdicts
    behavioral_enriched: bool = False  # Whether VM behavioral data was used
    behavioral_source: Optional[str] = None  # 'vm_local' or 'sandbox_service'


@app.on_event("startup")
async def startup_event():
    """Load model and scaler on startup"""
    global model, scaler, model_metadata, pe_extractor, vt_enricher, model_feature_names
    
    logger.info("🚀 Starting Gradient Boosting Model Service...")
    
    try:
        # Find the latest model file
        models_dir = Path("C:/Users/User/OneDrive/Test/K/models")
        
        # Look for Gradient Boosting .pkl files
        model_files = list(models_dir.glob("gradient_boosting_zenodo_*.pkl"))
        
        if not model_files:
            logger.warning("No trained model found - service will run in signature-only mode")
            return
        
        # Use the latest model
        latest_model = max(model_files, key=lambda p: p.stat().st_mtime)
        timestamp = latest_model.stem.split('_')[-2] + '_' + latest_model.stem.split('_')[-1]

        logger.info(f"Loading Gradient Boosting model from {latest_model.name}")
        model = joblib.load(str(latest_model))
        logger.info(f"✓ Model loaded successfully")
        logger.info(f"  Model type: {type(model).__name__}")
        logger.info(f"  N estimators: {model.n_estimators}")
        
        # Load corresponding scaler
        scaler_path = models_dir / f"scaler_gb_{timestamp}.pkl"
        if scaler_path.exists():
            scaler = joblib.load(scaler_path)
            logger.info(f"✓ Scaler loaded from {scaler_path.name}")
            logger.info(f"  Features in scaler: {scaler.n_features_in_}")
        else:
            logger.warning("⚠️  Scaler not found - predictions may be inaccurate")
        
        # Load feature names
        features_path = models_dir / f"features_gb_{timestamp}.json"
        if features_path.exists():
            with open(features_path) as f:
                model_feature_names = json.load(f)
            logger.info(f"✓ Feature names loaded: {len(model_feature_names)} features")
        else:
            logger.warning("⚠️  Feature names not found")
        
        # Load metadata
        metadata_path = models_dir / f"gradient_boosting_metadata_{timestamp}.json"
        if metadata_path.exists():
            with open(metadata_path) as f:
                model_metadata = json.load(f)
            logger.info(f"✓ Model metadata loaded")
            logger.info(f"  Accuracy: {model_metadata.get('performance', {}).get('accuracy', 'N/A')}")
            logger.info(f"  AUC: {model_metadata.get('performance', {}).get('roc_auc', 'N/A')}")
            logger.info(f"  Model trained with {len(model_metadata.get('feature_names', []))} clean features")
        else:
            logger.warning("⚠️  Metadata not found")
        
        # Initialize PE feature extractor
        if PE_AVAILABLE:
            pe_extractor = PEFeatureExtractor()
            logger.info(f"✓ PE feature extractor initialized ({pe_extractor.n_features} features)")
            
            # Try to initialize VT enricher (optional)
            try:
                vt_enricher = VirusTotalEnricher()
                logger.info(f"✓ VirusTotal enricher initialized")
            except Exception as e:
                logger.warning(f"VT enricher not available: {e}")
                logger.info("  Service will run without VT enrichment")
        else:
            logger.warning("PE feature extraction not available - using legacy byte mode")
        
        logger.info("✅ Gradient Boosting Model Service ready!")
        
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        logger.warning("Service will run in signature-only mode")


def extract_pe_features_from_bytes(file_bytes: bytes, filename: str = "uploaded_file") -> Optional[np.ndarray]:
    """Extract PE features from raw bytes by saving to temp file"""
    if pe_extractor is None:
        logger.error("PE extractor not available")
        return None
    
    # Save bytes to temporary file for PE parsing
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name
    
    try:
        # Extract features
        features = pe_extractor.extract(tmp_path)
        return features
    finally:
        # Clean up temp file
        try:
            Path(tmp_path).unlink()
        except:
            pass


def check_signatures(file_bytes: bytes) -> Optional[str]:
    """Check for known malware signatures"""
    for name, signature in SIGNATURES.items():
        if signature in file_bytes:
            return name
    return None


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0-8, where >7 suggests packing/encryption)"""
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = byte_counts[byte_counts > 0] / len(data)
    
    # Calculate entropy
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return float(entropy)


def is_suspicious_file(file_bytes: bytes, filename: str) -> tuple[bool, str]:
    """
    Check for suspicious indicators that warrant VT enrichment
    Returns: (is_suspicious, reason)
    """
    file_size = len(file_bytes)
    entropy = calculate_entropy(file_bytes)
    
    # Small files are often packed malware
    if file_size < 10000:  # < 10KB
        return True, f"small_file ({file_size} bytes)"
    
    # High entropy suggests encryption/packing
    if entropy > 7.2:
        return True, f"high_entropy ({entropy:.2f})"
    
    # Very large files can be suspicious too
    if file_size > 50_000_000:  # > 50MB
        return True, f"large_file ({file_size:,} bytes)"
    
    return False, "none"


def normalize_pe_features(features: np.ndarray) -> np.ndarray:
    """
    Simple normalization for PE features when scaler is not available
    Uses min-max normalization to scale to [0, 1] range
    """
    # Clip extreme outliers (99.9th percentile)
    features_clipped = np.clip(features, -1e10, 1e10)
    
    # Min-max normalization to [0, 1]
    min_val = features_clipped.min()
    max_val = features_clipped.max()
    
    if max_val - min_val > 0:
        normalized = (features_clipped - min_val) / (max_val - min_val)
    else:
        normalized = features_clipped
    
    return normalized


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "SecureGuard Gradient Boosting Model Service",
        "version": "2.0.0",
        "status": "running",
        "model_loaded": model is not None,
        "model_type": "GradientBoosting",
        "n_features": len(model_feature_names) if model_feature_names else 0
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "scaler_loaded": scaler is not None,
        "model_type": "GradientBoosting",
        "n_estimators": model.n_estimators if model else 0,
        "n_features": len(model_feature_names),
        "metadata": model_metadata
    }


@app.post("/predict/bytes", response_model=PredictResponse)
async def predict_from_bytes(file: UploadFile = File(...)):
    """
    Predict from uploaded file bytes using PE feature extraction
    FIXED: Now extracts PE features instead of raw bytes
    
    Args:
        file: Uploaded file
        
    Returns:
        Prediction results
    """
    start_time = time.time()
    
    try:
        # Read file bytes
        file_bytes = await file.read()
        
        # Check signatures first (fast)
        """signature_match = check_signatures(file_bytes)
        if signature_match:
            scan_time = (time.time() - start_time) * 1000
            return PredictResponse(
                is_malicious=True,
                confidence=1.0,
                prediction_label="MALICIOUS",
                raw_score=1.0,
                detection_method="signature",
                signature_type=signature_match.upper(),
                scan_time_ms=round(scan_time, 2)
            )
        
        # If no model, return benign (conservative)
        if model is None or scaler is None:
            scan_time = (time.time() - start_time) * 1000
            return PredictResponse(
                is_malicious=False,
                confidence=0.5,
                prediction_label="CLEAN",
                raw_score=0.0,
                detection_method="none",
                scan_time_ms=round(scan_time, 2)
            )
        """
        # Extract PE features
        features = extract_pe_features_from_bytes(file_bytes, file.filename or "uploaded_file")
        
        if features is None:
            logger.warning(f"Failed to extract PE features from {file.filename or 'uploaded_file'}")
            scan_time = (time.time() - start_time) * 1000
            return PredictResponse(
                is_malicious=False,
                confidence=0.5,
                prediction_label="UNKNOWN",
                raw_score=0.0,
                detection_method="extraction_failed",
                scan_time_ms=round(scan_time, 2),
                pe_features_extracted=False
            )
        
        # Validate feature count
        if len(features) != N_FEATURES:
            raise ValueError(f"Expected {N_FEATURES} features, got {len(features)}")
        
        # Scale features
        if scaler is not None:
            try:
                # Convert to DataFrame with feature names to avoid sklearn warning
                features_df = pd.DataFrame(features.reshape(1, -1), columns=pe_extractor.FEATURE_NAMES)
                features_scaled = scaler.transform(features_df)
                logger.debug("Using fitted scaler for normalization")
            except (ValueError, AttributeError) as e:
                logger.warning(f"Scaler dimension mismatch: {e} - using basic normalization")
                features_scaled = normalize_pe_features(features).reshape(1, -1)
        else:
            # No scaler - use basic normalization
            logger.debug("No scaler available - using basic normalization")
            features_scaled = normalize_pe_features(features).reshape(1, -1)
        
        # Get prediction from Gradient Boosting model
        prediction_proba = model.predict_proba(features_scaled)
        prediction_prob = float(prediction_proba[0][1])  # Probability of malicious class
        
        # Determine result
        is_malicious = prediction_prob >= 0.5
        confidence = prediction_prob if is_malicious else (1 - prediction_prob)
        
        scan_time = (time.time() - start_time) * 1000
        
        return PredictResponse(
            is_malicious=bool(is_malicious),
            confidence=float(confidence),
            prediction_label="MALICIOUS" if is_malicious else "CLEAN",
            raw_score=float(prediction_prob),
            detection_method="pe_static",
            scan_time_ms=round(scan_time, 2),
            pe_features_extracted=True
        )
        
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/features", response_model=PredictResponse)
async def predict_from_features(request: PredictRequest):
    """
    Predict from pre-extracted features (for tabular data)
    
    Args:
        request: Features array
        
    Returns:
        Prediction results
    """
    start_time = time.time()
    
    try:
        if not request.features:
            raise HTTPException(status_code=400, detail="No features provided")
        
        if model is None:
            raise HTTPException(status_code=503, detail="Model not loaded")
        
        # Convert to numpy array
        features = np.array(request.features, dtype=np.float32)
        
        # Apply scaler if available
        if scaler is not None:
            # Convert to DataFrame with feature names to avoid sklearn warning
            if pe_extractor is not None:
                features_df = pd.DataFrame(features.reshape(1, -1), columns=pe_extractor.FEATURE_NAMES)
                features_scaled = scaler.transform(features_df)
            else:
                features_scaled = scaler.transform(features.reshape(1, -1))
        else:
            features_scaled = features.reshape(1, -1)
        
        # Get prediction from Gradient Boosting model
        prediction_proba = model.predict_proba(features_scaled)
        prediction_prob = float(prediction_proba[0][1])  # Probability of malicious class
        
        # Determine result
        is_malicious = prediction_prob >= 0.5
        confidence = prediction_prob if is_malicious else (1 - prediction_prob)
        
        scan_time = (time.time() - start_time) * 1000
        
        return PredictResponse(
            is_malicious=bool(is_malicious),
            confidence=float(confidence),
            prediction_label="MALICIOUS" if is_malicious else "CLEAN",
            raw_score=float(prediction_prob),
            detection_method="gradient_boosting",
            scan_time_ms=round(scan_time, 2)
        )
        
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/staged", response_model=PredictResponse)
async def predict_staged(
    file: UploadFile = File(...),
    behavioral_data: Optional[str] = Form(None),  # JSON string of VM behavioral data  
    run_local_scan: bool = True # DISABLED BY DEFAULT - use run_local_scan=true to enable
):
    """
    Staged analysis: PE static → Behavioral enrichment if uncertain
    
    ARCHITECTURE:
    - Demo/Testing: Uses pre-captured behavioral_data.json from vm_behavioral_monitor.py
    - Production: Would call separate Sandboxing Microservice (Cuckoo/CAPE/Custom)
    
    Stage 1: PE static analysis
    - Extract PE features from uploaded file
    - Run initial ML prediction
    - If confidence > 0.85 → Return MALICIOUS
    - If confidence < 0.15 → Return CLEAN
    
    Stage 2: Behavioral enrichment (only if 0.15 ≤ confidence ≤ 0.85)
    - Option A (Demo): Use provided behavioral_data from VM monitor
    - Option B (Production): Call sandboxing service API
    - Option C (Fallback): Call VirusTotal API for behavioral features
    - Merge behavioral features with PE features
    - Re-predict with enriched features
    - Return final verdict
    
    Args:
        file: Uploaded file (PE executable)
        behavioral_data: Optional JSON string from vm_behavioral_monitor.py
                        Format: {"files": {...}, "registry": {...}, "network": {...}}
        run_local_scan: If True, run vm_behavioral_monitor.py locally (DEMO MODE)
                       Runs malware in subprocess with timeout - test/demo only!
        
    Returns:
        Prediction results with behavioral enrichment if needed
        
    PRODUCTION DEPLOYMENT:
    In production, you would:
    1. Deploy vm_behavioral_monitor.py as a microservice (Sandboxing Service)
    2. Run it in isolated VMs/containers (Docker + KVM/VirtualBox)
    3. This endpoint calls: POST /sandbox/analyze with file upload
    4. Sandbox service returns behavioral_data.json
    5. Model service merges features and predicts
    
    DEMO WORKFLOW:
    1. Run: python vm_behavioral_monitor.py malware.exe (in VM)
    2. Get: behavioral_data.json
    3. Upload file + behavioral JSON to this endpoint
    4. Get: ML prediction with behavioral enrichment
    """
    start_time = time.time()
    
    try:
        # Read file bytes
        file_bytes = await file.read()
        """
        # Check signatures first (fast)
        signature_match = check_signatures(file_bytes)
        if signature_match:
            scan_time = (time.time() - start_time) * 1000
            return PredictResponse(
                is_malicious=True,
                confidence=1.0,
                prediction_label="MALICIOUS",
                raw_score=1.0,
                detection_method="signature",
                signature_type=signature_match.upper(),
                scan_time_ms=round(scan_time, 2)
            )
        
        if model is None or scaler is None or pe_extractor is None:
            scan_time = (time.time() - start_time) * 1000
            return PredictResponse(
                is_malicious=False,
                confidence=0.5,
                prediction_label="CLEAN",
                raw_score=0.0,
                detection_method="none",
                scan_time_ms=round(scan_time, 2)
            )
        """
        # === PRE-STAGE: Check for suspicious indicators ===
        is_suspicious, suspicion_reason = is_suspicious_file(file_bytes, file.filename or "uploaded_file")        
        force_vt = False  # Will be set to True if VT enrichment is needed
        if is_suspicious:
            logger.info(f"File flagged as suspicious: {suspicion_reason} - VT enrichment will be mandatory")
        
        # === STAGE 1: PE Static Analysis ===
        logger.info(f"Stage 1: Extracting PE features from {file.filename or 'uploaded_file'}")
        features = extract_pe_features_from_bytes(file_bytes, file.filename or "uploaded_file")
        
        if features is None:
            logger.warning("PE feature extraction failed")
            scan_time = (time.time() - start_time) * 1000
            return PredictResponse(
                is_malicious=False,
                confidence=0.5,
                prediction_label="UNKNOWN",
                raw_score=0.0,
                detection_method="extraction_failed",
                scan_time_ms=round(scan_time, 2),
                pe_features_extracted=False
            )
        
        # Scale and predict
        if scaler is not None:
            try:
                # Convert to DataFrame with feature names to avoid sklearn warning
                features_df = pd.DataFrame(features.reshape(1, -1), columns=pe_extractor.FEATURE_NAMES)
                features_scaled = scaler.transform(features_df)
            except (ValueError, AttributeError) as e:
                logger.warning(f"Scaler dimension mismatch: {e} - using basic normalization")
                features_scaled = normalize_pe_features(features).reshape(1, -1)
        else:
            features_scaled = normalize_pe_features(features).reshape(1, -1)
            
        # Get prediction from Gradient Boosting model
        prediction_proba = model.predict_proba(features_scaled)
        prediction_prob = float(prediction_proba[0][1])  # Probability of malicious class
        
        # Calculate confidence
        is_malicious_stage1 = prediction_prob >= 0.5
        confidence_stage1 = prediction_prob if is_malicious_stage1 else (1 - prediction_prob)
        
        logger.info(f"Stage 1 result: raw_score={prediction_prob:.3f}, confidence={confidence_stage1:.3f} ({'MALICIOUS' if is_malicious_stage1 else 'CLEAN'})")
        
        # MANDATORY VT enrichment for suspicious files (packed/small/encrypted)
        if is_suspicious:
            logger.info(f"Suspicious file detected ({suspicion_reason}) - forcing VT enrichment")
            force_vt = True
        # Check if confident enough (only skip VT if very confident AND not suspicious)
        elif prediction_prob >= CONFIDENCE_HIGH:
            # High confidence - MALICIOUS
            scan_time = (time.time() - start_time) * 1000
            return PredictResponse(
                is_malicious=True,
                confidence=float(prediction_prob),
                prediction_label="MALICIOUS",
                raw_score=float(prediction_prob),
                detection_method="pe_static",
                scan_time_ms=round(scan_time, 2),
                pe_features_extracted=True
            )
        elif prediction_prob <= CONFIDENCE_LOW:
            # High confidence - CLEAN (but still check if suspicious)
            if not is_suspicious:
                scan_time = (time.time() - start_time) * 1000
                return PredictResponse(
                    is_malicious=False,
                    confidence=float(1 - prediction_prob),
                    prediction_label="CLEAN",
                    raw_score=float(prediction_prob),
                    detection_method="pe_static",
                    scan_time_ms=round(scan_time, 2),
                    pe_features_extracted=True
                )
            else:
                logger.info(f"Model confident but file is suspicious - forcing VT check")
                force_vt = True
        else:
            # Uncertain range
            force_vt = True
        
        # === STAGE 2: Behavioral Enrichment ===
        # Priority: VM Behavioral Data > VT API > None
        
        vt_data = None
        vm_data = None
        behavioral_source = None
        
        # Option A: Use provided VM behavioral data (Pre-captured)
        if behavioral_data:
            try:
                logger.info("Stage 2: Using pre-captured VM behavioral data")
                vm_data = json.loads(behavioral_data)
                vt_data = convert_vm_data_to_vt_format(vm_data)
                behavioral_source = "vm_precaptured"
                logger.info(f"  ✓ VM data loaded: {len(vm_data.get('files', {}).get('created', []))} files created")
                logger.info(f"  ✓ Files encrypted: {len(vm_data.get('files', {}).get('encrypted', []))}")
                logger.info(f"  ✓ Registry writes: {vm_data.get('registry', {}).get('write', 0)}")
            except Exception as e:
                logger.error(f"Failed to parse behavioral_data: {e}")
                behavioral_source = None
        
        # Option B: Run behavioral scan locally (NEW - DEMO MODE)
        elif run_local_scan and VM_MONITOR_AVAILABLE:
            logger.info("Stage 2: Running local behavioral scan (DEMO MODE)")
            logger.warning("⚠️  LOCAL SCAN MODE - For testing/demo only!")
            logger.warning("⚠️  Production would call Cuckoo Sandbox API")
            
            # Save uploaded file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            
            try:
                # Run the monitor as subprocess
                vm_data = run_behavioral_scan_local(tmp_path, timeout=15)
                
                if vm_data:
                    vt_data = convert_vm_data_to_vt_format(vm_data)
                    behavioral_source = "vm_local_subprocess"
                    logger.info("✓ Local behavioral scan complete")
                else:
                    logger.warning("Local behavioral scan failed")
            finally:
                # Clean up temp file
                try:
                    Path(tmp_path).unlink()
                except:
                    pass

        # Option C: Fallback to VirusTotal API enrichment

        tmp_path = None  # Track temp file for cleanup
        if not vt_data and force_vt:
            logger.info(f"Stage 2: VT enrichment triggered (suspicious={is_suspicious}, confidence={prediction_prob:.3f})")
        
            if vt_enricher is None:
                logger.warning("="*60)
                logger.warning("VT ENRICHER NOT AVAILABLE!")
                logger.warning("Check VT API key configuration")
                logger.warning("Returning Stage 1 result without behavioral enrichment")
                logger.warning("="*60)
                is_malicious = prediction_prob >= 0.5
                confidence = prediction_prob if is_malicious else (1 - prediction_prob)
                scan_time = (time.time() - start_time) * 1000
                return PredictResponse(
                    is_malicious=bool(is_malicious),
                    confidence=float(confidence),
                    prediction_label="MALICIOUS" if is_malicious else "CLEAN",
                    raw_score=float(prediction_prob),
                    detection_method="pe_static",
                    scan_time_ms=round(scan_time, 2),
                    pe_features_extracted=True
                )
            
            # Save to temp file for VT check
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            
            try:
                logger.info("Calling VirusTotal API for enrichment...")
                vt_data = vt_enricher.check_file(tmp_path)
                behavioral_source = "virustotal_api"
                
            finally:
                # Clean up temp file
                if tmp_path:
                    try:
                        Path(tmp_path).unlink()
                    except:
                        pass
        
        # === STAGE 3: Enrich features and re-predict ===
        if vt_data:
                logger.info("="*60)
                logger.info("VT DATA RECEIVED:")
                logger.info(f"  Detection ratio: {vt_data.get('detection', {}).get('malicious', 0)}/{vt_data.get('detection', {}).get('total', 0)}")
                logger.info(f"  VT verdict: {'MALICIOUS' if vt_data.get('detection', {}).get('malicious', 0) > 0 else 'CLEAN'}")
                
               # Extract AV detections (which AVs flagged it and why)
                av_detections = {}
                if 'scans' in vt_data:
                    for av_name, av_result in vt_data['scans'].items():
                        # VirusTotal API v3 structure: each result has 'category' and 'result' fields
                        # category can be: 'malicious', 'suspicious', 'undetected', 'harmless', etc.
                        category = av_result.get('category', '')
                        if category in ['malicious', 'suspicious']:
                            av_detections[av_name] = av_result.get('result', category)

                logger.info(f"  AV Detections ({len(av_detections)}): {list(av_detections.keys())[:10]}...")  # Show first 10
                if av_detections:
                    logger.info(f"  Sample verdicts: {dict(list(av_detections.items())[:5])}")
                logger.info("="*60)
                
                # Enrich features with VT behavioral data
                enriched_features = pe_extractor._enrich_with_vt(features, vt_data)
                
                logger.info(f"Behavioral features added:")
                logger.info(f"  Registry: {enriched_features[53:57]}")
                logger.info(f"  Network: {enriched_features[57:61]}")
                logger.info(f"  Processes: {enriched_features[61:65]}")
                logger.info(f"  Files: {enriched_features[65:69]}")
                logger.info(f"  DLLs/APIs: {enriched_features[69:71]}")
                
                # Re-predict with enriched features (if rules didn't trigger)
                if scaler is not None:
                    try:
                        # Convert to DataFrame with feature names to avoid sklearn warning
                        enriched_df = pd.DataFrame(enriched_features.reshape(1, -1), columns=pe_extractor.FEATURE_NAMES)
                        enriched_scaled = scaler.transform(enriched_df)
                    except (ValueError, AttributeError) as e:
                        logger.warning(f"Scaler dimension mismatch: {e} - using basic normalization")
                        enriched_scaled = normalize_pe_features(enriched_features).reshape(1, -1)
                else:
                    enriched_scaled = normalize_pe_features(enriched_features).reshape(1, -1)
                    
                # Get prediction from Gradient Boosting model
                enriched_proba = model.predict_proba(enriched_scaled)
                enriched_prob = float(enriched_proba[0][1])  # Probability of malicious class
                
                logger.info(f"Stage 2 ML result: raw_score={enriched_prob:.3f} ({'MALICIOUS' if enriched_prob >= 0.5 else 'CLEAN'})")
                
                # Use VT detection ratio as primary signal if available
                vt_malicious = vt_data.get('detection', {}).get('malicious', 0)
                vt_total = vt_data.get('detection', {}).get('total', 0)
                
                # If VT has high detection ratio, override ML prediction
                if vt_total > 0:
                    vt_detection_rate = vt_malicious / vt_total
                    if vt_detection_rate > 0.3:  # >30% of AVs flagged it
                        logger.info(f"VT override: {vt_detection_rate:.1%} detection rate → MALICIOUS")
                        is_malicious = True
                        confidence = vt_detection_rate
                    else:
                        is_malicious = enriched_prob >= 0.5
                        confidence = enriched_prob if is_malicious else (1 - enriched_prob)
                else:
                    is_malicious = enriched_prob >= 0.5
                    confidence = enriched_prob if is_malicious else (1 - enriched_prob)
                
                # Format VT detection ratio
                vt_ratio = f"{vt_data['detection']['malicious']}/{vt_data['detection']['total']}"
                
                # Limit detections to top 10 for response (avoid huge payload)
                top_detections = dict(list(av_detections.items())[:10]) if av_detections else None
                
                scan_time = (time.time() - start_time) * 1000
                return PredictResponse(
                    is_malicious=bool(is_malicious),
                    confidence=float(confidence),
                    prediction_label="MALICIOUS" if is_malicious else "CLEAN",
                    raw_score=float(enriched_prob),
                    detection_method=f"pe_{behavioral_source}_enriched" if behavioral_source else "pe_vt_enriched",
                    scan_time_ms=round(scan_time, 2),
                    pe_features_extracted=True,
                    vt_enriched=(behavioral_source == "virustotal_api"),
                    behavioral_enriched=True,
                    behavioral_source=behavioral_source,
                    vt_detection_ratio=vt_ratio if behavioral_source == "virustotal_api" else None,
                    suspicious_indicators=suspicion_reason if is_suspicious else None,
                    vt_detections=top_detections if behavioral_source == "virustotal_api" else None
                )
        else:
            # No behavioral enrichment available
            logger.warning("="*60)
            logger.warning("NO BEHAVIORAL DATA AVAILABLE")
            logger.warning("Returning Stage 1 prediction without enrichment")
            logger.warning("="*60)
            is_malicious = prediction_prob >= 0.5
            confidence = prediction_prob if is_malicious else (1 - prediction_prob)
            scan_time = (time.time() - start_time) * 1000
            return PredictResponse(
                is_malicious=bool(is_malicious),
                confidence=float(confidence),
                prediction_label="MALICIOUS" if is_malicious else "CLEAN",
                raw_score=float(prediction_prob),
                detection_method="pe_static",
                scan_time_ms=round(scan_time, 2),
                suspicious_indicators=suspicion_reason if is_suspicious else None,
                pe_features_extracted=True
            )
        
    except Exception as e:
        logger.error(f"Staged prediction failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_stats():
    """Get model statistics"""
    if model is None:
        return {
            "model_loaded": False,
            "message": "No model loaded - running in signature-only mode"
        }
    
    return {
        "model_loaded": True,
        "model_info": {
            "type": "1D CNN",
            "input_shape": str(model.input_shape),
            "output_shape": str(model.output_shape),
            "parameters": model.count_params(),
            "layers": len(model.layers),
            "expected_features": N_FEATURES
        },
        "metadata": model_metadata,
        "pe_extractor_available": pe_extractor is not None,
        "vt_enricher_available": vt_enricher is not None,
        "scaler_loaded": scaler is not None
    }


if __name__ == "__main__":
    print("\n" + "="*70)
    print("SecureGuard CNN Model Service")
    print("="*70)
    print("Running on: http://127.0.0.1:8001")
    print("Environment: Python 3.10 + TensorFlow")
    print("="*70 + "\n")
    
    uvicorn.run(
        "model_service:app",
        host="127.0.0.1",
        port=8001,  # Different port from main API
        reload=True,
        log_level="info"
    )
