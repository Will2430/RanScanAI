"""
CNN Model Serving API
Runs in Python 3.10 conda environment with TensorFlow support
Serves the trained Zenodo CNN model via REST API
"""

from fastapi import FastAPI, HTTPException, File, UploadFile, Form, Depends
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
import os
import tempfile
import subprocess
import json
import hashlib
import pickle
from datetime import datetime


# Add workspace root to path for testing_code imports
WORKSPACE_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from testing_code.dynamic_path_config.path_config import get_test_folder

# Configure logging FIRST
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

# Global model instances
model = None
scaler = None
model_metadata = {}
pe_extractor = None
vt_enricher = None
model_feature_names = []  # Features the model expects

# CNN model for Stage 2 (sequential API analysis)
cnn_model = None
cnn_scaler = None
cnn_metadata = {}
vocab = {}  # API vocabulary loaded from api_vocab_fixed.pkl

# Feature extraction config
N_FEATURES = 67  # PE extractor produces 67 features (53 static + 14 behavioral, cleaned)

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

# Database imports (for Azure PostgreSQL logging)
DB_AVAILABLE = False  # Default to False
try:
    from sqlalchemy.ext.asyncio import AsyncSession
    from db_manager import (
        init_db, 
        get_session, 
        save_terminal_log, 
        save_scan_history
    )
    from terminal_logger import LoggingCapture, format_scan_output
    DB_AVAILABLE = True
    logger.info("✓ Database modules loaded successfully")
except ImportError as e:
    logger.warning(f"Database modules not available: {e}")
    AsyncSession = None  # Dummy type for function signatures

try:
    from pe_feature_extractor import PEFeatureExtractor
    from vt_integration import VirusTotalEnricher
    PE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"PE/VT modules not available: {e}")
    PE_AVAILABLE = False

# Import behavioral data converter
try:
    from testing_code.activity_monitor.host_analyze_vm_data import convert_vm_data_to_vt_format
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
VM_ANALYZER_SCRIPT = Path(__file__).parent.parent / "testing_code" / "activity_monitor" / "vm_complete_analyzer.py"
VM_ANALYZER_AVAILABLE = VM_ANALYZER_SCRIPT.exists()
ANALYSIS_RESULTS_DIR = VM_ANALYZER_SCRIPT.parent / "analysis_results" if VM_ANALYZER_AVAILABLE else None
TEST_FOLDER = get_test_folder()

if VM_ANALYZER_AVAILABLE:
    logger.info(f"✓ Complete analyzer available: {VM_ANALYZER_SCRIPT}")
else:
    logger.warning(f"✗ Complete analyzer not found: {VM_ANALYZER_SCRIPT}")


def run_complete_analysis(file_path: str, timeout: int = 180) -> Optional[dict]:
    """
    Run vm_complete_analyzer.py as subprocess (SANDBOX EXECUTION)
    
    Captures BOTH:
    - Behavioral aggregates (for Stage 1.5 XGBoost enrichment)
    - Sequential API traces (for Stage 2 CNN analysis)
    
    Args:
        file_path: Path to executable
        timeout: Max execution time (default 150s for full analysis + Frida)
        
    Returns:
        Dict from complete_analysis.json or None if failed
    """
    if not VM_ANALYZER_AVAILABLE:
        logger.error("Complete analyzer script not available")
        return None
    
    # Ensure analysis results directory exists
    if ANALYSIS_RESULTS_DIR:
        ANALYSIS_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    
    try:
        logger.info(f"🔬 Running COMPLETE behavioral analysis on {Path(file_path).name}")
        logger.warning("⚠️  SANDBOX MODE - Malware will be executed!")
        logger.info(f"   Analyzer: {VM_ANALYZER_SCRIPT.name}")
        logger.info(f"   Timeout: {timeout}s")
        
        # Run analyzer as subprocess
        import os
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'  # Immediate output flushing
        env['PYTHONUTF8'] = '1'        # Force UTF-8 IO so the analyzer doesn't replace sys.stdout
        env['PYTHONIOENCODING'] = 'utf-8:replace'  # Belt-and-suspenders UTF-8 enforcement
        
        # Determine the Python executable to use
        # Prefer the conda base env which has psutil/winreg, fallback to sys.executable
        import shutil
        analyzer_python = shutil.which("python") or sys.executable
        logger.info(f"   Python: {analyzer_python}")
        
        # Use Popen + real-time line streaming so every phase is visible in logs immediately
        import threading, time as _time
        proc = subprocess.Popen(
            [analyzer_python, str(VM_ANALYZER_SCRIPT), str(file_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=str(VM_ANALYZER_SCRIPT.parent),
            env=env
        )

        stderr_lines = []

        def _drain_stderr():
            for line in proc.stderr:
                line = line.rstrip()
                if line:
                    stderr_lines.append(line)
                    logger.warning(f"[ANALYZER STDERR] {line}")

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        # Stream stdout line-by-line to logs in real-time
        start_ts = _time.time()
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                logger.info(f"[ANALYZER] {line}")
            elapsed = _time.time() - start_ts
            if elapsed > timeout:
                logger.warning(f"⏱️  Streaming timeout ({timeout}s elapsed) - killing analyzer")
                proc.kill()
                break

        proc.stdout.close()
        stderr_thread.join(timeout=5)
        return_code = proc.wait(timeout=10)

        logger.info(f"✓ Analyzer process completed (exit code: {return_code})")
        if return_code not in (0, -9, 15):  # 0=success, -9/15=killed intentionally
            logger.warning(f"Analyzer exited with non-zero code: {return_code}")
        
        # Find the most recently written analysis file (stable or timestamped)
        if not ANALYSIS_RESULTS_DIR or not ANALYSIS_RESULTS_DIR.exists():
            logger.error("Analysis results directory not found")
            logger.error(f"Expected directory: {ANALYSIS_RESULTS_DIR}")
            return None
            
        analysis_files = list(ANALYSIS_RESULTS_DIR.glob("complete_analysis_*.json"))
        if not analysis_files:
            logger.error("No analysis output file found")
            logger.error(f"Searched directory: {ANALYSIS_RESULTS_DIR}")
            logger.error(f"Files in directory: {list(ANALYSIS_RESULTS_DIR.glob('*'))}")
            return None
        
        latest_analysis = max(analysis_files, key=lambda p: p.stat().st_mtime)
        logger.info(f"Loading analysis from: {latest_analysis.name}")
        
        with open(latest_analysis, 'r') as f:
            complete_data = json.load(f)
        
        logger.info(f"✅ Complete analysis loaded:")
        logger.info(f"   API sequence length: {len(complete_data.get('api_sequence', []))}")
        logger.info(f"   Files encrypted: {complete_data.get('ml_features', {}).get('file_encrypted_count', 0)}")
        logger.info(f"   Registry writes: {complete_data.get('ml_features', {}).get('registry_write_count', 0)}")
        logger.info(f"   Risk score: {complete_data.get('risk_score', 0)}")
        
        return complete_data
        
    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️  Analysis timed out after {timeout}s (process killed)")
        logger.info("Attempting to load partial analysis results...")
        # Try to load partial results
        if ANALYSIS_RESULTS_DIR and ANALYSIS_RESULTS_DIR.exists():
            analysis_files = list(ANALYSIS_RESULTS_DIR.glob("complete_analysis*.json"))
            if analysis_files:
                latest_analysis = max(analysis_files, key=lambda p: p.stat().st_mtime)
                logger.info(f"✓ Partial analysis found: {latest_analysis.name}")
                with open(latest_analysis, 'r') as f:
                    return json.load(f)
        logger.warning("✗ No analysis results found after timeout")
        return None
        
    except Exception as e:
        logger.error(f"Complete analysis failed: {e}", exc_info=True)
        return None


# Database dependency helper
async def get_db_session() -> Optional[AsyncSession]:
    """
    Optional database session dependency
    Returns session if DB_AVAILABLE, None otherwise
    """
    if DB_AVAILABLE:
        async for session in get_session():
            yield session
    else:
        yield None
        
def extract_pe_features_from_bytes(file_bytes: bytes, filename: str = "uploaded_file") -> Optional[np.ndarray]:
    """Extract PE features from raw bytes by saving to temp file"""
    if pe_extractor is None:
        logger.error("PE extractor not available")
        return None
    
    # Use a project-local temp_scans folder instead of %TEMP%.
    # %TEMP% is aggressively monitored by Windows Defender which locks .exe files
    # immediately after creation, causing pefile errno 22 (invalid argument).
    temp_dir = Path(__file__).parent / "temp_scans"
    temp_dir.mkdir(exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(suffix=".exe", dir=temp_dir)
    try:
        os.write(fd, file_bytes)
        os.close(fd)  # Explicitly close fd BEFORE pefile opens the file

        # Retry up to 3 times in case AV briefly locks the file
        features = None
        last_err = None
        for attempt in range(3):
            features = pe_extractor.extract(tmp_path)
            if features is not None:
                break
            import time as _t
            logger.warning(f"PE extract attempt {attempt+1} failed, retrying...")
            _t.sleep(0.3)

        return features
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except Exception:
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


def convert_complete_analysis_to_vt_format(complete_data: dict) -> dict:
    """
    Convert complete_analysis.json to VT enrichment format for Stage 1.5
    Uses behavioral aggregates (not sequential API data)
    
    NOTE: Excludes data leakage features (processes_malicious, processes_suspicious,
          files_malicious, files_suspicious) removed during training cleanup
    
    Args:
        complete_data: Dict from vm_complete_analyzer.py output
        
    Returns:
        VT-compatible enrichment dict for pe_extractor._enrich_with_vt()
    """
    ml_features = complete_data.get('ml_features', {})
    patterns = complete_data.get('patterns', {})

    # --- files ---
    # 'files_unknown' is the closest VT analogue to "files touched by malware".
    # Include created + encrypted + deleted so the model sees the true scope.
    files_unknown = (
        ml_features.get('file_created_count', 0)
        + ml_features.get('file_encrypted_count', 0)
        + ml_features.get('file_deleted_count', 0)
    )
    # 'files_text' maps to ransom notes (plain-text files dropped by ransomware)
    files_text = ml_features.get('ransom_note_count', 0)

    # Pull api_summary for fields that live there but not in ml_features
    api_summary = complete_data.get('api_summary', {})

    # --- registry ---
    # ml_features uses registry_read_count / registry_write_count / registry_delete_count
    # api_summary uses api_registry_reads / api_registry_writes (same values, different key names)
    reg_read   = ml_features.get('registry_read_count',
                 api_summary.get('api_registry_reads', 0))
    reg_write  = ml_features.get('registry_write_count',
                 api_summary.get('api_registry_writes', 0))
    reg_delete = ml_features.get('registry_delete_count', 0)
    reg_count = reg_read + reg_write + reg_delete

    # --- network ---
    # api_network_connections / api_network_dns come from ws2_32.dll Frida hooks (new in updated tracer)
    # psutil-based count (network_connection_count) is a fallback for slow TCP connections
    net_connections = max(
        ml_features.get('api_network_connections', 0),
        ml_features.get('api_network_operations', 0)
    )
    net_dns = ml_features.get('api_network_dns', 0)
    net_threats = 0
    # If C2 pattern was detected but psutil/frida missed the actual connections, apply a floor
    if patterns.get('network_c2_communication') and net_connections == 0:
        net_connections = 10
        net_threats = 1
    if patterns.get('network_c2_communication') and net_dns == 0:
        net_dns = 50   # Conservative floor for DNS

    # --- processes ---
    # system_process_count = total processes on the system during malware execution (psutil)
    # api_process_enumerations = how many times malware called process-enum APIs (Frida/api_summary)
    # Both map to Zenodo's 'processes_monitored'; take whichever is larger.
    system_procs = max(
        ml_features.get('system_process_count', 0),
        api_summary.get('api_process_enumerations', 0)
    )
    # Fallback: use child process spawns if nothing else available
    if system_procs == 0:
        system_procs = ml_features.get('process_spawn_count', 0)

    # --- dlls / apis ---
    dll_count = ml_features.get('dll_load_count', 0)
    api_count = ml_features.get('api_sequence_length', 0)

    vt_format = {
        'behavior': {
            'registry': {
                'read': reg_read,          # NtOpenKey + NtQueryValueKey calls
                'write': reg_write,
                'delete': reg_delete,
                'total': reg_count
            },
            'network': {
                'threats': net_threats,
                'dns': net_dns,            # getaddrinfo / sendto calls via ws2_32
                'http': 0,
                'connections': net_connections  # connect() calls via ws2_32
            },
            'processes': {
                'monitored': system_procs,  # Total system processes seen during run
                'total': system_procs
            },
            'files': {
                'text': files_text,         # ransom notes
                'unknown': files_unknown    # all files touched
            },
            'dlls': dll_count,
            'apis': api_count
        },
        'tags': [k for k, v in patterns.items() if v],
        'source': 'vm_complete_analyzer'
    }

    logger.info(f"   Behavioral mapping for model:")
    logger.info(f"     files_unknown={files_unknown} (created={ml_features.get('file_created_count',0)} + "
                f"encrypted={ml_features.get('file_encrypted_count',0)} + deleted={ml_features.get('file_deleted_count',0)})")
    logger.info(f"     files_text={files_text} (ransom notes)")
    logger.info(f"     registry_read={reg_read}, registry_write={reg_write}, registry_delete={reg_delete}")
    logger.info(f"     network_connections={net_connections}, network_dns={net_dns}, network_threats={net_threats}")
    logger.info(f"     processes_monitored={system_procs} (system_process_count), dlls={dll_count}, apis={api_count}")
    logger.info(f"     active patterns: {[k for k,v in patterns.items() if v]}")

    return vt_format

def extract_api_sequence(json_file_path):
        """
        Extract API call sequence from JSON trace file.
        Supports multiple formats:
        1. Custom format: {'api_sequence': [{'api': 'name'}, ...]}
        2. Cuckoo Sandbox: {'behavior': {'processes': [{'calls': [{'api': 'name'}, ...]}]}}
        
        Args:
            json_file_path: Path to JSON file with API trace
            
        Returns:
            List of API call names in sequence
        """
        logger.info(f"\nExtracting API calls from {json_file_path}...")
        
        with open(json_file_path, 'r') as f:
            data = json.load(f)
        
        api_calls = []
        
        # Format 1: Custom format with api_sequence
        if 'api_sequence' in data:
            logger.info("  Detected format: Custom API sequence")
            for call in data['api_sequence']:
                if 'api' in call:
                    api_calls.append(call['api'])
        
        # Format 2: Cuckoo Sandbox format
        elif 'behavior' in data and 'processes' in data['behavior']:
            logger.info("  Detected format: Cuckoo Sandbox")
            for process in data['behavior']['processes']:
                if 'calls' in process:
                    for call in process['calls']:
                        if 'api' in call:
                            api_calls.append(call['api'])
            logger.info(f"  Processed {len(data['behavior']['processes'])} process(es)")
        
        else:
            logger.warning("  ⚠️  Unknown JSON format. Expected 'api_sequence' or 'behavior.processes.calls'")
        
        logger.info(f"✓ Extracted {len(api_calls)} API calls")
        
        if len(api_calls) > 0:
            # Show first few calls
            logger.info(f"  First 10 calls: {api_calls[:10]}")
            
            # Count unique APIs
            unique_apis = len(set(api_calls))
            logger.info(f"  Unique APIs: {unique_apis}")
        
        return api_calls
    
def sequence_to_indices(api_sequence):
        """Convert API sequence to indices."""
        indices = []
        for api in api_sequence:
            api_lower = api.lower()
            indices.append(vocab.get(api_lower, 1))  # 1 = <UNK>
        return indices
    
def pad_sequence(sequence):
        max_sequence_length = 2000
        """Pad sequence to max_sequence_length."""
        padded = np.zeros((1, max_sequence_length), dtype=np.int32)
        
        if len(sequence) > max_sequence_length:
            # Truncate from the beginning (keep most recent calls)
            padded[0] = sequence[-max_sequence_length:]
        else:
            # Pad at the beginning
            padded[0, -len(sequence):] = sequence
        
        return padded


@app.on_event("startup")
async def startup_event():
    """Load model and scaler on startup"""
    global model, scaler, model_metadata, pe_extractor, vt_enricher, model_feature_names
    global cnn_model, cnn_scaler, cnn_metadata, vocab  # CNN model globals + vocabulary
    
    logger.info("🚀 Starting Gradient Boosting Model Service...")
    
    # Initialize database connection
    if DB_AVAILABLE:
        try:
            logger.info("Initializing database connection...")
            await init_db()
            logger.info("✓ Database tables initialized")
        except Exception as e:
            logger.warning(f"Database initialization failed: {e}")
            logger.warning("⚠️  Continuing without database logging...")
    
    try:
        # Find the latest model file
        BASE_DIR = Path(__file__).resolve().parent.parent  # adjust as needed
        models_dir = BASE_DIR / "models"
        
        # Look for Gradient Boosting .pkl files
        model_files = list(models_dir.glob("xgboost_zenodo_*.pkl"))
        
        if not model_files:
            logger.warning("No trained model found - service will run in signature-only mode")
            return
        
        # Use the latest model
        latest_model = max(model_files, key=lambda p: p.stat().st_mtime)
        timestamp = latest_model.stem.split('_')[-2] + '_' + latest_model.stem.split('_')[-1]

        logger.info(f"Loading XGBoost model from {latest_model.name}")
        model = joblib.load(str(latest_model))
        logger.info(f"✓ Model loaded successfully")
        logger.info(f"  Model type: {type(model).__name__}")
        logger.info(f"  N estimators: {model.n_estimators}")
        
        # Load corresponding scaler
        scaler_path = models_dir / f"scaler_xgb_{timestamp}.pkl"
        if scaler_path.exists():
            scaler = joblib.load(scaler_path)
            logger.info(f"✓ Scaler loaded from {scaler_path.name}")
            logger.info(f"  Features in scaler: {scaler.n_features_in_}")
        else:
            logger.warning("⚠️  Scaler not found - predictions may be inaccurate")
        
        # Load feature names
        features_path = models_dir / f"features_xgb_{timestamp}.json"
        if features_path.exists():
            with open(features_path) as f:
                model_feature_names = json.load(f)
            logger.info(f"✓ Feature names loaded: {len(model_feature_names)} features")
        else:
            logger.warning("⚠️  Feature names not found")
        
        # Load metadata
        metadata_path = models_dir / f"xgboost_metadata_{timestamp}.json"
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
        
        # Load 1D CNN model for Stage 2 (sequential API analysis)
        try:
            # Check if TensorFlow/Keras is available
            try:
                from tensorflow import keras
                logger.info("Checking for CNN model...")
            except ImportError:
                logger.warning("⚠️  TensorFlow not available - Stage 2 (CNN) will be unavailable")
                raise
            
            cnn_files = list(models_dir.glob("best_fixed_cnn_*.keras"))
            if cnn_files:
                latest_cnn = max(cnn_files, key=lambda p: p.stat().st_mtime)
                cnn_timestamp = latest_cnn.stem.split('_')[-2] + '_' + latest_cnn.stem.split('_')[-1]
                
                logger.info(f"Loading 1D CNN model from {latest_cnn.name}")
                cnn_model = keras.models.load_model(str(latest_cnn))
                logger.info(f"✓ CNN model loaded successfully")
                logger.info(f"  Model type: {type(cnn_model).__name__}")
                logger.info(f"  Input shape: {cnn_model.input_shape}")
                logger.info(f"  Output shape: {cnn_model.output_shape}")
                logger.info(f"  Parameters: {cnn_model.count_params():,}")
                
                vocab_path = models_dir / f"api_vocab_fixed.pkl"
                # Load vocabulary
                with open(vocab_path, 'rb') as f:
                    vocab = pickle.load(f)
                print(f"✓ Vocabulary loaded from {vocab_path}")
                print(f"  Vocabulary size: {len(vocab)}")

                logger.info("✓ Stage 2 (CNN sequential analysis) available")
            else:
                logger.warning("⚠️  No CNN model found - Stage 2 will be unavailable")
                logger.info("  System will use XGBoost-only analysis")
        except Exception as e:
            logger.warning(f"Failed to load CNN model: {e}")
            logger.info("  Stage 2 (sequential analysis) will be unavailable")
        
        logger.info("✅ Model Scanning Service ready!")
        
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        logger.warning("Service will run in signature-only mode")



async def queue_uncertain_sample_with_file(
    db: AsyncSession,
    file_bytes: bytes,
    file_name: str,
    features: np.ndarray,
    prediction_prob: float,
    behavioral_enriched: bool,
    behavioral_source: Optional[str]
):
    """
    Queue uncertain sample and store file copy for later VT upload
    
    Creates persistent copy at: adaptive_learning/queued_files/{hash}.bin
    
    Args:
        db: Database session
        file_bytes: Raw file bytes
        file_name: Original filename
        features: Feature vector (after enrichment)
        prediction_prob: Raw probability of malicious class
        behavioral_enriched: Whether behavioral features were added
        behavioral_source: Source of behavioral data
    """
    # Calculate file hash
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    
    # Create queued files directory
    queue_dir = Path(__file__).parent.parent / 'adaptive_learning' / 'queued_files'
    queue_dir.mkdir(parents=True, exist_ok=True)
    
    # Save file copy
    file_storage_path = queue_dir / f"{file_hash}.bin"
    with open(file_storage_path, 'wb') as f:
        f.write(file_bytes)
    
    logger.info(f"💾 Saved file copy for VT upload: {file_storage_path.name}")
    
    # Serialize features
    features_json = json.dumps(features.tolist())
    
    # Calculate prediction values
    ml_prediction = int(prediction_prob >= 0.5)  # 0=malicious, 1=benign
    ml_confidence = prediction_prob if prediction_prob >= 0.5 else (1 - prediction_prob)
    prediction_label = "MALICIOUS" if prediction_prob >= 0.5 else "CLEAN"
    
    # Insert into database queue
    from db_manager import queue_uncertain_sample
    await queue_uncertain_sample(
        session=db,
        file_hash=file_hash,
        file_name=file_name,
        file_path=file_name,  # Original path not available for uploads
        file_size=len(file_bytes),
        file_storage_path=str(file_storage_path),
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        ml_raw_score=prediction_prob,
        prediction_label=prediction_label,
        features_json=features_json,
        behavioral_enriched=behavioral_enriched,
        behavioral_source=behavioral_source
    )
    
    logger.info(f"📋 Queued sample for VT upload: {file_hash[:8]}... (confidence: {ml_confidence:.2%})")


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
    run_sandbox: bool = True,  # Explicit opt-in for sandbox (dangerous!)
    db: Optional[AsyncSession] = Depends(get_db_session)
):
    """
    Three-Stage Detection with Soft Voting Ensemble
    
    Stage 1: Static PE triage (XGBoost on all 67 features, behavioral zeros)
      - Provides initial assessment (logged but doesn't block sandbox)
      
    Sandbox: vm_complete_analyzer.py (if run_sandbox=True)
      - Executes malware, captures behavioral aggregates + API sequences
      - Always triggered when run_sandbox=True (confidence checking disabled)
      
    Stage 1.5: XGBoost enriched (67 features with real behavioral data)
    Stage 2: 1D CNN on API sequences
      - Run in parallel after sandbox execution
    
    Soft Voting: Average predictions from Stage 1.5 and Stage 2
      - Final_prob = (xgboost_prob + cnn_prob) / 2
      - Reduces false negatives through model diversity
    
    Args:
        file: Uploaded file (PE executable)
        run_sandbox: If True, enable sandbox execution
                    WARNING: Executes malware! Use only in isolated VM
        db: Database session for logging
        
    Returns:
        Prediction results with soft voting if sandbox was triggered
    """
    start_time = time.time()
    
    # Start logging capture if database available
    log_capture = None
    if DB_AVAILABLE:
        log_capture = LoggingCapture(__name__)
        log_capture.__enter__()
    
    try:
        file_bytes = await file.read()
        
        # === STAGE 1: Static PE Triage ===
        logger.info(f"🔍 Stage 1: Static PE analysis on {file.filename or 'uploaded_file'}")
        features_full = extract_pe_features_from_bytes(file_bytes, file.filename or "uploaded_file")
        
        if features_full is None:
            raise HTTPException(status_code=400, detail="PE extraction failed")
        
        # CRITICAL: XGBoost model was trained on ALL 67 features (53 static + 14 behavioral)
        # Stage 1 fast triage: Use all features but behavioral features will be zeros (not yet enriched)
        # This is more honest than subsetting features - model sees full feature space
        
        # Scale and predict (Stage 1 - all features, behavioral zeros)
        if scaler is not None:
            try:
                # Create feature DataFrame with all features
                features_df = pd.DataFrame(features_full.reshape(1, -1), columns=pe_extractor.FEATURE_NAMES)
                features_scaled = scaler.transform(features_df)
            except Exception as e:
                logger.warning(f"Scaler error: {e} - using basic normalization")
                features_scaled = normalize_pe_features(features_full).reshape(1, -1)
        else:
            features_scaled = normalize_pe_features(features_full).reshape(1, -1)
        
        # XGBoost prediction (behavioral features are zeros at this stage)
        stage1_proba = model.predict_proba(features_scaled)
        stage1_prob = float(stage1_proba[0][1])
        stage1_confidence = stage1_prob if stage1_prob >= 0.5 else (1 - stage1_prob)
        
        logger.info(f"   Stage 1 result: raw_score={stage1_prob:.3f}, confidence={stage1_confidence:.3f}({'MALICIOUS' if stage1_prob >= 0.5 else 'CLEAN'})")
        
        # === SANDBOX CHECK ===
        if not run_sandbox:
            logger.warning("⚠️  Sandbox disabled - returning Stage 1 result only")
            logger.warning("    Set run_sandbox=true to enable behavioral analysis")
            scan_time = (time.time() - start_time) * 1000
            is_malicious = stage1_prob >= 0.5
            
            return PredictResponse(
                is_malicious=is_malicious,
                confidence=float(stage1_confidence),
                prediction_label="MALICIOUS" if is_malicious else "CLEAN",raw_score=float(stage1_prob),
                detection_method="stage1_no_sandbox",
                scan_time_ms=round(scan_time, 2),
                pe_features_extracted=True
            )
        
        logger.info(f"🔬 Triggering sandbox analysis (Stage 1: {stage1_prob:.2%} malicious)")
        
        # Save file for sandbox in project-local folder (avoids %TEMP% AV interference)
        temp_dir = Path(__file__).parent / "temp_scans"
        temp_dir.mkdir(exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(suffix=".exe", dir=temp_dir)
        os.write(fd, file_bytes)
        os.close(fd)
        
        try:
            # Run complete analyzer
            complete_data = run_complete_analysis(tmp_path, timeout=180)
            
            if not complete_data:
                logger.error("Sandbox analysis failed - falling back to Stage 1")
                scan_time = (time.time() - start_time) * 1000
                is_malicious = stage1_prob >= 0.5
                
                return PredictResponse(
                    is_malicious=is_malicious,
                    confidence=float(stage1_confidence),
                    prediction_label="MALICIOUS" if is_malicious else "CLEAN",
                    raw_score=float(stage1_prob),
                    detection_method="stage1_sandbox_failed",
                    scan_time_ms=round(scan_time, 2),
                    pe_features_extracted=True
                )
            
            # === STAGE 1.5: XGBoost with Behavioral Enrichment ===
            logger.info(f"📊 Stage 1.5: XGBoost with behavioral aggregates")
            
            vt_format = convert_complete_analysis_to_vt_format(complete_data)
            features_enriched = pe_extractor._enrich_with_vt(features_full, vt_format)
            
            # Scale and predict (Stage 1.5 - all 67 features)
            if scaler is not None:
                try:
                    enriched_df = pd.DataFrame(features_enriched.reshape(1, -1), columns=pe_extractor.FEATURE_NAMES)
                    enriched_scaled = scaler.transform(enriched_df)
                except Exception as e:
                    logger.warning(f"Scaler error: {e} - using basic normalization")
                    enriched_scaled = normalize_pe_features(features_enriched).reshape(1, -1)
            else:
                enriched_scaled = normalize_pe_features(features_enriched).reshape(1, -1)
            
            stage1_5_proba = model.predict_proba(enriched_scaled)
            stage1_5_prob = float(stage1_5_proba[0][1])
            stage1_5_confidence = stage1_5_proba[0][1] if stage1_5_proba.shape[1] > 1 else 0.5  # Default confidence if no second class
            
            logger.info(f"   Stage 1.5 result: raw_score={stage1_5_prob:.3f}, confidence={stage1_5_confidence:.3f}({'MALICIOUS' if stage1_5_prob >= 0.5 else 'CLEAN'})")
            
            # === STAGE 2: 1D CNN on API Sequence ===
            stage2_prob = None
            if cnn_model is not None:
                logger.info(f"🧠 Stage 2: CNN on API sequence")
                analysis_file = list(ANALYSIS_RESULTS_DIR.glob("complete_analysis_*.json"))
                latest_analysis = max(analysis_file, key=lambda p: p.stat().st_mtime)
                api_sequence = complete_data.get('api_sequence', [])
                if api_sequence and len(api_sequence) > 0:
                    try:
                        api_calls = extract_api_sequence(latest_analysis)

                        # Convert to indices
                        indexed_sequence = sequence_to_indices(api_calls)

                        # Pad sequence
                        padded_sequence = pad_sequence(indexed_sequence)

                        # CNN prediction
                        stage2_proba = cnn_model.predict(padded_sequence, verbose=0)
                        stage2_prob = float(stage2_proba[0][1] if stage2_proba.shape[1] > 1 else stage2_proba[0][0])
                        stage2_confidence = float(stage2_proba[0][1] if stage2_proba.shape[1] > 1 else 0)
                        
                        logger.info(f"  Stage 2 result: raw_score={stage2_prob:.3f}, confidence={stage2_confidence:.3f}({'MALICIOUS' if stage2_prob >= 0.5 else 'CLEAN'})")
                    except Exception as e:
                        logger.error(f"CNN prediction failed: {e}")
                        stage2_prob = None
                else:
                    logger.warning("   No API sequence captured - skipping Stage 2")
            else:
                logger.warning("   CNN model not loaded - skipping Stage 2")
            
            # === SOFT VOTING ENSEMBLE ===
            if stage2_prob is not None:
                # Average predictions from Stage 1.5 (XGBoost) and Stage 2 (CNN)
                final_prob = (stage1_5_prob + stage2_prob) / 2
                detection_method = "soft_voting_xgb_cnn"
                logger.info(f"🎯 Soft Voting: ({stage1_5_prob:.3f} + {stage2_prob:.3f}) / 2 = {final_prob:.3f}")
            else:
                # Fallback to Stage 1.5 only
                final_prob = stage1_5_prob
                detection_method = "stage1_5_enriched_only"
                logger.info(f"🎯 Stage 1.5 only (no CNN): {final_prob:.3f}")
            
            is_malicious = final_prob >= 0.5
            final_confidence = final_prob if is_malicious else (1 - final_prob)
            
            # === UNCERTAIN SAMPLE QUEUEING (based on soft voting confidence) ===
            UNCERTAINTY_THRESHOLD = 0.85
            if final_confidence < UNCERTAINTY_THRESHOLD and db is not None:
                try:
                    await queue_uncertain_sample_with_file(
                        db=db,
                        file_bytes=file_bytes,
                        file_name=file.filename or 'uploaded_file',
                        features=features_enriched,
                        prediction_prob=final_prob,
                        behavioral_enriched=True,
                        behavioral_source='vm_complete_analyzer'
                    )
                    logger.info(f"📋 Sample queued for VT verification (soft voting confidence: {final_confidence:.2%})")
                except Exception as queue_error:
                    logger.error(f"Failed to queue sample: {queue_error}")
            
            scan_time = (time.time() - start_time) * 1000
            
            # Save to database
            if DB_AVAILABLE and log_capture and db:
                try:
                    log_capture.__exit__(None, None, None)
                    output = log_capture.get_output()
                    
                    result_dict = {
                        'is_malicious': bool(is_malicious),
                        'confidence': float(final_confidence),
                        'prediction_label': 'MALICIOUS' if is_malicious else 'CLEAN',
                        'scan_time_ms': scan_time,
                        'file_size': len(file_bytes),
                        'behavioral_enriched': True,
                        'behavioral_source': 'vm_complete_analyzer',
                        'detection_method': detection_method
                    }
                    
                    await save_terminal_log(
                        session=db,
                        command=f"predict_staged: {file.filename or 'uploaded_file'}",
                        command_type="malware_scan",
                        stdout=output['stdout'],
                        stderr=output['stderr'],
                        execution_time_ms=scan_time,
                        scan_result=result_dict,
                        file_path=file.filename or 'uploaded_file'
                    )
                    
                    await save_scan_history(
                        session=db,
                        file_path=file.filename or 'uploaded_file',
                        result=result_dict,
                        model_type=f"Soft Voting ({detection_method})"
                    )
                    
                    logger.info("✓ Scan results logged to database")
                except Exception as db_error:
                    logger.error(f"Failed to log to database: {db_error}")
            
            return PredictResponse(
                is_malicious=bool(is_malicious),
                confidence=float(final_confidence),
                prediction_label="MALICIOUS" if is_malicious else "CLEAN",
                raw_score=float(final_prob),
                detection_method=detection_method,
                scan_time_ms=round(scan_time, 2),
                pe_features_extracted=True,
                behavioral_enriched=True,
                behavioral_source='vm_complete_analyzer'
            )
            
        finally:
            # Clean up temp file
            try:
                Path(tmp_path).unlink()
            except:
                pass
            
    except Exception as e:
        logger.error(f"Staged prediction failed: {e}", exc_info=True)
        # Stop capture on error
        if log_capture:
            try:
                log_capture.__exit__(None, None, None)
            except:
                pass
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


# ==============================================================================
# DATABASE LOG QUERY ENDPOINTS
# ==============================================================================

@app.get("/logs/recent")
async def get_recent_logs(
    limit: int = 50,
    command_type: Optional[str] = None,
    db: Optional[AsyncSession] = Depends(get_db_session)
):
    """
    Get recent terminal logs from model service
    
    Query params:
    - limit: Max number of logs (default: 50)
    - command_type: Filter by type (e.g., "malware_scan")
    """
    if not DB_AVAILABLE or db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    from sqlalchemy import select, desc
    from db_manager import TerminalLog
    
    stmt = select(TerminalLog).order_by(desc(TerminalLog.timestamp)).limit(limit)
    
    if command_type:
        stmt = stmt.where(TerminalLog.command_type == command_type)
    
    result = await db.execute(stmt)
    logs = result.scalars().all()
    
    return {
        "total": len(logs),
        "service": "model_service",
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "command": log.command,
                "type": log.command_type,
                "execution_time_ms": log.execution_time_ms,
                "success": log.success,
                "scan_result": log.scan_result
            }
            for log in logs
        ]
    }


@app.get("/logs/scans")
async def get_scan_history(
    limit: int = 100,
    malicious_only: bool = False,
    db: Optional[AsyncSession] = Depends(get_db_session)
):
    """
    Get scan history with filtering
    
    Query params:
    - limit: Max number of scans (default: 100)
    - malicious_only: Only return malware detections (default: false)
    """
    if not DB_AVAILABLE or db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    from sqlalchemy import select, desc
    from db_manager import ScanHistory
    
    stmt = select(ScanHistory).order_by(desc(ScanHistory.timestamp))
    
    if malicious_only:
        stmt = stmt.where(ScanHistory.is_malicious == True)
    
    stmt = stmt.limit(limit)
    
    result = await db.execute(stmt)
    scans = result.scalars().all()
    
    return {
        "total": len(scans),
        "service": "model_service",
        "scans": [
            {
                "id": scan.id,
                "timestamp": scan.timestamp.isoformat(),
                "file_name": scan.file_name,
                "is_malicious": scan.is_malicious,
                "confidence": scan.confidence,
                "prediction_label": scan.prediction_label,
                "model_type": scan.model_type,
                "scan_time_ms": scan.scan_time_ms,
                "vt_detection": scan.vt_detection_ratio
            }
            for scan in scans
        ]
    }


@app.get("/logs/stats")
async def get_log_statistics(db: Optional[AsyncSession] = Depends(get_db_session)):
    """Get aggregate statistics from scan history"""
    if not DB_AVAILABLE or db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    from db_manager import get_scan_stats
    
    stats = await get_scan_stats(db)
    
    return {
        "status": "success",
        "service": "model_service",
        "statistics": stats
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
        reload=False,
        log_level="info"
    )
