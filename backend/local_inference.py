"""
Local model inference — runs inside main.py when model_service (port 8001) is unreachable.

Pipeline:
  Stage 1  — XGBoost on static PE features  (always available if models/ present)
  Stage 2  — 1D-CNN on API-call sequences    (only when TF available AND sandbox ran)

Without the sandbox, only Stage 1 runs.  This is enough for Docker / offline mode.
"""

import asyncio
import hashlib
import json
import logging
import os
import pickle
import tempfile
import time
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# Override with MODELS_DIR env var.
# • In Docker the Dockerfile sets MODELS_DIR=/app/models
# • In dev the models/ folder lives one level above backend/
_DEFAULT_MODELS_DIR = Path(os.getenv(
    "MODELS_DIR",
    str(Path(__file__).parent.parent / "models")
))
MODELS_DIR: Path = _DEFAULT_MODELS_DIR

# Staged-analysis thresholds (match model_service.py)
CONFIDENCE_LOW  = 0.15
CONFIDENCE_HIGH = 0.85

# ---------------------------------------------------------------------------
# Module-level model globals (populated by load_models())
# ---------------------------------------------------------------------------
_xgb_model   = None
_xgb_scaler  = None
_xgb_feature_names: list = []
_cnn_model   = None
_cnn_vocab:  dict = {}
_pe_extractor = None   # PEFeatureExtractor instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_models() -> bool:
    """
    Load XGBoost (+ scaler) and optionally CNN from MODELS_DIR.
    Returns True if at least XGBoost loaded successfully.
    """
    global _xgb_model, _xgb_scaler, _xgb_feature_names
    global _cnn_model, _cnn_vocab, _pe_extractor

    models_dir = MODELS_DIR
    if not models_dir.exists():
        logger.error(f"[local_inference] models dir not found: {models_dir}")
        return False

    logger.info(f"[local_inference] Loading models from {models_dir}")

    # ── XGBoost ──────────────────────────────────────────────────────────────
    xgb_files = sorted(models_dir.glob("xgboost_zenodo_*.pkl"), key=lambda p: p.stat().st_mtime)
    if not xgb_files:
        logger.error("[local_inference] No XGBoost model found — local inference unavailable")
        return False

    xgb_pkl = xgb_files[-1]
    ts_parts = xgb_pkl.stem.split("_")
    timestamp = ts_parts[-2] + "_" + ts_parts[-1]

    _xgb_model = joblib.load(str(xgb_pkl))
    logger.info(f"[local_inference] ✓ XGBoost loaded: {xgb_pkl.name}")

    scaler_path = models_dir / f"scaler_xgb_{timestamp}.pkl"
    if scaler_path.exists():
        _xgb_scaler = joblib.load(str(scaler_path))
        logger.info(f"[local_inference] ✓ Scaler loaded ({_xgb_scaler.n_features_in_} features)")

    features_path = models_dir / f"features_xgb_{timestamp}.json"
    if features_path.exists():
        with open(features_path, encoding="utf-8") as f:
            _xgb_feature_names = json.load(f)

    # ── PE extractor ─────────────────────────────────────────────────────────
    try:
        from pe_feature_extractor import PEFeatureExtractor
        _pe_extractor = PEFeatureExtractor()
        logger.info(f"[local_inference] ✓ PE extractor ready ({_pe_extractor.n_features} features)")
    except Exception as e:
        logger.warning(f"[local_inference] PE extractor unavailable: {e}")

    # ── CNN (optional — needs TensorFlow) ────────────────────────────────────
    try:
        from tensorflow import keras as _keras  # noqa: F401
        cnn_files = sorted(models_dir.glob("best_fixed_cnn_*.keras"), key=lambda p: p.stat().st_mtime)
        if cnn_files:
            _cnn_model = _keras.models.load_model(str(cnn_files[-1]), compile=False)
            logger.info(f"[local_inference] ✓ CNN loaded: {cnn_files[-1].name}")

            vocab_files = sorted(models_dir.glob("api_vocab_fixed_*.pkl"), key=lambda p: p.stat().st_mtime)
            vocab_path = vocab_files[-1] if vocab_files else models_dir / "api_vocab_fixed.pkl"
            if vocab_path.exists():
                with open(vocab_path, "rb") as f:
                    _cnn_vocab = pickle.load(f)
                logger.info(f"[local_inference] ✓ Vocab loaded ({len(_cnn_vocab)} tokens)")
        else:
            logger.info("[local_inference] No CNN .keras file found — Stage 2 unavailable locally")
    except Exception as e:
        logger.info(f"[local_inference] CNN not loaded (TF unavailable or missing files): {e}")

    return True


def is_loaded() -> bool:
    """Return True if models are ready for inference."""
    return _xgb_model is not None


# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

def _normalize(features: np.ndarray) -> np.ndarray:
    """Min-max fallback normalization when scaler is not available."""
    clipped = np.clip(features, -1e10, 1e10)
    mn, mx = clipped.min(), clipped.max()
    return (clipped - mn) / (mx - mn) if mx > mn else clipped


def _xgb_predict(features: np.ndarray):
    """Run XGBoost on a (1, N) feature array. Returns raw malicious probability."""
    if _xgb_scaler is not None:
        try:
            df = pd.DataFrame(features.reshape(1, -1), columns=_pe_extractor.FEATURE_NAMES)
            scaled = _xgb_scaler.transform(df)
        except Exception as e:
            logger.warning(f"[local_inference] Scaler transform failed: {e} — using basic normalization")
            scaled = _normalize(features).reshape(1, -1)
    else:
        scaled = _normalize(features).reshape(1, -1)

    proba = _xgb_model.predict_proba(scaled)
    return float(proba[0][1])


# ---------------------------------------------------------------------------
# Main entry point called from main.py
# ---------------------------------------------------------------------------

async def run_staged(file_bytes: bytes, filename: str, queue: asyncio.Queue) -> None:
    """
    Stage 1 local inference (XGBoost static PE only — no sandbox/Frida available here).

    Puts SSE-compatible dicts into `queue`, matching the format produced by the
    httpx proxy in main.py so the SSE stream endpoint works identically.

    Queue message shapes:
      {"type": "log",    "msg": "..."}
      {"type": "result", "data": {...}}
      {"type": "error",  "msg": "...", "status": N}
    """
    start = time.time()

    async def log(msg: str):
        await queue.put({"type": "log", "msg": msg})

    try:
        if not is_loaded():
            await queue.put({"type": "error", "msg": "Local models not loaded", "status": 503})
            return

        if _pe_extractor is None:
            await queue.put({"type": "error", "msg": "PE extractor not available", "status": 503})
            return

        await log(f"🔍 [local] Stage 1: Static PE analysis on {filename}")

        # Write bytes to a temp file so PEFeatureExtractor can open it
        temp_dir = Path(__file__).parent / "temp_scans"
        temp_dir.mkdir(exist_ok=True)
        fd, tmp = tempfile.mkstemp(suffix=".exe", dir=temp_dir)
        try:
            os.write(fd, file_bytes)
            os.close(fd)
            features = _pe_extractor.extract(tmp)
        finally:
            Path(tmp).unlink(missing_ok=True)

        if features is None:
            await queue.put({"type": "error", "msg": "PE feature extraction failed — file may not be a valid PE", "status": 400})
            return

        prob = _xgb_predict(features)
        confidence = prob if prob >= 0.5 else (1 - prob)
        label = "MALICIOUS" if prob >= 0.5 else "CLEAN"

        await log(f"   Stage 1: {label} (score={prob:.3f}, confidence={confidence:.3f})")
        await log("⚠️  [local mode] Sandbox/CNN stage unavailable — returning Stage 1 XGBoost result only")

        scan_time = (time.time() - start) * 1000
        result = {
            "is_malicious": bool(prob >= 0.5),
            "confidence": float(confidence),
            "prediction_label": label,
            "raw_score": float(prob),
            "detection_method": "local_xgboost_stage1",
            "scan_time_ms": round(scan_time, 2),
            "pe_features_extracted": True,
            "behavioral_enriched": False,
            "file_hash": hashlib.sha256(file_bytes).hexdigest(),
        }
        await queue.put({"type": "result", "data": result})

    except Exception as e:
        logger.error(f"[local_inference] run_staged failed: {e}", exc_info=True)
        await queue.put({"type": "error", "msg": str(e), "status": 500})
