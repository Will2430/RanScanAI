"""
Adaptive Learning System - Model Retrainer

Runs train_cnn_fixed.py and train_xgboost_zenodo.py as subprocesses so that
heavy ML dependencies (TensorFlow, XGBoost) are never loaded into the FastAPI
server process.

After each script finishes, reads the newest metadata JSON written to models/
to surface post-training metrics back to the caller.

Usage (from retrain_routes.py):
    from adaptive_learning.model_retrainer import ModelRetrainer
    retrainer = ModelRetrainer()
    results = retrainer.run_all()          # sync — must be called from executor
"""

import json
import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# Directory layout (relative to this file):
#   backend/adaptive_learning/model_retrainer.py  <- here
#   backend/training_script/                      <- training scripts
#   K/models/                                     <- output: .keras, .pkl, metadata JSONs
_THIS_DIR   = Path(__file__).resolve().parent           # backend/adaptive_learning/
_SCRIPT_DIR = _THIS_DIR.parent / "training_script"      # backend/training_script/
_MODELS_DIR = _THIS_DIR.parent.parent / "models"        # K/models/


class ModelRetrainer:
    """
    Manages execution of the CNN and XGBoost training scripts.

    Both scripts are launched as subprocesses so TensorFlow / XGBoost are
    isolated from the FastAPI worker process.  This also means each run gets a
    completely fresh Python interpreter — no cached state between retraining
    sessions.

    After a script exits successfully the retrainer locates the metadata JSON
    that was written to models/ and returns it as a plain dict so the caller
    can persist the metrics to the database.
    """

    def __init__(self):
        self.script_dir = _SCRIPT_DIR
        self.models_dir = _MODELS_DIR

    # ── Internal helpers ──────────────────────────────────────────────────

    def _run_script(self, script_name: str, timeout: int) -> subprocess.CompletedProcess:
        """
        Launch *script_name* inside script_dir and wait for it to finish.

        stdout / stderr are inherited so training progress is visible in the
        parent process log / console rather than being silently swallowed.

        Raises:
            subprocess.TimeoutExpired  — if the script takes longer than *timeout* seconds
            subprocess.CalledProcessError — (not raised; caller checks returncode)
        """
        script_path = self.script_dir / script_name
        if not script_path.exists():
            raise FileNotFoundError(f"Training script not found: {script_path}")

        logger.info(f"[RETRAIN] Launching {script_name} (timeout={timeout}s) ...")
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(self.script_dir),   # so relative path imports inside the scripts work
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.error(f"[RETRAIN] {script_name} exited with code {result.returncode}")
        else:
            logger.info(f"[RETRAIN] {script_name} finished successfully")

        return result

    def _latest_metadata(self, pattern: str) -> dict | None:
        """
        Find the most recently modified file matching *pattern* in models_dir
        and return its parsed JSON, or None if no match / parse error.
        """
        files = sorted(
            self.models_dir.glob(pattern),
            key=lambda p: p.stat().st_mtime,
        )
        if not files:
            logger.warning(
                f"[RETRAIN] No metadata file matching '{pattern}' found in {self.models_dir}"
            )
            return None
        try:
            with open(files[-1]) as f:
                data = json.load(f)
            logger.info(f"[RETRAIN] Read metadata from {files[-1].name}")
            return data
        except Exception as exc:
            logger.error(f"[RETRAIN] Could not parse {files[-1].name}: {exc}")
            return None

    # ── Public API ────────────────────────────────────────────────────────

    def run_cnn(self, timeout: int = 7200) -> dict | None:
        """
        Run train_cnn_fixed.py.

        Returns:
            Parsed cnn_fixed_metadata_*.json dict on success, else None.
        """
        try:
            proc = self._run_script("train_cnn_fixed.py", timeout)
            if proc.returncode != 0:
                return None
            return self._latest_metadata("cnn_fixed_metadata_*.json")
        except subprocess.TimeoutExpired:
            logger.error(f"[RETRAIN] CNN training timed out after {timeout}s")
            return None
        except FileNotFoundError as exc:
            logger.error(f"[RETRAIN] {exc}")
            return None
        except Exception as exc:
            logger.error(f"[RETRAIN] CNN training error: {exc}", exc_info=True)
            return None

    def run_xgboost(self, timeout: int = 3600) -> dict | None:
        """
        Run train_xgboost_zenodo.py.

        Returns:
            Parsed xgboost_metadata_*.json dict on success, else None.
        """
        try:
            proc = self._run_script("train_xgboost_zenodo.py", timeout)
            if proc.returncode != 0:
                return None
            return self._latest_metadata("xgboost_metadata_*.json")
        except subprocess.TimeoutExpired:
            logger.error(f"[RETRAIN] XGBoost training timed out after {timeout}s")
            return None
        except FileNotFoundError as exc:
            logger.error(f"[RETRAIN] {exc}")
            return None
        except Exception as exc:
            logger.error(f"[RETRAIN] XGBoost training error: {exc}", exc_info=True)
            return None

    def run_all(
        self,
        run_cnn: bool = True,
        run_xgboost: bool = True,
        timeout_cnn: int = 7200,
        timeout_xgb: int = 3600,
    ) -> dict:
        """
        Run one or both training scripts sequentially (CNN first, then XGBoost).

        This is a blocking / synchronous call — wrap it in
        ``asyncio.get_event_loop().run_in_executor(None, ...)`` when calling
        from an async context so the event loop is not blocked.

        Returns:
            {
                "cnn":     dict | None,   # parsed metadata from CNN run
                "xgboost": dict | None,   # parsed metadata from XGBoost run
                "errors":  list[str],     # names of scripts that failed
            }
        """
        results: dict = {"cnn": None, "xgboost": None, "errors": []}

        if run_cnn:
            logger.info("[RETRAIN] ── CNN training ───────────────────────────────────────")
            results["cnn"] = self.run_cnn(timeout=timeout_cnn)
            if results["cnn"] is None:
                results["errors"].append("train_cnn_fixed.py")
                logger.warning("[RETRAIN] CNN training did not produce a metadata file")

        if run_xgboost:
            logger.info("[RETRAIN] ── XGBoost training ─────────────────────────────────")
            results["xgboost"] = self.run_xgboost(timeout=timeout_xgb)
            if results["xgboost"] is None:
                results["errors"].append("train_xgboost_zenodo.py")
                logger.warning("[RETRAIN] XGBoost training did not produce a metadata file")

        n_attempted = int(run_cnn) + int(run_xgboost)
        n_failed    = len(results["errors"])
        status = "success" if n_failed == 0 else ("partial" if n_failed < n_attempted else "failed")
        logger.info(f"[RETRAIN] run_all complete — status={status}, errors={results['errors']}")
        return results