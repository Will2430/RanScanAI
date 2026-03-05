"""
Retrain Center API Routes
Provides endpoints for the admin Retrain Center page:
  GET  /api/retrain/approved-samples  — list samples approved for retraining
  GET  /api/retrain/model-metadata    — latest model performance from model_training_history
  POST /api/retrain/trigger           — kick off the retraining scheduler
  DELETE /api/retrain/flush-queue     — demo reset: clear queue so files can be re-scanned
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from db_manager import (
    get_session_maker,
    get_session,
    get_approved_for_retrain,
    get_latest_model_metadata,
    get_all_model_versions,
    export_approved_samples_for_retraining,
    insert_model_training_record,
    flush_uncertain_queue,
    ModelTrainingHistory,
)
from auth.routes import get_current_admin
from db_manager import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/retrain", tags=["retrain"])

RETRAINING_THRESHOLD = 100  # recommended minimum samples


# ── Response Schemas ─────────────────────────────────────────────────────────

class ApprovedSampleItem(BaseModel):
    id: int
    file_name: str
    file_hash: str
    ml_prediction: int          # 0 = malicious, 1 = benign
    ml_confidence: float
    prediction_label: str
    vt_status: str
    behavioral_enriched: bool
    created_at: str             # ISO string
    admin_decision_date: Optional[str] = None

    class Config:
        from_attributes = True


class ApprovedSamplesResponse(BaseModel):
    count: int
    threshold: int
    threshold_met: bool
    samples: List[ApprovedSampleItem]


class ModelMetadataResponse(BaseModel):
    id: int
    version: str
    model_type: str
    model_path: Optional[str]
    dataset: Optional[str]
    accuracy: float
    precision: Optional[float]
    recall: Optional[float]
    f1_score: Optional[float]
    fpr: Optional[float]
    auc: Optional[float]
    n_features: Optional[int]
    vocab_size: Optional[int]
    total_samples: Optional[int]
    notes: Optional[str]
    trained_at: str
    samples_added: Optional[int] = None
    accuracy_delta: Optional[float] = None


class TriggerRequest(BaseModel):
    force: bool = False   # bypass threshold check when True


class TriggerResponse(BaseModel):
    status: str           # "triggered" | "insufficient_samples"
    sample_count: int
    threshold: int
    message: str


class ModelVersionItem(BaseModel):
    """Compact row for the version dropdown and chart."""
    id: int
    version: str
    model_type: str
    accuracy: float
    precision: Optional[float]
    recall: Optional[float]
    f1_score: Optional[float]
    fpr: Optional[float]
    auc: Optional[float]
    samples_added: Optional[int]
    accuracy_delta: Optional[float]
    trained_at: str
    notes: Optional[str]

    class Config:
        from_attributes = True


class FlushRequest(BaseModel):
    queue_ids: Optional[List[int]] = None  # None = flush ALL


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/approved-samples", response_model=ApprovedSamplesResponse)
async def get_approved_samples(
    admin: User = Depends(get_current_admin),
):
    """
    Return all uncertain_sample_queue entries whose parent scan_history row
    has been approved for retraining (admin_review=True).
    """
    SessionLocal = get_session_maker()
    try:
        async with SessionLocal() as session:
            rows = await get_approved_for_retrain(session)

            items = []
            for row in rows:
                usq = row[0]               # UncertainSampleQueue ORM object
                admin_decision_date = row[4]  # sh_admin_decision_date

                items.append(ApprovedSampleItem(
                    id=usq.id,
                    file_name=usq.file_name,
                    file_hash=usq.file_hash,
                    ml_prediction=usq.ml_prediction,
                    ml_confidence=round(usq.ml_confidence, 4),
                    prediction_label=usq.prediction_label,
                    vt_status=usq.status,
                    behavioral_enriched=usq.behavioral_enriched,
                    created_at=usq.created_at.isoformat() if usq.created_at else "",
                    admin_decision_date=admin_decision_date.isoformat() if admin_decision_date else None,
                ))

            count = len(items)
            return ApprovedSamplesResponse(
                count=count,
                threshold=RETRAINING_THRESHOLD,
                threshold_met=count >= RETRAINING_THRESHOLD,
                samples=items,
            )

    except Exception as e:
        logger.error(f"[retrain] get_approved_samples failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/model-metadata", response_model=ModelMetadataResponse)
async def get_model_metadata(
    admin: User = Depends(get_current_admin),
):
    """Return the latest model training record from model_training_history."""
    SessionLocal = get_session_maker()
    try:
        async with SessionLocal() as session:
            row: ModelTrainingHistory = await get_latest_model_metadata(session)
            if not row:
                raise HTTPException(status_code=404, detail="No model metadata found. Ensure init_db() has run.")

            return ModelMetadataResponse(
                id=row.id,
                version=row.version,
                model_type=row.model_type,
                model_path=row.model_path,
                dataset=row.dataset,
                accuracy=row.accuracy,
                precision=row.precision,
                recall=row.recall,
                f1_score=row.f1_score,
                fpr=row.fpr,
                auc=row.auc,
                n_features=row.n_features,
                vocab_size=row.vocab_size,
                total_samples=row.total_samples,
                notes=row.notes,
                trained_at=row.trained_at.isoformat() if row.trained_at else "",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[retrain] get_model_metadata failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/model-versions", response_model=List[ModelVersionItem])
async def list_model_versions(
    admin: User = Depends(get_current_admin),
):
    """Return all model training history rows ordered oldest→newest (for chart + dropdown)."""
    SessionLocal = get_session_maker()
    try:
        async with SessionLocal() as session:
            rows = await get_all_model_versions(session)
            return [
                ModelVersionItem(
                    id=r.id,
                    version=r.version,
                    model_type=r.model_type,
                    accuracy=r.accuracy,
                    precision=r.precision,
                    recall=r.recall,
                    f1_score=r.f1_score,
                    fpr=r.fpr,
                    auc=r.auc,
                    samples_added=r.samples_added,
                    accuracy_delta=r.accuracy_delta,
                    trained_at=r.trained_at.isoformat() if r.trained_at else "",
                    notes=r.notes,
                )
                for r in rows
            ]
    except Exception as e:
        logger.error(f"[retrain] list_model_versions failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/model-metadata/{record_id}", response_model=ModelMetadataResponse)
async def get_model_metadata_by_id(
    record_id: int,
    admin: User = Depends(get_current_admin),
):
    """Return full metadata for a specific model_training_history row."""
    from sqlalchemy import select
    SessionLocal = get_session_maker()
    try:
        async with SessionLocal() as session:
            result = await session.execute(
                select(ModelTrainingHistory).where(ModelTrainingHistory.id == record_id)
            )
            row = result.scalar_one_or_none()
            if not row:
                raise HTTPException(status_code=404, detail=f"No record with id {record_id}")
            return ModelMetadataResponse(
                id=row.id,
                version=row.version,
                model_type=row.model_type,
                model_path=row.model_path,
                dataset=row.dataset,
                accuracy=row.accuracy,
                precision=row.precision,
                recall=row.recall,
                f1_score=row.f1_score,
                fpr=row.fpr,
                auc=row.auc,
                n_features=row.n_features,
                vocab_size=row.vocab_size,
                total_samples=row.total_samples,
                notes=row.notes,
                trained_at=row.trained_at.isoformat() if row.trained_at else "",
                samples_added=row.samples_added,
                accuracy_delta=row.accuracy_delta,
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[retrain] get_model_metadata_by_id failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export-samples")
async def export_samples(
    admin: User = Depends(get_current_admin),
):
    """
    Export approved uncertain_sample_queue entries to augment files:
    - augment_cnn.json  (API call sequences for CNN retraining)
    - augment_xgb.csv   (feature vectors for XGBoost retraining)
    Returns row counts and output file paths.
    """
    import json as _json
    from pathlib import Path
    SessionLocal = get_session_maker()
    try:
        # Load XGBoost feature names from metadata so CSV columns are correct
        xgb_feature_names: Optional[List[str]] = None
        models_dir = Path(__file__).parent.parent / "models"
        xgb_meta_files = sorted(models_dir.glob("xgboost_metadata_*.json"))
        if xgb_meta_files:
            with open(xgb_meta_files[-1]) as f:
                xgb_meta = _json.load(f)
            xgb_feature_names = xgb_meta.get("feature_names")

        async with SessionLocal() as session:
            result = await export_approved_samples_for_retraining(
                session, xgb_feature_names=xgb_feature_names
            )

        logger.info(f"[retrain] Admin {admin.username} exported samples: {result}")
        return result

    except Exception as e:
        logger.error(f"[retrain] export_samples failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/trigger", response_model=TriggerResponse)
async def trigger_retraining(
    body: TriggerRequest,
    admin: User = Depends(get_current_admin),
):
    """
    Kick off the retraining pipeline.

    If sample_count < threshold AND force=False, returns insufficient_samples.
    Otherwise, exports augment files and launches train_cnn_fixed.py +
    train_xgboost_zenodo.py as subprocesses via ModelRetrainer, then logs
    new model_training_history rows with real metrics.
    """
    SessionLocal = get_session_maker()
    try:
        async with SessionLocal() as session:
            rows = await get_approved_for_retrain(session)
            sample_count = len(rows)

        if sample_count < RETRAINING_THRESHOLD and not body.force:
            return TriggerResponse(
                status="insufficient_samples",
                sample_count=sample_count,
                threshold=RETRAINING_THRESHOLD,
                message=(
                    f"Only {sample_count} / {RETRAINING_THRESHOLD} samples approved. "
                    "Set force=true to proceed anyway."
                ),
            )

        # Fire retraining scheduler as background task
        asyncio.create_task(_run_retrain_background(admin.username, sample_count))

        return TriggerResponse(
            status="triggered",
            sample_count=sample_count,
            threshold=RETRAINING_THRESHOLD,
            message=f"Retraining job queued with {sample_count} approved sample(s).",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[retrain] trigger failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _run_retrain_background(triggered_by: str, sample_count: int):
    """Background coroutine: exports augment files, runs both training scripts, logs results."""
    try:
        logger.info(f"[retrain] Background retraining started (triggered by {triggered_by}, {sample_count} samples)")

        # 1. Export approved samples to augment files (CNN JSON + XGBoost CSV)
        import asyncio as _asyncio
        import json as _json
        from pathlib import Path
        from db_manager import export_approved_samples_for_retraining
        from sqlalchemy import select as _select
        from db_manager import ModelTrainingHistory as _MTH
        SessionLocal = get_session_maker()

        export_result = {}
        try:
            models_dir = Path(__file__).parent.parent / "models"
            xgb_feature_names = None
            xgb_meta_files = sorted(models_dir.glob("xgboost_metadata_*.json"))
            if xgb_meta_files:
                with open(xgb_meta_files[-1]) as f:
                    xgb_feature_names = _json.load(f).get("feature_names")

            async with SessionLocal() as session:
                export_result = await export_approved_samples_for_retraining(
                    session, xgb_feature_names=xgb_feature_names
                )
            logger.info(f"[retrain] Augment files written: {export_result}")
        except Exception as _ex:
            logger.warning(f"[retrain] Export step failed (non-fatal): {_ex}")

        # 2. Run CNN + XGBoost training scripts via ModelRetrainer (blocking — use executor)
        from adaptive_learning.model_retrainer import ModelRetrainer
        _retrainer = ModelRetrainer()
        _loop = _asyncio.get_event_loop()
        train_results = await _loop.run_in_executor(None, _retrainer.run_all)
        logger.info(f"[retrain] Training finished — errors={train_results['errors']}")

        # 3. For each model that trained successfully, insert a history record
        #    Helper: query latest row for a specific model_type family
        async def _latest_for_type(session, type_fragment: str):
            stmt = (
                _select(_MTH)
                .where(_MTH.model_type.ilike(f"%{type_fragment}%"))
                .order_by(_MTH.trained_at.desc())
                .limit(1)
            )
            res = await session.execute(stmt)
            return res.scalar_one_or_none()

        def _bump_version(version: str | None, default: str) -> str:
            """Increment the minor component of a version string (e.g. v1.3 → v1.4).
            Returns *default* when there is no previous version."""
            if not version:
                return default
            try:
                if "." in version:
                    parts = version.lstrip("v").split(".")
                    return f"v{parts[0]}.{int(parts[1]) + 1}"
            except Exception:
                pass
            return f"{version}+1"

        notes_base = f"Triggered by admin '{triggered_by}' with {sample_count} approved samples"

        # 3a. CNN result
        cnn_meta = train_results.get("cnn")
        if cnn_meta:
            async with SessionLocal() as session:
                prev_cnn = await _latest_for_type(session, "CNN")
                prev_acc = prev_cnn.accuracy if prev_cnn else None
                new_acc  = float(cnn_meta.get("accuracy", 0.0))
                acc_delta = round(new_acc - prev_acc, 6) if prev_acc is not None else None
                new_ver  = _bump_version(prev_cnn.version if prev_cnn else None, "v1.0")
                await insert_model_training_record(
                    session=session,
                    version=new_ver,
                    model_type=cnn_meta.get("model_type", "1D CNN"),
                    accuracy=new_acc,
                    total_samples=(prev_cnn.total_samples or 0) + sample_count if prev_cnn else sample_count,
                    dataset=cnn_meta.get("dataset", "Zenodo"),
                    precision=cnn_meta.get("precision"),
                    recall=cnn_meta.get("recall"),
                    f1_score=cnn_meta.get("f1_score"),
                    fpr=cnn_meta.get("fpr"),
                    auc=cnn_meta.get("auc"),
                    n_features=cnn_meta.get("n_features"),
                    vocab_size=cnn_meta.get("vocab_size"),
                    notes=f"{notes_base} [CNN]",
                    samples_added=sample_count,
                    accuracy_delta=acc_delta,
                )
            logger.info(f"[retrain] CNN history record inserted (v{new_ver}, acc={new_acc:.4f})")

        # 3b. XGBoost result
        xgb_meta = train_results.get("xgboost")
        if xgb_meta:
            perf = xgb_meta.get("performance", {})
            async with SessionLocal() as session:
                prev_xgb = await _latest_for_type(session, "XGB")
                prev_acc = prev_xgb.accuracy if prev_xgb else None
                new_acc  = float(perf.get("accuracy", 0.0))
                acc_delta = round(new_acc - prev_acc, 6) if prev_acc is not None else None
                new_ver  = _bump_version(prev_xgb.version if prev_xgb else None, "vXGB-1.0")
                await insert_model_training_record(
                    session=session,
                    version=new_ver,
                    model_type=xgb_meta.get("model_type", "XGBClassifier"),
                    accuracy=new_acc,
                    total_samples=(
                        (xgb_meta.get("training_samples") or 0)
                        + (xgb_meta.get("test_samples") or 0)
                    ) or ((prev_xgb.total_samples or 0) + sample_count if prev_xgb else sample_count),
                    dataset=xgb_meta.get("dataset", "Zenodo"),
                    auc=perf.get("roc_auc"),
                    n_features=xgb_meta.get("n_features"),
                    notes=f"{notes_base} [XGBoost]",
                    samples_added=sample_count,
                    accuracy_delta=acc_delta,
                )
            logger.info(f"[retrain] XGBoost history record inserted (v{new_ver}, acc={new_acc:.4f})")

        if not cnn_meta and not xgb_meta:
            logger.error("[retrain] Both training scripts failed — no history records inserted")

    except Exception as e:
        logger.error(f"[retrain] Background task failed: {e}", exc_info=True)


@router.delete("/flush-queue")
async def flush_queue(
    body: FlushRequest = FlushRequest(),
    admin: User = Depends(get_current_admin),
):
    """
    Demo reset: reset admin_review=False on scan_history rows linked to the queue,
    WITHOUT deleting uncertain_sample_queue entries. This lets admins re-approve
    samples without needing to re-scan files.

    Pass queue_ids to reset specific entries, or omit to reset all.
    """
    SessionLocal = get_session_maker()
    try:
        async with SessionLocal() as session:
            reset_count = await flush_uncertain_queue(session, body.queue_ids or None)

        logger.info(f"[retrain] Admin {admin.username} reset admin_review on {reset_count} scan_history rows")
        return {
            "reset_count": reset_count,
            "message": f"Flushed — admin_review reset on {reset_count} sample{'s' if reset_count != 1 else ''}. Re-approve to retrain.",
        }

    except Exception as e:
        logger.error(f"[retrain] flush_queue failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
