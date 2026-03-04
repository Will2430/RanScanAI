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


class TriggerRequest(BaseModel):
    force: bool = False   # bypass threshold check when True


class TriggerResponse(BaseModel):
    status: str           # "triggered" | "insufficient_samples"
    sample_count: int
    threshold: int
    message: str


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


@router.post("/trigger", response_model=TriggerResponse)
async def trigger_retraining(
    body: TriggerRequest,
    admin: User = Depends(get_current_admin),
):
    """
    Kick off the retraining pipeline.

    If sample_count < threshold AND force=False, returns insufficient_samples.
    Otherwise, runs retraining_scheduler.run_retraining_scheduler() as an
    asyncio background task and logs a new model_training_history row.
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
    """Background coroutine: runs the retraining scheduler and logs result."""
    try:
        logger.info(f"[retrain] Background retraining started (triggered by {triggered_by}, {sample_count} samples)")

        # Import here to avoid circular deps / heavy import on startup
        from schedulers.retraining_scheduler import run_retraining_scheduler
        result = await run_retraining_scheduler()

        logger.info(f"[retrain] Scheduler finished: {result}")

        # Log a new training history record (demo: records the trigger event)
        SessionLocal = get_session_maker()
        async with SessionLocal() as session:
            latest = await get_latest_model_metadata(session)
            new_version = "demo"
            if latest and latest.version:
                try:
                    major, minor = latest.version.split(".")
                    new_version = f"{major}.{int(minor) + 1}"
                except Exception:
                    new_version = f"{latest.version}+1"

            await insert_model_training_record(
                session=session,
                version=new_version,
                model_type=latest.model_type if latest else "1D CNN",
                accuracy=latest.accuracy if latest else 0.0,
                total_samples=(latest.total_samples or 0) + sample_count,
                model_path=latest.model_path if latest else None,
                dataset=latest.dataset if latest else "Zenodo",
                precision=latest.precision if latest else None,
                recall=latest.recall if latest else None,
                f1_score=latest.f1_score if latest else None,
                fpr=latest.fpr if latest else None,
                auc=latest.auc if latest else None,
                n_features=latest.n_features if latest else None,
                vocab_size=latest.vocab_size if latest else None,
                notes=f"Triggered by admin '{triggered_by}' with {sample_count} approved samples",
            )

        logger.info(f"[retrain] Training history record inserted (v{new_version})")

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
