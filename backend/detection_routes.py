"""
Detection Events API routes
Provides endpoints for the Detection Events UI page
to fetch scan history from the database.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import logging

from db_manager import get_session_maker, ScanHistory

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/detections", tags=["detections"])


# ---------- Response Schemas ----------

class DetectionItem(BaseModel):
    """Single detection record returned to the frontend."""
    id: int
    file_name: str
    timestamp: str          # ISO-formatted string
    display_time: str       # Human-friendly string: "22 February 2026 18:24:05"
    is_malicious: bool
    confidence: float
    prediction_label: str   # "MALWARE" or "BENIGN"
    model_type: Optional[str] = None

    class Config:
        from_attributes = True


class DetectionsResponse(BaseModel):
    """Envelope returned by GET /api/detections"""
    count: int
    detections: List[DetectionItem]


# ---------- Helpers ----------

def _format_display_time(dt: datetime) -> str:
    """Convert a datetime to '22 February 2026 18:24:05' format."""
    months = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December",
    ]
    return (
        f"{dt.day:02d} {months[dt.month - 1]} {dt.year} "
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
    )


# ---------- Endpoints ----------

@router.get("", response_model=DetectionsResponse)
async def get_detections(
    limit: int = Query(200, ge=1, le=1000, description="Max rows to return"),
    malicious_only: bool = Query(False, description="Only return malicious detections"),
):
    """
    Fetch scan history from the database.

    Returns detections ordered by timestamp descending (newest first).
    """
    from sqlalchemy import select, desc, func

    SessionLocal = get_session_maker()

    try:
        async with SessionLocal() as session:
            # Build query
            stmt = (
                select(ScanHistory)
                .order_by(desc(ScanHistory.timestamp))
                .limit(limit)
            )

            if malicious_only:
                stmt = stmt.where(ScanHistory.is_malicious == True)  # noqa: E712

            result = await session.execute(stmt)
            rows = list(result.scalars().all())

            # Total count (unfiltered, for the header metric)
            total_count = await session.scalar(
                select(func.count(ScanHistory.id))
            )

            detections = [
                DetectionItem(
                    id=row.id,
                    file_name=row.file_name,
                    timestamp=row.timestamp.isoformat() if row.timestamp else "",
                    display_time=_format_display_time(row.timestamp) if row.timestamp else "",
                    is_malicious=row.is_malicious,
                    confidence=round(row.confidence, 4) if row.confidence else 0.0,
                    prediction_label=row.prediction_label or ("MALWARE" if row.is_malicious else "BENIGN"),
                    model_type=row.model_type,
                )
                for row in rows
            ]

            return DetectionsResponse(count=total_count or 0, detections=detections)

    except Exception as e:
        logger.error(f"Failed to fetch detections: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")
