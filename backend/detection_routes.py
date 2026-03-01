"""
Detection Events API routes
Provides endpoints for the Detection Events UI page
to fetch scan history from the database.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import logging

from db_manager import get_session_maker, get_session, ScanHistory, User
from auth.routes import get_current_user, get_current_admin

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
    username: Optional[str] = None
    role: Optional[str] = None

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
    current_user: User = Depends(get_current_user),
):
    """
    Fetch scan history from the database, filtered by the authenticated user.

    Returns detections ordered by timestamp descending (newest first).
    """
    from sqlalchemy import select, desc, func

    SessionLocal = get_session_maker()

    try:
        async with SessionLocal() as session:
            # Build query — filter by the logged-in user's ID
            stmt = (
                select(ScanHistory)
                .where(ScanHistory.user_id == current_user.user_id)
                .order_by(desc(ScanHistory.timestamp))
                .limit(limit)
            )

            if malicious_only:
                stmt = stmt.where(ScanHistory.is_malicious == True)  # noqa: E712

            result = await session.execute(stmt)
            rows = list(result.scalars().all())

            # Total count for this user
            total_count = await session.scalar(
                select(func.count(ScanHistory.id))
                .where(ScanHistory.user_id == current_user.user_id)
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


# ---------- Single Detection Detail ----------

class DetectionDetailResponse(BaseModel):
    """Full detail view of a single scan result."""
    id: int
    file_name: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    is_malicious: bool
    confidence: float
    prediction_label: str
    model_type: Optional[str] = None
    scan_time_ms: Optional[float] = None
    features_analyzed: Optional[int] = None
    timestamp: str
    display_time: str

    class Config:
        from_attributes = True


@router.get("/user/latest", response_model=DetectionDetailResponse)
async def get_latest_detection(
    current_user: User = Depends(get_current_user),
):
    """
    Fetch the most recent detection for the authenticated user.
    Returns full detail view of the latest scan result.
    """
    from sqlalchemy import select, desc

    SessionLocal = get_session_maker()

    try:
        async with SessionLocal() as session:
            stmt = (
                select(ScanHistory)
                .where(ScanHistory.user_id == current_user.user_id)
                .order_by(desc(ScanHistory.timestamp))
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()

            if not row:
                raise HTTPException(status_code=404, detail="No detections found for this user")

            return DetectionDetailResponse(
                id=row.id,
                file_name=row.file_name,
                file_path=row.file_path,
                file_size=row.file_size,
                file_hash=row.file_hash,
                is_malicious=row.is_malicious,
                confidence=round(row.confidence, 4) if row.confidence else 0.0,
                prediction_label=row.prediction_label or ("MALWARE" if row.is_malicious else "BENIGN"),
                model_type=row.model_type,
                scan_time_ms=round(row.scan_time_ms, 2) if row.scan_time_ms else None,
                features_analyzed=row.features_analyzed,
                timestamp=row.timestamp.isoformat() if row.timestamp else "",
                display_time=_format_display_time(row.timestamp) if row.timestamp else "",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch latest detection: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")


@router.get("/{detection_id}", response_model=DetectionDetailResponse)
async def get_detection_detail(
    detection_id: int,
    current_user: User = Depends(get_current_user),
):
    """
    Fetch full details for a single detection by ID.
    Only returns detections belonging to the authenticated user.
    """
    from sqlalchemy import select

    SessionLocal = get_session_maker()

    try:
        async with SessionLocal() as session:
            stmt = (
                select(ScanHistory)
                .where(ScanHistory.id == detection_id)
                .where(ScanHistory.user_id == current_user.user_id)
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()

            if not row:
                raise HTTPException(status_code=404, detail="Detection not found")

            return DetectionDetailResponse(
                id=row.id,
                file_name=row.file_name,
                file_path=row.file_path,
                file_size=row.file_size,
                file_hash=row.file_hash,
                is_malicious=row.is_malicious,
                confidence=round(row.confidence, 4) if row.confidence else 0.0,
                prediction_label=row.prediction_label or ("MALWARE" if row.is_malicious else "BENIGN"),
                model_type=row.model_type,
                scan_time_ms=round(row.scan_time_ms, 2) if row.scan_time_ms else None,
                features_analyzed=row.features_analyzed,
                timestamp=row.timestamp.isoformat() if row.timestamp else "",
                display_time=_format_display_time(row.timestamp) if row.timestamp else "",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch detection detail: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")


# ---------- Admin Endpoints (no user_id filter) ----------

class AdminStatsResponse(BaseModel):
    """Aggregated stats for admin dashboard."""
    total_scans: int
    total_threats: int
    total_benign: int
    critical_threats: int        # confidence >= 0.9
    total_users: int
    detections: List[DetectionItem]


@router.get("/admin/all", response_model=DetectionsResponse)
async def get_all_detections(
    limit: int = Query(200, ge=1, le=5000, description="Max rows to return"),
    malicious_only: bool = Query(False, description="Only return malicious detections"),
    admin: User = Depends(get_current_admin),
):
    """
    Admin-only: Fetch ALL scan history across all users (no user_id filter).
    """
    from sqlalchemy import select, desc, func

    SessionLocal = get_session_maker()

    try:
        async with SessionLocal() as session:
            stmt = (
                select(ScanHistory)
                .order_by(desc(ScanHistory.timestamp))
                .limit(limit)
            )

            if malicious_only:
                stmt = stmt.where(ScanHistory.is_malicious == True)  # noqa: E712

            result = await session.execute(stmt)
            rows = list(result.scalars().all())

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
        logger.error(f"Admin: Failed to fetch all detections: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")


@router.get("/admin/stats", response_model=AdminStatsResponse)
async def get_admin_stats(
    admin: User = Depends(get_current_admin),
):
    """
    Admin-only: Aggregated stats across all users for the admin dashboard cards.
    """
    from sqlalchemy import select, func

    SessionLocal = get_session_maker()

    try:
        async with SessionLocal() as session:
            # Total scans
            total_scans = await session.scalar(
                select(func.count(ScanHistory.id))
            ) or 0

            # Total threats (malicious)
            total_threats = await session.scalar(
                select(func.count(ScanHistory.id)).where(ScanHistory.is_malicious == True)  # noqa: E712
            ) or 0

            # Critical threats (malicious AND confidence >= 0.9)
            critical_threats = await session.scalar(
                select(func.count(ScanHistory.id))
                .where(ScanHistory.is_malicious == True)  # noqa: E712
                .where(ScanHistory.confidence >= 0.9)
            ) or 0

            total_benign = total_scans - total_threats

            # Total users
            total_users = await session.scalar(
                select(func.count(User.user_id))
            ) or 0

            # Latest detections for table (join with User to get username & role)
            from sqlalchemy.orm import selectinload
            stmt = (
                select(ScanHistory)
                .options(selectinload(ScanHistory.user))
                .order_by(ScanHistory.timestamp.desc())
                .limit(200)
            )
            result = await session.execute(stmt)
            rows = list(result.scalars().all())

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
                    username=row.user.username if row.user else None,
                    role=row.user.role if row.user else None,
                )
                for row in rows
            ]

            return AdminStatsResponse(
                total_scans=total_scans,
                total_threats=total_threats,
                total_benign=total_benign,
                critical_threats=critical_threats,
                total_users=total_users,
                detections=detections,
            )

    except Exception as e:
        logger.error(f"Admin: Failed to fetch stats: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")
