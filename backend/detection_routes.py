"""
Detection Events API routes
Provides endpoints for the Detection Events UI page
to fetch scan history from the database.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
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
    date: Optional[str] = None  # Alias for display_time (used by UncertainSample component)
    is_malicious: bool
    confidence: float
    prediction_label: str   # "MALWARE" or "BENIGN"
    model_type: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None
    admin_review: Optional[bool] = None  # True if an admin has already reviewed this sample

    class Config:
        from_attributes = True


class DetectionsResponse(BaseModel):
    """Envelope returned by GET /api/detections"""
    count: int
    detections: List[DetectionItem]


class UserMonthlyStats(BaseModel):
    """Monthly statistics for a single user."""
    username: str
    role: str
    total_scans: int
    malicious_count: int
    benign_count: int
    critical_count: int  # confidence >= 0.9


class MonthlyReportResponse(BaseModel):
    """Response for monthly user report."""
    month: str  # YYYY-MM format
    users: List[UserMonthlyStats]


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
                    date=_format_display_time(row.timestamp) if row.timestamp else "",
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
                    date=_format_display_time(row.timestamp) if row.timestamp else "",
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
                    date=_format_display_time(row.timestamp) if row.timestamp else "",
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

# ---------- Uncertain Samples (AI Review) ----------

class ReviewRequest(BaseModel):
    """Request body for submitting a review decision."""
    admin_decision: str  # 'benign' or 'malware'


@router.get("/admin/uncertain", response_model=DetectionsResponse)
async def get_uncertain_samples(
    limit: int = Query(100, ge=1, le=1000, description="Max rows to return"),
    admin: User = Depends(get_current_admin),
):
    """
    Admin-only: Fetch uncertain samples (confidence between 0.3 and 0.7).
    These are samples where the AI is not confident about the classification.
    """
    from sqlalchemy import select, desc, func, and_

    SessionLocal = get_session_maker()

    try:
        async with SessionLocal() as session:
            uncertain_filter = and_(
                ScanHistory.confidence >= 0.3,
                ScanHistory.confidence <= 0.7,
                ScanHistory.admin_review == False,  # Exclude already-reviewed samples  # noqa: E712
            )

            stmt = (
                select(ScanHistory)
                .options(selectinload(ScanHistory.user))
                .where(uncertain_filter)
                .order_by(ScanHistory.confidence.asc())  # Show least confident first
                .limit(limit)
            )

            result = await session.execute(stmt)
            rows = list(result.scalars().all())

            total_count = await session.scalar(
                select(func.count(ScanHistory.id)).where(uncertain_filter)
            ) or 0

            detections = [
                DetectionItem(
                    id=row.id,
                    file_name=row.file_name,
                    timestamp=row.timestamp.isoformat() if row.timestamp else "",
                    display_time=_format_display_time(row.timestamp) if row.timestamp else "",
                    date=_format_display_time(row.timestamp) if row.timestamp else "",
                    is_malicious=row.is_malicious,
                    confidence=round(row.confidence, 4) if row.confidence else 0.0,
                    prediction_label=row.prediction_label or ("MALWARE" if row.is_malicious else "BENIGN"),
                    model_type=row.model_type,
                    username=row.user.username if row.user else None,
                    role=row.user.role if row.user else None,
                    admin_review=row.admin_review,
                )
                for row in rows
            ]

            return DetectionsResponse(count=total_count, detections=detections)

    except Exception as e:
        logger.error(f"Admin: Failed to fetch uncertain samples: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")


@router.post("/admin/review/{detection_id}")
async def submit_detection_review(
    detection_id: int,
    review: ReviewRequest,
    admin: User = Depends(get_current_admin),
):
    """
    Admin-only: Submit a review decision for an uncertain sample.
    Updates the detection with the admin's classification decision.
    """
    from sqlalchemy import select, update

    SessionLocal = get_session_maker()

    if review.admin_decision not in ['benign', 'malware']:
        raise HTTPException(status_code=400, detail="Invalid decision. Must be 'benign' or 'malware'.")

    try:
        async with SessionLocal() as session:
            # Verify detection exists
            stmt = select(ScanHistory).where(ScanHistory.id == detection_id)
            result = await session.execute(stmt)
            detection = result.scalar_one_or_none()

            if not detection:
                raise HTTPException(status_code=404, detail="Detection not found")

            # Update with admin decision
            is_malicious = (review.admin_decision == 'malware')
            update_stmt = (
                update(ScanHistory)
                .where(ScanHistory.id == detection_id)
                .values(
                    is_malicious=is_malicious,
                    prediction_label="MALWARE" if is_malicious else "BENIGN",
                    admin_review=True,
                    admin_decision_date=datetime.utcnow()
                )
            )
            await session.execute(update_stmt)
            await session.commit()

            logger.info(f"Admin {admin.username} reviewed detection {detection_id}: {review.admin_decision}")

            return {
                "success": True,
                "message": f"Detection {detection_id} marked as {review.admin_decision}",
                "detection_id": detection_id
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin: Failed to submit review for detection {detection_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit review: {str(e)}")


# ---------- Monthly User Report ----------

@router.get("/admin/monthly-report", response_model=MonthlyReportResponse)
async def get_monthly_report(
    month: str = Query(..., description="Month in YYYY-MM format (e.g., 2026-03)"),
    admin: User = Depends(get_current_admin),
):
    """
    Admin-only: Get aggregated monthly statistics per user.
    Returns total scans, threats found, detection rate, and critical detections.
    """
    from sqlalchemy import select, func, and_, extract, Integer, case

    SessionLocal = get_session_maker()

    # Validate month format
    try:
        month_parts = month.split('-')
        if len(month_parts) != 2:
            raise ValueError
        year = int(month_parts[0])
        month_num = int(month_parts[1])
        if month_num < 1 or month_num > 12:
            raise ValueError
    except (ValueError, IndexError):
        raise HTTPException(status_code=400, detail="Invalid month format. Use YYYY-MM (e.g., 2026-03)")

    try:
        async with SessionLocal() as session:
            # Query: Group scans by user for the given month
            stmt = (
                select(
                    User.username,
                    User.role,
                    func.count(ScanHistory.id).label('total_scans'),
                    func.sum(case((ScanHistory.is_malicious == True, 1), else_=0)).label('malicious_count'),  # noqa: E712
                    func.sum(case((ScanHistory.is_malicious == False, 1), else_=0)).label('benign_count'),  # noqa: E712
                    func.sum(case((and_(ScanHistory.is_malicious == True, ScanHistory.confidence >= 0.9), 1), else_=0)).label('critical_count'),  # noqa: E712
                )
                .select_from(User)
                .outerjoin(ScanHistory)
                .where(
                    and_(
                        extract('year', ScanHistory.timestamp) == year,
                        extract('month', ScanHistory.timestamp) == month_num,
                    )
                )
                .group_by(User.user_id, User.username, User.role)
                .order_by(User.username)
            )

            result = await session.execute(stmt)
            rows = result.all()

            users = [
                UserMonthlyStats(
                    username=row.username,
                    role=row.role or "user",
                    total_scans=row.total_scans or 0,
                    malicious_count=int(row.malicious_count or 0),
                    benign_count=int(row.benign_count or 0),
                    critical_count=int(row.critical_count or 0),
                )
                for row in rows
                if row.total_scans and row.total_scans > 0  # Only include users with activity
            ]

            return MonthlyReportResponse(month=month, users=users)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin: Failed to fetch monthly report: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")
