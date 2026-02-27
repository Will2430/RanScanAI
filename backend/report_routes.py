"""
Monthly Reports API routes
Aggregates scan_history records into monthly report summaries.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, date
import calendar
import logging

from db_manager import get_session_maker, ScanHistory, User
from auth.routes import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])

MONTH_NAMES = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]


# ---------- Response Schemas ----------

class ReportSummary(BaseModel):
    """One row in the monthly reports list."""
    id: str              # e.g. "R01"
    year: int
    month: int
    month_name: str
    label: str           # "2026 February Detailed Report"
    total_scans: int
    malicious_count: int
    benign_count: int
    threat_rate: float   # 0.0 – 100.0


class ReportRecord(BaseModel):
    """One scan row inside a monthly detail report."""
    file: str
    date: str            # ISO date string
    classification: str  # "Malicious" | "Benign"
    confidence: float    # 0.0 – 1.0
    threat: str          # "Ransomware" | "Suspicious" | "—"


class ReportDetail(BaseModel):
    id: str
    year: int
    month: int
    month_name: str
    start_date: str
    end_date: str
    generated: str
    total_scans: int
    malicious_count: int
    benign_count: int
    threat_rate: float
    records: List[ReportRecord]


class ReportsListResponse(BaseModel):
    count: int
    reports: List[ReportSummary]


# ---------- Helpers ----------

def _threat_label(row: ScanHistory) -> str:
    """Derive a threat label from scan data."""
    if not row.is_malicious:
        return "—"
    if row.confidence >= 0.90:
        return "Ransomware"
    if row.confidence >= 0.75:
        return "Trojan"
    return "Suspicious"


def _report_id(index: int) -> str:
    return f"R{str(index).zfill(2)}"


# ---------- Endpoints ----------

@router.get("", response_model=ReportsListResponse)
async def list_reports(
    limit: int = Query(12, ge=1, le=60, description="Max months to return"),
    current_user: User = Depends(get_current_user),
):
    """
    Return a list of months that have scan data for the authenticated user, newest first.
    Each entry is an aggregated monthly summary.
    """
    from sqlalchemy import select, func, extract, Integer, cast, case

    SessionLocal = get_session_maker()

    try:
        async with SessionLocal() as session:
            # Group scan_history rows by year + month, filtered by user
            yr_col = extract("year",  ScanHistory.timestamp).label("yr")
            mo_col = extract("month", ScanHistory.timestamp).label("mo")

            stmt = (
                select(
                    yr_col,
                    mo_col,
                    func.count(ScanHistory.id).label("total"),
                    func.sum(
                        case((ScanHistory.is_malicious == True, 1), else_=0)
                    ).label("malicious"),
                )
                .where(ScanHistory.user_id == current_user.user_id)
                .group_by(yr_col, mo_col)
                .order_by(yr_col.desc(), mo_col.desc())
                .limit(limit)
            )

            result = await session.execute(stmt)
            rows = result.all()

            reports = []
            for idx, row in enumerate(rows, start=1):
                yr  = int(row.yr)
                mo  = int(row.mo)
                total = int(row.total)
                mal   = int(row.malicious or 0)
                ben   = total - mal
                rate  = round((mal / total) * 100, 1) if total else 0.0
                mn    = MONTH_NAMES[mo - 1]

                reports.append(ReportSummary(
                    id=_report_id(len(rows) - idx + 1),
                    year=yr,
                    month=mo,
                    month_name=mn,
                    label=f"{yr} {mn} Detailed Report",
                    total_scans=total,
                    malicious_count=mal,
                    benign_count=ben,
                    threat_rate=rate,
                ))

            return ReportsListResponse(count=len(reports), reports=reports)

    except Exception as e:
        logger.error(f"Failed to fetch reports list: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")


@router.get("/{year}/{month}", response_model=ReportDetail)
async def get_report_detail(
    year: int,
    month: int,
    current_user: User = Depends(get_current_user),
):
    """
    Return all scan records for the given year/month.
    """
    from sqlalchemy import select, extract, desc, func, case

    if not (1 <= month <= 12):
        raise HTTPException(status_code=400, detail="Month must be 1-12")

    SessionLocal = get_session_maker()

    try:
        async with SessionLocal() as session:
            stmt = (
                select(ScanHistory)
                .where(ScanHistory.user_id == current_user.user_id)
                .where(extract("year",  ScanHistory.timestamp) == year)
                .where(extract("month", ScanHistory.timestamp) == month)
                .order_by(desc(ScanHistory.timestamp))
            )
            result = await session.execute(stmt)
            rows = list(result.scalars().all())

            if not rows:
                # Return empty report rather than 404 so the UI renders cleanly
                mn = MONTH_NAMES[month - 1]
                last_day = calendar.monthrange(year, month)[1]
                return ReportDetail(
                    id=_report_id(0),
                    year=year, month=month, month_name=mn,
                    start_date=f"1 {mn} {year}",
                    end_date=f"{last_day} {mn} {year}",
                    generated=datetime.utcnow().strftime("%d %B %Y"),
                    total_scans=0, malicious_count=0, benign_count=0,
                    threat_rate=0.0, records=[],
                )

            total = len(rows)
            mal   = sum(1 for r in rows if r.is_malicious)
            ben   = total - mal
            rate  = round((mal / total) * 100, 1) if total else 0.0
            mn    = MONTH_NAMES[month - 1]
            last_day = calendar.monthrange(year, month)[1]

            records = [
                ReportRecord(
                    file=r.file_name,
                    date=r.timestamp.date().isoformat() if r.timestamp else "",
                    classification="Malicious" if r.is_malicious else "Benign",
                    confidence=round(r.confidence, 4),
                    threat=_threat_label(r),
                )
                for r in rows
            ]

            # Derive a sequential report ID by counting months up to this one
            count_stmt = (
                select(
                    func.count(
                        func.distinct(
                            extract("year",  ScanHistory.timestamp) * 100 +
                            extract("month", ScanHistory.timestamp)
                        )
                    )
                )
                .where(ScanHistory.user_id == current_user.user_id)
                .where(
                    (extract("year",  ScanHistory.timestamp) * 100 +
                     extract("month", ScanHistory.timestamp))
                    <=
                    (year * 100 + month)
                )
            )
            seq = await session.scalar(count_stmt) or 1

            return ReportDetail(
                id=_report_id(int(seq)),
                year=year, month=month, month_name=mn,
                start_date=f"1 {mn} {year}",
                end_date=f"{last_day} {mn} {year}",
                generated=datetime.utcnow().strftime("%d %B %Y"),
                total_scans=total,
                malicious_count=mal,
                benign_count=ben,
                threat_rate=rate,
                records=records,
            )

    except Exception as e:
        logger.error(f"Failed to fetch report detail {year}/{month}: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")
