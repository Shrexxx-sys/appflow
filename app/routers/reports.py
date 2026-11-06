"""
routers/reports.py - build and download PDF reports (API key required).
"""
import os

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models
from app.auth import require_api_key
from app.database import get_db
from app.schemas import ReportOut
from app.services.lookups import get_session_or_404
from app.services.pdf_report import create_report
from app.services.serializers import report_out

router = APIRouter(tags=["reports"], dependencies=[Depends(require_api_key)])


@router.post("/sessions/{session_id}/report", response_model=ReportOut, status_code=201)
def build_report(session_id: int, db: Session = Depends(get_db)):
    """Create a PDF now. Then download it from `download_url` (send the X-API-Key header)."""
    session = get_session_or_404(db, session_id)
    return report_out(create_report(db, session))


@router.get("/sessions/{session_id}/reports", response_model=list[ReportOut])
def list_reports(session_id: int, db: Session = Depends(get_db)):
    """All reports generated for a session, newest first."""
    get_session_or_404(db, session_id)
    rows = db.scalars(select(models.Report).where(models.Report.session_id == session_id)
                      .order_by(models.Report.id.desc()))
    return [report_out(r) for r in rows]


@router.get("/reports/{report_id}/download", response_class=FileResponse,
            responses={200: {"content": {"application/pdf": {}}}})
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(models.Report, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Report {report_id} not found")
    if not os.path.exists(report.file_path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report file is missing on disk; generate a new one")
    # The file path comes from OUR database, never from the user, so it can't point elsewhere.
    return FileResponse(report.file_path, media_type="application/pdf", filename=report.filename)
