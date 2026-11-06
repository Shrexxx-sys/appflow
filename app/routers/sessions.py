"""
routers/sessions.py - start, stop, list and delete monitoring sessions.
"""
import logging
import os

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import models
from app.auth import require_api_key
from app.database import get_db
from app.schemas import DeleteResult, SessionCreate, SessionOut
from app.services.live import manager
from app.services.lookups import get_session_or_404
from app.services.serializers import session_out

log = logging.getLogger("appflow.sessions")
router = APIRouter(tags=["sessions"])
protected = [Depends(require_api_key)]


@router.post("/sessions", response_model=SessionOut, status_code=201, dependencies=protected)
def start_session(body: SessionCreate, db: Session = Depends(get_db)):
    """Android app calls this when the user taps START. Keep the returned `id`."""
    # Re-use the application row if this app was monitored before ("get or create").
    app_row = db.scalar(select(models.Application).where(models.Application.package_name == body.package_name))
    if app_row is None:
        app_row = models.Application(package_name=body.package_name, app_name=body.app_name)
        db.add(app_row)
    elif body.app_name:
        app_row.app_name = body.app_name  # keep the friendly name up to date

    session = models.MonitoringSession(application=app_row, device_label=body.device_label,
                                       status="active", is_mock=body.is_mock)
    db.add(session)
    db.commit()
    return session_out(session)


@router.post("/sessions/{session_id}/stop", response_model=SessionOut, dependencies=protected)
async def stop_session(session_id: int, db: Session = Depends(get_db)):
    """User taps STOP. Calling it twice is safe (it just returns the stopped session)."""
    session = get_session_or_404(db, session_id)
    if session.status == "active":
        session.status = "stopped"
        session.stopped_at = models.utcnow()
        db.commit()
        out = session_out(session)
        await manager.broadcast(session.id, {"type": "session_stopped", "session_id": session.id,
                                             "data": out.model_dump(mode="json")})
        return out
    return session_out(session)


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(db: Session = Depends(get_db)):
    """All sessions, newest first."""
    rows = db.scalars(select(models.MonitoringSession).order_by(models.MonitoringSession.id.desc()))
    return [session_out(s) for s in rows]


@router.get("/sessions/{session_id}", response_model=SessionOut)
def get_session(session_id: int, db: Session = Depends(get_db)):
    return session_out(get_session_or_404(db, session_id))


@router.delete("/sessions/{session_id}", response_model=DeleteResult, dependencies=protected)
async def delete_session(session_id: int, db: Session = Depends(get_db)):
    """
    PRIVACY: permanently delete a session and EVERYTHING linked to it:
    connections, statistics, alerts, AI insights, report rows AND the PDF files on disk.
    The application row is removed too if no other session uses it.
    Live dashboards watching this session are notified and disconnected.
    """
    session = get_session_or_404(db, session_id)

    # Count first, so we can tell the user exactly what was removed.
    child_tables = {
        "network_connections": models.NetworkConnection,
        "traffic_statistics": models.TrafficStatistic,
        "security_alerts": models.SecurityAlert,
        "ai_insights": models.AIInsight,
        "reports": models.Report,
    }
    counts = {name: db.scalar(select(func.count()).select_from(table).where(table.session_id == session_id))
              for name, table in child_tables.items()}

    # Delete PDF files from disk (rows alone would leave the files behind).
    for report in session.reports:
        try:
            if os.path.exists(report.file_path):
                os.remove(report.file_path)
        except OSError as e:
            log.warning("Could not delete report file %s: %s", report.file_path, e)

    app_row = session.application
    db.delete(session)  # cascade removes all child rows (see models.py)
    db.flush()
    remaining = db.scalar(select(func.count()).select_from(models.MonitoringSession)
                          .where(models.MonitoringSession.application_id == app_row.id))
    counts["applications"] = 0
    if remaining == 0:
        db.delete(app_row)
        counts["applications"] = 1
    db.commit()

    await manager.broadcast(session_id, {"type": "session_deleted", "session_id": session_id, "data": None})
    await manager.close_room(session_id)
    return DeleteResult(deleted=True, session_id=session_id, rows_deleted=counts, is_mock=session.is_mock)
