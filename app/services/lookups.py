"""lookups.py - small shared helpers for routers."""
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app import models


def get_session_or_404(db: Session, session_id: int) -> models.MonitoringSession:
    """Return the session, or stop the request with a clear 404 (instead of crashing with 500)."""
    s = db.get(models.MonitoringSession, session_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Session {session_id} not found")
    return s
