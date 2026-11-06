"""
routers/insights.py - AI explanations of a session's alerts (API key required).
"""
from fastapi import APIRouter, Body, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models
from app.auth import require_api_key
from app.database import get_db
from app.schemas import InsightOut, InsightRequest
from app.services.insights import get_or_create_insight
from app.services.lookups import get_session_or_404
from app.services.serializers import insight_out

router = APIRouter(tags=["insights"], dependencies=[Depends(require_api_key)])


@router.post("/sessions/{session_id}/insights", response_model=InsightOut)
def create_insight(session_id: int, body: InsightRequest | None = Body(None), db: Session = Depends(get_db)):
    """
    Explain the session's alerts with Gemini (sanitized metadata only).
    * Same evidence as last time -> cached answer, `cached: true`, instant.
    * Gemini missing / slow / failing -> `source: "fallback"` with a rule-based text. Still saved.
    * This is a plain `def` (not async): FastAPI runs it in a worker thread,
      so waiting for Gemini doesn't freeze the rest of the server.
    """
    session = get_session_or_404(db, session_id)
    row, cached = get_or_create_insight(db, session, force_refresh=bool(body and body.force_refresh))
    return insight_out(row, cached=cached)


@router.get("/sessions/{session_id}/insights", response_model=list[InsightOut])
def list_insights(session_id: int, db: Session = Depends(get_db)):
    """All saved explanations for the session, newest first."""
    get_session_or_404(db, session_id)
    rows = db.scalars(select(models.AIInsight).where(models.AIInsight.session_id == session_id)
                      .order_by(models.AIInsight.id.desc()))
    return [insight_out(r, cached=True) for r in rows]
