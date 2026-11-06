"""
routers/dashboard.py - read-only endpoints for Member 4's dashboard (no API key needed).
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.schemas import (AlertOut, CompareOut, ConnectionOut, EvidenceType, SessionDiff, SessionSummary,
                         Severity, Timeline)
from app.services.analytics import build_summary, build_timeline
from app.services.lookups import get_session_or_404
from app.services.serializers import alert_out, connection_out

router = APIRouter(tags=["dashboard"])


@router.get("/sessions/{session_id}/summary", response_model=SessionSummary)
def session_summary(session_id: int, db: Session = Depends(get_db)):
    """Everything for the top cards: totals, risk, alert counts, top 5 domains."""
    return build_summary(db, get_session_or_404(db, session_id))


@router.get("/sessions/{session_id}/timeline", response_model=Timeline)
def session_timeline(session_id: int,
                     interval_seconds: int = Query(10, ge=1, le=3600, description="width of one chart bucket"),
                     db: Session = Depends(get_db)):
    """Bytes per interval (not cumulative) + alert markers, for the traffic chart."""
    return build_timeline(db, get_session_or_404(db, session_id), interval_seconds)


@router.get("/sessions/{session_id}/connections", response_model=list[ConnectionOut])
def session_connections(session_id: int,
                        limit: int = Query(500, ge=1, le=5000, description="max rows to return"),
                        offset: int = Query(0, ge=0, description="skip this many rows (for paging)"),
                        db: Session = Depends(get_db)):
    """Connections of a session, oldest first. Use limit/offset to page through long sessions."""
    get_session_or_404(db, session_id)
    q = (select(models.NetworkConnection)
         .where(models.NetworkConnection.session_id == session_id)
         .order_by(models.NetworkConnection.timestamp, models.NetworkConnection.id)
         .limit(limit).offset(offset))
    return [connection_out(c) for c in db.scalars(q)]


@router.get("/sessions/{session_id}/alerts", response_model=list[AlertOut])
def session_alerts(session_id: int,
                   severity: Severity | None = Query(None, description="only this severity"),
                   evidence_type: EvidenceType | None = Query(None, description="only this evidence type"),
                   db: Session = Depends(get_db)):
    """Alerts of a session, oldest first, optionally filtered."""
    get_session_or_404(db, session_id)
    q = select(models.SecurityAlert).where(models.SecurityAlert.session_id == session_id)
    if severity:
        q = q.where(models.SecurityAlert.severity == severity.value)
    if evidence_type:
        q = q.where(models.SecurityAlert.evidence_type == evidence_type.value)
    q = q.order_by(models.SecurityAlert.detected_at, models.SecurityAlert.id)
    return [alert_out(a) for a in db.scalars(q)]


def _destinations(db: Session, session_id: int) -> set[str]:
    C = models.NetworkConnection
    return set(db.scalars(select(func.coalesce(C.domain, C.ip)).where(C.session_id == session_id).distinct()))


def _alert_rules(db: Session, session_id: int) -> set[str]:
    A = models.SecurityAlert
    return set(db.scalars(select(A.rule_id).where(A.session_id == session_id).distinct()))


@router.get("/compare", response_model=CompareOut)
def compare_sessions(session_a: int = Query(..., description="first (e.g. older) session id"),
                     session_b: int = Query(..., description="second (e.g. newer) session id"),
                     db: Session = Depends(get_db)):
    """Side-by-side comparison of two sessions: totals, risk, and which domains/rules differ."""
    if session_a == session_b:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Pick two different sessions")
    a = build_summary(db, get_session_or_404(db, session_a))
    b = build_summary(db, get_session_or_404(db, session_b))
    dom_a, dom_b = _destinations(db, session_a), _destinations(db, session_b)
    rules_a, rules_b = _alert_rules(db, session_a), _alert_rules(db, session_b)
    risk_diff = (b.risk_score - a.risk_score) if a.risk_score is not None and b.risk_score is not None else None
    return CompareOut(
        session_a=a, session_b=b,
        difference_b_minus_a=SessionDiff(
            total_bytes_up=b.total_bytes_up - a.total_bytes_up,
            total_bytes_down=b.total_bytes_down - a.total_bytes_down,
            total_connections=b.total_connections - a.total_connections,
            alerts_total=b.alert_counts.total - a.alert_counts.total,
            risk_score=risk_diff),
        domains_only_in_a=sorted(dom_a - dom_b)[:100],
        domains_only_in_b=sorted(dom_b - dom_a)[:100],
        domains_in_both=sorted(dom_a & dom_b)[:100],
        alert_rules_only_in_a=sorted(rules_a - rules_b),
        alert_rules_only_in_b=sorted(rules_b - rules_a),
        is_mock=a.is_mock or b.is_mock,
    )
