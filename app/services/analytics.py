"""
analytics.py - turns stored rows into the numbers the dashboard shows.

These are simple AGGREGATIONS (sums, counts, grouping). There is NO detection
here - deciding what is suspicious is Member 2's job.
Used by: dashboard endpoints, the WebSocket, Gemini insights, PDF reports, compare.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import models
from app.schemas import (AlertCounts, DomainStat, SessionSummary, Severity, Timeline,
                         TimelineEvent, TimelinePoint)
from app.services.serializers import app_out

MAX_TIMELINE_POINTS = 500  # keep charts fast even for very long sessions


def risk_level(score: int | None) -> Severity | None:
    """Display label. Proposed thresholds (confirm with Member 2): 0-39 low, 40-69 medium, 70+ high."""
    if score is None:
        return None
    if score >= 70:
        return Severity.high
    if score >= 40:
        return Severity.medium
    return Severity.low


def latest_snapshot(db: Session, session_id: int) -> models.TrafficStatistic | None:
    return db.scalar(select(models.TrafficStatistic)
                     .where(models.TrafficStatistic.session_id == session_id)
                     .order_by(models.TrafficStatistic.captured_at.desc(), models.TrafficStatistic.id.desc())
                     .limit(1))


def top_domains(db: Session, session_id: int, limit: int = 5) -> list[DomainStat]:
    """Group connections by domain (or IP when no domain was seen) and rank by total bytes."""
    C = models.NetworkConnection
    name = func.coalesce(C.domain, C.ip)  # coalesce = "first value that is not NULL"
    total = func.sum(C.bytes_up + C.bytes_down)
    q = (select(name, func.sum(C.bytes_up), func.sum(C.bytes_down), func.count(C.id))
         .where(C.session_id == session_id)
         .group_by(name).order_by(total.desc()).limit(limit))
    return [DomainStat(domain=d, bytes_up=up or 0, bytes_down=down or 0, connection_count=n)
            for d, up, down, n in db.execute(q)]


def alert_counts(db: Session, session_id: int) -> AlertCounts:
    A = models.SecurityAlert
    rows = db.execute(select(A.severity, func.count(A.id)).where(A.session_id == session_id)
                      .group_by(A.severity))
    counts = AlertCounts()
    for severity, n in rows:
        if severity in ("low", "medium", "high"):
            setattr(counts, severity, n)
        counts.total += n
    return counts


def build_summary(db: Session, session: models.MonitoringSession) -> SessionSummary:
    """
    Totals come from Member 2's latest CUMULATIVE snapshot (their numbers are the
    source of truth). If no snapshot exists yet, we fall back to summing connections.
    """
    snap = latest_snapshot(db, session.id)
    if snap:
        up, down = snap.total_bytes_up, snap.total_bytes_down
        total_conns, unique = snap.total_connections, snap.unique_domains
    else:
        C = models.NetworkConnection
        up, down, total_conns, unique = db.execute(
            select(func.coalesce(func.sum(C.bytes_up), 0), func.coalesce(func.sum(C.bytes_down), 0),
                   func.count(C.id), func.count(func.distinct(C.domain)))
            .where(C.session_id == session.id)).one()

    end = session.stopped_at or datetime.now(timezone.utc)
    return SessionSummary(
        session_id=session.id, app=app_out(session.application), status=session.status,
        started_at=session.started_at, stopped_at=session.stopped_at,
        duration_seconds=max(0, int((end - session.started_at).total_seconds())),
        total_bytes_up=up, total_bytes_down=down, total_connections=total_conns, unique_domains=unique,
        risk_score=session.risk_score, risk_level=risk_level(session.risk_score),
        alert_counts=alert_counts(db, session.id), top_domains=top_domains(db, session.id),
        is_mock=session.is_mock,
    )


def build_timeline(db: Session, session: models.MonitoringSession, interval_seconds: int = 10) -> Timeline:
    """
    Chart data. Each snapshot holds RUNNING totals, so the bytes for one moment are
    (this snapshot - previous snapshot). We then group those differences into
    buckets of `interval_seconds` (e.g. one bar per 10 seconds).
    """
    snaps = list(db.scalars(select(models.TrafficStatistic)
                            .where(models.TrafficStatistic.session_id == session.id)
                            .order_by(models.TrafficStatistic.captured_at, models.TrafficStatistic.id)))
    alerts = list(db.scalars(select(models.SecurityAlert)
                             .where(models.SecurityAlert.session_id == session.id)
                             .order_by(models.SecurityAlert.detected_at, models.SecurityAlert.id)))
    events = [TimelineEvent(timestamp=a.detected_at, alert_id=a.id, title=a.title, severity=a.severity)
              for a in alerts]

    if not snaps:
        return Timeline(session_id=session.id, interval_seconds=interval_seconds, points=[], events=events,
                        is_mock=session.is_mock)

    # Start the chart at the first snapshot. (Phone clock and laptop clock may
    # differ a bit, so we don't use the server's started_at here.)
    origin = snaps[0].captured_at
    span = (snaps[-1].captured_at - origin).total_seconds()
    # Long session? Widen the buckets so we never send more than MAX_TIMELINE_POINTS.
    while span / interval_seconds >= MAX_TIMELINE_POINTS:
        interval_seconds *= 2
    n_buckets = int(span // interval_seconds) + 1

    buckets = [{"up": 0, "down": 0, "conns": 0, "risk": None, "has_data": False} for _ in range(n_buckets)]
    prev_up = prev_down = 0
    for s in snaps:
        i = int((s.captured_at - origin).total_seconds() // interval_seconds)
        b = buckets[i]
        # max(0, ...) protects the chart if totals ever go backwards (e.g. a counter reset).
        b["up"] += max(0, s.total_bytes_up - prev_up)
        b["down"] += max(0, s.total_bytes_down - prev_down)
        b["conns"] += s.new_connections
        if s.risk_score is not None:
            b["risk"] = s.risk_score
        b["has_data"] = True
        prev_up, prev_down = s.total_bytes_up, s.total_bytes_down

    points, last_risk = [], None
    for i, b in enumerate(buckets):
        if b["risk"] is not None:
            last_risk = b["risk"]  # empty buckets keep the previous risk so the line doesn't drop to zero
        points.append(TimelinePoint(
            timestamp=origin + timedelta(seconds=i * interval_seconds),
            bytes_up=b["up"], bytes_down=b["down"], new_connections=b["conns"], risk_score=last_risk))

    return Timeline(session_id=session.id, interval_seconds=interval_seconds, points=points, events=events,
                    is_mock=session.is_mock)
