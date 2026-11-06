"""
routers/observations.py - Member 2 sends analysed data here.

We only STORE what Member 2's rules produced. We do NOT re-run detection.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import models
from app.auth import require_api_key
from app.database import get_db
from app.schemas import ObservationAck, ObservationIn
from app.services.live import manager
from app.services.lookups import get_session_or_404
from app.services.serializers import alert_out, connection_out, iso_utc

router = APIRouter(tags=["ingestion"])


def save_observation(db: Session, body: ObservationIn) -> tuple[models.MonitoringSession,
                                                                list[models.NetworkConnection],
                                                                list[models.SecurityAlert]]:
    """Validate the session and write everything in ONE transaction (all saved or nothing saved)."""
    session = get_session_or_404(db, body.session_id)
    if session.status != "active":
        # 409 Conflict: the request is valid JSON, but the session is already finished.
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Session {session.id} is stopped; start a new session to send more data")

    # Data is mock if EITHER the batch or the whole session says so (rule: mark mock data).
    is_mock = body.is_mock or session.is_mock

    conns = [models.NetworkConnection(
        session_id=session.id, domain=c.domain,
        domain_source=c.domain_source.value if c.domain_source else None,
        ip=str(c.ip), port=c.port, protocol=c.protocol.value,
        bytes_up=c.bytes_up, bytes_down=c.bytes_down, timestamp=c.timestamp,
        duration_ms=c.duration_ms, is_mock=is_mock) for c in body.connections]

    alerts = [models.SecurityAlert(
        session_id=session.id, rule_id=a.rule_id, title=a.title, description=a.description,
        severity=a.severity.value, evidence_type=a.evidence_type.value, evidence=a.evidence,
        related_domain=a.related_domain, related_ip=a.related_ip, related_port=a.related_port,
        detected_at=a.detected_at, is_mock=is_mock) for a in body.alerts]

    snapshot = models.TrafficStatistic(
        session_id=session.id, captured_at=body.captured_at,
        total_bytes_up=body.stats.total_bytes_up, total_bytes_down=body.stats.total_bytes_down,
        total_connections=body.stats.total_connections, unique_domains=body.stats.unique_domains,
        new_connections=len(conns), risk_score=body.risk_score, is_mock=is_mock)

    if body.risk_score is not None:
        session.risk_score = body.risk_score  # the session always shows the latest score

    db.add_all([*conns, *alerts, snapshot])
    db.commit()
    return session, conns, alerts


@router.post("/observations", response_model=ObservationAck, status_code=202,
             dependencies=[Depends(require_api_key)])
async def receive_observation(body: ObservationIn, db: Session = Depends(get_db)):
    """
    Member 2 calls this every few seconds.
    * `stats` = cumulative totals so far, `connections`/`alerts` = only NEW items.
    * 404 if the session doesn't exist, 409 if it is already stopped.
    * After saving, the batch is pushed live to dashboards on /ws/{session_id}.
    """
    session, conns, alerts = save_observation(db, body)

    # `async def` + `await` lets us push to WebSockets without blocking the server.
    await manager.broadcast(session.id, {
        "type": "observation", "session_id": session.id,
        "data": {
            "captured_at": iso_utc(body.captured_at),
            "stats": body.stats.model_dump(),
            "risk_score": session.risk_score,
            "new_connections": [connection_out(c).model_dump(mode="json") for c in conns],
            "new_alerts": [alert_out(a).model_dump(mode="json") for a in alerts],
        },
    })
    return ObservationAck(accepted=True, session_id=session.id, connections_saved=len(conns),
                          alerts_saved=len(alerts), received_at=datetime.now(timezone.utc),
                          is_mock=session.is_mock or body.is_mock)
