"""
routers/live.py - WebSocket /ws/{session_id}

Messages the dashboard receives (all JSON):
  {"type": "hello",           "session_id": 1, "data": <SessionSummary>}      right after connecting
  {"type": "observation",     "session_id": 1, "data": {captured_at, stats, risk_score,
                                                         new_connections, new_alerts}}
  {"type": "session_stopped", "session_id": 1, "data": <SessionOut>}
  {"type": "session_deleted", "session_id": 1, "data": null}
  {"type": "error",           "session_id": 1, "data": {"detail": "..."}}

The client may send any text (e.g. "ping") to keep the connection alive; we reply {"type": "pong"}.
No API key: this is read-only dashboard data, like the GET endpoints.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app import models
from app.database import SessionLocal
from app.services.analytics import build_summary
from app.services.live import manager

router = APIRouter(tags=["live"])


@router.websocket("/ws/{session_id}")
async def live_updates(ws: WebSocket, session_id: int):
    # Short-lived DB session: just to check the session exists and send a starting summary.
    with SessionLocal() as db:
        session = db.get(models.MonitoringSession, session_id)
        hello = build_summary(db, session).model_dump(mode="json") if session else None

    await manager.join(session_id, ws)
    if hello is None:
        await ws.send_json({"type": "error", "session_id": session_id,
                            "data": {"detail": f"Session {session_id} not found"}})
        manager.leave(session_id, ws)
        await ws.close(code=4404)  # 4000-4999 = custom app close codes
        return

    await ws.send_json({"type": "hello", "session_id": session_id, "data": hello})
    try:
        while True:  # wait for client messages; this is also how we notice a disconnect
            await ws.receive_text()
            await ws.send_json({"type": "pong", "session_id": session_id, "data": None})
    except WebSocketDisconnect:
        pass
    finally:
        manager.leave(session_id, ws)
