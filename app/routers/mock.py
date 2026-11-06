"""
routers/mock.py - Phase 0 MOCK endpoints.

Mounted under /mock since Phase 1 (e.g. GET /mock/sessions/1/summary).
They use the same response shapes as the real endpoints, so Member 4 can build the
dashboard now and nothing changes for them when Phase 1 plugs in the database
(only "is_mock" turns false).

Write endpoints (POST /sessions, POST /observations) VALIDATE the JSON but do
not store it yet. Member 2 can already use POST /observations to check that
the JSON they send is in the right format.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from app import mock_data
from app.auth import require_api_key
from app.schemas import (AlertOut, AppOut, ConnectionOut, DeleteResult, InsightOut, InsightRequest,
                         ObservationAck, ObservationIn, ReportOut, SessionCreate, SessionOut,
                         SessionSummary, Timeline)

router = APIRouter()
protected = [Depends(require_api_key)]  # shortcut: "this endpoint needs X-API-Key"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _require_session(session_id: int) -> None:
    """Return 404 (not 500) when someone asks for a session that doesn't exist."""
    if mock_data.get_session(session_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Session {session_id} not found")


# ----------------------------- sessions ------------------------------------

@router.post("/sessions", response_model=SessionOut, status_code=201,
             dependencies=protected)
def start_session(body: SessionCreate):
    """Android app calls this when the user taps START. (Mock: returns id 3, not stored.)"""
    return SessionOut(id=3, app=AppOut(id=3, package_name=body.package_name, app_name=body.app_name),
                      status="active", device_label=body.device_label, started_at=_now(),
                      stopped_at=None, risk_score=None, is_mock=True)


@router.post("/sessions/{session_id}/stop", response_model=SessionOut,
             dependencies=protected)
def stop_session(session_id: int):
    """Android app calls this when the user taps STOP."""
    _require_session(session_id)
    s = mock_data.get_session(session_id)
    if s.status == "active":
        s.status, s.stopped_at = "stopped", _now()
    return s


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions():
    """All sessions, for the dashboard's session list."""
    return mock_data.list_sessions()


@router.delete("/sessions/{session_id}", response_model=DeleteResult,
               dependencies=protected)
def delete_session(session_id: int):
    """Privacy feature: wipe all data of one session. (Mock: nothing is deleted.)"""
    _require_session(session_id)
    return DeleteResult(deleted=False, session_id=session_id, is_mock=True,
                        rows_deleted={"network_connections": 0, "traffic_statistics": 0,
                                      "security_alerts": 0, "ai_insights": 0, "reports": 0})


# ----------------------------- ingestion -----------------------------------

@router.post("/observations", response_model=ObservationAck, status_code=202,
             dependencies=protected)
def receive_observation(body: ObservationIn):
    """Member 2 sends a batch here every few seconds. (Mock: validated, not stored.)"""
    _require_session(body.session_id)
    return ObservationAck(accepted=True, session_id=body.session_id,
                          connections_saved=len(body.connections), alerts_saved=len(body.alerts),
                          received_at=_now(), is_mock=True)


# ----------------------------- dashboard reads -----------------------------

@router.get("/sessions/{session_id}/summary", response_model=SessionSummary)
def session_summary(session_id: int):
    _require_session(session_id)
    return mock_data.get_summary(session_id)


@router.get("/sessions/{session_id}/connections", response_model=list[ConnectionOut])
def session_connections(session_id: int):
    _require_session(session_id)
    return mock_data.get_connections(session_id)


@router.get("/sessions/{session_id}/alerts", response_model=list[AlertOut])
def session_alerts(session_id: int):
    _require_session(session_id)
    return mock_data.get_alerts(session_id)


@router.get("/sessions/{session_id}/timeline", response_model=Timeline)
def session_timeline(session_id: int):
    _require_session(session_id)
    return mock_data.get_timeline(session_id)


# ----------------------------- AI insights ---------------------------------

@router.post("/sessions/{session_id}/insights", response_model=InsightOut,
             dependencies=protected)
def create_insight(session_id: int, body: InsightRequest | None = None):
    """(Phase 4: will call Gemini with sanitized evidence.) Mock: canned text."""
    _require_session(session_id)
    return mock_data.get_insight(session_id)


@router.get("/sessions/{session_id}/insights", response_model=list[InsightOut],
            dependencies=protected)
def list_insights(session_id: int):
    _require_session(session_id)
    return [mock_data.get_insight(session_id)]


# ----------------------------- reports -------------------------------------

@router.post("/sessions/{session_id}/report", response_model=ReportOut, status_code=201,
             dependencies=protected)
def create_report(session_id: int):
    """(Phase 5: builds a real PDF.) Mock: returns metadata only."""
    _require_session(session_id)
    report_id = session_id * 10 + 1
    return ReportOut(id=report_id, session_id=session_id,
                     filename=f"appflow_session_{session_id}_report.pdf",
                     download_url=f"/reports/{report_id}/download", created_at=_now(), is_mock=True)


@router.get("/reports/{report_id}/download", dependencies=protected)
def download_report(report_id: int):
    raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED,
                        "PDF generation arrives in Phase 5. The response will be application/pdf.")
