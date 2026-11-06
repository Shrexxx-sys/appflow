"""Phase 6: privacy delete, compare, error handling."""
import os

from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import AUTH, make_alert, make_observation, start_session


def _filled_session(client, package="com.example.demoshop", domain="api.demoshop.example", alerts=None):
    sid = start_session(client, package=package)
    conn = {"domain": domain, "ip": "198.51.100.10", "port": 443, "protocol": "TCP",
            "bytes_up": 100, "bytes_down": 900, "timestamp": "2026-11-05T10:00:05Z"}
    client.post("/observations", json=make_observation(sid, connections=[conn], alerts=alerts or []),
                headers=AUTH)
    return sid


# ---------------- delete ----------------

def test_delete_requires_key(client):
    sid = start_session(client)
    assert client.delete(f"/sessions/{sid}").status_code == 401


def test_delete_removes_everything_including_pdf(client):
    sid = _filled_session(client, alerts=[make_alert()])
    client.post(f"/sessions/{sid}/insights", headers=AUTH)
    report = client.post(f"/sessions/{sid}/report", headers=AUTH).json()
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        pdf_path = db.get(models.Report, report["id"]).file_path
    assert os.path.exists(pdf_path)

    r = client.delete(f"/sessions/{sid}", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["deleted"] is True
    assert body["rows_deleted"] == {"network_connections": 1, "traffic_statistics": 1, "security_alerts": 1,
                                    "ai_insights": 1, "reports": 1, "applications": 1}
    assert not os.path.exists(pdf_path)
    assert client.get(f"/sessions/{sid}/summary").status_code == 404
    assert client.get(f"/reports/{report['id']}/download", headers=AUTH).status_code == 404
    with SessionLocal() as db:  # nothing left behind in any table
        for table in (models.NetworkConnection, models.TrafficStatistic, models.SecurityAlert,
                      models.AIInsight, models.Report, models.Application):
            assert db.query(table).count() == 0


def test_delete_keeps_application_used_by_other_sessions(client):
    a = _filled_session(client)
    b = _filled_session(client)
    assert client.delete(f"/sessions/{a}", headers=AUTH).json()["rows_deleted"]["applications"] == 0
    assert client.get(f"/sessions/{b}/summary").status_code == 200


def test_delete_notifies_live_dashboards(client):
    sid = start_session(client)
    with client.websocket_connect(f"/ws/{sid}") as ws:
        ws.receive_json()  # hello
        client.delete(f"/sessions/{sid}", headers=AUTH)
        assert ws.receive_json()["type"] == "session_deleted"


def test_delete_unknown_is_404(client):
    assert client.delete("/sessions/999", headers=AUTH).status_code == 404


# ---------------- compare ----------------

def test_compare_two_sessions(client):
    a = _filled_session(client, domain="api.demoshop.example")
    b = _filled_session(client, domain="analytics.tracker.example", alerts=[make_alert()])
    r = client.get(f"/compare?session_a={a}&session_b={b}")
    assert r.status_code == 200
    c = r.json()
    assert c["domains_only_in_a"] == ["api.demoshop.example"]
    assert c["domains_only_in_b"] == ["analytics.tracker.example"]
    assert c["alert_rules_only_in_b"] == ["R02_UNCOMMON_PORT"]
    assert c["difference_b_minus_a"]["alerts_total"] == 1
    assert c["difference_b_minus_a"]["risk_score"] == 0


def test_compare_validation(client):
    a = start_session(client)
    assert client.get(f"/compare?session_a={a}&session_b={a}").status_code == 400
    assert client.get(f"/compare?session_a={a}&session_b=999").status_code == 404
    assert client.get(f"/compare?session_a={a}").status_code == 422


# ---------------- errors ----------------

def test_unexpected_crash_returns_clean_json_500():
    async def boom():
        raise RuntimeError("secret internal detail")

    app.add_api_route("/_test_crash", boom, include_in_schema=False)
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/_test_crash")
    assert r.status_code == 500
    assert r.json() == {"detail": "Internal server error. See the server log."}
    assert "secret" not in r.text


def test_validation_error_format(client):
    r = client.post("/sessions", json={"package_name": ""}, headers=AUTH)
    assert r.status_code == 422
    assert r.json()["detail"][0]["loc"] == ["body", "package_name"]


def test_cors_allows_dashboard_origin(client):
    r = client.options("/sessions", headers={"Origin": "http://localhost:5173",
                                             "Access-Control-Request-Method": "GET"})
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] in ("*", "http://localhost:5173")


def test_openapi_docs_available(client):
    assert client.get("/docs").status_code == 200
    paths = client.get("/openapi.json").json()["paths"]
    for p in ["/sessions", "/observations", "/sessions/{session_id}/summary", "/sessions/{session_id}/insights",
              "/sessions/{session_id}/report", "/reports/{report_id}/download", "/compare", "/health"]:
        assert p in paths
