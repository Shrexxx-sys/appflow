"""Phase 1: sessions, ingestion, storage, API-key auth."""
from tests.conftest import AUTH, make_alert, make_observation, start_session


def test_health_reports_database(client):
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["database"] == "ok" and body["mode"] == "database"


def test_start_session_requires_key(client):
    assert client.post("/sessions", json={"package_name": "com.x"}).status_code == 401
    assert client.post("/sessions", json={"package_name": "com.x"},
                       headers={"X-API-Key": "wrong"}).status_code == 401


def test_start_and_list_sessions(client):
    sid = start_session(client)
    sessions = client.get("/sessions").json()
    assert [s["id"] for s in sessions] == [sid]
    assert sessions[0]["status"] == "active"
    assert sessions[0]["is_mock"] is True
    assert sessions[0]["app"]["package_name"] == "com.example.demoshop"
    assert sessions[0]["started_at"].endswith("Z")  # UTC timestamps


def test_same_app_reuses_application_row(client):
    a = start_session(client)
    b = start_session(client)
    sessions = {s["id"]: s for s in client.get("/sessions").json()}
    assert sessions[a]["app"]["id"] == sessions[b]["app"]["id"]


def test_observation_is_stored(client):
    sid = start_session(client)
    obs = make_observation(sid, alerts=[make_alert()])
    r = client.post("/observations", json=obs, headers=AUTH)
    assert r.status_code == 202, r.text
    assert r.json()["connections_saved"] == 1 and r.json()["alerts_saved"] == 1

    conns = client.get(f"/sessions/{sid}/connections").json()
    assert len(conns) == 1 and conns[0]["ip"] == "198.51.100.10" and conns[0]["is_mock"] is True
    alerts = client.get(f"/sessions/{sid}/alerts").json()
    assert alerts[0]["evidence_type"] == "observed" and alerts[0]["evidence"] == {"port": 7777, "count": 2}
    assert client.get(f"/sessions/{sid}").json()["risk_score"] == 20


def test_observation_without_key_is_401_and_not_stored(client):
    sid = start_session(client)
    assert client.post("/observations", json=make_observation(sid)).status_code == 401
    assert client.get(f"/sessions/{sid}/connections").json() == []


def test_observation_for_unknown_session_is_404(client):
    assert client.post("/observations", json=make_observation(999), headers=AUTH).status_code == 404


def test_invalid_evidence_type_is_422(client):
    sid = start_session(client)
    obs = make_observation(sid, alerts=[make_alert(evidence_type="probably_bad")])
    assert client.post("/observations", json=obs, headers=AUTH).status_code == 422


def test_stop_session_then_observation_is_409(client):
    sid = start_session(client)
    r = client.post(f"/sessions/{sid}/stop", headers=AUTH)
    assert r.json()["status"] == "stopped" and r.json()["stopped_at"] is not None
    assert client.post(f"/sessions/{sid}/stop", headers=AUTH).status_code == 200  # safe to repeat
    assert client.post("/observations", json=make_observation(sid), headers=AUTH).status_code == 409


def test_timezone_offsets_are_converted_to_utc(client):
    sid = start_session(client)
    obs = make_observation(sid, t="2026-11-05T15:30:05+05:30")  # India time
    client.post("/observations", json=obs, headers=AUTH)
    assert client.get(f"/sessions/{sid}/connections").json()[0]["timestamp"] == "2026-11-05T10:00:05Z"


def test_connections_paging(client):
    sid = start_session(client)
    conns = [{"domain": f"d{i}.example", "ip": "198.51.100.1", "port": 443, "protocol": "TCP",
              "bytes_up": 1, "bytes_down": 1, "timestamp": f"2026-11-05T10:00:{i:02d}Z"} for i in range(10)]
    client.post("/observations", json=make_observation(sid, connections=conns), headers=AUTH)
    page = client.get(f"/sessions/{sid}/connections?limit=3&offset=3").json()
    assert [c["domain"] for c in page] == ["d3.example", "d4.example", "d5.example"]


def test_domain_source_is_optional_and_stored(client):
    sid = start_session(client)
    conns = [
        {"domain": "api.demoshop.example", "domain_source": "sni", "ip": "198.51.100.10", "port": 443,
         "protocol": "TCP", "bytes_up": 1, "bytes_down": 1, "timestamp": "2026-11-05T10:00:01Z"},
        {"domain": None, "domain_source": "unavailable", "ip": "203.0.113.9", "port": 443,
         "protocol": "TCP", "bytes_up": 1, "bytes_down": 1, "timestamp": "2026-11-05T10:00:02Z"},
        {"domain": "x.example", "ip": "198.51.100.11", "port": 443,          # field omitted -> null
         "protocol": "TCP", "bytes_up": 1, "bytes_down": 1, "timestamp": "2026-11-05T10:00:03Z"},
    ]
    assert client.post("/observations", json=make_observation(sid, connections=conns), headers=AUTH).status_code == 202
    got = [c["domain_source"] for c in client.get(f"/sessions/{sid}/connections").json()]
    assert got == ["sni", "unavailable", None]
    bad = make_observation(sid, connections=[{**conns[0], "domain_source": "guess"}])
    assert client.post("/observations", json=bad, headers=AUTH).status_code == 422


def test_old_database_without_domain_source_is_upgraded_on_startup(client):
    """Regression: an appflow.db created before `domain_source` existed made every POST /observations
    fail with 500 ("no column named domain_source"). Startup must add the column and keep old rows."""
    from sqlalchemy import inspect, text

    from app.database import engine, init_db

    sid = start_session(client)
    with engine.begin() as conn:                      # make the test DB look like the OLD layout
        conn.execute(text("ALTER TABLE network_connections DROP COLUMN domain_source"))
        conn.execute(text("INSERT INTO network_connections (session_id, domain, ip, port, protocol, bytes_up, "
                          "bytes_down, timestamp, is_mock) VALUES (:s, 'old.example', '198.51.100.1', 443, "
                          "'TCP', 1, 2, '2026-11-05 10:00:00', 1)"), {"s": sid})
    assert "domain_source" not in [c["name"] for c in inspect(engine).get_columns("network_connections")]

    init_db()                                         # what happens when the backend restarts

    assert "domain_source" in [c["name"] for c in inspect(engine).get_columns("network_connections")]
    r = client.post("/observations", json=make_observation(sid, t="2026-11-05T10:00:06Z"), headers=AUTH)
    assert r.status_code == 202, r.text
    rows = client.get(f"/sessions/{sid}/connections").json()
    assert [c["domain"] for c in rows] == ["old.example", "api.demoshop.example"]   # old data kept
    assert rows[0]["domain_source"] is None                                          # old rows: unknown
