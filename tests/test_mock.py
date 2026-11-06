"""
Tests for the /mock endpoints (Phase 0 fake data for the dashboard).
TestClient calls the app directly in memory - no server needs to be running.
"""
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import AUTH

client = TestClient(app)

VALID_OBSERVATION = {
    "session_id": 1,
    "captured_at": "2026-11-05T10:05:00Z",
    "risk_score": 65,
    "stats": {"total_bytes_up": 12400000, "total_bytes_down": 172200000,
              "total_connections": 28, "unique_domains": 5},
    "connections": [{"domain": "api.demoshop.example", "ip": "198.51.100.10", "port": 443,
                     "protocol": "TCP", "bytes_up": 3100, "bytes_down": 48200,
                     "timestamp": "2026-11-05T10:04:58Z"}],
    "alerts": [],
    "is_mock": True,
}


def test_sessions_list_is_marked_mock():
    r = client.get("/mock/sessions")
    assert r.status_code == 200
    assert len(r.json()) >= 1
    assert all(s["is_mock"] is True for s in r.json())


def test_summary_matches_member2_example():
    s = client.get("/mock/sessions/1/summary").json()
    assert s["total_bytes_down"] == 172_200_000   # 172.2 MB
    assert s["total_bytes_up"] == 12_400_000      # 12.4 MB
    assert s["risk_score"] == 65
    assert s["alert_counts"] == {"low": 0, "medium": 2, "high": 1, "total": 3}


def test_every_alert_has_valid_evidence_type_and_no_malware_word():
    for a in client.get("/mock/sessions/1/alerts").json():
        assert a["evidence_type"] in {"observed", "inferred", "potential_risk", "not_observable"}
        assert "malware" not in (a["title"] + a["description"]).lower()


def test_unknown_session_is_404():
    assert client.get("/mock/sessions/999/summary").status_code == 404


def test_write_without_key_is_401():
    r = client.post("/mock/observations", json=VALID_OBSERVATION)
    assert r.status_code == 401


def test_valid_observation_accepted():
    r = client.post("/mock/observations", json=VALID_OBSERVATION, headers=AUTH)
    assert r.status_code == 202
    assert r.json()["connections_saved"] == 1


def test_bad_observation_rejected_with_422():
    bad = {**VALID_OBSERVATION, "connections": [{**VALID_OBSERVATION["connections"][0], "port": 99999}]}
    assert client.post("/mock/observations", json=bad, headers=AUTH).status_code == 422

    bad_evidence = {**VALID_OBSERVATION, "alerts": [{
        "rule_id": "X", "title": "t", "description": "d", "severity": "high",
        "evidence_type": "definitely_hacked",   # not an allowed value
        "detected_at": "2026-11-05T10:05:00Z"}]}
    assert client.post("/mock/observations", json=bad_evidence, headers=AUTH).status_code == 422
