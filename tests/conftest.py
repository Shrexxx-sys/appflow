"""
conftest.py - shared test setup (pytest loads this automatically).

We point the app at a TEMPORARY database and reports folder BEFORE importing it,
so tests never touch your real appflow.db. Real env vars win over .env.
"""
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="appflow_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["REPORTS_DIR"] = os.path.join(_tmp, "reports")
os.environ["API_KEY"] = "test-key"
os.environ["GEMINI_API_KEY"] = ""          # tests never call the real Gemini
os.environ["GEMINI_TIMEOUT_SECONDS"] = "1"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402

AUTH = {"X-API-Key": "test-key"}


@pytest.fixture(autouse=True)
def fresh_db():
    """Every test starts with empty tables."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    # `with` = one shared event loop for the whole test (needed for WebSocket tests).
    with TestClient(app) as c:
        yield c


# ---- helpers used by many tests --------------------------------------------

def start_session(client, package="com.example.demoshop", is_mock=True) -> int:
    r = client.post("/sessions", json={"package_name": package, "app_name": "DemoShop",
                                       "is_mock": is_mock}, headers=AUTH)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def make_observation(session_id, t="2026-11-05T10:00:05Z", up=1000, down=5000, total_conns=1,
                     connections=None, alerts=None, risk=20):
    return {
        "session_id": session_id, "captured_at": t, "risk_score": risk,
        "stats": {"total_bytes_up": up, "total_bytes_down": down,
                  "total_connections": total_conns, "unique_domains": 1},
        "connections": connections if connections is not None else [
            {"domain": "api.demoshop.example", "ip": "198.51.100.10", "port": 443, "protocol": "TCP",
             "bytes_up": up, "bytes_down": down, "timestamp": t}],
        "alerts": alerts or [],
        "is_mock": True,
    }


def make_alert(severity="medium", evidence_type="observed", t="2026-11-05T10:00:06Z", port=7777):
    return {"rule_id": "R02_UNCOMMON_PORT", "title": "Connection on an uncommon port",
            "description": "TCP to 203.0.113.45 on port 7777.", "severity": severity,
            "evidence_type": evidence_type, "evidence": {"port": port, "count": 2},
            "related_ip": "203.0.113.45", "related_port": port, "detected_at": t}
