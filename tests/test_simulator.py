"""simulator.py runs end-to-end against the app (TestClient is an httpx.Client, so run() accepts it)."""
import simulator
from tests.conftest import AUTH


def test_simulator_produces_all_three_patterns(client):
    client.headers.update(AUTH)
    sid = simulator.run(client, duration=40, interval=0, seed=42, quiet=True)

    session = client.get(f"/sessions/{sid}").json()
    assert session["status"] == "stopped" and session["is_mock"] is True

    alerts = client.get(f"/sessions/{sid}/alerts").json()
    by_rule = {a["rule_id"]: a for a in alerts}
    assert set(by_rule) == {"R01_PERIODIC_CONNECTIONS", "R02_UNCOMMON_PORT", "R03_HIGH_UPLOAD_THIRD_PARTY"}
    assert by_rule["R03_HIGH_UPLOAD_THIRD_PARTY"]["evidence_type"] == "inferred"  # a guess is never "observed"
    assert all(a["is_mock"] for a in alerts)

    summary = client.get(f"/sessions/{sid}/summary").json()
    assert summary["alert_counts"] == {"low": 0, "medium": 2, "high": 1, "total": 3}
    assert summary["total_bytes_down"] > 0
    assert "analytics.tracker.example" in [d["domain"] for d in summary["top_domains"]]
    assert any(c["port"] == 7777 for c in client.get(f"/sessions/{sid}/connections").json())
    assert len(client.get(f"/sessions/{sid}/timeline?interval_seconds=1").json()["points"]) >= 1
