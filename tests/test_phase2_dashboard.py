"""Phase 2: summary, timeline, alert filters."""
from tests.conftest import AUTH, make_alert, make_observation, start_session


def _send(client, obs):
    r = client.post("/observations", json=obs, headers=AUTH)
    assert r.status_code == 202, r.text


def test_summary_of_empty_session(client):
    sid = start_session(client)
    s = client.get(f"/sessions/{sid}/summary").json()
    assert s["total_bytes_up"] == 0 and s["total_bytes_down"] == 0
    assert s["alert_counts"]["total"] == 0 and s["top_domains"] == [] and s["risk_level"] is None


def test_summary_matches_member2_example(client):
    """172.2 MB down, 12.4 MB up, risk 65, two medium + one high alert."""
    sid = start_session(client)
    conns = [
        {"domain": "cdn.demoshop.example", "ip": "198.51.100.20", "port": 443, "protocol": "TCP",
         "bytes_up": 400_000, "bytes_down": 160_000_000, "timestamp": "2026-11-05T10:00:01Z"},
        {"domain": "analytics.tracker.example", "ip": "203.0.113.7", "port": 443, "protocol": "TCP",
         "bytes_up": 12_000_000, "bytes_down": 200_000, "timestamp": "2026-11-05T10:00:02Z"},
        {"domain": None, "ip": "203.0.113.45", "port": 7777, "protocol": "TCP",
         "bytes_up": 0, "bytes_down": 12_000_000, "timestamp": "2026-11-05T10:00:03Z"},
    ]
    alerts = [make_alert("medium"), make_alert("medium"), make_alert("high", "inferred")]
    obs = make_observation(sid, up=12_400_000, down=172_200_000, total_conns=3, connections=conns,
                           alerts=alerts, risk=65)
    _send(client, obs)

    s = client.get(f"/sessions/{sid}/summary").json()
    assert s["total_bytes_down"] == 172_200_000 and s["total_bytes_up"] == 12_400_000
    assert s["risk_score"] == 65 and s["risk_level"] == "medium"
    assert s["alert_counts"] == {"low": 0, "medium": 2, "high": 1, "total": 3}
    assert s["top_domains"][0]["domain"] == "cdn.demoshop.example"          # biggest first
    assert "203.0.113.45" in [d["domain"] for d in s["top_domains"]]        # IP used when no domain


def test_summary_uses_latest_cumulative_snapshot(client):
    sid = start_session(client)
    _send(client, make_observation(sid, t="2026-11-05T10:00:01Z", up=100, down=1000))
    _send(client, make_observation(sid, t="2026-11-05T10:00:02Z", up=250, down=3000))
    s = client.get(f"/sessions/{sid}/summary").json()
    assert (s["total_bytes_up"], s["total_bytes_down"]) == (250, 3000)  # not 350/4000


def test_timeline_converts_running_totals_to_per_interval(client):
    sid = start_session(client)
    _send(client, make_observation(sid, t="2026-11-05T10:00:00Z", up=100, down=1000, risk=10))
    _send(client, make_observation(sid, t="2026-11-05T10:00:03Z", up=300, down=4000, risk=20))
    _send(client, make_observation(sid, t="2026-11-05T10:00:25Z", up=400, down=4500,
                                   alerts=[make_alert(t="2026-11-05T10:00:25Z")], risk=50))
    t = client.get(f"/sessions/{sid}/timeline?interval_seconds=10").json()
    pts = t["points"]
    assert len(pts) == 3                                       # 0-10s, 10-20s, 20-30s
    assert (pts[0]["bytes_up"], pts[0]["bytes_down"]) == (300, 4000)
    assert (pts[1]["bytes_up"], pts[1]["risk_score"]) == (0, 20)   # empty bucket keeps last risk
    assert (pts[2]["bytes_up"], pts[2]["bytes_down"], pts[2]["risk_score"]) == (100, 500, 50)
    assert sum(p["new_connections"] for p in pts) == 3
    assert len(t["events"]) == 1 and t["events"][0]["severity"] == "medium"


def test_timeline_is_capped_for_long_sessions(client):
    sid = start_session(client)
    _send(client, make_observation(sid, t="2026-11-05T10:00:00Z"))
    _send(client, make_observation(sid, t="2026-11-05T12:00:00Z", up=2000, down=9000))  # 2 hours later
    t = client.get(f"/sessions/{sid}/timeline?interval_seconds=1").json()
    assert len(t["points"]) <= 500 and t["interval_seconds"] > 1


def test_alert_filters(client):
    sid = start_session(client)
    _send(client, make_observation(sid, alerts=[make_alert("medium", "observed"),
                                                make_alert("high", "inferred"),
                                                make_alert("low", "potential_risk")]))
    assert len(client.get(f"/sessions/{sid}/alerts").json()) == 3
    assert [a["severity"] for a in client.get(f"/sessions/{sid}/alerts?severity=high").json()] == ["high"]
    inferred = client.get(f"/sessions/{sid}/alerts?evidence_type=inferred").json()
    assert [a["evidence_type"] for a in inferred] == ["inferred"]
    assert client.get(f"/sessions/{sid}/alerts?severity=critical").status_code == 422


def test_dashboard_404s(client):
    for path in ["summary", "timeline", "alerts", "connections"]:
        assert client.get(f"/sessions/999/{path}").status_code == 404
