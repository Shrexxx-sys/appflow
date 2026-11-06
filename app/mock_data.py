"""
mock_data.py - FAKE data so Member 4 can build the dashboard on Day 1.

Every object here has is_mock=True. All IPs are from documentation-only
ranges (192.0.2.x, 198.51.100.x, 203.0.113.x) and all domains end in
".example", so nothing points at a real company.

The numbers are internally consistent: per-domain bytes add up to the
session totals (172.2 MB down, 12.4 MB up), like the example from Member 2.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from app.schemas import (AlertCounts, AlertOut, AppOut, ConnectionOut, DomainStat,
                         InsightOut, SessionOut, SessionSummary, Severity, Timeline,
                         TimelineEvent, TimelinePoint)

# Each traffic row: (domain, ip, port, protocol, total_bytes_up, total_bytes_down, n_connections)
# domain=None means "no DNS name was seen for this IP".
DEMOSHOP_TRAFFIC = [
    ("api.demoshop.example",      "198.51.100.10", 443,  "TCP", 1_900_000,  38_000_000, 6),
    ("cdn.demoshop.example",      "198.51.100.20", 443,  "TCP",   400_000, 121_500_000, 5),
    ("analytics.tracker.example", "203.0.113.7",   443,  "TCP", 9_800_000,     600_000, 8),
    ("ads.adnetwork.example",     "203.0.113.30",  443,  "UDP",   200_000,  11_900_000, 3),
    ("dns.resolver.example",      "192.0.2.53",    53,   "UDP",    20_000,      60_000, 4),
    (None,                        "203.0.113.45",  7777, "TCP",    80_000,     140_000, 2),
]

NOTES_TRAFFIC = [
    ("sync.notesapp.example", "198.51.100.40", 443, "TCP", 150_000, 900_000, 4),
    ("dns.resolver.example",  "192.0.2.53",    53,  "UDP",   4_000,  12_000, 2),
]

T0 = datetime(2026, 11, 5, 10, 0, 0, tzinfo=timezone.utc)

MOCK_SESSIONS = {
    1: {
        "app": AppOut(id=1, package_name="com.example.demoshop", app_name="DemoShop"),
        "status": "stopped",
        "device_label": "Pixel 7 (mock)",
        "started_at": T0,
        "duration_seconds": 600,  # 10 minutes
        "risk_score": 65,
        "traffic": DEMOSHOP_TRAFFIC,
    },
    2: {
        "app": AppOut(id=2, package_name="com.example.notesapp", app_name="NotesApp"),
        "status": "active",
        "device_label": "Pixel 7 (mock)",
        "started_at": T0 + timedelta(minutes=30),
        "duration_seconds": 240,  # 4 minutes so far
        "risk_score": 12,
        "traffic": NOTES_TRAFFIC,
    },
}

# Alerts only for session 1: two medium + one high (matches Member 2's example).
# Note the careful wording: no "malware", and we say what we CANNOT see.
MOCK_ALERTS = {
    1: [
        dict(rule_id="R01_PERIODIC_CONNECTIONS", severity="medium", evidence_type="observed",
             title="Repeated periodic connections to one domain",
             description=("analytics.tracker.example was contacted 8 times at roughly 75-second "
                          "intervals. The timing pattern is observed; whether the user triggered "
                          "these calls cannot be determined from network metadata."),
             evidence={"domain": "analytics.tracker.example", "count": 8, "avg_interval_seconds": 75},
             related_domain="analytics.tracker.example", related_ip="203.0.113.7", related_port=443,
             offset_s=190),
        dict(rule_id="R02_UNCOMMON_PORT", severity="medium", evidence_type="observed",
             title="Connection on an uncommon port",
             description=("TCP connections to 203.0.113.45 on port 7777. No DNS name was seen for "
                          "this IP. Uncommon ports are not harmful by themselves but are worth reviewing."),
             evidence={"ip": "203.0.113.45", "port": 7777, "protocol": "TCP", "count": 2,
                       "dns_name_seen": False},
             related_domain=None, related_ip="203.0.113.45", related_port=7777,
             offset_s=310),
        dict(rule_id="R03_HIGH_UPLOAD_THIRD_PARTY", severity="high", evidence_type="inferred",
             title="High upload volume to a likely third-party domain",
             description=("9.8 MB was uploaded to analytics.tracker.example (79% of all upload), about "
                          "16x what was downloaded from it. The domain does not match the app's own "
                          "domain, so it is INFERRED to be third-party. What data was uploaded cannot "
                          "be observed because the traffic is encrypted. Unusual behavior worth reviewing."),
             evidence={"domain": "analytics.tracker.example", "bytes_up": 9_800_000,
                       "bytes_down": 600_000, "share_of_total_upload_pct": 79},
             related_domain="analytics.tracker.example", related_ip="203.0.113.7", related_port=443,
             offset_s=480),
    ],
}


def _risk_level(score: int | None) -> Severity | None:
    """Proposed display thresholds (to confirm with Member 2): 0-39 low, 40-69 medium, 70+ high."""
    if score is None:
        return None
    if score >= 70:
        return Severity.high
    if score >= 40:
        return Severity.medium
    return Severity.low


# ---------------------------------------------------------------------------
# Public helper functions used by routers/mock.py
# ---------------------------------------------------------------------------

def get_session(session_id: int) -> SessionOut | None:
    s = MOCK_SESSIONS.get(session_id)
    if s is None:
        return None
    stopped = s["started_at"] + timedelta(seconds=s["duration_seconds"]) if s["status"] == "stopped" else None
    return SessionOut(id=session_id, app=s["app"], status=s["status"], device_label=s["device_label"],
                      started_at=s["started_at"], stopped_at=stopped, risk_score=s["risk_score"], is_mock=True)


def list_sessions() -> list[SessionOut]:
    return [get_session(sid) for sid in MOCK_SESSIONS]


def get_connections(session_id: int) -> list[ConnectionOut]:
    """Split each traffic row into N connections spread evenly over the session."""
    s = MOCK_SESSIONS[session_id]
    rows = []
    for d_idx, (domain, ip, port, proto, up, down, n) in enumerate(s["traffic"]):
        for k in range(n):
            # last connection gets the remainder so the sum is exact
            part_up = up // n + (up % n if k == n - 1 else 0)
            part_down = down // n + (down % n if k == n - 1 else 0)
            offset = int(s["duration_seconds"] * (k + 0.5) / n) + d_idx * 3
            rows.append((s["started_at"] + timedelta(seconds=offset), domain, ip, port, proto,
                         part_up, part_down))
    rows.sort(key=lambda r: r[0])  # oldest first
    return [
        ConnectionOut(id=session_id * 1000 + i, session_id=session_id, domain=dom, ip=ip, port=port,
                      protocol=proto, bytes_up=bu, bytes_down=bd, timestamp=ts,
                      duration_ms=400 + (i * 137) % 2000, is_mock=True)
        for i, (ts, dom, ip, port, proto, bu, bd) in enumerate(rows, start=1)
    ]


def get_alerts(session_id: int) -> list[AlertOut]:
    s = MOCK_SESSIONS[session_id]
    out = []
    for i, a in enumerate(MOCK_ALERTS.get(session_id, []), start=1):
        a = dict(a)
        offset = a.pop("offset_s")
        out.append(AlertOut(id=session_id * 100 + i, session_id=session_id,
                            detected_at=s["started_at"] + timedelta(seconds=offset), is_mock=True, **a))
    return out


def get_summary(session_id: int) -> SessionSummary:
    s = MOCK_SESSIONS[session_id]
    sess = get_session(session_id)
    conns = get_connections(session_id)
    alerts = get_alerts(session_id)

    # Group bytes by domain (fall back to IP when no domain was seen).
    per_domain = defaultdict(lambda: {"bytes_up": 0, "bytes_down": 0, "connection_count": 0})
    for c in conns:
        key = c.domain or c.ip
        per_domain[key]["bytes_up"] += c.bytes_up
        per_domain[key]["bytes_down"] += c.bytes_down
        per_domain[key]["connection_count"] += 1
    top = sorted(per_domain.items(), key=lambda kv: kv[1]["bytes_up"] + kv[1]["bytes_down"], reverse=True)

    counts = AlertCounts()
    for a in alerts:
        setattr(counts, a.severity.value, getattr(counts, a.severity.value) + 1)
    counts.total = len(alerts)

    return SessionSummary(
        session_id=session_id, app=sess.app, status=sess.status,
        started_at=sess.started_at, stopped_at=sess.stopped_at,
        duration_seconds=s["duration_seconds"],
        total_bytes_up=sum(c.bytes_up for c in conns),
        total_bytes_down=sum(c.bytes_down for c in conns),
        total_connections=len(conns),
        unique_domains=len({c.domain for c in conns if c.domain}),
        risk_score=s["risk_score"], risk_level=_risk_level(s["risk_score"]),
        alert_counts=counts,
        top_domains=[DomainStat(domain=d, **v) for d, v in top[:5]],
        is_mock=True,
    )


def get_timeline(session_id: int, interval_seconds: int = 60) -> Timeline:
    s = MOCK_SESSIONS[session_id]
    conns = get_connections(session_id)
    alerts = get_alerts(session_id)
    n_points = max(1, s["duration_seconds"] // interval_seconds)

    points = []
    for i in range(n_points):
        start = s["started_at"] + timedelta(seconds=i * interval_seconds)
        end = start + timedelta(seconds=interval_seconds)
        in_bucket = [c for c in conns if start <= c.timestamp < end]
        # Mock risk curve: grows as alerts appear, ending at the final score.
        seen = sum(1 for a in alerts if a.detected_at < end)
        risk = s["risk_score"] if not alerts else round(10 + (s["risk_score"] - 10) * seen / len(alerts))
        points.append(TimelinePoint(timestamp=start, bytes_up=sum(c.bytes_up for c in in_bucket),
                                    bytes_down=sum(c.bytes_down for c in in_bucket),
                                    new_connections=len(in_bucket), risk_score=risk))

    events = [TimelineEvent(timestamp=a.detected_at, alert_id=a.id, title=a.title, severity=a.severity)
              for a in alerts]
    return Timeline(session_id=session_id, interval_seconds=interval_seconds,
                    points=points, events=events, is_mock=True)


def get_insight(session_id: int) -> InsightOut:
    """A pre-written explanation in the same style Gemini will be asked to use."""
    summary = get_summary(session_id)
    evidence = {
        "app": summary.app.package_name,
        "total_bytes_up": summary.total_bytes_up,
        "total_bytes_down": summary.total_bytes_down,
        "top_domains": [d.model_dump() for d in summary.top_domains],
        "alerts": [{"title": a.title, "severity": a.severity.value, "evidence_type": a.evidence_type.value,
                    "evidence": a.evidence} for a in get_alerts(session_id)],
    }
    if summary.alert_counts.total == 0:
        text = ("MOCK INSIGHT: No alerts were raised for this session. Traffic went mainly to the app's "
                "own sync domain. Encrypted contents cannot be observed.")
    else:
        text = (
            "MOCK INSIGHT (not generated by Gemini).\n\n"
            "Observed: most download traffic (about 121.5 MB) came from cdn.demoshop.example, which "
            "matches the app's own domain and is typical for images or media.\n\n"
            "Worth reviewing: analytics.tracker.example received 9.8 MB of uploads, the largest share of "
            "all upload traffic, through 8 connections at regular ~75-second intervals. That the domain "
            "is third-party is inferred from its name. Two connections also used TCP port 7777 to an IP "
            "with no DNS name.\n\n"
            "Cannot be observed: the contents of these connections are encrypted, so we cannot tell what "
            "data was sent or why. This is unusual behavior worth reviewing, not proof of wrongdoing."
        )
    return InsightOut(id=session_id * 10 + 1, session_id=session_id, source="mock", model=None, text=text,
                      evidence_used=evidence, cached=True,
                      created_at=MOCK_SESSIONS[session_id]["started_at"] + timedelta(minutes=11),
                      is_mock=True)
