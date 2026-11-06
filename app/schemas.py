"""
schemas.py  -  THE JSON CONTRACT
=================================
Every request body and every response of the API is described here as a
Pydantic model.

WHY: FastAPI uses these classes to
  1. validate incoming JSON (wrong type / missing field -> automatic 422 error),
  2. shape outgoing JSON,
  3. generate the interactive docs at /docs.
So this file is the single source of truth that Member 2 and Member 4 code against.

Conventions (shared with teammates):
  * All timestamps are ISO-8601 in UTC, e.g. "2026-11-05T10:00:00Z".
  * All byte counts are integers in BYTES (not MB). The dashboard formats them.
  * Every object the backend returns has "is_mock" so fake data is never
    mistaken for real data.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


# ---------------------------------------------------------------------------
# Enums: a fixed list of allowed values. Anything else -> 422 error.
# ---------------------------------------------------------------------------

class EvidenceType(str, Enum):
    """How sure are we? (project rule #1: never label a guess as 'observed')"""
    observed = "observed"              # directly seen in metadata (an IP, a port, a byte count)
    inferred = "inferred"              # a conclusion drawn from observed facts
    potential_risk = "potential_risk"  # something that *could* be a problem, not proven
    not_observable = "not_observable"  # we cannot see this (e.g. encrypted contents)


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class SessionStatus(str, Enum):
    active = "active"
    stopped = "stopped"


class DomainSource(str, Enum):
    """HOW we know the domain name of a connection."""
    dns = "dns"                  # seen in a DNS response for this IP
    sni = "sni"                  # seen in the TLS ClientHello (Server Name Indication)
    unavailable = "unavailable"  # not observable (e.g. encrypted DNS / ECH)


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


# ---------------------------------------------------------------------------
# INPUT models  (what Android app / Member 2 SEND to the backend)
# ---------------------------------------------------------------------------

class SessionCreate(BaseModel):
    """Body of POST /sessions - the Android app starts monitoring an app."""
    package_name: str = Field(..., min_length=1, max_length=255, examples=["com.example.demoshop"])
    app_name: str | None = Field(None, max_length=255, examples=["DemoShop"])
    device_label: str | None = Field(None, max_length=100, examples=["Pixel 7 (team phone)"])
    is_mock: bool = False


class ConnectionIn(BaseModel):
    """One network connection seen by the analysis engine."""
    domain: str | None = Field(None, max_length=255, description="null if no domain name was observable")
    domain_source: DomainSource | None = Field(None, description="dns | sni | unavailable (optional)")
    ip: IPvAnyAddress = Field(..., description="IPv4 or IPv6")
    port: int = Field(..., ge=0, le=65535)
    protocol: Protocol
    bytes_up: int = Field(0, ge=0, description="bytes sent by the phone")
    bytes_down: int = Field(0, ge=0, description="bytes received by the phone")
    timestamp: datetime = Field(..., description="when the connection started (UTC)")
    duration_ms: int | None = Field(None, ge=0)


class StatsIn(BaseModel):
    """
    CUMULATIVE totals for the whole session so far (not just this batch).
    WHY cumulative: if one batch is lost on bad Wi-Fi, the next batch still
    carries the correct totals. The backend computes per-interval deltas itself.
    """
    total_bytes_up: int = Field(..., ge=0)
    total_bytes_down: int = Field(..., ge=0)
    total_connections: int = Field(..., ge=0)
    unique_domains: int = Field(..., ge=0)


class AlertIn(BaseModel):
    """One finding produced by Member 2's deterministic rules."""
    rule_id: str = Field(..., max_length=64, examples=["R02_UNCOMMON_PORT"])
    title: str = Field(..., max_length=200)
    description: str = Field(..., max_length=2000)
    severity: Severity
    evidence_type: EvidenceType
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Metadata facts behind the alert, e.g. {'port': 7777, 'count': 2}. Never payloads.",
    )
    related_domain: str | None = None
    related_ip: str | None = None
    related_port: int | None = Field(None, ge=0, le=65535)
    detected_at: datetime


class ObservationIn(BaseModel):
    """
    Body of POST /observations. Member 2 sends one of these every few seconds.
    connections = only NEW connections since the previous batch.
    alerts      = only NEW alerts since the previous batch.
    stats       = cumulative totals (see StatsIn).
    """
    session_id: int
    captured_at: datetime
    risk_score: int | None = Field(None, ge=0, le=100)
    stats: StatsIn
    connections: list[ConnectionIn] = Field(default_factory=list, max_length=1000)
    alerts: list[AlertIn] = Field(default_factory=list, max_length=100)
    is_mock: bool = False

    # This example shows up in /docs so teammates can copy it.
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "session_id": 1,
        "captured_at": "2026-11-05T10:05:00Z",
        "risk_score": 65,
        "stats": {"total_bytes_up": 12400000, "total_bytes_down": 172200000,
                  "total_connections": 28, "unique_domains": 5},
        "connections": [{
            "domain": "api.demoshop.example", "ip": "198.51.100.10", "port": 443,
            "protocol": "TCP", "bytes_up": 3100, "bytes_down": 48200,
            "timestamp": "2026-11-05T10:04:58Z", "duration_ms": 850}],
        "alerts": [{
            "rule_id": "R02_UNCOMMON_PORT", "title": "Connection on an uncommon port",
            "description": "TCP connection to 203.0.113.45 on port 7777 with no DNS name.",
            "severity": "medium", "evidence_type": "observed",
            "evidence": {"port": 7777, "ip": "203.0.113.45", "count": 2},
            "related_domain": None, "related_ip": "203.0.113.45", "related_port": 7777,
            "detected_at": "2026-11-05T10:04:59Z"}],
        "is_mock": True,
    }]})


class InsightRequest(BaseModel):
    """Optional body of POST /sessions/{id}/insights."""
    force_refresh: bool = Field(False, description="true = ignore cache and ask Gemini again")


# ---------------------------------------------------------------------------
# OUTPUT models  (what the backend RETURNS, mostly to Member 4's dashboard)
# ---------------------------------------------------------------------------

class AppOut(BaseModel):
    id: int
    package_name: str
    app_name: str | None


class SessionOut(BaseModel):
    id: int
    app: AppOut
    status: SessionStatus
    device_label: str | None
    started_at: datetime
    stopped_at: datetime | None
    risk_score: int | None
    is_mock: bool


class ObservationAck(BaseModel):
    """Reply to POST /observations so Member 2 knows what was saved."""
    accepted: bool
    session_id: int
    connections_saved: int
    alerts_saved: int
    received_at: datetime
    is_mock: bool


class ConnectionOut(BaseModel):
    id: int
    session_id: int
    domain: str | None
    domain_source: DomainSource | None = None
    ip: str
    port: int
    protocol: Protocol
    bytes_up: int
    bytes_down: int
    timestamp: datetime
    duration_ms: int | None
    is_mock: bool


class AlertOut(BaseModel):
    id: int
    session_id: int
    rule_id: str
    title: str
    description: str
    severity: Severity
    evidence_type: EvidenceType
    evidence: dict[str, Any]
    related_domain: str | None
    related_ip: str | None
    related_port: int | None
    detected_at: datetime
    is_mock: bool


class DomainStat(BaseModel):
    domain: str = Field(..., description="domain name, or the raw IP if no domain was seen")
    bytes_up: int
    bytes_down: int
    connection_count: int


class AlertCounts(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0
    total: int = 0


class SessionSummary(BaseModel):
    """GET /sessions/{id}/summary - everything the dashboard's top cards need."""
    session_id: int
    app: AppOut
    status: SessionStatus
    started_at: datetime
    stopped_at: datetime | None
    duration_seconds: int
    total_bytes_up: int
    total_bytes_down: int
    total_connections: int
    unique_domains: int
    risk_score: int | None
    risk_level: Severity | None = Field(
        None, description="Display label from risk_score: 0-39 low, 40-69 medium, 70-100 high (proposed thresholds)")
    alert_counts: AlertCounts
    top_domains: list[DomainStat]
    is_mock: bool


class TimelinePoint(BaseModel):
    """One point on the traffic chart (bytes are for THAT interval, not cumulative)."""
    timestamp: datetime
    bytes_up: int
    bytes_down: int
    new_connections: int
    risk_score: int | None


class TimelineEvent(BaseModel):
    """A marker on the chart where an alert happened."""
    timestamp: datetime
    alert_id: int
    title: str
    severity: Severity


class Timeline(BaseModel):
    session_id: int
    interval_seconds: int
    points: list[TimelinePoint]
    events: list[TimelineEvent]
    is_mock: bool


class InsightOut(BaseModel):
    """An AI explanation. 'source' tells the UI where the text came from."""
    id: int
    session_id: int
    source: Literal["gemini", "fallback", "mock"]
    model: str | None
    text: str
    evidence_used: dict[str, Any] = Field(
        ..., description="The exact SANITIZED summary that was sent to Gemini (for transparency)")
    cached: bool
    created_at: datetime
    is_mock: bool


class ReportOut(BaseModel):
    id: int
    session_id: int
    filename: str
    download_url: str
    created_at: datetime
    is_mock: bool


class DeleteResult(BaseModel):
    deleted: bool
    session_id: int
    rows_deleted: dict[str, int]
    is_mock: bool


class SessionDiff(BaseModel):
    """Session B minus session A (positive = B is bigger)."""
    total_bytes_up: int
    total_bytes_down: int
    total_connections: int
    alerts_total: int
    risk_score: int | None


class CompareOut(BaseModel):
    """GET /compare - e.g. the same app before and after changing its permissions."""
    session_a: SessionSummary
    session_b: SessionSummary
    difference_b_minus_a: SessionDiff
    domains_only_in_a: list[str]
    domains_only_in_b: list[str]
    domains_in_both: list[str]
    alert_rules_only_in_a: list[str]
    alert_rules_only_in_b: list[str]
    is_mock: bool


class HealthOut(BaseModel):
    status: str
    version: str
    time: datetime
    mode: Literal["mock", "database"]
    database: Literal["ok", "error"] = "ok"
    gemini_configured: bool = False
