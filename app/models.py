"""
models.py - the 7 database tables.

How they relate (1 -> many means "one row here owns many rows there"):

    applications 1 ──> many monitoring_sessions
    monitoring_sessions 1 ──> many network_connections   (every connection seen)
                          ──> many traffic_statistics    (one snapshot per POST /observations)
                          ──> many security_alerts       (findings from Member 2's rules)
                          ──> many ai_insights           (Gemini / fallback explanations)
                          ──> many reports               (generated PDFs)

cascade="all, delete-orphan" means: delete a session -> all its child rows
are deleted too. That is what makes DELETE /sessions/{id} a real privacy wipe.
"""
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, UTCDateTime


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Application(Base):
    """An installed Android app that was monitored at least once."""
    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(primary_key=True)
    package_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)  # e.g. com.example.demoshop
    app_name: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    sessions: Mapped[list["MonitoringSession"]] = relationship(back_populates="application")


class MonitoringSession(Base):
    """One START -> STOP monitoring run."""
    __tablename__ = "monitoring_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(ForeignKey("applications.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="active")  # "active" | "stopped"
    device_label: Mapped[str | None] = mapped_column(String(100))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    stopped_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    risk_score: Mapped[int | None] = mapped_column(Integer)  # latest score from Member 2
    is_mock: Mapped[bool] = mapped_column(Boolean, default=False)

    application: Mapped[Application] = relationship(back_populates="sessions")
    connections: Mapped[list["NetworkConnection"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True)
    statistics: Mapped[list["TrafficStatistic"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True)
    alerts: Mapped[list["SecurityAlert"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True)
    insights: Mapped[list["AIInsight"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True)
    reports: Mapped[list["Report"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True)


class NetworkConnection(Base):
    """One connection: who the app talked to, on which port, how many bytes."""
    __tablename__ = "network_connections"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("monitoring_sessions.id", ondelete="CASCADE"))
    domain: Mapped[str | None] = mapped_column(String(255))  # null if no domain name was observable
    domain_source: Mapped[str | None] = mapped_column(String(16))  # dns | sni | unavailable
    ip: Mapped[str] = mapped_column(String(45))  # 45 chars fits IPv6
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8))
    bytes_up: Mapped[int] = mapped_column(Integer, default=0)
    bytes_down: Mapped[int] = mapped_column(Integer, default=0)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    is_mock: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped[MonitoringSession] = relationship(back_populates="connections")

    # An index makes "all connections of session X, by time" fast.
    __table_args__ = (Index("ix_conn_session_time", "session_id", "timestamp"),)


class TrafficStatistic(Base):
    """
    A snapshot of the CUMULATIVE totals at one moment (one row per observation batch).
    The timeline is built from the differences between consecutive snapshots.
    """
    __tablename__ = "traffic_statistics"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("monitoring_sessions.id", ondelete="CASCADE"))
    captured_at: Mapped[datetime] = mapped_column(UTCDateTime)
    total_bytes_up: Mapped[int] = mapped_column(Integer)
    total_bytes_down: Mapped[int] = mapped_column(Integer)
    total_connections: Mapped[int] = mapped_column(Integer)
    unique_domains: Mapped[int] = mapped_column(Integer)
    new_connections: Mapped[int] = mapped_column(Integer, default=0)  # how many arrived in this batch
    risk_score: Mapped[int | None] = mapped_column(Integer)
    is_mock: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped[MonitoringSession] = relationship(back_populates="statistics")

    __table_args__ = (Index("ix_stats_session_time", "session_id", "captured_at"),)


class SecurityAlert(Base):
    """A finding from Member 2's deterministic rules. We store it, we never re-detect."""
    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("monitoring_sessions.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(8))         # low | medium | high
    evidence_type: Mapped[str] = mapped_column(String(16))   # observed | inferred | potential_risk | not_observable
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)  # stored as JSON text
    related_domain: Mapped[str | None] = mapped_column(String(255))
    related_ip: Mapped[str | None] = mapped_column(String(45))
    related_port: Mapped[int | None] = mapped_column(Integer)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime)
    is_mock: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped[MonitoringSession] = relationship(back_populates="alerts")


class AIInsight(Base):
    """An explanation of the alerts. Also works as the CACHE (see evidence_hash)."""
    __tablename__ = "ai_insights"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("monitoring_sessions.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(16))  # "gemini" | "fallback"
    model: Mapped[str | None] = mapped_column(String(64))
    text: Mapped[str] = mapped_column(Text)
    evidence_used: Mapped[dict] = mapped_column(JSON)  # the sanitized input, for transparency
    # Fingerprint of evidence_used. Same evidence -> same hash -> reuse the old answer.
    evidence_hash: Mapped[str] = mapped_column(String(64), index=True)
    error: Mapped[str | None] = mapped_column(String(300))  # why we fell back, if we did
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    is_mock: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped[MonitoringSession] = relationship(back_populates="insights")


class Report(Base):
    """A generated PDF file on disk."""
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("monitoring_sessions.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    is_mock: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped[MonitoringSession] = relationship(back_populates="reports")
