"""
serializers.py - turn database rows (SQLAlchemy objects) into API objects (Pydantic).

WHY a separate step: the DB row has internal columns (file_path, evidence_hash...)
that the dashboard should not see, and the API shape should not change just
because a column is renamed.
"""
from datetime import datetime, timezone

from app import models
from app.schemas import AlertOut, AppOut, ConnectionOut, InsightOut, ReportOut, SessionOut


def iso_utc(dt: datetime) -> str:
    """Format any datetime as UTC 'YYYY-MM-DDTHH:MM:SSZ' (naive = assumed UTC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def app_out(a: models.Application) -> AppOut:
    return AppOut(id=a.id, package_name=a.package_name, app_name=a.app_name)


def session_out(s: models.MonitoringSession) -> SessionOut:
    return SessionOut(id=s.id, app=app_out(s.application), status=s.status, device_label=s.device_label,
                      started_at=s.started_at, stopped_at=s.stopped_at, risk_score=s.risk_score,
                      is_mock=s.is_mock)


def connection_out(c: models.NetworkConnection) -> ConnectionOut:
    return ConnectionOut(id=c.id, session_id=c.session_id, domain=c.domain,
                         domain_source=c.domain_source, ip=c.ip, port=c.port,
                         protocol=c.protocol, bytes_up=c.bytes_up, bytes_down=c.bytes_down,
                         timestamp=c.timestamp, duration_ms=c.duration_ms, is_mock=c.is_mock)


def alert_out(a: models.SecurityAlert) -> AlertOut:
    return AlertOut(id=a.id, session_id=a.session_id, rule_id=a.rule_id, title=a.title,
                    description=a.description, severity=a.severity, evidence_type=a.evidence_type,
                    evidence=a.evidence or {}, related_domain=a.related_domain, related_ip=a.related_ip,
                    related_port=a.related_port, detected_at=a.detected_at, is_mock=a.is_mock)


def insight_out(i: models.AIInsight, cached: bool) -> InsightOut:
    return InsightOut(id=i.id, session_id=i.session_id, source=i.source, model=i.model, text=i.text,
                      evidence_used=i.evidence_used, cached=cached, created_at=i.created_at,
                      is_mock=i.is_mock)


def report_out(r: models.Report) -> ReportOut:
    return ReportOut(id=r.id, session_id=r.session_id, filename=r.filename,
                     download_url=f"/reports/{r.id}/download", created_at=r.created_at, is_mock=r.is_mock)
