"""
insights.py - asks Gemini to EXPLAIN alerts in plain language.

Flow:
  1. build_evidence()  -> a small, SANITIZED summary (domains, ports, byte totals, counts, alerts).
                          No payloads, no free text from the phone, nothing that looks personal.
  2. fingerprint it    -> if we already explained the exact same evidence, return the saved answer (cache).
  3. call Gemini       -> with a hard timeout so the demo never hangs.
  4. if anything fails -> build a clear rule-based fallback text instead.
  5. ALWAYS save a record in ai_insights (gemini or fallback).

Gemini only EXPLAINS. Detection is done by Member 2's deterministic rules.
"""
import hashlib
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import config, models
from app.services.analytics import build_summary

log = logging.getLogger("appflow.insights")

# A background thread lets us stop WAITING after N seconds even if the SDK is stuck.
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="gemini")

SYSTEM_PROMPT = """You explain network-monitoring results for a security dashboard used by non-experts.
Rules you must follow:
- Only explain the evidence provided. Do not invent requests, data contents, or malicious intent.
- The tool only sees network METADATA (domains, IPs, ports, byte counts, timing). Encrypted contents are NOT visible; say so where relevant.
- Respect the evidence_type labels: call something "observed" only if it is labelled observed; present "inferred" items as inferences and "potential_risk" items as possibilities.
- Never call the app malware, spyware, or malicious. Use wording like "unusual behavior worth reviewing".
- If simulated_test_data is true, mention once that this is simulated test data.
- Plain, friendly language. At most 200 words. Use these four short headings:
  What was observed / What is inferred / What cannot be known / Suggested next steps"""

NOT_OBSERVABLE = [
    "the contents of encrypted connections (what data was actually sent or received)",
    "which screen or feature of the app triggered a connection",
    "the intent behind any connection",
]

# Words the output must never contain (project rule: never label an app as malware).
BANNED_WORDS = re.compile(r"\b(malware|spyware|virus|trojan)\b", re.IGNORECASE)

# --- sanitization helpers ---------------------------------------------------
_BLOCKED_KEY_PARTS = ("payload", "body", "content", "password", "passwd", "token", "cookie", "auth",
                      "secret", "email", "phone", "user", "header", "url", "query", "imei", "location",
                      "contact", "account")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")  # looks like a key/hash/session token


def _clean_value(v):
    """Keep only simple, short, non-personal values. Return None to drop the value."""
    if isinstance(v, bool) or isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        if len(v) > 100 or _EMAIL.search(v) or _LONG_TOKEN.search(v):
            return None
        return v
    if isinstance(v, list):
        cleaned = [c for c in (_clean_value(x) for x in v[:10]) if c is not None and not isinstance(c, list)]
        return cleaned or None
    return None  # nested dicts and anything else are dropped


def sanitize_evidence_dict(evidence: dict) -> dict:
    """Filter Member 2's per-alert evidence: drop risky keys and risky values."""
    out = {}
    for key, value in (evidence or {}).items():
        k = str(key).lower()
        if len(k) > 40 or any(part in k for part in _BLOCKED_KEY_PARTS):
            continue
        cleaned = _clean_value(value)
        if cleaned is not None:
            out[k] = cleaned
    return out


def build_evidence(db: Session, session: models.MonitoringSession) -> dict:
    """The ONLY data that is ever sent to Gemini. Notice: no descriptions, no device label."""
    summary = build_summary(db, session)
    C = models.NetworkConnection
    ports = db.execute(select(C.port, C.protocol, func.count(C.id)).where(C.session_id == session.id)
                       .group_by(C.port, C.protocol).order_by(func.count(C.id).desc()).limit(10))
    alerts = db.scalars(select(models.SecurityAlert).where(models.SecurityAlert.session_id == session.id)
                        .order_by(models.SecurityAlert.detected_at, models.SecurityAlert.id).limit(20))
    return {
        "app_package": summary.app.package_name,
        "simulated_test_data": session.is_mock,
        "session_status": summary.status.value,
        "total_bytes_up": summary.total_bytes_up,
        "total_bytes_down": summary.total_bytes_down,
        "total_connections": summary.total_connections,
        "unique_domains": summary.unique_domains,
        "risk_score": summary.risk_score,
        "risk_level": summary.risk_level.value if summary.risk_level else None,
        "top_domains": [d.model_dump() for d in summary.top_domains],
        "ports_used": [{"port": p, "protocol": proto, "connection_count": n} for p, proto, n in ports],
        "alerts": [{
            "rule_id": a.rule_id, "title": a.title[:120], "severity": a.severity,
            "evidence_type": a.evidence_type, "related_domain": a.related_domain,
            "related_port": a.related_port, "evidence": sanitize_evidence_dict(a.evidence),
        } for a in alerts],
        "not_observable": NOT_OBSERVABLE,
    }


def evidence_hash(evidence: dict) -> str:
    """Same evidence -> same 64-char fingerprint. sort_keys makes key order irrelevant."""
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode()).hexdigest()


# --- Gemini call ------------------------------------------------------------

def _call_gemini(evidence: dict) -> str:
    """Real network call. Kept tiny so tests can replace it with a fake."""
    from google import genai  # imported here so the app still starts if the package is missing
    from google.genai import types

    # attempts=1 -> NO automatic retries. The SDK otherwise retries up to 4 extra times on 429/503,
    # which would silently burn the free-plan quota. On failure we use the fallback text instead.
    client = genai.Client(api_key=config.GEMINI_API_KEY,
                          http_options=types.HttpOptions(timeout=int(config.GEMINI_TIMEOUT_SECONDS * 1000),
                                                         retry_options=types.HttpRetryOptions(attempts=1)))
    response = client.models.generate_content(
        model=config.GEMINI_MODEL,
        contents="Evidence (JSON):\n" + json.dumps(evidence, indent=2),
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT, temperature=0.2,
            # No automatic tool/function calling: one plain request in, one text answer out.
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True)),
    )
    return (response.text or "").strip()


def _safe_error(e: Exception) -> str:
    """Short error text for the DB, never containing the API key."""
    msg = f"{type(e).__name__}: {e}"
    if config.GEMINI_API_KEY:
        msg = msg.replace(config.GEMINI_API_KEY, "***")
    return msg[:250]


def ask_gemini(evidence: dict) -> tuple[str | None, str | None]:
    """Returns (text, None) on success or (None, reason) on any failure. Never raises."""
    if not config.GEMINI_API_KEY:
        return None, "no GEMINI_API_KEY configured"
    future = _executor.submit(_call_gemini, evidence)
    try:
        text = future.result(timeout=config.GEMINI_TIMEOUT_SECONDS)
    except FutureTimeout:
        return None, f"Gemini timed out after {config.GEMINI_TIMEOUT_SECONDS:g}s"
    except Exception as e:  # bad key, quota, network, unknown model name...
        # Full detail goes to the server console (for you); the user gets a short reason.
        log.warning("Gemini call failed: %s", _safe_error(e))
        code = getattr(e, "code", None)
        return None, f"Gemini request failed: {type(e).__name__}" + (f" {code}" if code else "")
    if not text:
        return None, "Gemini returned an empty response"
    if BANNED_WORDS.search(text):
        return None, "Gemini response used disallowed wording"
    return text, None


# --- fallback ---------------------------------------------------------------

def _mb(n: int) -> str:
    return f"{n / 1_000_000:.1f} MB"


def fallback_text(evidence: dict, reason: str) -> str:
    """A rule-based explanation built only from the evidence, so the user still gets something useful."""
    alerts = evidence["alerts"]
    lines = [f"AI explanation unavailable ({reason}). Automatic summary of the evidence:", "", "What was observed:"]
    lines.append(f"- The app sent {_mb(evidence['total_bytes_up'])} and received {_mb(evidence['total_bytes_down'])} "
                 f"over {evidence['total_connections']} connections to {evidence['unique_domains']} domains.")
    if evidence["top_domains"]:
        tops = ", ".join(f"{d['domain']} ({_mb(d['bytes_up'] + d['bytes_down'])})" for d in evidence["top_domains"][:3])
        lines.append(f"- Top destinations: {tops}.")
    for label, kind in (("What was observed", "observed"), ("What is inferred", "inferred"),
                        ("Potential risks", "potential_risk")):
        items = [a for a in alerts if a["evidence_type"] == kind]
        if kind != "observed" and items:
            lines += ["", f"{label}:"]
        lines += [f"- {a['title']} (severity: {a['severity']})" for a in items]
    lines += ["", "What cannot be known:"] + [f"- {x}" for x in evidence["not_observable"]]
    if evidence.get("simulated_test_data"):
        lines += ["", "Note: this session uses simulated test data."]
    lines += ["", "These findings describe unusual behavior worth reviewing, not proof of wrongdoing."]
    return "\n".join(lines)


# --- main entry point -------------------------------------------------------

def get_or_create_insight(db: Session, session: models.MonitoringSession,
                          force_refresh: bool = False) -> tuple[models.AIInsight, bool]:
    """Returns (insight_row, was_cached)."""
    evidence = build_evidence(db, session)
    fingerprint = evidence_hash(evidence)

    if not force_refresh:
        cached = db.scalar(select(models.AIInsight)
                           .where(models.AIInsight.session_id == session.id,
                                  models.AIInsight.evidence_hash == fingerprint)
                           .order_by(models.AIInsight.id.desc()).limit(1))
        # Reuse a Gemini answer; reuse a fallback only if Gemini still isn't configured.
        if cached and (cached.source == "gemini" or not config.GEMINI_API_KEY):
            return cached, True

    text, error = ask_gemini(evidence)
    row = models.AIInsight(
        session_id=session.id, evidence_used=evidence, evidence_hash=fingerprint, is_mock=session.is_mock,
        source="gemini" if text else "fallback",
        model=config.GEMINI_MODEL if text else None,
        text=text or fallback_text(evidence, error),
        error=error,
    )
    db.add(row)
    db.commit()
    return row, False


def latest_insight(db: Session, session_id: int) -> models.AIInsight | None:
    return db.scalar(select(models.AIInsight).where(models.AIInsight.session_id == session_id)
                     .order_by(models.AIInsight.id.desc()).limit(1))
