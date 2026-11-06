"""Phase 4: Gemini insights - sanitization, caching, fallback, timeout. Gemini is always FAKED here."""
import time

import pytest

from app import config
from app.services import insights
from tests.conftest import AUTH, make_alert, make_observation, start_session


@pytest.fixture
def session_with_alert(client):
    sid = start_session(client)
    alert = make_alert("high", "inferred")
    alert["evidence"] = {"bytes_up": 9_800_000, "domain": "analytics.tracker.example",
                         "payload": "SECRET BODY", "user_email": "x@y.com", "note": "mail me at a@b.com",
                         "session_token": "abc", "hash": "A" * 40, "nested": {"a": 1}}
    alert["description"] = "Free text that must never reach Gemini"
    client.post("/observations", json=make_observation(sid, alerts=[alert], risk=65), headers=AUTH)
    return sid


@pytest.fixture
def fake_gemini(monkeypatch):
    """Pretend Gemini is configured and record every call."""
    calls = []

    def fake(evidence):
        calls.append(evidence)
        return "What was observed: 9.8 MB uploaded. What cannot be known: encrypted contents."

    monkeypatch.setattr(config, "GEMINI_API_KEY", "fake-key")
    monkeypatch.setattr(insights, "_call_gemini", fake)
    return calls


def test_insights_require_api_key(client, session_with_alert):
    assert client.post(f"/sessions/{session_with_alert}/insights").status_code == 401
    assert client.get(f"/sessions/{session_with_alert}/insights").status_code == 401


def test_no_key_gives_fallback_and_saves_record(client, session_with_alert):
    r = client.post(f"/sessions/{session_with_alert}/insights", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "fallback" and "no GEMINI_API_KEY configured" in body["text"]
    assert "cannot be known" in body["text"] and "malware" not in body["text"].lower()
    assert body["is_mock"] is True
    assert len(client.get(f"/sessions/{session_with_alert}/insights", headers=AUTH).json()) == 1


def test_evidence_is_sanitized(client, session_with_alert, fake_gemini):
    client.post(f"/sessions/{session_with_alert}/insights", headers=AUTH)
    sent = fake_gemini[0]
    ev = sent["alerts"][0]["evidence"]
    assert ev == {"bytes_up": 9_800_000, "domain": "analytics.tracker.example"}  # risky keys/values dropped
    flat = str(sent)
    for forbidden in ["SECRET BODY", "x@y.com", "a@b.com", "Free text", "AAAA"]:
        assert forbidden not in flat
    assert "description" not in sent["alerts"][0]


def test_gemini_success_then_cache_then_force_refresh(client, session_with_alert, fake_gemini):
    url = f"/sessions/{session_with_alert}/insights"
    first = client.post(url, headers=AUTH).json()
    assert first["source"] == "gemini" and first["cached"] is False and first["model"] == config.GEMINI_MODEL

    second = client.post(url, headers=AUTH).json()
    assert second["cached"] is True and second["id"] == first["id"]
    assert len(fake_gemini) == 1                      # Gemini was NOT called again

    third = client.post(url, json={"force_refresh": True}, headers=AUTH).json()
    assert third["cached"] is False and len(fake_gemini) == 2


def test_new_evidence_invalidates_cache(client, session_with_alert, fake_gemini):
    url = f"/sessions/{session_with_alert}/insights"
    client.post(url, headers=AUTH)
    client.post("/observations", json=make_observation(session_with_alert, up=5000, down=9000), headers=AUTH)
    assert client.post(url, headers=AUTH).json()["cached"] is False
    assert len(fake_gemini) == 2


def test_gemini_error_gives_fallback(client, session_with_alert, monkeypatch):
    def boom(evidence):
        raise RuntimeError("quota exceeded for fake-key")

    monkeypatch.setattr(config, "GEMINI_API_KEY", "fake-key")
    monkeypatch.setattr(insights, "_call_gemini", boom)
    body = client.post(f"/sessions/{session_with_alert}/insights", headers=AUTH).json()
    assert body["source"] == "fallback" and "Gemini request failed: RuntimeError" in body["text"]
    assert "fake-key" not in body["text"]             # the key is never leaked


def test_gemini_timeout_does_not_hang(client, session_with_alert, monkeypatch):
    def slow(evidence):
        time.sleep(3)
        return "too late"

    monkeypatch.setattr(config, "GEMINI_API_KEY", "fake-key")
    monkeypatch.setattr(config, "GEMINI_TIMEOUT_SECONDS", 0.5)
    monkeypatch.setattr(insights, "_call_gemini", slow)
    start = time.monotonic()
    body = client.post(f"/sessions/{session_with_alert}/insights", headers=AUTH).json()
    assert time.monotonic() - start < 2.5
    assert body["source"] == "fallback" and "timed out" in body["text"]


def test_banned_wording_is_rejected(client, session_with_alert, monkeypatch):
    monkeypatch.setattr(config, "GEMINI_API_KEY", "fake-key")
    monkeypatch.setattr(insights, "_call_gemini", lambda ev: "This app is clearly MALWARE.")
    body = client.post(f"/sessions/{session_with_alert}/insights", headers=AUTH).json()
    assert body["source"] == "fallback" and "malware" not in body["text"].lower().replace("disallowed", "")


def test_unknown_session_404(client):
    assert client.post("/sessions/999/insights", headers=AUTH).status_code == 404


def test_real_client_is_configured_without_retries_or_tool_calls(monkeypatch):
    """The SDK retries 4x by default; we must send exactly ONE request per call (free-plan quota)."""
    from google import genai
    captured = {}

    class FakeModels:
        def generate_content(self, **kwargs):
            captured["config"] = kwargs["config"]
            class R:
                text = "ok"
            return R()

    class FakeClient:
        def __init__(self, api_key, http_options):
            captured["http_options"] = http_options
            self.models = FakeModels()

    monkeypatch.setattr(config, "GEMINI_API_KEY", "fake-key")
    monkeypatch.setattr(genai, "Client", FakeClient)
    assert insights._call_gemini({"x": 1}) == "ok"          # no network: the client is fake
    assert captured["http_options"].retry_options.attempts == 1
    assert captured["config"].automatic_function_calling.disable is True   # no automatic tool calls
