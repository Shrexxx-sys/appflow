"""Phase 3: WebSocket live updates."""
from tests.conftest import AUTH, make_alert, make_observation, start_session


def test_ws_hello_then_observation_then_stop(client):
    sid = start_session(client)
    with client.websocket_connect(f"/ws/{sid}") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello" and hello["data"]["session_id"] == sid

        obs = make_observation(sid, t="2026-11-05T15:30:05+05:30", alerts=[make_alert()], risk=40)
        assert client.post("/observations", json=obs, headers=AUTH).status_code == 202
        msg = ws.receive_json()
        assert msg["type"] == "observation"
        assert msg["data"]["captured_at"] == "2026-11-05T10:00:05Z"   # converted to UTC
        assert msg["data"]["risk_score"] == 40
        assert len(msg["data"]["new_connections"]) == 1
        assert msg["data"]["new_alerts"][0]["evidence_type"] == "observed"

        client.post(f"/sessions/{sid}/stop", headers=AUTH)
        assert ws.receive_json()["type"] == "session_stopped"


def test_ws_ping_pong(client):
    sid = start_session(client)
    with client.websocket_connect(f"/ws/{sid}") as ws:
        ws.receive_json()  # hello
        ws.send_text("ping")
        assert ws.receive_json()["type"] == "pong"


def test_ws_unknown_session_gets_error(client):
    with client.websocket_connect("/ws/999") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error" and "not found" in msg["data"]["detail"]


def test_ws_only_receives_its_own_session(client):
    a, b = start_session(client), start_session(client)
    with client.websocket_connect(f"/ws/{a}") as ws:
        ws.receive_json()  # hello
        client.post("/observations", json=make_observation(b), headers=AUTH)  # other session
        client.post("/observations", json=make_observation(a), headers=AUTH)
        assert ws.receive_json()["session_id"] == a
