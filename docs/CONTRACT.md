# AppFlow Sentinel – API Contract (v1.0)

The full live, clickable version is at **`http://<backend-laptop-ip>:8000/docs`**.
If this file and `/docs` disagree, `/docs` is correct (it is generated from `app/schemas.py`).

## General rules
| Rule | Detail |
|---|---|
| Timestamps | ISO-8601. Send any time zone; the backend stores UTC and returns `"...Z"`. A timestamp **without** a zone is assumed to be UTC. |
| Bytes | Integers in **bytes** (172.2 MB → `172200000`). The dashboard formats them. |
| `is_mock` | Every response object has it. `true` = fake/simulated data. |
| Auth | Header `X-API-Key: <key>` (ask Member 3). Required on all writes, insights, reports, delete. |
| Errors | `{"detail": "..."}`. 400 bad combination · 401 bad/missing key · 404 unknown id · 409 session already stopped · 422 invalid JSON (`detail` is a list showing which field is wrong) · 500 server bug (short message, details in server log) |
| `evidence_type` | One of `observed`, `inferred`, `potential_risk`, `not_observable`. Anything else gets a 422. |
| Wording | Never "malware". Use "unusual behavior worth reviewing". |
| Mock data | Fake data for UI work lives under **`/mock/...`** with the same shapes (e.g. `GET /mock/sessions/1/summary`). |

---

## Part A – What Member 1 / Member 2 SEND

### `POST /sessions`  (auth) – user taps START
```json
{ "package_name": "com.example.demoshop", "app_name": "DemoShop",
  "device_label": "Pixel 7", "is_mock": false }
```
→ `201` with a **Session** object (see Part B). Keep the returned `id`.
Monitoring the same `package_name` again re-uses the same `app.id`.

### `POST /sessions/{id}/stop`  (auth) – user taps STOP
No body. → `200` Session with `status: "stopped"`. Safe to call twice.

### `POST /observations`  (auth) – Member 2, every 1–5 seconds
```json
{
  "session_id": 1,
  "captured_at": "2026-11-05T10:05:00Z",
  "risk_score": 65,
  "stats": { "total_bytes_up": 12400000, "total_bytes_down": 172200000,
             "total_connections": 28, "unique_domains": 5 },
  "connections": [
    { "domain": "api.demoshop.example", "ip": "198.51.100.10", "port": 443,
      "protocol": "TCP", "bytes_up": 3100, "bytes_down": 48200,
      "timestamp": "2026-11-05T10:04:58Z", "duration_ms": 850, "domain_source": "sni" }
  ],
  "alerts": [
    { "rule_id": "R02_UNCOMMON_PORT", "title": "Connection on an uncommon port",
      "description": "TCP connection to 203.0.113.45 on port 7777 with no DNS name.",
      "severity": "medium", "evidence_type": "observed",
      "evidence": { "port": 7777, "ip": "203.0.113.45", "count": 2 },
      "related_domain": null, "related_ip": "203.0.113.45", "related_port": 7777,
      "detected_at": "2026-11-05T10:04:59Z" }
  ],
  "is_mock": false
}
```
* `stats` = **cumulative totals for the whole session so far**, not this batch only.
* `connections` and `alerts` = only **new** items since the previous batch (max 1000 / 100 per batch).
* `domain` may be `null` (no name observable). Optional `domain_source`: `dns` (from a DNS reply) | `sni` (from the TLS ClientHello) | `unavailable`. `protocol`: `TCP | UDP | ICMP | OTHER`.
* `severity`: `low | medium | high`. `risk_score`: 0–100 or `null`.
* `evidence` holds metadata facts only (numbers, short strings), never payloads or personal data.
* Sending to a stopped session gives **409**. Send the final batch *before* calling stop.

→ `202` `{ "accepted": true, "session_id": 1, "connections_saved": 1, "alerts_saved": 1, "received_at": "...", "is_mock": false }`

---

## Part B – What Member 4's dashboard RECEIVES

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /health` | – | `{status, version, time, mode, database, gemini_configured}` |
| `GET /sessions` | – | list of **Session**, newest first |
| `GET /sessions/{id}` | – | **Session** |
| `GET /sessions/{id}/summary` | – | **Summary** |
| `GET /sessions/{id}/connections?limit=500&offset=0` | – | list of **Connection**, oldest first |
| `GET /sessions/{id}/alerts?severity=high&evidence_type=inferred` | – | list of **Alert** (filters optional) |
| `GET /sessions/{id}/timeline?interval_seconds=10` | – | **Timeline** |
| `GET /compare?session_a=1&session_b=2` | – | **Compare** |
| `POST /sessions/{id}/insights` | ✔ | **Insight** (body optional: `{"force_refresh": false}`) |
| `GET /sessions/{id}/insights` | ✔ | list of **Insight**, newest first |
| `POST /sessions/{id}/report` | ✔ | **Report** (`201`) |
| `GET /sessions/{id}/reports` | ✔ | list of **Report** |
| `GET /reports/{id}/download` | ✔ | the PDF file (`application/pdf`) |
| `DELETE /sessions/{id}` | ✔ | `{deleted, session_id, rows_deleted: {...per table}, is_mock}` |
| `WS /ws/{session_id}` | – | live messages (see below) |

**Session**
```json
{ "id": 1, "app": {"id": 1, "package_name": "com.example.demoshop", "app_name": "DemoShop"},
  "status": "active", "device_label": "Pixel 7",
  "started_at": "2026-11-05T10:00:00Z", "stopped_at": null,
  "risk_score": 65, "is_mock": false }
```

**Summary** (for the top cards and the domain chart)
```json
{ "session_id": 1, "app": {...}, "status": "stopped",
  "started_at": "...", "stopped_at": "...", "duration_seconds": 600,
  "total_bytes_up": 12400000, "total_bytes_down": 172200000,
  "total_connections": 28, "unique_domains": 5,
  "risk_score": 65, "risk_level": "medium",
  "alert_counts": {"low": 0, "medium": 2, "high": 1, "total": 3},
  "top_domains": [ {"domain": "cdn.demoshop.example", "bytes_up": 400000,
                    "bytes_down": 121500000, "connection_count": 5} ],
  "is_mock": false }
```
Totals come from Member 2's latest cumulative `stats`. `top_domains` (max 5) is computed from stored connections; a raw IP appears when no domain was seen.
`risk_level` thresholds are a **proposal** to confirm with Member 2: 0–39 low, 40–69 medium, 70–100 high.

**Connection**: `{id, session_id, domain, domain_source, ip, port, protocol, bytes_up, bytes_down, timestamp, duration_ms, is_mock}`

**Alert**: `{id, session_id, rule_id, title, description, severity, evidence_type, evidence, related_domain, related_ip, related_port, detected_at, is_mock}`

**Timeline** (bytes per interval, *not* cumulative; `events` = chart markers)
```json
{ "session_id": 1, "interval_seconds": 10,
  "points": [ {"timestamp": "2026-11-05T10:00:00Z", "bytes_up": 1541666,
               "bytes_down": 6408333, "new_connections": 2, "risk_score": 10} ],
  "events": [ {"timestamp": "2026-11-05T10:03:10Z", "alert_id": 101,
               "title": "Repeated periodic connections to one domain", "severity": "medium"} ],
  "is_mock": false }
```
Max 500 points: for long sessions the backend widens `interval_seconds` automatically (check the returned value).
Empty intervals have 0 bytes and keep the previous `risk_score`.

**Compare**
```json
{ "session_a": <Summary>, "session_b": <Summary>,
  "difference_b_minus_a": {"total_bytes_up": -2000, "total_bytes_down": 5000,
                           "total_connections": 3, "alerts_total": 1, "risk_score": 15},
  "domains_only_in_a": [...], "domains_only_in_b": [...], "domains_in_both": [...],
  "alert_rules_only_in_a": [...], "alert_rules_only_in_b": [...], "is_mock": false }
```

**Insight**
```json
{ "id": 11, "session_id": 1, "source": "gemini | fallback", "model": "gemini-flash-latest",
  "text": "...", "evidence_used": { ...exact sanitized summary sent to the AI... },
  "cached": true, "created_at": "...", "is_mock": false }
```
* `source: "fallback"`: Gemini was missing, slow (>15 s) or failed. The text is a rule-based summary; show it anyway.
* `cached: true`: same evidence as a previous call, answer returned instantly without calling Gemini.
* `evidence_used` lets the UI show exactly what the AI saw (transparency).

**Report**: `{id, session_id, filename, download_url, created_at, is_mock}`.
A plain `<a href>` can't send the `X-API-Key` header, so download like this:
```js
const res = await fetch(BASE + report.download_url, { headers: { "X-API-Key": KEY } });
const url = URL.createObjectURL(await res.blob());
window.open(url);   // or set it as an <a download> href
```

**WebSocket** `ws://<host>:8000/ws/{session_id}`
```json
{ "type": "hello",           "session_id": 1, "data": <Summary> }
{ "type": "observation",     "session_id": 1,
  "data": { "captured_at": "...Z", "stats": {...}, "risk_score": 65,
            "new_connections": [<Connection>...], "new_alerts": [<Alert>...] } }
{ "type": "session_stopped", "session_id": 1, "data": <Session> }
{ "type": "session_deleted", "session_id": 1, "data": null }     // then the socket closes (code 4410)
{ "type": "error",           "session_id": 1, "data": {"detail": "Session 1 not found"} }  // then closes (4404)
{ "type": "pong",            "session_id": 1, "data": null }     // reply to any text you send, e.g. "ping"
```
Tip: on `hello`, render the summary; on each `observation`, add the new connections/alerts and update the totals from `stats`.
If the socket drops, reconnect and you will get a fresh `hello`.

## Note for the demo
The dashboard needs the API key to call insights and reports, so the key ends up in browser JS where anyone using the dashboard can read it.
That's fine for a hackathon on a private Wi-Fi network, but it is not real security.
