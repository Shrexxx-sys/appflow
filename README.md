# AppFlow Sentinel

**See who an Android app talks to — live, on a dashboard — without reading a single encrypted byte.**

AppFlow Sentinel monitors the **network metadata** of one app you choose (destination IPs, domain names, ports,
protocols, byte counts, timing), flags unusual behavior with deterministic rules, and shows everything on a web
dashboard with an optional AI explanation and a PDF report.

## What it does
- Captures the chosen app's traffic on the phone with Android's `VpnService` (per-app, with your explicit consent).
- Groups packets into connections, learns domain names from **observed** DNS answers and TLS server names (SNI).
- Runs four fixed rules (high upload, repeated connections, uncommon port, regular repeated contact) and an
  explainable 0–100 risk score (0–39 low, 40–69 medium, 70+ high).
- Labels every finding as `observed`, `inferred`, `potential_risk` or `not_observable`.
- Streams it to a FastAPI backend and a live dashboard (charts, alerts, connections table, PDF report).
- Optionally asks Gemini to **explain** the findings from a small sanitized summary (falls back to a rule-based text).

## What it does NOT do
- It does **not** decrypt HTTPS or read message contents, and it never stores or sends payloads.
- It does **not** call any app "malware" — findings are "unusual behavior worth reviewing", not proof of wrongdoing.
- It does **not** let the AI detect anything; detection is deterministic code.
- It cannot see domain names hidden by encrypted DNS (DoH/DoT) or Encrypted Client Hello — those show as `unavailable`.

## Architecture
```
 Phone                                          Laptop (same Wi-Fi)
┌──────────────────────────────────────┐      ┌──────────────────────────────┐      ┌────────────────────┐
│ Android app (android/app)            │      │ FastAPI backend (app/)       │      │ Dashboard          │
│  VpnService, chosen app only         │ JSON │  SQLite, REST, WebSocket     │ REST │ (dashboard/)       │
│  PacketForwarder: app <-> internet   │─────>│  Gemini explanations (opt.)  │─────>│ HTML/CSS/JS        │
│  every packet -> queue               │ HTTP │  PDF reports                 │  WS  │ Chart.js           │
│ Analysis engine (android/analysis)   │      └──────────────────────────────┘      └────────────────────┘
│  parse -> connections -> DNS/SNI     │                    ▲
│  -> rules -> risk score -> batch     │      simulator.py ─┘  (fake data for demos/tests, marked is_mock)
└──────────────────────────────────────┘
```

## Folder tree
```
appflow-backend/
├── app/                    FastAPI backend (routers/, services/, models, schemas = JSON contract)
├── tests/                  backend pytest suite
├── dashboard/              index.html, style.css, app.js, config.example.js (copy to config.js)
├── android/
│   ├── analysis/           plain-Java analysis engine + JUnit tests (no Android imports)
│   └── app/                Android app: MainActivity, SentinelVpnService, PacketForwarder, TcpProxy, PacketBuilder
├── docs/CONTRACT.md        JSON contract between the parts
├── simulator.py            sends realistic fake observations
├── requirements.txt  Dockerfile  .env.example
```

## How to run
**1. Backend** (Python 3.12+)
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env          # set API_KEY (and GEMINI_API_KEY if you have one)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
API docs: http://localhost:8000/docs (click **Authorize**, paste your API key).

Upgrading from an older version: at startup the backend adds any new optional columns to an existing
`appflow.db` (existing rows are kept and the change is logged as `Upgraded old database: ...`). If a required
column were ever missing it stops with a message asking you to rename `appflow.db` — it never deletes data.

**2. Dashboard** (second terminal)
```powershell
copy dashboard\config.example.js dashboard\config.js   # paste API_KEY from .env into config.js
python -m http.server 5500 -d dashboard
```
Open http://localhost:5500 — or from a phone on the same Wi-Fi: `http://<laptop IPv4 from ipconfig>:5500`.

**3. Data**
- Simulated: `python simulator.py --duration 120` (third terminal).
- Real phone: open `android/` in Android Studio, run the app on your phone, pick an app, enter
  `http://<laptop IPv4>:8000` and the API key, tap **Start monitoring**, accept the VPN dialog.

## How to run the tests
```powershell
pytest -q                                 # backend
```
Analysis engine + forwarder (run on the laptop's JVM, no phone needed): open `android/` in Android Studio and run
the `analysis > test` and `app > testDebugUnitTest` Gradle tasks (Gradle panel → Tasks → verification). After
Android Studio has created the `gradlew` script you can also run `gradlew :analysis:test :app:testDebugUnitTest`.
The analysis suite includes `BackendIntegrationTest`, which runs only when `APPFLOW_BACKEND_URL` and
`APPFLOW_API_KEY` point at a running backend (it is skipped otherwise). Tests never call the real Gemini API.

## Demo script (5 minutes)
1. Start backend + dashboard. Show the empty state.
2. Start the phone app (or `simulator.py` — the dashboard shows a clear **SIMULATED** banner).
3. Watch connections, upload/download and the timeline update live; point out the `dns` / `sni` / `unavailable`
   badges ("we only show names we actually saw").
4. Alerts appear with severity, evidence type and evidence numbers; show that "regular repeated contact" is
   labelled **inferred** because background state cannot be observed.
5. Click **Explain with AI** — Gemini text, or a clearly labelled rule-based fallback.
6. Click **Generate report** — PDF with Observed / Inferred / Potential risks / Cannot be observed / AI explanation.
7. Stop monitoring. Optionally delete the session (privacy feature).

## Honest limitations
- **The Android VPN has not been verified on a real phone.** The app code type-checks against the Android 15 API and
  the forwarder passed laptop tests with real sockets, but the Gradle build and on-device behaviour are untested.
- The forwarder is a small Java TCP/UDP relay: IPv4 only (the app's IPv6 is blocked so it falls back to IPv4), no
  retransmission towards the app, no window scaling. Heavy apps (video streaming) may be slower.
- A connection is reported once (when it closes, idles, or after 30 s); later bytes still count in the totals.
- DNS goes to 8.8.8.8 through the VPN so answers are observable. Private DNS (DoT), DoH and ECH hide names.
- Only one VPN app can run at a time on Android.
- The dashboard's API key lives in browser JavaScript: demo-level protection, use it on a private network only.
- A successful Gemini answer has not been verified yet (the only real test call timed out); the fallback works.

## Ethical use
Only monitor devices and apps that you own or are explicitly authorised to test. Monitoring someone else's traffic
without permission may be illegal.
