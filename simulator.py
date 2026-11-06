"""
simulator.py - pretends to be the Android app + Member 2's analysis engine.

It starts a session, then every second sends a FAKE observation batch to the
backend, then stops the session. Everything is marked "is_mock": true.

Traffic it generates:
  * normal  : app API calls, CDN downloads, ads, DNS lookups
  * pattern 1 (repeated background calls): analytics.tracker.example every 5 ticks,
    mostly UPLOAD -> after 4 calls we raise R01 (medium, observed)
  * pattern 2 (unusual port): TCP 7777 to an IP with no DNS name -> R02 (medium, observed)
  * pattern 3: >1.2 MB uploaded to the analytics domain -> R03 (high, INFERRED: "third-party"
    is a guess from the domain name, and what was uploaded cannot be observed)

The alerts here imitate Member 2's rules so we can test without them.
The real backend never creates alerts itself.

Usage (server must be running):
    python simulator.py                       # 60 seconds, 1 batch per second
    python simulator.py --duration 30 --interval 0.5
    python simulator.py --url http://192.168.1.5:8000 --no-stop
"""
import argparse
import os
import random
import sys
import time
from datetime import datetime, timezone

import httpx
from dotenv import load_dotenv

# (domain, ip, port, protocol, (min_up, max_up), (min_down, max_down))  - fake but realistic sizes
NORMAL_TRAFFIC = [
    ("api.demoshop.example", "198.51.100.10", 443, "TCP", (800, 6_000), (5_000, 120_000)),
    ("cdn.demoshop.example", "198.51.100.20", 443, "TCP", (300, 1_500), (80_000, 2_500_000)),
    ("ads.adnetwork.example", "203.0.113.30", 443, "UDP", (500, 3_000), (20_000, 400_000)),
    ("dns.resolver.example", "192.0.2.53", 53, "UDP", (60, 120), (90, 300)),
]
BEACON = ("analytics.tracker.example", "203.0.113.7", 443, "TCP")
ODD_PORT = (None, "203.0.113.45", 7777, "TCP")
BEACON_EVERY = 5         # ticks between background calls
ODD_PORT_TICKS = {12, 35}  # ticks when the unusual-port connection happens


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class FakeAnalyzer:
    """Keeps running totals and decides when to raise each (fake) alert - once each."""

    def __init__(self, session_id: int, seed: int | None = None, interval: float = 1.0):
        self.session_id = session_id
        self.rng = random.Random(seed)
        self.interval = interval
        self.up = self.down = self.n_conns = 0
        self.domains: set[str] = set()
        self.beacon_count = 0
        self.beacon_up = 0
        self.raised: set[str] = set()
        self.mediums = self.highs = 0

    def _conn(self, domain, ip, port, proto, up, down):
        self.up += up
        self.down += down
        self.n_conns += 1
        if domain:
            self.domains.add(domain)
        return {"domain": domain, "domain_source": "dns" if domain else "unavailable",
                "ip": ip, "port": port, "protocol": proto, "bytes_up": up,
                "bytes_down": down, "timestamp": now_iso(), "duration_ms": self.rng.randint(80, 2500)}

    def _alert(self, rule_id, severity, evidence_type, title, description, evidence,
               domain=None, ip=None, port=None):
        self.raised.add(rule_id)
        if severity == "high":
            self.highs += 1
        else:
            self.mediums += 1
        return {"rule_id": rule_id, "title": title, "description": description, "severity": severity,
                "evidence_type": evidence_type, "evidence": evidence, "related_domain": domain,
                "related_ip": ip, "related_port": port, "detected_at": now_iso()}

    def next_batch(self, tick: int) -> dict:
        r = self.rng
        conns, alerts = [], []

        # Normal traffic: 1-3 connections per tick.
        for domain, ip, port, proto, up_range, down_range in r.sample(NORMAL_TRAFFIC, r.randint(1, 3)):
            conns.append(self._conn(domain, ip, port, proto, r.randint(*up_range), r.randint(*down_range)))

        # Pattern 1: repeated background calls, mostly upload.
        if tick % BEACON_EVERY == 0:
            up = r.randint(200_000, 300_000)
            conns.append(self._conn(*BEACON, up, r.randint(2_000, 8_000)))
            self.beacon_count += 1
            self.beacon_up += up

        # Pattern 2: an unusual port with no DNS name.
        if tick in ODD_PORT_TICKS:
            conns.append(self._conn(*ODD_PORT, r.randint(1_000, 40_000), r.randint(1_000, 60_000)))
            if "R02_UNCOMMON_PORT" not in self.raised:
                alerts.append(self._alert(
                    "R02_UNCOMMON_PORT", "medium", "observed", "Connection on an uncommon port",
                    "TCP connection to 203.0.113.45 on port 7777. No DNS name was seen for this IP. "
                    "Uncommon ports are not harmful by themselves but are worth reviewing.",
                    {"ip": "203.0.113.45", "port": 7777, "protocol": "TCP", "dns_name_seen": False},
                    ip="203.0.113.45", port=7777))

        if self.beacon_count >= 4 and "R01_PERIODIC_CONNECTIONS" not in self.raised:
            alerts.append(self._alert(
                "R01_PERIODIC_CONNECTIONS", "medium", "observed", "Repeated periodic connections to one domain",
                f"analytics.tracker.example was contacted {self.beacon_count} times at regular intervals. "
                "Whether the user triggered these calls cannot be determined from network metadata.",
                {"domain": BEACON[0], "count": self.beacon_count,
                 "avg_interval_seconds": round(BEACON_EVERY * self.interval, 1)},
                domain=BEACON[0], ip=BEACON[1], port=443))

        if self.beacon_up > 1_200_000 and "R03_HIGH_UPLOAD_THIRD_PARTY" not in self.raised:
            alerts.append(self._alert(
                "R03_HIGH_UPLOAD_THIRD_PARTY", "high", "inferred", "High upload volume to a likely third-party domain",
                f"{self.beacon_up / 1e6:.1f} MB uploaded to analytics.tracker.example. The domain does not match "
                "the app's own domain, so it is inferred to be third-party. The uploaded contents cannot be "
                "observed (encrypted). Unusual behavior worth reviewing.",
                {"domain": BEACON[0], "bytes_up": self.beacon_up, "connections": self.beacon_count},
                domain=BEACON[0], ip=BEACON[1], port=443))

        # A simple fake risk score that rises with alerts.
        risk = min(100, 10 + 15 * self.mediums + 25 * self.highs)
        return {
            "session_id": self.session_id, "captured_at": now_iso(), "risk_score": risk,
            "stats": {"total_bytes_up": self.up, "total_bytes_down": self.down,
                      "total_connections": self.n_conns, "unique_domains": len(self.domains)},
            "connections": conns, "alerts": alerts, "is_mock": True,
        }


def run(client: httpx.Client, duration: int = 60, interval: float = 1.0, stop: bool = True,
        seed: int | None = None, quiet: bool = False) -> int:
    """Start a session, send `duration` batches, optionally stop. Returns the session id."""
    say = (lambda *a: None) if quiet else print

    r = client.post("/sessions", json={"package_name": "com.example.demoshop",
                                       "app_name": "DemoShop (simulated)",
                                       "device_label": "simulator.py", "is_mock": True})
    if r.status_code != 201:
        sys.exit(f"Could not start session: {r.status_code} {r.text}")
    session_id = r.json()["id"]
    say(f"Started session {session_id}. Watch it at /sessions/{session_id}/summary  (Ctrl+C to stop)")

    analyzer = FakeAnalyzer(session_id, seed=seed, interval=interval)
    try:
        for tick in range(1, duration + 1):
            batch = analyzer.next_batch(tick)
            try:
                resp = client.post("/observations", json=batch)
            except httpx.HTTPError as e:  # server restarting, Wi-Fi blip... keep going
                say(f"[tick {tick}] network error: {e}")
                time.sleep(interval)
                continue
            if resp.status_code == 409:
                say("Session was stopped elsewhere. Exiting.")
                return session_id
            if resp.status_code != 202:
                say(f"[tick {tick}] server said {resp.status_code}: {resp.text[:200]}")
            else:
                flag = "  <-- ALERT: " + ", ".join(a["rule_id"] for a in batch["alerts"]) if batch["alerts"] else ""
                say(f"[tick {tick:3d}] up={analyzer.up / 1e6:6.2f} MB  down={analyzer.down / 1e6:7.2f} MB  "
                    f"conns={analyzer.n_conns:4d}  risk={batch['risk_score']:3d}{flag}")
            if interval:
                time.sleep(interval)
    except KeyboardInterrupt:
        say("\nInterrupted.")
    finally:
        if stop:
            client.post(f"/sessions/{session_id}/stop")
            say(f"Stopped session {session_id}.")
    return session_id


def main():
    load_dotenv()
    p = argparse.ArgumentParser(description="Send fake AppFlow observations to the backend.")
    p.add_argument("--url", default="http://localhost:8000", help="backend base URL")
    p.add_argument("--duration", type=int, default=60, help="number of batches to send")
    p.add_argument("--interval", type=float, default=1.0, help="seconds between batches")
    p.add_argument("--seed", type=int, default=None, help="random seed for repeatable runs")
    p.add_argument("--no-stop", action="store_true", help="leave the session active at the end")
    args = p.parse_args()

    api_key = os.getenv("API_KEY")
    if not api_key:
        sys.exit("API_KEY not found. Run this from the project folder (where .env is).")

    with httpx.Client(base_url=args.url, headers={"X-API-Key": api_key}, timeout=10) as client:
        try:
            client.get("/health").raise_for_status()
        except httpx.HTTPError as e:
            sys.exit(f"Backend not reachable at {args.url} ({e}). Is uvicorn running?")
        run(client, duration=args.duration, interval=args.interval, stop=not args.no_stop, seed=args.seed)


if __name__ == "__main__":
    main()
