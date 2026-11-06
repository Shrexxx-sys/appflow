// app.js - AppFlow Sentinel dashboard (plain JavaScript, no frameworks).
//
// Data flow:
//   * REST API (fetch)      -> full snapshots: sessions, summary, connections, alerts, timeline
//   * WebSocket /ws/{id}    -> live pushes; we append new connections and schedule a refresh
//   * If the WebSocket is down, we fall back to polling every 5 s and reconnect with back-off.
// SAFETY: data from the network (domain names!) is only ever inserted with textContent,
// never innerHTML, so a malicious name like "<img onerror=...>" is shown as plain text.
"use strict";

const CFG = window.APPFLOW_CONFIG || {};
const MAX_TABLE_ROWS = 300;     // drawing thousands of rows makes phones slow
const CONN_FETCH_LIMIT = 2000;
const FALLBACK_POLL_MS = 5000;

const EVIDENCE_INFO = {
  observed: ["observed", "Directly seen in the network metadata (e.g. a port, a byte count)."],
  inferred: ["inferred", "A conclusion drawn from observed facts - not directly seen."],
  potential_risk: ["potential risk", "Something that could matter - not proven."],
  not_observable: ["not observable", "Cannot be seen from metadata (e.g. encrypted contents)."],
};

const state = {
  sessions: [],
  sessionId: null,
  userPicked: false,      // true once the user chose a session by hand
  summary: null,
  connections: [],        // oldest first, like the API
  connIds: new Set(),     // to skip duplicates arriving by both REST and WebSocket
  alertsKey: "",          // to re-draw the alert list only when it changed
  lastUpdate: null,
  ws: null,
  wsOpen: false,
  wsRetry: 0,
  wsTimer: null,
  wsHadDrop: false,
  refreshTimer: null,
  tableTimer: null,
  charts: {},
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const $ = (id) => document.getElementById(id);

/** Create an element with optional class and SAFE text content. */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function fmtBytes(n) {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = Number(n);
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function fmtDateTime(iso) {
  return iso ? new Date(iso).toLocaleString() : "—";
}

function fmtDuration(totalSeconds) {
  const s = Math.max(0, Math.round(totalSeconds || 0));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h ? `${h}h ${m}m ${sec}s` : m ? `${m}m ${sec}s` : `${sec}s`;
}

class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

/**
 * One place for every backend call.
 * WHY: timeouts, the API-key header and friendly error messages are handled once, here.
 */
async function api(path, { method = "GET", body, auth = false, raw = false, timeoutMs = 10000 } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (auth) headers["X-API-Key"] = CFG.API_KEY;

  const controller = new AbortController();               // lets us cancel a request that hangs
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(CFG.BACKEND_URL + path, {
      method, headers, signal: controller.signal,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    const why = err.name === "AbortError" ? "timed out" : "is unreachable";
    throw new ApiError(`Backend ${why} at ${CFG.BACKEND_URL}. Is uvicorn running with --host 0.0.0.0?`, 0);
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const j = await res.json();
      detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch { /* body was not JSON */ }
    if (res.status === 401) detail = "API key rejected (401). Make API_KEY in dashboard/config.js match the backend .env.";
    throw new ApiError(detail, res.status);
  }
  return raw ? res : res.json();
}

function showError(message) {
  const b = $("error-banner");
  b.textContent = message;
  b.hidden = false;
}
function clearError() { $("error-banner").hidden = true; }

function markUpdated() {
  state.lastUpdate = new Date();
  renderLastUpdate();
}

function renderLastUpdate() {
  if (!state.lastUpdate) return;
  const ago = Math.round((Date.now() - state.lastUpdate.getTime()) / 1000);
  $("last-update").textContent = `Updated ${state.lastUpdate.toLocaleTimeString()} (${ago}s ago)`;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
async function loadSessions() {
  let sessions;
  try {
    sessions = await api("/sessions");
    clearError();
  } catch (err) {
    showError(err.message);
    $("loading-state").textContent = "Could not load sessions. Retrying every few seconds…";
    return;
  }
  state.sessions = sessions;
  $("loading-state").hidden = true;
  renderSessionSelect();

  if (sessions.length === 0) {
    $("empty-state").hidden = false;
    $("dashboard").hidden = true;
    $("mock-banner").hidden = true;
    closeWs();
    state.sessionId = null;
    return;
  }
  $("empty-state").hidden = true;

  // The API returns newest first. Prefer the newest ACTIVE session, else the newest one.
  const preferred = sessions.find((s) => s.status === "active") || sessions[0];
  const current = sessions.find((s) => s.id === state.sessionId);
  // Follow a newly started session automatically, unless the user picked one by hand.
  if (!current || (!state.userPicked && preferred.status === "active" && preferred.id !== state.sessionId)) {
    await selectSession(preferred.id);
  }
}

function renderSessionSelect() {
  const select = $("session-select");
  const options = state.sessions.map((s) => {
    const label = `#${s.id} ${s.app.app_name || s.app.package_name} — ${s.status}${s.is_mock ? " (mock)" : ""}`;
    const opt = el("option", null, label);
    opt.value = String(s.id);
    return opt;
  });
  select.replaceChildren(...options);
  if (state.sessionId !== null) select.value = String(state.sessionId);
}

async function selectSession(id) {
  closeWs();
  state.sessionId = id;
  state.summary = null;
  state.connections = [];
  state.connIds = new Set();
  state.alertsKey = "";
  state.wsRetry = 0;
  state.wsHadDrop = false;
  $("session-select").value = String(id);
  $("dashboard").hidden = false;
  $("conn-body").replaceChildren(emptyRow("Loading connections…"));
  resetInsightPanel();
  $("report-list").replaceChildren();
  $("report-status").textContent = "Sections: observed facts, inferred, potential risks, cannot be observed, AI explanation.";
  await Promise.all([refreshAll(), loadConnections(), loadInsights(), loadReports()]);
  connectWs();
}

/** Re-fetch everything that is cheap: summary, timeline, alerts. */
async function refreshAll() {
  await Promise.all([refreshSummary(), refreshTimeline(), refreshAlerts()]);
}

/** Many live messages per second -> at most one refreshAll() per REFRESH_MS. */
function scheduleRefresh() {
  if (state.refreshTimer) return;
  state.refreshTimer = setTimeout(async () => {
    state.refreshTimer = null;
    await refreshAll();
  }, CFG.REFRESH_MS || 2000);
}

// ---------------------------------------------------------------------------
// Summary cards
// ---------------------------------------------------------------------------
async function refreshSummary() {
  const id = state.sessionId;
  try {
    const summary = await api(`/sessions/${id}/summary`);
    if (id !== state.sessionId) return;  // user switched session while we waited
    renderSummary(summary);
    clearError();
    markUpdated();
  } catch (err) {
    showError(err.message);
  }
}

function renderSummary(s) {
  state.summary = s;
  const active = s.status === "active";
  $("status-dot").className = active ? "dot active" : "dot";
  $("status-label").textContent = active ? "Monitoring active" : "Monitoring stopped";
  $("app-name").textContent = `${s.app.app_name || ""} (${s.app.package_name})`;
  $("status-details").textContent =
    `Started ${fmtDateTime(s.started_at)} · ${active ? "running for" : "lasted"} ${fmtDuration(s.duration_seconds)}`;
  $("mock-banner").hidden = !s.is_mock;

  $("stat-connections").textContent = s.total_connections.toLocaleString();
  $("stat-domains").textContent = `${s.unique_domains} unique domains`;
  $("stat-upload").textContent = fmtBytes(s.total_bytes_up);
  $("stat-download").textContent = fmtBytes(s.total_bytes_down);
  renderRisk(s.risk_score, s.risk_level);

  const c = s.alert_counts;
  $("stat-alerts").textContent = c.total;
  $("stat-alert-split").textContent = `${c.high} high · ${c.medium} medium · ${c.low} low`;
  renderDomainChart(s.top_domains);
}

function renderRisk(score, level) {
  $("stat-risk").textContent = score ?? "—";
  const badge = $("stat-risk-level");
  badge.textContent = level || "n/a";
  badge.className = `badge ${level || ""}`;
  $("risk-fill").style.width = `${score || 0}%`;
}

// ---------------------------------------------------------------------------
// Charts (Chart.js). If the CDN is unreachable, everything else still works.
// ---------------------------------------------------------------------------
function chartsReady() {
  if (typeof window.Chart === "undefined") {
    for (const id of ["chart-domains-msg", "chart-timeline-msg"]) {
      $(id).textContent = "Charts unavailable: Chart.js could not be loaded from the CDN (no internet?). All other data still works.";
      $(id).hidden = false;
    }
    return false;
  }
  if (state.charts.domains) return true;

  Chart.defaults.color = "#9aa0c8";
  Chart.defaults.borderColor = "#2b2f55";
  Chart.defaults.font.family = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";

  const shorten = (label) => (label.length > 22 ? `${label.slice(0, 21)}…` : label);
  state.charts.domains = new Chart($("chart-domains"), {
    type: "bar",
    data: { labels: [], datasets: [
      { label: "Upload", data: [], backgroundColor: "#8b5cf6", borderRadius: 4 },
      { label: "Download", data: [], backgroundColor: "#3b82f6", borderRadius: 4 },
    ] },
    options: {
      indexAxis: "y", responsive: true, maintainAspectRatio: false, animation: false,
      scales: {
        x: { beginAtZero: true, title: { display: true, text: "MB" } },
        y: { ticks: { callback(value) { return shorten(this.getLabelForValue(value)); } } },
      },
      plugins: { tooltip: { callbacks: { label: (ctx) => `${ctx.dataset.label}: ${fmtBytes(ctx.raw * 1e6)}` } } },
    },
  });

  state.charts.timeline = new Chart($("chart-timeline"), {
    type: "line",
    data: { labels: [], datasets: [
      { label: "Upload (KB)", data: [], borderColor: "#8b5cf6", backgroundColor: "rgba(139,92,246,0.15)",
        fill: true, tension: 0.3, pointRadius: 0, yAxisID: "y" },
      { label: "Download (KB)", data: [], borderColor: "#3b82f6", backgroundColor: "rgba(59,130,246,0.15)",
        fill: true, tension: 0.3, pointRadius: 0, yAxisID: "y" },
      { label: "Risk score", data: [], borderColor: "#f59e0b", borderDash: [5, 4], pointRadius: 0,
        stepped: true, yAxisID: "risk" },
      { label: "Alert", data: [], showLine: false, pointStyle: "triangle", pointRadius: 8,
        backgroundColor: "#ef4444", borderColor: "#ef4444", yAxisID: "risk" },
    ] },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        y: { beginAtZero: true, title: { display: true, text: "KB per interval" } },
        risk: { position: "right", min: 0, max: 100, grid: { drawOnChartArea: false },
                title: { display: true, text: "risk" } },
      },
      plugins: { tooltip: { callbacks: { label: (ctx) => {
        if (ctx.dataset.label === "Alert") return ctx.raw === null ? null : `Alert: ${state.charts.alertTitles[ctx.dataIndex]}`;
        return `${ctx.dataset.label}: ${ctx.formattedValue}`;
      } } } },
    },
  });
  return true;
}

function renderDomainChart(topDomains) {
  if (!chartsReady()) return;
  const msg = $("chart-domains-msg");
  msg.hidden = topDomains.length > 0;
  msg.textContent = "No traffic recorded yet.";
  const chart = state.charts.domains;
  chart.data.labels = topDomains.map((d) => d.domain);
  chart.data.datasets[0].data = topDomains.map((d) => d.bytes_up / 1e6);
  chart.data.datasets[1].data = topDomains.map((d) => d.bytes_down / 1e6);
  chart.update("none");
}

/** Pick a bucket size that gives a readable chart for the session length. */
function timelineInterval() {
  const secs = state.summary ? state.summary.duration_seconds : 0;
  if (secs < 120) return 2;
  if (secs < 900) return 10;
  return 30;
}

async function refreshTimeline() {
  const id = state.sessionId;
  try {
    const t = await api(`/sessions/${id}/timeline?interval_seconds=${timelineInterval()}`);
    if (id !== state.sessionId) return;
    renderTimeline(t);
  } catch (err) {
    showError(err.message);
  }
}

function renderTimeline(t) {
  $("timeline-note").textContent = `per ${t.interval_seconds}s`;
  if (!chartsReady()) return;
  const msg = $("chart-timeline-msg");
  msg.hidden = t.points.length > 0;
  msg.textContent = "No traffic recorded yet.";

  const chart = state.charts.timeline;
  chart.data.labels = t.points.map((p) => fmtTime(p.timestamp));
  chart.data.datasets[0].data = t.points.map((p) => p.bytes_up / 1000);
  chart.data.datasets[1].data = t.points.map((p) => p.bytes_down / 1000);
  chart.data.datasets[2].data = t.points.map((p) => p.risk_score);

  // Put a red triangle on the bucket where each alert happened.
  const marks = t.points.map(() => null);
  const titles = t.points.map(() => "");
  if (t.points.length) {
    const t0 = new Date(t.points[0].timestamp).getTime();
    for (const ev of t.events) {
      const idx = Math.min(t.points.length - 1,
        Math.max(0, Math.floor((new Date(ev.timestamp).getTime() - t0) / (t.interval_seconds * 1000))));
      marks[idx] = t.points[idx].risk_score ?? 50;
      titles[idx] = titles[idx] ? `${titles[idx]}; ${ev.title}` : ev.title;
    }
  }
  chart.data.datasets[3].data = marks;
  state.charts.alertTitles = titles;
  chart.update("none");
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
async function refreshAlerts() {
  const id = state.sessionId;
  try {
    const alerts = await api(`/sessions/${id}/alerts`);
    if (id !== state.sessionId) return;
    renderAlerts(alerts);
  } catch (err) {
    showError(err.message);
  }
}

function renderAlerts(alerts) {
  const key = alerts.map((a) => a.id).join(",");
  if (key === state.alertsKey && key !== "") return;  // unchanged: don't redraw (keeps scroll position)
  state.alertsKey = key;
  const list = $("alerts-list");
  if (alerts.length === 0) {
    list.replaceChildren(el("p", "muted",
      "No alerts so far. This only means no rule fired - it is not proof that the app is safe."));
    return;
  }
  list.replaceChildren(...alerts.slice().reverse().map(alertCard));  // newest first
}

function alertCard(a) {
  const box = el("div", `alert ${a.severity}`);
  const head = el("div", "row-actions");
  const [typeLabel, typeHelp] = EVIDENCE_INFO[a.evidence_type] || [a.evidence_type, ""];
  const typeBadge = el("span", "badge type", typeLabel);
  typeBadge.title = typeHelp;
  head.append(el("span", `badge ${a.severity}`, a.severity), typeBadge,
              el("span", "muted small", fmtTime(a.detected_at)));

  const chips = el("div", "chips");
  const target = [a.related_domain, a.related_ip, a.related_port && `port ${a.related_port}`].filter(Boolean);
  if (target.length) chips.appendChild(el("span", "chip", target.join(" · ")));
  for (const [k, v] of Object.entries(a.evidence || {})) {
    chips.appendChild(el("span", "chip", `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`));
  }
  box.append(head, el("div", "alert-title", a.title), el("p", null, a.description), chips);
  return box;
}

// ---------------------------------------------------------------------------
// Connections table
// ---------------------------------------------------------------------------
async function loadConnections() {
  const id = state.sessionId;
  try {
    const rows = await api(`/sessions/${id}/connections?limit=${CONN_FETCH_LIMIT}`);
    if (id !== state.sessionId) return;
    state.connections = rows;
    state.connIds = new Set(rows.map((c) => c.id));
    renderConnections();
  } catch (err) {
    showError(err.message);
  }
}

function addConnections(newRows) {
  for (const c of newRows) {
    if (state.connIds.has(c.id)) continue;
    state.connIds.add(c.id);
    state.connections.push(c);
  }
  // Redraw at most twice a second, however fast data arrives.
  if (!state.tableTimer) {
    state.tableTimer = setTimeout(() => { state.tableTimer = null; renderConnections(); }, 500);
  }
}

function emptyRow(text) {
  const tr = el("tr", "empty-row");
  const td = el("td", null, text);
  td.colSpan = 7;
  tr.appendChild(td);
  return tr;
}

function renderConnections() {
  const query = $("conn-search").value.trim().toLowerCase();
  const proto = $("conn-protocol").value;

  // Newest first for display; filter by search text and protocol.
  const matches = [];
  for (let i = state.connections.length - 1; i >= 0; i--) {
    const c = state.connections[i];
    if (proto && c.protocol !== proto) continue;
    if (query && !`${c.domain || ""} ${c.ip} ${c.port}`.toLowerCase().includes(query)) continue;
    matches.push(c);
  }

  const shown = matches.slice(0, MAX_TABLE_ROWS);
  const body = $("conn-body");
  if (state.connections.length === 0) {
    body.replaceChildren(emptyRow("No connections recorded yet for this session."));
  } else if (shown.length === 0) {
    body.replaceChildren(emptyRow("No connections match your search."));
  } else {
    body.replaceChildren(...shown.map(connectionRow));
  }
  $("conn-count").textContent =
    `Showing ${shown.length} of ${matches.length} matching · ${state.connections.length} loaded`;
}

function connectionRow(c) {
  const tr = el("tr");
  tr.appendChild(el("td", null, fmtTime(c.timestamp)));

  const domainCell = el("td", "domain");
  domainCell.title = c.domain || "No domain name observable";
  domainCell.appendChild(el("span", c.domain ? null : "muted", c.domain || "(not observable)"));
  if (c.domain_source) {
    domainCell.append(" ");
    domainCell.appendChild(el("span", "badge src", c.domain_source));
  }
  tr.appendChild(domainCell);

  tr.appendChild(el("td", null, c.ip));
  tr.appendChild(el("td", null, c.port));
  tr.appendChild(el("td", null, c.protocol));
  tr.appendChild(el("td", "num", fmtBytes(c.bytes_up)));
  tr.appendChild(el("td", "num", fmtBytes(c.bytes_down)));
  return tr;
}

// ---------------------------------------------------------------------------
// AI insights (Gemini via the backend). We ONLY show text the backend returned.
// ---------------------------------------------------------------------------
function apiKeyMissing() {
  return !CFG.API_KEY || CFG.API_KEY.startsWith("PASTE_");
}

const KEY_HELP = "Set API_KEY in dashboard/config.js (copy it from the backend .env) to use this.";

function resetInsightPanel() {
  $("insight-meta").replaceChildren();
  $("insight-text").hidden = true;
  $("insight-evidence").hidden = true;
  $("insight-status").textContent = "Gemini explains the alerts from summarized metadata only. It does not detect anything itself.";
}

async function loadInsights() {
  if (apiKeyMissing()) {
    $("insight-status").textContent = KEY_HELP;
    return;
  }
  const id = state.sessionId;
  try {
    const list = await api(`/sessions/${id}/insights`, { auth: true });
    if (id !== state.sessionId) return;
    if (list.length) renderInsight(list[0]);  // newest first
    else $("insight-status").textContent = 'No AI explanation yet. Click "Explain with AI".';
  } catch (err) {
    $("insight-status").textContent = `Could not load AI explanations: ${err.message}`;
  }
}

async function requestInsight() {
  if (apiKeyMissing()) { $("insight-status").textContent = KEY_HELP; return; }
  const id = state.sessionId;
  const btn = $("insight-btn");
  btn.disabled = true;
  btn.textContent = "Asking…";
  $("insight-status").textContent =
    "Asking Gemini… this can take up to ~15 s. If Gemini is unavailable you get a rule-based summary instead.";
  try {
    const insight = await api(`/sessions/${id}/insights`, {
      method: "POST", body: { force_refresh: false }, auth: true, timeoutMs: 45000,
    });
    if (id === state.sessionId) renderInsight(insight);
  } catch (err) {
    $("insight-status").textContent = `AI explanation failed: ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Explain with AI";
  }
}

function renderInsight(i) {
  const badges = [];
  if (i.source === "gemini") {
    badges.push(el("span", "badge type", `Gemini${i.model ? ` · ${i.model}` : ""}`));
    $("insight-status").textContent = "AI-generated explanation of the evidence. Treat it as a helper, not a verdict.";
  } else if (i.source === "fallback") {
    badges.push(el("span", "badge medium", "rule-based fallback"));
    $("insight-status").textContent =
      "Gemini was unavailable, so this text was generated by code from the same evidence (not by AI).";
  } else {
    badges.push(el("span", "badge", i.source));
  }
  if (i.cached) badges.push(el("span", "badge", "cached"));
  if (i.is_mock) badges.push(el("span", "badge medium", "mock data"));
  badges.push(el("span", "muted small", fmtDateTime(i.created_at)));
  $("insight-meta").replaceChildren(...badges);

  const text = $("insight-text");
  text.textContent = i.text.replace(/\*\*/g, "");  // drop markdown bold markers, keep plain text
  text.hidden = false;
  $("insight-evidence-pre").textContent = JSON.stringify(i.evidence_used, null, 2);
  $("insight-evidence").hidden = false;
}

// ---------------------------------------------------------------------------
// PDF reports. A plain <a href> cannot send the X-API-Key header, so we fetch
// the PDF ourselves and hand the browser a temporary "blob" URL to save.
// ---------------------------------------------------------------------------
async function loadReports() {
  if (apiKeyMissing()) {
    $("report-status").textContent = KEY_HELP;
    return;
  }
  const id = state.sessionId;
  try {
    const reports = await api(`/sessions/${id}/reports`, { auth: true });
    if (id !== state.sessionId) return;
    renderReports(reports);
  } catch (err) {
    $("report-status").textContent = `Could not load reports: ${err.message}`;
  }
}

function renderReports(reports) {
  const items = reports.map((r) => {
    const li = el("li");
    const left = el("span");
    left.append(el("span", null, r.filename), el("span", "muted small", ` · ${fmtDateTime(r.created_at)}`));
    const btn = el("button", "secondary", "Download PDF");
    btn.type = "button";
    btn.addEventListener("click", () => downloadReport(r, btn));
    li.append(left, btn);
    return li;
  });
  $("report-list").replaceChildren(...items);
}

async function generateReport() {
  if (apiKeyMissing()) { $("report-status").textContent = KEY_HELP; return; }
  const id = state.sessionId;
  const btn = $("report-btn");
  btn.disabled = true;
  btn.textContent = "Building PDF…";
  $("report-status").textContent = "Building the PDF (it reuses the cached AI explanation if there is one)…";
  try {
    const report = await api(`/sessions/${id}/report`, { method: "POST", auth: true, timeoutMs: 60000 });
    if (id !== state.sessionId) return;
    $("report-status").textContent = `Report ready: ${report.filename}`;
    await loadReports();
    await downloadReport(report);
  } catch (err) {
    $("report-status").textContent = `Report failed: ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Generate report";
  }
}

async function downloadReport(report, button) {
  if (button) { button.disabled = true; button.textContent = "Downloading…"; }
  try {
    const res = await api(report.download_url, { auth: true, raw: true, timeoutMs: 30000 });
    const url = URL.createObjectURL(await res.blob());
    const a = el("a");
    a.href = url;
    a.download = report.filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);  // free the memory a bit later
  } catch (err) {
    $("report-status").textContent = `Download failed: ${err.message}`;
  } finally {
    if (button) { button.disabled = false; button.textContent = "Download PDF"; }
  }
}

// ---------------------------------------------------------------------------
// Live updates (WebSocket) with automatic reconnect
// ---------------------------------------------------------------------------
function setLive(mode) {
  const pill = $("live-pill");
  const labels = { live: ["Live", "pill-live"], wait: ["Reconnecting…", "pill-wait"], off: ["Offline", "pill-off"] };
  const [text, cls] = labels[mode];
  pill.textContent = text;
  pill.className = `pill ${cls}`;
}

function connectWs() {
  const id = state.sessionId;
  if (id === null) return;
  const url = `${CFG.BACKEND_URL.replace(/^http/, "ws")}/ws/${id}`;  // http->ws, https->wss
  let ws;
  try {
    ws = new WebSocket(url);
  } catch {
    scheduleReconnect(id);
    return;
  }
  state.ws = ws;

  ws.onopen = () => {
    if (ws !== state.ws) return;
    state.wsOpen = true;
    state.wsRetry = 0;
    setLive("live");
  };
  ws.onmessage = (event) => {
    if (ws !== state.ws) return;           // a message from an old socket: ignore
    let msg;
    try { msg = JSON.parse(event.data); } catch { return; }
    handleLive(msg);
  };
  ws.onclose = (event) => {
    if (ws !== state.ws) return;           // we closed it on purpose (session switch)
    state.ws = null;
    state.wsOpen = false;
    if (event.code === 4404 || event.code === 4410) {  // session missing / deleted: don't retry
      setLive("off");
      loadSessions();
      return;
    }
    state.wsHadDrop = true;
    setLive("wait");
    scheduleReconnect(id);
  };
  // onerror is always followed by onclose, which handles the retry.
}

function scheduleReconnect(id) {
  if (id !== state.sessionId) return;
  const delay = Math.min(10000, 1000 * 2 ** state.wsRetry);  // 1 s, 2 s, 4 s, 8 s, then 10 s
  state.wsRetry += 1;
  clearTimeout(state.wsTimer);
  state.wsTimer = setTimeout(() => { if (id === state.sessionId) connectWs(); }, delay);
}

function closeWs() {
  clearTimeout(state.wsTimer);
  state.wsOpen = false;
  if (state.ws) {
    const old = state.ws;
    state.ws = null;  // set first, so its onclose knows it was on purpose
    old.close();
  }
  setLive("off");
}

function handleLive(msg) {
  switch (msg.type) {
    case "hello":
      renderSummary(msg.data);
      markUpdated();
      if (state.wsHadDrop) {   // we were disconnected: data may have been missed
        state.wsHadDrop = false;
        loadConnections();
        refreshAll();
      }
      break;
    case "observation": {
      const d = msg.data;
      addConnections(d.new_connections || []);
      // Instant feedback from the pushed totals; the full refresh follows shortly.
      $("stat-connections").textContent = d.stats.total_connections.toLocaleString();
      $("stat-upload").textContent = fmtBytes(d.stats.total_bytes_up);
      $("stat-download").textContent = fmtBytes(d.stats.total_bytes_down);
      if (d.risk_score !== null && d.risk_score !== undefined) {
        $("stat-risk").textContent = d.risk_score;
        $("risk-fill").style.width = `${d.risk_score}%`;
      }
      markUpdated();
      scheduleRefresh();
      break;
    }
    case "session_stopped":
      refreshAll();
      loadSessions();
      break;
    case "session_deleted":
      showError(`Session #${msg.session_id} was deleted.`);
      state.sessionId = null;
      loadSessions();
      break;
    case "error":
      showError(msg.data && msg.data.detail ? msg.data.detail : "Live update error");
      break;
    default:
      break;  // "pong" and unknown types
  }
}

// ---------------------------------------------------------------------------
// Start-up
// ---------------------------------------------------------------------------
function init() {
  if (!CFG.BACKEND_URL) {
    showError("dashboard/config.js is missing or has no BACKEND_URL.");
    return;
  }
  $("session-select").addEventListener("change", (e) => {
    state.userPicked = true;
    selectSession(Number(e.target.value));
  });
  $("conn-search").addEventListener("input", renderConnections);
  $("conn-protocol").addEventListener("change", renderConnections);
  $("insight-btn").addEventListener("click", requestInsight);
  $("report-btn").addEventListener("click", generateReport);
  if (apiKeyMissing()) {
    showError("API_KEY is not set in dashboard/config.js. Live data works, but AI explanations and reports need it.");
  }

  loadSessions();
  setInterval(loadSessions, 10000);            // notice new sessions
  setInterval(renderLastUpdate, 1000);         // keep "Xs ago" ticking
  setInterval(() => {                          // keep the socket alive through idle periods
    if (state.ws && state.wsOpen) state.ws.send("ping");
  }, 25000);
  setInterval(() => {                          // fallback: poll if live updates are down
    if (state.sessionId !== null && !state.wsOpen) { refreshAll(); loadConnections(); }
  }, FALLBACK_POLL_MS);
}

document.addEventListener("DOMContentLoaded", init);
