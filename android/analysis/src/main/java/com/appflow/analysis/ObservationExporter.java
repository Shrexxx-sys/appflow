package com.appflow.analysis;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Talks to the FastAPI backend (see docs/CONTRACT.md):
 *   POST /sessions, POST /sessions/{id}/stop, POST /observations  - all with the X-API-Key header.
 *
 * JSON is written by hand (no library needed) and every string is escaped.
 * Only METADATA is sent: domains, IPs, ports, byte counts, timing, alerts. Never payloads.
 * Uses java.net.HttpURLConnection, which exists both on Android and on a normal JVM.
 */
public final class ObservationExporter {

    /** HTTP status + response body. */
    public static final class Response {
        public final int status;
        public final String body;

        Response(int status, String body) {
            this.status = status;
            this.body = body;
        }

        public boolean ok() { return status >= 200 && status < 300; }
    }

    private static final Pattern FIRST_ID = Pattern.compile("\"id\"\\s*:\\s*(\\d+)");
    private final String baseUrl;
    private final String apiKey;
    private final int timeoutMs;

    public ObservationExporter(String baseUrl, String apiKey) {
        this(baseUrl, apiKey, 5000);
    }

    public ObservationExporter(String baseUrl, String apiKey, int timeoutMs) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.apiKey = apiKey;
        this.timeoutMs = timeoutMs;
    }

    // ------------------------------------------------------------- backend calls

    /** POST /sessions -> returns the new session id. */
    public long startSession(String packageName, String appName, String deviceLabel, boolean isMock)
            throws IOException {
        String json = "{\"package_name\":" + q(packageName) + ",\"app_name\":" + q(appName)
                + ",\"device_label\":" + q(deviceLabel) + ",\"is_mock\":" + isMock + "}";
        Response r = post("/sessions", json);
        if (r.status != 201) throw new IOException("Start session failed: HTTP " + r.status + " " + r.body);
        Matcher m = FIRST_ID.matcher(r.body);   // the session "id" is the first field in the reply
        if (!m.find()) throw new IOException("No session id in reply: " + r.body);
        return Long.parseLong(m.group(1));
    }

    public Response stopSession(long sessionId) throws IOException {
        return post("/sessions/" + sessionId + "/stop", null);
    }

    public Response postObservation(String json) throws IOException {
        return post("/observations", json);
    }

    Response post(String path, String json) throws IOException {
        HttpURLConnection con = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        try {
            con.setRequestMethod("POST");
            con.setConnectTimeout(timeoutMs);
            con.setReadTimeout(timeoutMs);
            con.setRequestProperty("X-API-Key", apiKey);
            con.setRequestProperty("Content-Type", "application/json");
            con.setDoOutput(true);
            byte[] body = (json == null ? "" : json).getBytes(StandardCharsets.UTF_8);
            con.setFixedLengthStreamingMode(body.length);
            try (OutputStream out = con.getOutputStream()) {
                out.write(body);
            }
            int status = con.getResponseCode();
            InputStream in = status >= 400 ? con.getErrorStream() : con.getInputStream();
            return new Response(status, readAll(in));
        } finally {
            con.disconnect();
        }
    }

    // ------------------------------------------------------------- JSON building

    /** Build one POST /observations body. stats = running totals; connections/alerts = only NEW ones. */
    public static String buildObservationJson(long sessionId, long capturedAtMs, long totalBytesUp,
                                              long totalBytesDown, int totalConnections, int uniqueDomains,
                                              Integer riskScore, List<ConnectionManager.Connection> connections,
                                              List<DetectionEngine.Alert> alerts, boolean isMock) {
        StringBuilder sb = new StringBuilder(256 + connections.size() * 220);
        sb.append("{\"session_id\":").append(sessionId)
          .append(",\"captured_at\":").append(q(iso(capturedAtMs)))
          .append(",\"risk_score\":").append(riskScore == null ? "null" : String.valueOf(riskScore))
          .append(",\"stats\":{\"total_bytes_up\":").append(totalBytesUp)
          .append(",\"total_bytes_down\":").append(totalBytesDown)
          .append(",\"total_connections\":").append(totalConnections)
          .append(",\"unique_domains\":").append(uniqueDomains).append("}");

        sb.append(",\"connections\":[");
        for (int i = 0; i < connections.size(); i++) {
            ConnectionManager.Connection c = connections.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"domain\":").append(q(c.domain))
              .append(",\"domain_source\":").append(q(c.domain == null ? "unavailable" : c.domainSource))
              .append(",\"ip\":").append(q(c.remoteIp))
              .append(",\"port\":").append(c.remotePort)
              .append(",\"protocol\":").append(q(c.protocol))
              .append(",\"bytes_up\":").append(c.bytesUp)
              .append(",\"bytes_down\":").append(c.bytesDown)
              .append(",\"timestamp\":").append(q(iso(c.firstSeenMs)))
              .append(",\"duration_ms\":").append(c.durationMs()).append('}');
        }
        sb.append("],\"alerts\":[");
        for (int i = 0; i < alerts.size(); i++) {
            DetectionEngine.Alert a = alerts.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"rule_id\":").append(q(a.ruleId))
              .append(",\"title\":").append(q(a.title))
              .append(",\"description\":").append(q(a.description))
              .append(",\"severity\":").append(q(a.severity))
              .append(",\"evidence_type\":").append(q(a.evidenceType))
              .append(",\"evidence\":").append(mapJson(a.evidence))
              .append(",\"related_domain\":").append(q(a.relatedDomain))
              .append(",\"related_ip\":").append(q(a.relatedIp))
              .append(",\"related_port\":").append(a.relatedPort == null ? "null" : String.valueOf(a.relatedPort))
              .append(",\"detected_at\":").append(q(iso(a.detectedAtMs))).append('}');
        }
        sb.append("],\"is_mock\":").append(isMock).append('}');
        return sb.toString();
    }

    static String iso(long epochMs) {
        return Instant.ofEpochMilli(epochMs).toString();   // e.g. 2026-11-05T10:00:05.123Z (UTC)
    }

    private static String mapJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append(q(e.getKey())).append(':');
            Object v = e.getValue();
            if (v == null) sb.append("null");
            else if (v instanceof Number || v instanceof Boolean) sb.append(v);
            else sb.append(q(String.valueOf(v)));
        }
        return sb.append('}').toString();
    }

    /** JSON string literal with escaping (quotes, backslashes, control characters). */
    static String q(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    private static String readAll(InputStream in) throws IOException {
        if (in == null) return "";
        try (InputStream s = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = s.read(buf)) != -1) out.write(buf, 0, n);
            return out.toString(StandardCharsets.UTF_8.name());
        }
    }
}
