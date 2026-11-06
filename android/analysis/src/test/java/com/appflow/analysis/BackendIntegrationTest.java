package com.appflow.analysis;

import static com.appflow.analysis.PacketInfo.Direction.DOWN;
import static com.appflow.analysis.PacketInfo.Direction.UP;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Sends SIMULATED packets through the real engine to a REAL running backend and checks that the
 * backend accepts the JSON and stores what we expect.
 * Runs only when APPFLOW_BACKEND_URL and APPFLOW_API_KEY are set (otherwise it is skipped).
 */
class BackendIntegrationTest {

    private static final String URL_ENV = System.getenv("APPFLOW_BACKEND_URL");
    private static final String KEY_ENV = System.getenv("APPFLOW_API_KEY");

    @Test
    void backendAcceptsEngineJson() throws Exception {
        assumeTrue(URL_ENV != null && KEY_ENV != null, "set APPFLOW_BACKEND_URL and APPFLOW_API_KEY to run");
        ObservationExporter exporter = new ObservationExporter(URL_ENV, KEY_ENV);
        long sessionId = exporter.startSession("com.example.demoshop", "DemoShop (simulated packets)",
                "BackendIntegrationTest", true);
        AnalysisEngine engine = new AnalysisEngine(sessionId, true, json -> exporter.postObservation(json).status, null);

        long t0 = System.currentTimeMillis() - 120_000;   // pretend the traffic happened in the last 2 minutes
        byte[] dns = TestPackets.udp4("192.0.2.53", 53, "10.0.0.2", 50000,
                TestPackets.dnsResponse("api.demoshop.example", "198.51.100.10"));
        engine.process(dns, dns.length, t0, DOWN, 1);
        for (int i = 0; i < 20; i++) {                    // normal API traffic, named via DNS
            byte[] up = TestPackets.tcp4("10.0.0.2", 40000, "198.51.100.10", 443, 0x18, new byte[300]);
            byte[] down = TestPackets.tcp4("198.51.100.10", 443, "10.0.0.2", 40000, 0x18, new byte[1400]);
            engine.process(up, up.length, t0 + 100 + i, UP, 1);
            engine.process(down, down.length, t0 + 150 + i, DOWN, 1);
        }
        for (int k = 0; k < 6; k++) {                     // regular uploads every 15 s, named via SNI
            long ts = t0 + 1_000 + k * 15_000L;
            byte[] hello = TestPackets.tcp4("10.0.0.2", 41000 + k, "203.0.113.7", 443, 0x18,
                    TestPackets.clientHello("tracker.example"));
            engine.process(hello, hello.length, ts, UP, 1);
            for (int i = 0; i < 150; i++) {
                byte[] up = TestPackets.tcp4("10.0.0.2", 41000 + k, "203.0.113.7", 443, 0x18, new byte[1400]);
                engine.process(up, up.length, ts + 1 + i, UP, 1);
            }
        }
        byte[] odd = TestPackets.tcp4("10.0.0.2", 42000, "203.0.113.45", 7777, PacketInfo.TCP_SYN, new byte[0]);
        engine.process(odd, odd.length, t0 + 100_000, UP, 1);

        ObservationExporter.Response r1 = exporter.postObservation(engine.buildBatch(t0 + 60_000, false));
        assertEquals(202, r1.status, r1.body);
        ObservationExporter.Response r2 = exporter.postObservation(engine.buildBatch(t0 + 110_000, true));
        assertEquals(202, r2.status, r2.body);
        assertEquals(200, exporter.stopSession(sessionId).status);

        String summary = get("/sessions/" + sessionId + "/summary");
        String conns = get("/sessions/" + sessionId + "/connections");
        String alerts = get("/sessions/" + sessionId + "/alerts");
        assertTrue(summary.contains("\"total_connections\":" + engine.connections().totalConnections()), summary);
        assertTrue(summary.contains("\"total_bytes_up\":" + engine.connections().totalBytesUp()), summary);
        assertTrue(conns.contains("\"domain\":\"api.demoshop.example\",\"domain_source\":\"dns\""), conns);
        assertTrue(conns.contains("\"domain\":\"tracker.example\",\"domain_source\":\"sni\""), conns);
        assertTrue(conns.contains("\"domain_source\":\"unavailable\""), conns);
        assertTrue(alerts.contains("R01_HIGH_UPLOAD"), alerts);
        assertTrue(alerts.contains("R03_UNUSUAL_PORT"), alerts);
        assertTrue(alerts.contains("\"rule_id\":\"R04_PERIODIC_CONTACT\""), alerts);
        assertTrue(alerts.contains("\"evidence_type\":\"inferred\""), alerts);
        assertTrue(alerts.contains("\"risk_points\""), alerts);
        assertTrue(summary.contains("\"risk_score\":" + engine.lastRiskScore()), summary);
        System.out.println("INTEGRATION OK session=" + sessionId + " risk=" + engine.lastRiskScore()
                + " connections=" + engine.connections().totalConnections());
    }

    private static String get(String path) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(URL_ENV + path).openConnection();
        c.setConnectTimeout(5000);
        c.setReadTimeout(5000);
        try (InputStream in = c.getInputStream()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            in.transferTo(out);
            return out.toString(StandardCharsets.UTF_8.name());
        } finally {
            c.disconnect();
        }
    }
}
