package com.appflow.analysis;

import static com.appflow.analysis.PacketInfo.Direction.UP;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class DetectionAndRiskTest {

    private final ConnectionManager cm = new ConnectionManager();
    private final DetectionEngine det = new DetectionEngine();

    private void send(String dst, int localPort, int remotePort, int payload, long ts) {
        PacketInfo p = TestPackets.parse(TestPackets.tcp4("10.0.0.2", localPort, dst, remotePort, 0x18,
                new byte[payload]), UP, ts);
        det.onPacket(p, cm.onPacket(p));
    }

    private List<DetectionEngine.Alert> alerts() {
        return det.drainNewAlerts();
    }

    @Test
    void highUploadFiresMediumThenHigh() {
        for (int i = 0; i < 800; i++) send("203.0.113.7", 40000, 443, 1400, i);      // ~1.15 MB up, nothing down
        List<DetectionEngine.Alert> a = alerts();
        assertEquals(1, a.size());
        assertEquals("R01_HIGH_UPLOAD", a.get(0).ruleId);
        assertEquals("medium", a.get(0).severity);
        assertEquals("observed", a.get(0).evidenceType);
        assertTrue((Long) a.get(0).evidence.get("bytes_up") >= DetectionEngine.HIGH_UPLOAD_BYTES);
        for (int i = 0; i < 3000; i++) send("203.0.113.7", 40000, 443, 1400, 1000 + i);   // > 5 MB
        a = alerts();
        assertEquals(1, a.size());
        assertEquals("high", a.get(0).severity);
        assertTrue(alerts().isEmpty());                                                // never repeats
    }

    @Test
    void repeatedConnectionsWithinAMinute() {
        for (int i = 0; i < 10; i++) send("198.51.100.5", 41000 + i, 443, 0, i * 3000L);
        List<DetectionEngine.Alert> a = alerts();
        assertEquals(1, a.stream().filter(x -> x.ruleId.equals("R02_REPEATED_CONNECTIONS")).count());
    }

    @Test
    void slowConnectionsAreNotRepeated() {
        for (int i = 0; i < 10; i++) send("198.51.100.5", 41000 + i, 443, 0, i * 20_000L);  // spread over 3 min
        assertTrue(alerts().stream().noneMatch(x -> x.ruleId.equals("R02_REPEATED_CONNECTIONS")));
    }

    @Test
    void unusualPortOncePerTarget() {
        send("203.0.113.45", 40000, 7777, 0, 1);
        send("203.0.113.45", 40001, 7777, 0, 2);
        send("198.51.100.10", 40002, 443, 0, 3);
        List<DetectionEngine.Alert> a = alerts();
        assertEquals(1, a.size());
        assertEquals("R03_UNUSUAL_PORT", a.get(0).ruleId);
        assertEquals("low", a.get(0).severity);
        assertEquals(7777, a.get(0).relatedPort);
    }

    @Test
    void regularContactIsInferredNotObserved() {
        for (int i = 0; i < 6; i++) send("203.0.113.7", 42000 + i, 443, 0, i * 15_000L);
        List<DetectionEngine.Alert> a = alerts();
        DetectionEngine.Alert p = a.stream().filter(x -> x.ruleId.equals("R04_PERIODIC_CONTACT")).findFirst().orElseThrow();
        assertEquals("inferred", p.evidenceType);                  // background state is not observable
        assertEquals(15.0, p.evidence.get("avg_interval_seconds"));
        assertTrue(p.description.contains("cannot be observed"));
    }

    @Test
    void irregularContactIsNotPeriodic() {
        long[] times = {0, 5_000, 45_000, 57_000, 87_000, 105_000};
        for (int i = 0; i < times.length; i++) send("203.0.113.7", 43000 + i, 443, 0, times[i]);
        assertTrue(alerts().stream().noneMatch(x -> x.ruleId.equals("R04_PERIODIC_CONTACT")));
    }

    @Test
    void alertsNeverSayMalware() {
        for (int i = 0; i < 800; i++) send("203.0.113.7", 40000, 443, 1400, i);
        send("203.0.113.45", 40001, 7777, 0, 900);
        for (DetectionEngine.Alert a : alerts()) {
            assertFalse((a.title + a.description).toLowerCase().contains("malware"));
            assertFalse(a.evidence.isEmpty());
        }
    }

    // ------------------------------------------------------------ risk scorer

    private static DetectionEngine.Alert alert(String rule, String sev, String type) {
        return new DetectionEngine.Alert(rule, "t", "d", sev, type, new java.util.LinkedHashMap<>(),
                null, "203.0.113.1", 443, 0);
    }

    @Test
    void scoreIsExplainable() {
        List<DetectionEngine.Alert> list = new ArrayList<>();
        list.add(alert("R03_UNUSUAL_PORT", "low", "observed"));          // +5
        list.add(alert("R02_REPEATED_CONNECTIONS", "medium", "observed")); // +15
        list.add(alert("R04_PERIODIC_CONTACT", "medium", "inferred"));     // +9 (15 x 0.6)
        list.add(alert("R01_HIGH_UPLOAD", "high", "observed"));            // +30
        RiskScorer.Score s = new RiskScorer().score(list);
        assertEquals(59, s.score);
        assertEquals("medium", s.level);
        assertEquals(4, s.breakdown.size());
        assertTrue(s.breakdown.get(2).startsWith("+9 R04_PERIODIC_CONTACT"));
        assertEquals(9, list.get(2).evidence.get("risk_points"));         // visible to dashboard/PDF
    }

    @Test
    void perRuleCapAndLevels() {
        List<DetectionEngine.Alert> list = new ArrayList<>();
        for (int i = 0; i < 5; i++) list.add(alert("R01_HIGH_UPLOAD", "high", "observed"));
        RiskScorer.Score s = new RiskScorer().score(list);
        assertEquals(40, s.score);                                         // capped at 40 for one rule
        assertEquals(0, list.get(4).riskPoints);
        assertEquals("low", RiskScorer.level(39));
        assertEquals("medium", RiskScorer.level(40));
        assertEquals("high", RiskScorer.level(70));
        assertEquals(0, new RiskScorer().score(List.of(alert("X", "high", "not_observable"))).score);
    }
}
