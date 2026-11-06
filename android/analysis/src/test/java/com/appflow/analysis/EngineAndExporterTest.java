package com.appflow.analysis;

import static com.appflow.analysis.PacketInfo.Direction.DOWN;
import static com.appflow.analysis.PacketInfo.Direction.UP;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class EngineAndExporterTest {

    @Test
    void jsonStringsAreEscaped() {
        assertEquals("\"a\\\"b\\\\c\\n\\u0001\"", ObservationExporter.q("a\"b\\c\n\u0001"));
        assertEquals("null", ObservationExporter.q(null));
        assertEquals("1970-01-01T00:00:01.500Z", ObservationExporter.iso(1500));
    }

    @Test
    void engineNamesConnectionsFromDnsAndSni() {
        AnalysisEngine e = new AnalysisEngine(7, true, json -> 202, null);
        long t = 1_000_000;
        // 1. DNS answer: api.demoshop.example -> 198.51.100.10
        byte[] dns = TestPackets.udp4("192.0.2.53", 53, "10.0.0.2", 50000,
                TestPackets.dnsResponse("api.demoshop.example", "198.51.100.10"));
        e.process(dns, dns.length, t, DOWN, 1);
        // 2. connection to that IP -> named via DNS
        byte[] syn = TestPackets.tcp4("10.0.0.2", 40000, "198.51.100.10", 443, PacketInfo.TCP_SYN, new byte[0]);
        e.process(syn, syn.length, t + 10, UP, 1);
        // 3. connection to an unknown IP whose ClientHello names it -> named via SNI
        byte[] hello = TestPackets.tcp4("10.0.0.2", 40001, "203.0.113.7", 443, 0x18,
                TestPackets.clientHello("tracker.example"));
        e.process(hello, hello.length, t + 20, UP, 1);
        // 4. connection with no visible name -> unavailable (never guessed)
        byte[] quiet = TestPackets.tcp4("10.0.0.2", 40002, "203.0.113.99", 443, PacketInfo.TCP_SYN, new byte[0]);
        e.process(quiet, quiet.length, t + 30, UP, 1);

        String json = e.buildBatch(t + 100, true);
        assertTrue(json.contains("\"domain\":\"api.demoshop.example\",\"domain_source\":\"dns\""), json);
        assertTrue(json.contains("\"domain\":\"tracker.example\",\"domain_source\":\"sni\""), json);
        assertTrue(json.contains("\"domain\":null,\"domain_source\":\"unavailable\",\"ip\":\"203.0.113.99\""), json);
        assertTrue(json.contains("\"session_id\":7"));
        assertTrue(json.contains("\"is_mock\":true"));
        // Only 2 names were really observed (api.* via DNS, tracker.* via SNI); the DNS server flow has none.
        assertTrue(json.contains("\"unique_domains\":2"), json);
    }

    @Test
    void batchesHaveRunningTotalsAndOnlyNewConnections() {
        AnalysisEngine e = new AnalysisEngine(1, false, json -> 202, null);
        byte[] p = TestPackets.udp4("10.0.0.2", 5000, "198.51.100.1", 9999, new byte[100]);
        e.process(p, p.length, 1000, UP, 1);
        String first = e.buildBatch(1000 + ConnectionManager.UDP_IDLE_MS + 1, false);
        String second = e.buildBatch(1000 + ConnectionManager.UDP_IDLE_MS + 2000, false);
        assertTrue(first.contains("\"total_bytes_up\":128"));
        assertTrue(first.contains("\"port\":9999"));
        assertTrue(first.contains("R03_UNUSUAL_PORT"));
        assertTrue(second.contains("\"total_bytes_up\":128"));   // totals repeat (cumulative)
        assertTrue(second.contains("\"connections\":[]"));       // but no connection twice
        assertTrue(second.contains("\"alerts\":[]"));            // and no alert twice
    }

    @Test
    void threadedEngineSendsBatchesAndFinalFlush() throws Exception {
        List<String> sent = new CopyOnWriteArrayList<>();
        AnalysisEngine e = new AnalysisEngine(3, true, json -> { sent.add(json); return 202; }, null);
        e.start();
        long now = System.currentTimeMillis();
        for (int i = 0; i < 500; i++) {
            byte[] p = TestPackets.tcp4("10.0.0.2", 40000 + (i % 5), "198.51.100.10", 443, 0x18, new byte[200]);
            assertTrue(e.submit(p, p.length, now + i, UP, 1));
        }
        e.stop();
        assertEquals(500, e.processedPackets());
        assertTrue(sent.size() >= 1);
        String last = sent.get(sent.size() - 1);
        assertTrue(last.contains("\"total_connections\":5"), last);
        long reported = sent.stream().mapToLong(j -> j.split("\"protocol\":\"TCP\"", -1).length - 1).sum();
        assertEquals(5, reported);                                // every connection reported exactly once
        assertTrue(!e.submit(new byte[40], 40, now, UP, 1));      // after stop: refused, never blocks
    }

    @Test
    void failedBatchIsRetriedWithTheNextOne() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        List<String> accepted = Collections.synchronizedList(new java.util.ArrayList<>());
        AnalysisEngine e = new AnalysisEngine(3, true, json -> {
            if (calls.incrementAndGet() == 1) throw new IOException("wifi blip");
            accepted.add(json);
            return 202;
        }, null);
        e.start();
        Thread.sleep(AnalysisEngine.EXPORT_INTERVAL_MS + 600);    // first periodic batch fails
        e.stop();                                                 // final batch triggers the retry
        assertTrue(accepted.size() >= 2, "failed batch should be resent: " + accepted.size());
        assertEquals(accepted.size(), e.acceptedBatches());
    }
}
