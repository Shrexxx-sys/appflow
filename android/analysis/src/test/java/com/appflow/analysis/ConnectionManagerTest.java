package com.appflow.analysis;

import static com.appflow.analysis.PacketInfo.Direction.DOWN;
import static com.appflow.analysis.PacketInfo.Direction.UP;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class ConnectionManagerTest {

    private static final String PHONE = "10.0.0.2";
    private static final String SERVER = "198.51.100.10";

    private static PacketInfo up(int localPort, int remotePort, int flags, int payload, long ts) {
        return TestPackets.parse(TestPackets.tcp4(PHONE, localPort, SERVER, remotePort, flags, new byte[payload]), UP, ts);
    }

    private static PacketInfo down(int localPort, int remotePort, int flags, int payload, long ts) {
        return TestPackets.parse(TestPackets.tcp4(SERVER, remotePort, PHONE, localPort, flags, new byte[payload]), DOWN, ts);
    }

    @Test
    void bothDirectionsAreOneConnection() {
        ConnectionManager cm = new ConnectionManager();
        ConnectionManager.Connection a = cm.onPacket(up(40000, 443, PacketInfo.TCP_SYN, 0, 1000));
        ConnectionManager.Connection b = cm.onPacket(down(40000, 443, PacketInfo.TCP_SYN | PacketInfo.TCP_ACK, 0, 1050));
        cm.onPacket(up(40000, 443, PacketInfo.TCP_ACK, 100, 1100));
        cm.onPacket(down(40000, 443, PacketInfo.TCP_ACK, 1000, 1500));
        assertSame(a, b);
        assertEquals(1, cm.totalConnections());
        assertEquals(40 + 140, a.bytesUp);                  // header-inclusive sizes
        assertEquals(40 + 1040, a.bytesDown);
        assertEquals(2, a.packetsUp);
        assertEquals(2, a.packetsDown);
        assertEquals(500, a.durationMs());
        assertEquals(SERVER, a.remoteIp);
        assertEquals(443, a.remotePort);
        assertEquals(cm.totalBytesUp(), a.bytesUp);
        assertEquals(cm.totalBytesDown(), a.bytesDown);
    }

    @Test
    void differentPortsAreDifferentConnections() {
        ConnectionManager cm = new ConnectionManager();
        cm.onPacket(up(40000, 443, 0, 0, 1));
        cm.onPacket(up(40001, 443, 0, 0, 2));
        cm.onPacket(up(40000, 8443, 0, 0, 3));
        assertEquals(3, cm.totalConnections());
    }

    @Test
    void finBothWaysClosesAndIsReportedOnce() {
        ConnectionManager cm = new ConnectionManager();
        cm.onPacket(up(40000, 443, PacketInfo.TCP_SYN, 0, 1000));
        cm.onPacket(up(40000, 443, PacketInfo.TCP_FIN | PacketInfo.TCP_ACK, 0, 2000));
        assertTrue(cm.collectReportable(2001).isEmpty());   // only one side finished
        ConnectionManager.Connection c = cm.onPacket(down(40000, 443, PacketInfo.TCP_FIN | PacketInfo.TCP_ACK, 0, 2100));
        assertTrue(c.isClosed());
        List<ConnectionManager.Connection> out = cm.collectReportable(2200);
        assertEquals(1, out.size());
        assertEquals(0, cm.activeCount());
        assertTrue(cm.collectReportable(99_000).isEmpty());
    }

    @Test
    void rstClosesImmediately() {
        ConnectionManager cm = new ConnectionManager();
        cm.onPacket(up(40000, 443, PacketInfo.TCP_SYN, 0, 1000));
        cm.onPacket(down(40000, 443, PacketInfo.TCP_RST, 0, 1100));
        assertEquals(1, cm.collectReportable(1200).size());
    }

    @Test
    void idleUdpIsReportedAndForgotten() {
        ConnectionManager cm = new ConnectionManager();
        cm.onPacket(TestPackets.parse(TestPackets.udp4(PHONE, 5000, "192.0.2.53", 53, new byte[30]), UP, 1000));
        assertTrue(cm.collectReportable(5000).isEmpty());
        assertEquals(1, cm.collectReportable(1000 + ConnectionManager.UDP_IDLE_MS + 1).size());
        assertEquals(0, cm.activeCount());
    }

    @Test
    void longOpenConnectionReportedOnceButStillCounted() {
        ConnectionManager cm = new ConnectionManager();
        cm.onPacket(up(40000, 443, PacketInfo.TCP_SYN, 0, 0));
        for (long t = 1000; t <= 31_000; t += 1000) cm.onPacket(down(40000, 443, PacketInfo.TCP_ACK, 500, t));
        assertEquals(1, cm.collectReportable(31_001).size());
        assertEquals(1, cm.activeCount());                  // still open, still tracked
        long before = cm.totalBytesDown();
        cm.onPacket(down(40000, 443, PacketInfo.TCP_ACK, 500, 32_000));
        assertTrue(cm.collectReportable(32_001).isEmpty()); // not reported twice
        assertEquals(before + 540, cm.totalBytesDown());    // but totals keep growing
    }

    @Test
    void portReuseAfterCloseStartsNewConnection() {
        ConnectionManager cm = new ConnectionManager();
        ConnectionManager.Connection first = cm.onPacket(up(40000, 443, PacketInfo.TCP_SYN, 0, 1));
        cm.onPacket(down(40000, 443, PacketInfo.TCP_RST, 0, 2));
        ConnectionManager.Connection second = cm.onPacket(up(40000, 443, PacketInfo.TCP_SYN, 0, 3));
        assertTrue(first != second);
        assertEquals(2, cm.totalConnections());
        assertEquals(2, cm.collectAll().size());
    }

    @Test
    void fragmentsCountInTotalsOnly() {
        ConnectionManager cm = new ConnectionManager();
        byte[] p = TestPackets.udp4(PHONE, 1, SERVER, 2, new byte[100]);
        TestPackets.put16(p, 6, 50);
        assertNull(cm.onPacket(TestPackets.parse(p, UP, 1)));
        assertEquals(p.length, cm.totalBytesUp());
        assertEquals(p.length, cm.untrackedBytes());
        assertEquals(0, cm.totalConnections());
    }

    @Test
    void tableLimitProtectsMemory() {
        ConnectionManager cm = new ConnectionManager(2);
        cm.onPacket(up(1, 443, 0, 0, 1));
        cm.onPacket(up(2, 443, 0, 0, 1));
        assertNull(cm.onPacket(up(3, 443, 0, 0, 1)));
        assertEquals(2, cm.totalConnections());
        assertEquals(40, cm.untrackedBytes());
    }

    @Test
    void domainsAreCountedOnce() {
        ConnectionManager cm = new ConnectionManager();
        ConnectionManager.Connection a = cm.onPacket(up(1, 443, 0, 0, 1));
        ConnectionManager.Connection b = cm.onPacket(up(2, 443, 0, 0, 1));
        cm.assignDomain(a, "api.example", "dns");
        cm.assignDomain(b, "api.example", "sni");
        cm.assignDomain(b, null, "dns");                    // ignored
        assertEquals(1, cm.uniqueDomains());
        assertEquals("sni", b.domainSource);
    }
}
