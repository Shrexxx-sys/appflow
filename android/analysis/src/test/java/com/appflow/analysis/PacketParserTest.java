package com.appflow.analysis;

import static com.appflow.analysis.PacketInfo.Direction.DOWN;
import static com.appflow.analysis.PacketInfo.Direction.UP;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

class PacketParserTest {

    @Test
    void parsesIpv4Tcp() {
        byte[] payload = "hello".getBytes();
        byte[] p = TestPackets.tcp4("10.0.0.2", 40000, "198.51.100.10", 443, PacketInfo.TCP_SYN, payload);
        PacketInfo i = TestPackets.parse(p, UP, 1000);
        assertNotNull(i);
        assertEquals(4, i.ipVersion);
        assertEquals("10.0.0.2", i.srcIp);
        assertEquals("198.51.100.10", i.dstIp);
        assertEquals(40000, i.srcPort);
        assertEquals(443, i.dstPort);
        assertEquals("TCP", i.protocolName());
        assertTrue(i.hasFlag(PacketInfo.TCP_SYN));
        assertFalse(i.hasFlag(PacketInfo.TCP_FIN));
        assertEquals(p.length, i.totalLength);
        assertEquals(40, i.payloadOffset);
        assertEquals(5, i.payloadLength);
        assertEquals(10123, i.uid);
    }

    @Test
    void parsesIpv4UdpAndDirectionHelpers() {
        byte[] p = TestPackets.udp4("192.0.2.53", 53, "10.0.0.2", 51000, new byte[12]);
        PacketInfo i = TestPackets.parse(p, DOWN, 1);
        assertEquals("UDP", i.protocolName());
        assertEquals("10.0.0.2", i.localIp());       // DOWN: phone is the destination
        assertEquals("192.0.2.53", i.remoteIp());
        assertEquals(51000, i.localPort());
        assertEquals(53, i.remotePort());
        assertEquals(28, i.payloadOffset);
        assertEquals(12, i.payloadLength);
    }

    @Test
    void parsesIpv6TcpAndUdp() {
        byte[] tcp = TestPackets.ipv6("fd00::2", "2001:db8::10", PacketInfo.PROTO_TCP,
                TestPackets.tcpHeader(40001, 443, PacketInfo.TCP_ACK), new byte[3]);
        PacketInfo t = TestPackets.parse(tcp, UP, 1);
        assertEquals(6, t.ipVersion);
        assertEquals(443, t.dstPort);
        assertEquals(TestPackets.parse(tcp, UP, 1).dstIp, t.dstIp);
        assertTrue(t.dstIp.startsWith("2001:db8:"));
        assertEquals(63, t.totalLength);

        byte[] udp = TestPackets.ipv6("fd00::2", "2001:db8::53", PacketInfo.PROTO_UDP,
                TestPackets.udpHeader(5353, 53, 4), new byte[4]);
        PacketInfo u = TestPackets.parse(udp, UP, 1);
        assertEquals("UDP", u.protocolName());
        assertEquals(53, u.dstPort);
        assertEquals(48, u.payloadOffset);
    }

    @Test
    void walksIpv6ExtensionHeaders() {
        byte[] hopByHop = new byte[8];
        hopByHop[0] = (byte) PacketInfo.PROTO_UDP;   // next header after this one = UDP
        hopByHop[1] = 0;                              // length = (0 + 1) * 8 bytes
        byte[] udp = TestPackets.udpHeader(1234, 53, 0);
        byte[] transport = new byte[16];
        System.arraycopy(hopByHop, 0, transport, 0, 8);
        System.arraycopy(udp, 0, transport, 8, 8);
        byte[] p = TestPackets.ipv6("fd00::2", "2001:db8::53", 0, transport, new byte[0]);
        PacketInfo i = TestPackets.parse(p, UP, 1);
        assertEquals(PacketInfo.PROTO_UDP, i.protocol);
        assertEquals(53, i.dstPort);
    }

    @Test
    void nonFirstIpv4FragmentHasNoPorts() {
        byte[] p = TestPackets.udp4("10.0.0.2", 1111, "198.51.100.1", 2222, new byte[20]);
        TestPackets.put16(p, 6, 185);                // fragment offset 185 (x8 bytes), not the first piece
        PacketInfo i = TestPackets.parse(p, UP, 1);
        assertTrue(i.fragment);
        assertFalse(i.hasPorts());
        assertEquals(p.length, i.totalLength);       // bytes still counted
    }

    @Test
    void nonFirstIpv6FragmentHasNoPorts() {
        byte[] frag = new byte[8];
        frag[0] = (byte) PacketInfo.PROTO_UDP;
        TestPackets.put16(frag, 2, 100 << 3);        // fragment offset 100
        byte[] p = TestPackets.ipv6("fd00::2", "2001:db8::1", 44, frag, new byte[30]);
        PacketInfo i = TestPackets.parse(p, UP, 1);
        assertTrue(i.fragment);
        assertFalse(i.hasPorts());
    }

    @Test
    void truncatedCopyKeepsRealLength() {
        byte[] p = TestPackets.tcp4("10.0.0.2", 1, "198.51.100.1", 443, 0, new byte[3000]);
        PacketInfo i = PacketParser.parse(p, 2048, 1, UP, -1);   // the engine copies at most 2 KB
        assertEquals(3040, i.totalLength);
        assertEquals(2048 - 40, i.payloadLength);
    }

    @Test
    void rejectsMalformedPackets() {
        assertNull(PacketParser.parse(null, 10, 1, UP, -1));
        assertNull(PacketParser.parse(new byte[0], 0, 1, UP, -1));
        assertNull(PacketParser.parse(new byte[10], 11, 1, UP, -1));              // length > buffer
        assertNull(PacketParser.parse(new byte[19], 19, 1, UP, -1));              // too short for IPv4
        byte[] badVersion = TestPackets.udp4("10.0.0.2", 1, "10.0.0.3", 2, new byte[0]);
        badVersion[0] = 0x75;
        assertNull(TestPackets.parse(badVersion, UP, 1));
        byte[] badIhl = TestPackets.udp4("10.0.0.2", 1, "10.0.0.3", 2, new byte[0]);
        badIhl[0] = 0x44;                                                          // IHL 4 < minimum 5
        assertNull(TestPackets.parse(badIhl, UP, 1));
        byte[] lyingLength = TestPackets.udp4("10.0.0.2", 1, "10.0.0.3", 2, new byte[0]);
        TestPackets.put16(lyingLength, 2, 10);                                     // total < header
        assertNull(TestPackets.parse(lyingLength, UP, 1));
        byte[] shortV6 = new byte[39];
        shortV6[0] = 0x60;                                                         // IPv6 but < 40 bytes
        assertNull(PacketParser.parse(shortV6, 39, 1, UP, -1));
    }

    @Test
    void cutOffTcpHeaderGivesNoPortsButNoCrash() {
        byte[] p = TestPackets.tcp4("10.0.0.2", 1, "198.51.100.1", 443, 0, new byte[0]);
        PacketInfo i = PacketParser.parse(p, 30, 1, UP, -1);   // only 10 of 20 TCP header bytes
        assertNotNull(i);
        assertFalse(i.hasPorts());
    }

    @Test
    void icmpHasNoPorts() {
        byte[] p = TestPackets.ipv4("10.0.0.2", "198.51.100.1", PacketInfo.PROTO_ICMP, new byte[8], new byte[0]);
        PacketInfo i = TestPackets.parse(p, UP, 1);
        assertEquals("ICMP", i.protocolName());
        assertFalse(i.hasPorts());
    }

    @Test
    void neverThrowsOnRandomOrCorruptedInput() {
        Random r = new Random(42);
        byte[] valid = TestPackets.tcp4("10.0.0.2", 40000, "198.51.100.10", 443, 0x18, new byte[64]);
        for (int n = 0; n < 20_000; n++) {
            byte[] junk;
            if (n % 2 == 0) {
                junk = new byte[r.nextInt(120)];
                r.nextBytes(junk);
                if (junk.length > 0) junk[0] = (byte) ((r.nextBoolean() ? 0x40 : 0x60) | (junk[0] & 0x0F));
            } else {
                junk = Arrays.copyOf(valid, valid.length);
                for (int k = 0; k < 4; k++) junk[r.nextInt(junk.length)] = (byte) r.nextInt(256);
            }
            int len = junk.length == 0 ? 0 : r.nextInt(junk.length + 1);
            PacketParser.parse(junk, len, n, n % 3 == 0 ? DOWN : UP, -1);  // must not throw
        }
    }
}
