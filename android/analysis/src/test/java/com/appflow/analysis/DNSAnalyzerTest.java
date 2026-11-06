package com.appflow.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

class DNSAnalyzerTest {

    @Test
    void learnsIpv4AndIpv6AnswersForTheAskedName() {
        DNSAnalyzer dns = new DNSAnalyzer();
        byte[] r = TestPackets.dnsResponse("API.Demoshop.example", "198.51.100.10", "2001:db8::10");
        assertEquals(2, dns.observeDnsResponse(r, 0, r.length));
        assertEquals("api.demoshop.example", dns.domainFor("198.51.100.10"));
        String v6 = TestPackets.parse(TestPackets.ipv6("fd00::2", "2001:db8::10", PacketInfo.PROTO_TCP,
                TestPackets.tcpHeader(1, 443, 0), new byte[0]), PacketInfo.Direction.UP, 1).dstIp;
        assertEquals("api.demoshop.example", dns.domainFor(v6));   // same string format as the parser
        assertNull(dns.domainFor("203.0.113.1"));                   // never guessed
    }

    @Test
    void worksInsideAUdpPacket() {
        DNSAnalyzer dns = new DNSAnalyzer();
        byte[] answer = TestPackets.dnsResponse("cdn.example", "198.51.100.20");
        byte[] pkt = TestPackets.udp4("192.0.2.53", 53, "10.0.0.2", 50000, answer);
        PacketInfo i = TestPackets.parse(pkt, PacketInfo.Direction.DOWN, 1);
        assertEquals(1, dns.observeDnsResponse(pkt, i.payloadOffset, i.payloadLength));
        assertEquals("cdn.example", dns.domainFor("198.51.100.20"));
    }

    @Test
    void ignoresQueriesAndErrors() {
        DNSAnalyzer dns = new DNSAnalyzer();
        byte[] query = TestPackets.dnsResponse("a.example", "198.51.100.1");
        query[2] = 0x01;                                           // QR = 0 -> question
        assertEquals(0, dns.observeDnsResponse(query, 0, query.length));
        byte[] nx = TestPackets.dnsResponse("a.example", "198.51.100.1");
        nx[3] = (byte) 0x83;                                       // rcode 3 = NXDOMAIN
        assertEquals(0, dns.observeDnsResponse(nx, 0, nx.length));
    }

    @Test
    void survivesCompressionLoopAndGarbage() {
        DNSAnalyzer dns = new DNSAnalyzer();
        byte[] loop = TestPackets.dnsResponse("a.example", "198.51.100.1");
        loop[12] = (byte) 0xC0;                                    // name = pointer to itself
        loop[13] = 12;
        assertEquals(0, dns.observeDnsResponse(loop, 0, loop.length));
        Random r = new Random(7);
        byte[] valid = TestPackets.dnsResponse("x.example", "198.51.100.1", "198.51.100.2");
        for (int n = 0; n < 20_000; n++) {
            byte[] junk = Arrays.copyOf(valid, valid.length);
            for (int k = 0; k < 3; k++) junk[r.nextInt(junk.length)] = (byte) r.nextInt(256);
            dns.observeDnsResponse(junk, 0, r.nextInt(junk.length + 1));       // must not throw
            DNSAnalyzer.extractSni(junk, 0, junk.length);
        }
    }

    @Test
    void rejectsWeirdCharactersInNames() {
        DNSAnalyzer dns = new DNSAnalyzer();
        byte[] r = TestPackets.dnsResponse("evil.example", "198.51.100.1");
        r[13] = '<';                                               // first label char
        assertEquals(0, dns.observeDnsResponse(r, 0, r.length));
    }

    @Test
    void extractsSniFromClientHello() {
        byte[] hello = TestPackets.clientHello("Tracker.Example");
        assertEquals("tracker.example", DNSAnalyzer.extractSni(hello, 0, hello.length));
        byte[] pkt = TestPackets.tcp4("10.0.0.2", 40000, "203.0.113.7", 443, 0x18, hello);
        PacketInfo i = TestPackets.parse(pkt, PacketInfo.Direction.UP, 1);
        assertEquals("tracker.example", DNSAnalyzer.extractSni(pkt, i.payloadOffset, i.payloadLength));
    }

    @Test
    void sniReturnsNullWhenNotObservable() {
        byte[] hello = TestPackets.clientHello("tracker.example");
        assertNull(DNSAnalyzer.extractSni(hello, 0, 60));                       // cut off
        assertNull(DNSAnalyzer.extractSni("GET / HTTP/1.1\r\nHost: x\r\n\r\n.....................".getBytes(), 0, 60));
        byte[] ech = hello.clone();
        // turn the first extension (supported_groups 0x000A) into ECH 0xFE0D -> name is only a decoy
        int extStart = indexOf(ech, new byte[] {0x00, 0x0A, 0x00, 0x04});
        ech[extStart] = (byte) 0xFE;
        ech[extStart + 1] = 0x0D;
        assertNull(DNSAnalyzer.extractSni(ech, 0, ech.length));
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i <= hay.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return i;
        }
        throw new AssertionError("pattern not found");
    }
}
