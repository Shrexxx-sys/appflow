package com.appflow.analysis;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

/** Test helper: builds real-looking IPv4/IPv6 + TCP/UDP packets, DNS answers and TLS ClientHellos. */
final class TestPackets {

    private TestPackets() { }

    static byte[] ip(String address) {
        try {
            return InetAddress.getByName(address).getAddress();  // literal IPs only: no DNS lookup
        } catch (Exception e) {
            throw new IllegalArgumentException(address, e);
        }
    }

    static byte[] tcpHeader(int srcPort, int dstPort, int flags) {
        byte[] h = new byte[20];
        put16(h, 0, srcPort);
        put16(h, 2, dstPort);
        h[12] = (byte) (5 << 4);   // data offset = 5 words = 20 bytes
        h[13] = (byte) flags;
        return h;
    }

    static byte[] udpHeader(int srcPort, int dstPort, int payloadLen) {
        byte[] h = new byte[8];
        put16(h, 0, srcPort);
        put16(h, 2, dstPort);
        put16(h, 4, 8 + payloadLen);
        return h;
    }

    static byte[] ipv4(String src, String dst, int protocol, byte[] transport, byte[] payload) {
        int total = 20 + transport.length + payload.length;
        byte[] p = new byte[total];
        p[0] = 0x45;                       // version 4, IHL 5
        put16(p, 2, total);
        p[8] = 64;                         // TTL
        p[9] = (byte) protocol;
        System.arraycopy(ip(src), 0, p, 12, 4);
        System.arraycopy(ip(dst), 0, p, 16, 4);
        System.arraycopy(transport, 0, p, 20, transport.length);
        System.arraycopy(payload, 0, p, 20 + transport.length, payload.length);
        return p;
    }

    static byte[] ipv6(String src, String dst, int nextHeader, byte[] transport, byte[] payload) {
        byte[] p = new byte[40 + transport.length + payload.length];
        p[0] = 0x60;
        put16(p, 4, transport.length + payload.length);
        p[6] = (byte) nextHeader;
        p[7] = 64;
        System.arraycopy(ip(src), 0, p, 8, 16);
        System.arraycopy(ip(dst), 0, p, 24, 16);
        System.arraycopy(transport, 0, p, 40, transport.length);
        System.arraycopy(payload, 0, p, 40 + transport.length, payload.length);
        return p;
    }

    static byte[] tcp4(String src, int sp, String dst, int dp, int flags, byte[] payload) {
        return ipv4(src, dst, PacketInfo.PROTO_TCP, tcpHeader(sp, dp, flags), payload);
    }

    static byte[] udp4(String src, int sp, String dst, int dp, byte[] payload) {
        return ipv4(src, dst, PacketInfo.PROTO_UDP, udpHeader(sp, dp, payload.length), payload);
    }

    static PacketInfo parse(byte[] p, PacketInfo.Direction dir, long ts) {
        return PacketParser.parse(p, p.length, ts, dir, 10123);
    }

    /** A DNS response for {@code name} with the given A/AAAA answers (uses a compression pointer). */
    static byte[] dnsResponse(String name, String... answers) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        write16(o, 0x1234);                 // id
        write16(o, 0x8180);                 // flags: response, recursion available, no error
        write16(o, 1);                      // questions
        write16(o, answers.length);         // answers
        write16(o, 0);
        write16(o, 0);
        for (String label : name.split("\\.")) {
            byte[] l = label.getBytes(StandardCharsets.US_ASCII);
            o.write(l.length);
            o.write(l, 0, l.length);
        }
        o.write(0);
        write16(o, 1);                      // QTYPE A
        write16(o, 1);                      // QCLASS IN
        for (String a : answers) {
            byte[] addr = ip(a);
            write16(o, 0xC00C);             // pointer to the name at offset 12
            write16(o, addr.length == 4 ? 1 : 28);
            write16(o, 1);
            write16(o, 0);
            write16(o, 300);                // TTL
            write16(o, addr.length);
            o.write(addr, 0, addr.length);
        }
        return o.toByteArray();
    }

    /** A minimal TLS 1.2-style ClientHello record containing the SNI extension. */
    static byte[] clientHello(String serverName) {
        byte[] host = serverName.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream sni = new ByteArrayOutputStream();
        write16(sni, host.length + 3);      // server_name_list length
        sni.write(0);                       // name type: host_name
        write16(sni, host.length);
        sni.write(host, 0, host.length);
        byte[] sniBody = sni.toByteArray();

        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        write16(ext, 0x000A);               // an unrelated extension first (supported_groups)
        write16(ext, 4);
        write16(ext, 2);
        write16(ext, 0x001D);
        write16(ext, 0x0000);               // server_name
        write16(ext, sniBody.length);
        ext.write(sniBody, 0, sniBody.length);
        byte[] exts = ext.toByteArray();

        ByteArrayOutputStream hello = new ByteArrayOutputStream();
        write16(hello, 0x0303);             // client version
        hello.write(new byte[32], 0, 32);   // random
        hello.write(0);                     // session id length
        write16(hello, 2);                  // cipher suites length
        write16(hello, 0x1301);
        hello.write(1);                     // compression methods length
        hello.write(0);
        write16(hello, exts.length);
        hello.write(exts, 0, exts.length);
        byte[] body = hello.toByteArray();

        ByteArrayOutputStream rec = new ByteArrayOutputStream();
        rec.write(0x16);                    // handshake
        write16(rec, 0x0301);
        write16(rec, body.length + 4);
        rec.write(0x01);                    // ClientHello
        rec.write(0);
        write16(rec, body.length);
        rec.write(body, 0, body.length);
        return rec.toByteArray();
    }

    static void put16(byte[] b, int i, int v) {
        b[i] = (byte) (v >> 8);
        b[i + 1] = (byte) v;
    }

    private static void write16(ByteArrayOutputStream o, int v) {
        o.write((v >> 8) & 0xFF);
        o.write(v & 0xFF);
    }
}
