package com.appflow.app;

/**
 * Builds IPv4 + TCP/UDP packets (with correct checksums) that we write back to the app,
 * and reads the TCP fields the forwarder needs. Plain Java: unit-tested on a laptop.
 */
final class PacketBuilder {

    static final int FIN = 0x01;
    static final int SYN = 0x02;
    static final int RST = 0x04;
    static final int PSH = 0x08;
    static final int ACK = 0x10;

    private static int nextId = 1;   // IPv4 identification field (only used on the forwarder thread)

    private PacketBuilder() { }

    /** A TCP segment from (srcIp:srcPort) to (dstIp:dstPort). options may be null. */
    static byte[] tcp(byte[] srcIp, int srcPort, byte[] dstIp, int dstPort, long seq, long ack, int flags,
                      int window, byte[] options, byte[] data, int off, int len) {
        int optLen = options == null ? 0 : options.length;     // must be a multiple of 4
        int tcpLen = 20 + optLen + len;
        byte[] p = ipv4Header(20 + tcpLen, 6, srcIp, dstIp);
        int t = 20;
        put16(p, t, srcPort);
        put16(p, t + 2, dstPort);
        put32(p, t + 4, seq);
        put32(p, t + 8, ack);
        p[t + 12] = (byte) (((20 + optLen) / 4) << 4);
        p[t + 13] = (byte) flags;
        put16(p, t + 14, Math.min(window, 0xFFFF));
        if (optLen > 0) System.arraycopy(options, 0, p, t + 20, optLen);
        if (len > 0) System.arraycopy(data, off, p, t + 20 + optLen, len);
        put16(p, t + 16, transportChecksum(p, t, tcpLen, 6));
        return p;
    }

    /** A UDP datagram from (srcIp:srcPort) to (dstIp:dstPort). */
    static byte[] udp(byte[] srcIp, int srcPort, byte[] dstIp, int dstPort, byte[] data, int off, int len) {
        int udpLen = 8 + len;
        byte[] p = ipv4Header(20 + udpLen, 17, srcIp, dstIp);
        put16(p, 20, srcPort);
        put16(p, 22, dstPort);
        put16(p, 24, udpLen);
        System.arraycopy(data, off, p, 28, len);
        int sum = transportChecksum(p, 20, udpLen, 17);
        put16(p, 26, sum == 0 ? 0xFFFF : sum);                  // 0 means "no checksum" in UDP
        return p;
    }

    /** MSS option (kind 2) telling the app to send segments of at most {@code mss} bytes. */
    static byte[] mssOption(int mss) {
        return new byte[] { 2, 4, (byte) (mss >> 8), (byte) mss };
    }

    private static byte[] ipv4Header(int totalLength, int protocol, byte[] src, byte[] dst) {
        byte[] p = new byte[totalLength];
        p[0] = 0x45;                                            // version 4, header 20 bytes
        put16(p, 2, totalLength);
        put16(p, 4, nextId++ & 0xFFFF);
        put16(p, 6, 0x4000);                                    // "don't fragment"
        p[8] = 64;                                              // TTL
        p[9] = (byte) protocol;
        System.arraycopy(src, 0, p, 12, 4);
        System.arraycopy(dst, 0, p, 16, 4);
        put16(p, 10, checksum(p, 0, 20, 0));
        return p;
    }

    /** TCP/UDP checksum over a pseudo-header (src, dst, protocol, length) + the segment. */
    static int transportChecksum(byte[] p, int off, int len, int protocol) {
        long sum = 0;
        for (int i = 12; i < 20; i += 2) sum += u16(p, i);       // source + destination IP
        sum += protocol;
        sum += len;
        return checksum(p, off, len, sum);
    }

    /** Internet checksum (RFC 1071): one's-complement sum of 16-bit words. */
    static int checksum(byte[] b, int off, int len, long initial) {
        long sum = initial;
        int i = off;
        for (; i + 1 < off + len; i += 2) sum += u16(b, i);
        if (i < off + len) sum += (b[i] & 0xFF) << 8;           // odd length: pad with a zero byte
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    // ---- readers / writers (network byte order) ----

    static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    static long u32(byte[] b, int i) {
        return ((long) u16(b, i) << 16) | u16(b, i + 2);
    }

    static void put16(byte[] b, int i, int v) {
        b[i] = (byte) (v >> 8);
        b[i + 1] = (byte) v;
    }

    static void put32(byte[] b, int i, long v) {
        put16(b, i, (int) (v >> 16) & 0xFFFF);
        put16(b, i + 2, (int) v & 0xFFFF);
    }

    /** MSS option value from a SYN's TCP options, or {@code fallback} if absent/broken. */
    static int readMss(byte[] p, int tcpOff, int tcpHeaderLen, int fallback) {
        int i = tcpOff + 20;
        int end = Math.min(p.length, tcpOff + tcpHeaderLen);
        while (i < end) {
            int kind = p[i] & 0xFF;
            if (kind == 0) break;                               // end of options
            if (kind == 1) { i++; continue; }                   // padding
            if (i + 1 >= end) break;
            int len = p[i + 1] & 0xFF;
            if (len < 2 || i + len > end) break;
            if (kind == 2 && len == 4) return u16(p, i + 2);
            i += len;
        }
        return fallback;
    }
}
