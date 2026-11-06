package com.appflow.analysis;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * Reads IPv4 / IPv6 + TCP / UDP headers from raw packet bytes.
 *
 * Input contract (from the VPN): bytes start at the IP header (no Ethernet header).
 * SAFETY: packets can be broken, cut off or fragmented. Every read is bounds-checked, and a
 * bad packet returns null - this class never throws on bad input and never reads past the end.
 */
public final class PacketParser {

    private static final int MAX_IPV6_EXTENSION_HEADERS = 8;  // stop endless/hostile header chains

    private PacketParser() { }

    /**
     * @param buf         packet bytes (may be a truncated copy - headers are enough)
     * @param capturedLen how many bytes of buf are valid
     * @return parsed header facts, or null if the packet is not a valid IPv4/IPv6 packet
     */
    public static PacketInfo parse(byte[] buf, int capturedLen, long timestampMs,
                                   PacketInfo.Direction direction, int uid) {
        if (buf == null || direction == null || capturedLen < 1 || capturedLen > buf.length) {
            return null;
        }
        int version = (buf[0] >> 4) & 0x0F;
        if (version == 4) return parseIpv4(buf, capturedLen, timestampMs, direction, uid);
        if (version == 6) return parseIpv6(buf, capturedLen, timestampMs, direction, uid);
        return null;
    }

    private static PacketInfo parseIpv4(byte[] b, int cap, long ts, PacketInfo.Direction dir, int uid) {
        if (cap < 20) return null;
        int headerLen = (b[0] & 0x0F) * 4;                 // IHL is counted in 4-byte words
        if (headerLen < 20 || headerLen > cap) return null;
        int totalLength = u16(b, 2);
        if (totalLength < headerLen) return null;          // lying length field
        int fragmentOffset = u16(b, 6) & 0x1FFF;           // non-zero = not the first fragment
        int protocol = u8(b, 9);
        String src = ipv4(b, 12);
        String dst = ipv4(b, 16);
        int end = Math.min(cap, totalLength);              // never trust bytes beyond either limit
        return transport(4, src, dst, protocol, totalLength, fragmentOffset != 0, b, headerLen, end, ts, dir, uid);
    }

    private static PacketInfo parseIpv6(byte[] b, int cap, long ts, PacketInfo.Direction dir, int uid) {
        if (cap < 40) return null;
        int totalLength = 40 + u16(b, 4);                  // fixed 40-byte header + payload length
        int nextHeader = u8(b, 6);
        String src = ipv6(b, 8);
        String dst = ipv6(b, 24);
        int end = Math.min(cap, totalLength);
        int offset = 40;
        boolean fragment = false;

        // Walk optional "extension headers" until we reach TCP/UDP/other.
        for (int i = 0; i < MAX_IPV6_EXTENSION_HEADERS; i++) {
            if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60) {     // hop-by-hop, routing, dest opts
                if (offset + 8 > end) return info(6, src, dst, nextHeader, -1, -1, totalLength, false, 0, -1, 0, ts, dir, uid);
                int len = (u8(b, offset + 1) + 1) * 8;
                nextHeader = u8(b, offset);
                offset += len;
            } else if (nextHeader == 44) {                                      // fragment header
                if (offset + 8 > end) return info(6, src, dst, nextHeader, -1, -1, totalLength, false, 0, -1, 0, ts, dir, uid);
                int fragOffset = u16(b, offset + 2) >> 3;
                nextHeader = u8(b, offset);
                offset += 8;
                fragment = fragOffset != 0;
                if (fragment) break;
            } else {
                break;
            }
        }
        return transport(6, src, dst, nextHeader, totalLength, fragment, b, offset, end, ts, dir, uid);
    }

    /** Read TCP/UDP ports (if present and complete) starting at {@code off}. */
    private static PacketInfo transport(int version, String src, String dst, int protocol, int totalLength,
                                        boolean fragment, byte[] b, int off, int end,
                                        long ts, PacketInfo.Direction dir, int uid) {
        if (fragment) {
            return info(version, src, dst, protocol, -1, -1, totalLength, true, 0, -1, 0, ts, dir, uid);
        }
        if (protocol == PacketInfo.PROTO_TCP && off + 20 <= end) {
            int dataOffset = ((u8(b, off + 12) >> 4) & 0x0F) * 4;
            int flags = u8(b, off + 13);
            int payloadStart = off + dataOffset;
            boolean validHeader = dataOffset >= 20 && payloadStart <= end;
            return info(version, src, dst, protocol, u16(b, off), u16(b, off + 2), totalLength, false, flags,
                    validHeader ? payloadStart : -1, validHeader ? end - payloadStart : 0, ts, dir, uid);
        }
        if (protocol == PacketInfo.PROTO_UDP && off + 8 <= end) {
            return info(version, src, dst, protocol, u16(b, off), u16(b, off + 2), totalLength, false, 0,
                    off + 8, end - (off + 8), ts, dir, uid);
        }
        // ICMP, other protocols, or a TCP/UDP header that was cut off: no ports.
        return info(version, src, dst, protocol, -1, -1, totalLength, false, 0, -1, 0, ts, dir, uid);
    }

    private static PacketInfo info(int v, String src, String dst, int proto, int sp, int dp, int total,
                                   boolean frag, int flags, int payOff, int payLen,
                                   long ts, PacketInfo.Direction dir, int uid) {
        return new PacketInfo(v, src, dst, proto, sp, dp, total, frag, flags, payOff, payLen, ts, dir, uid);
    }

    // ---- tiny byte helpers (Java bytes are signed, so we mask with 0xFF) ----

    static int u8(byte[] b, int i) {
        return b[i] & 0xFF;
    }

    static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);   // network byte order = big-endian
    }

    private static String ipv4(byte[] b, int i) {
        return u8(b, i) + "." + u8(b, i + 1) + "." + u8(b, i + 2) + "." + u8(b, i + 3);
    }

    private static String ipv6(byte[] b, int i) {
        try {
            // getByAddress only formats the 16 bytes - it never does a DNS lookup.
            return InetAddress.getByAddress(Arrays.copyOfRange(b, i, i + 16)).getHostAddress();
        } catch (UnknownHostException e) {
            return "::";  // impossible for a 16-byte array, but never crash
        }
    }
}
