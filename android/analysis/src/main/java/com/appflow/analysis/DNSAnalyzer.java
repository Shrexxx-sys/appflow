package com.appflow.analysis;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Learns domain names that are ACTUALLY visible in the traffic:
 *   1. DNS responses (UDP port 53): "name X has IP Y"  -> domain_source "dns"
 *   2. TLS ClientHello server name (SNI)               -> domain_source "sni"
 * If neither is visible (encrypted DNS / DoH, ECH, cached answers), the domain stays null
 * ("unavailable"). We never guess a name.
 *
 * Note: one CDN IP can serve many names; the most recent DNS answer wins.
 */
public final class DNSAnalyzer {

    private static final int MAX_ENTRIES = 5000;
    private static final int MAX_NAME_JUMPS = 10;       // protects against looping compression pointers
    private static final int TYPE_A = 1;
    private static final int TYPE_AAAA = 28;
    private static final int EXT_SERVER_NAME = 0x0000;
    private static final int EXT_ECH = 0xFE0D;          // Encrypted Client Hello

    /** IP -> domain, oldest entries dropped first so memory stays bounded. */
    private final Map<String, String> ipToName = new LinkedHashMap<>(256, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
            return size() > MAX_ENTRIES;
        }
    };

    /** Domain observed for this IP in a DNS answer, or null. */
    public String domainFor(String ip) {
        return ip == null ? null : ipToName.get(ip);
    }

    public int knownMappings() {
        return ipToName.size();
    }

    /**
     * Read a DNS RESPONSE (the UDP payload) and remember every A/AAAA answer.
     * @return how many IP->name mappings were learned (0 for queries or broken data)
     */
    public int observeDnsResponse(byte[] b, int off, int len) {
        if (b == null || off < 0 || len < 12 || off + len > b.length) return 0;
        int end = off + len;
        int flags = PacketParser.u16(b, off + 2);
        if ((flags & 0x8000) == 0) return 0;            // QR bit 0 = a question, not an answer
        if ((flags & 0x000F) != 0) return 0;            // error code (e.g. NXDOMAIN)
        int questions = PacketParser.u16(b, off + 4);
        int answers = PacketParser.u16(b, off + 6);
        if (questions < 1) return 0;

        int[] pos = { off + 12 };
        String asked = readName(b, off, end, pos);      // the name the app asked for
        if (asked == null || pos[0] + 4 > end) return 0;
        pos[0] += 4;                                    // QTYPE + QCLASS
        for (int q = 1; q < questions; q++) {           // rare: skip any extra questions
            if (readName(b, off, end, pos) == null || pos[0] + 4 > end) return 0;
            pos[0] += 4;
        }

        int learned = 0;
        for (int a = 0; a < answers; a++) {
            if (readName(b, off, end, pos) == null || pos[0] + 10 > end) break;
            int type = PacketParser.u16(b, pos[0]);
            int rdLength = PacketParser.u16(b, pos[0] + 8);
            int rdata = pos[0] + 10;
            if (rdata + rdLength > end) break;
            if ((type == TYPE_A && rdLength == 4) || (type == TYPE_AAAA && rdLength == 16)) {
                String ip = ipString(b, rdata, rdLength);
                if (ip != null) {
                    ipToName.put(ip, asked);            // CNAME chains still map to what the app asked
                    learned++;
                }
            }
            pos[0] = rdata + rdLength;
        }
        return learned;
    }

    /**
     * Read the server name (SNI) from a TLS ClientHello at the start of a TCP payload.
     * Returns null if this is not a ClientHello, it is cut off, or it uses ECH
     * (then the visible name is only a decoy, so we report "unavailable" instead of a wrong name).
     */
    public static String extractSni(byte[] b, int off, int len) {
        if (b == null || off < 0 || len < 47 || off + len > b.length) return null;
        int end = off + len;
        if (PacketParser.u8(b, off) != 0x16) return null;          // TLS handshake record
        if (PacketParser.u8(b, off + 5) != 0x01) return null;      // ClientHello
        int p = off + 9;                                           // after record(5) + handshake(4) headers
        p += 2 + 32;                                               // client version + random
        if (p + 1 > end) return null;
        p += 1 + PacketParser.u8(b, p);                            // session id
        if (p + 2 > end) return null;
        p += 2 + PacketParser.u16(b, p);                           // cipher suites
        if (p + 1 > end) return null;
        p += 1 + PacketParser.u8(b, p);                            // compression methods
        if (p + 2 > end) return null;
        int extEnd = Math.min(end, p + 2 + PacketParser.u16(b, p));
        p += 2;

        String name = null;
        while (p + 4 <= extEnd) {
            int type = PacketParser.u16(b, p);
            int extLen = PacketParser.u16(b, p + 2);
            int body = p + 4;
            if (body + extLen > extEnd) return null;               // cut off
            if (type == EXT_ECH) return null;
            if (type == EXT_SERVER_NAME && extLen >= 5 && PacketParser.u8(b, body + 2) == 0) {
                int nameLen = PacketParser.u16(b, body + 3);
                if (body + 5 + nameLen <= body + extLen) name = cleanName(b, body + 5, nameLen);
            }
            p = body + extLen;
        }
        return name;
    }

    // ---- helpers ----

    /** Read a (possibly compressed) DNS name. pos[0] is advanced past it. Null if broken. */
    private static String readName(byte[] b, int msgStart, int end, int[] pos) {
        StringBuilder sb = new StringBuilder();
        int p = pos[0];
        int jumps = 0;
        boolean jumped = false;
        while (true) {
            if (p >= end) return null;
            int len = PacketParser.u8(b, p);
            if (len == 0) {
                if (!jumped) pos[0] = p + 1;
                break;
            }
            if ((len & 0xC0) == 0xC0) {                             // compression pointer
                if (p + 1 >= end || ++jumps > MAX_NAME_JUMPS) return null;
                int target = msgStart + (((len & 0x3F) << 8) | PacketParser.u8(b, p + 1));
                if (!jumped) pos[0] = p + 2;
                jumped = true;
                p = target;
                continue;
            }
            if (len > 63 || p + 1 + len > end) return null;
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < len; i++) sb.append((char) PacketParser.u8(b, p + 1 + i));
            if (sb.length() > 253) return null;
            p += 1 + len;
        }
        return validName(sb.toString());
    }

    private static String cleanName(byte[] b, int off, int len) {
        if (len < 1 || len > 253) return null;
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append((char) PacketParser.u8(b, off + i));
        return validName(sb.toString());
    }

    /** Keep only normal hostnames (letters, digits, '-', '.', '_'); anything else is dropped. */
    private static String validName(String s) {
        if (s.isEmpty()) return null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_';
            if (!ok) return null;
        }
        return s.toLowerCase(Locale.ROOT);
    }

    private static String ipString(byte[] b, int off, int len) {
        try {
            // Same formatting as PacketParser, so the IP strings match exactly.
            return InetAddress.getByAddress(Arrays.copyOfRange(b, off, off + len)).getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
