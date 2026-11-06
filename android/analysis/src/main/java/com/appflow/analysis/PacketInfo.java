package com.appflow.analysis;

/**
 * Facts read from the HEADERS of one IP packet (the "envelope", never the letter inside).
 *
 * Created only by {@link PacketParser}. Holds no payload bytes; payloadOffset/payloadLength only
 * tell where the payload starts in the caller's buffer (used briefly to read DNS answers and the
 * TLS server name, then forgotten).
 */
public final class PacketInfo {

    /** UP = phone -> internet (read from the VPN), DOWN = internet -> phone (written to the VPN). */
    public enum Direction { UP, DOWN }

    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;
    public static final int PROTO_ICMPV6 = 58;

    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_ACK = 0x10;

    public final int ipVersion;          // 4 or 6
    public final String srcIp;
    public final String dstIp;
    public final int protocol;           // IANA number: 6 = TCP, 17 = UDP, ...
    public final int srcPort;            // -1 when unknown (not TCP/UDP, fragment, truncated header)
    public final int dstPort;
    public final int totalLength;        // packet size according to the IP header (used for byte counts)
    public final boolean fragment;       // a non-first IP fragment: it carries no TCP/UDP header
    public final int tcpFlags;           // 0 when not TCP
    public final int payloadOffset;      // start of TCP/UDP payload in the captured buffer, -1 if none
    public final int payloadLength;      // payload bytes AVAILABLE in the captured buffer
    public final long timestampMs;
    public final Direction direction;
    public final int uid;                // Android app UID if known, else -1

    PacketInfo(int ipVersion, String srcIp, String dstIp, int protocol, int srcPort, int dstPort,
               int totalLength, boolean fragment, int tcpFlags, int payloadOffset, int payloadLength,
               long timestampMs, Direction direction, int uid) {
        this.ipVersion = ipVersion;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.protocol = protocol;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.totalLength = totalLength;
        this.fragment = fragment;
        this.tcpFlags = tcpFlags;
        this.payloadOffset = payloadOffset;
        this.payloadLength = payloadLength;
        this.timestampMs = timestampMs;
        this.direction = direction;
        this.uid = uid;
    }

    public boolean isTcp() { return protocol == PROTO_TCP; }
    public boolean isUdp() { return protocol == PROTO_UDP; }
    public boolean hasPorts() { return srcPort >= 0 && dstPort >= 0; }
    public boolean hasFlag(int flag) { return (tcpFlags & flag) != 0; }

    /** The phone's side of the conversation (depends on direction). */
    public String localIp() { return direction == Direction.UP ? srcIp : dstIp; }
    public String remoteIp() { return direction == Direction.UP ? dstIp : srcIp; }
    public int localPort() { return direction == Direction.UP ? srcPort : dstPort; }
    public int remotePort() { return direction == Direction.UP ? dstPort : srcPort; }

    /** Protocol name in the backend's vocabulary: TCP | UDP | ICMP | OTHER. */
    public String protocolName() {
        switch (protocol) {
            case PROTO_TCP: return "TCP";
            case PROTO_UDP: return "UDP";
            case PROTO_ICMP:
            case PROTO_ICMPV6: return "ICMP";
            default: return "OTHER";
        }
    }

    @Override
    public String toString() {
        return protocolName() + " " + srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort
                + " len=" + totalLength + " " + direction + (fragment ? " frag" : "");
    }
}
