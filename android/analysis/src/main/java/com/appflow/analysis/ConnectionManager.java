package com.appflow.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Groups packets into connections ("flows") and keeps running traffic statistics.
 *
 * A connection is identified by its 5-tuple: protocol + phone IP/port + server IP/port.
 * Packets in BOTH directions with the same 5-tuple belong to ONE connection.
 *
 * Reporting rule (the backend wants only NEW connections per batch): a connection is reported
 * once, when it closes (FIN both ways / RST), goes idle, or has been open REPORT_OPEN_AFTER_MS.
 * Bytes after that still count in the session totals, but not in that connection's row.
 *
 * Not thread-safe: only the analysis worker thread uses it.
 */
public final class ConnectionManager {

    public static final long TCP_IDLE_MS = 15_000;
    public static final long UDP_IDLE_MS = 10_000;
    public static final long REPORT_OPEN_AFTER_MS = 30_000;
    public static final int DEFAULT_MAX_ACTIVE = 10_000;

    /** One connection between the phone and a server. */
    public static final class Connection {
        public final String protocol;       // TCP | UDP | ICMP | OTHER
        public final String localIp;
        public final int localPort;
        public final String remoteIp;
        public final int remotePort;
        public final int uid;
        public final long firstSeenMs;
        public long lastSeenMs;
        public long bytesUp;
        public long bytesDown;
        public int packetsUp;
        public int packetsDown;
        public String domain;               // null when not observable
        public String domainSource = "unavailable";   // dns | sni | unavailable
        boolean finUp;
        boolean finDown;
        boolean closed;
        boolean reported;
        boolean sniChecked;                 // we only look for the TLS name in the first payload

        Connection(PacketInfo p) {
            this.protocol = p.protocolName();
            this.localIp = p.localIp();
            this.localPort = Math.max(0, p.localPort());
            this.remoteIp = p.remoteIp();
            this.remotePort = Math.max(0, p.remotePort());
            this.uid = p.uid;
            this.firstSeenMs = p.timestampMs;
            this.lastSeenMs = p.timestampMs;
        }

        public long durationMs() { return Math.max(0, lastSeenMs - firstSeenMs); }
        public boolean isClosed() { return closed; }
    }

    private final int maxActive;
    private final Map<String, Connection> active = new HashMap<>();
    private final List<Connection> finished = new ArrayList<>();   // replaced before being reported
    private final Set<String> domains = new HashSet<>();

    // ---- traffic statistics for the whole session (running totals) ----
    private long totalBytesUp;
    private long totalBytesDown;
    private long totalPacketsUp;
    private long totalPacketsDown;
    private long untrackedBytes;     // e.g. IP fragments we cannot assign to a connection
    private int totalConnections;

    public ConnectionManager() { this(DEFAULT_MAX_ACTIVE); }

    public ConnectionManager(int maxActive) { this.maxActive = maxActive; }

    /**
     * Count one packet. Returns its connection (possibly brand new), or null if the packet
     * cannot be assigned to a connection (fragments, or the table is full).
     */
    public Connection onPacket(PacketInfo p) {
        boolean up = p.direction == PacketInfo.Direction.UP;
        if (up) { totalBytesUp += p.totalLength; totalPacketsUp++; }
        else { totalBytesDown += p.totalLength; totalPacketsDown++; }

        if (p.fragment) {               // no ports -> we cannot tell which connection it belongs to
            untrackedBytes += p.totalLength;
            return null;
        }
        String key = key(p);
        Connection c = active.get(key);

        // Same 5-tuple re-used for a NEW TCP connection after the old one closed.
        if (c != null && c.closed && p.isTcp() && p.hasFlag(PacketInfo.TCP_SYN) && !p.hasFlag(PacketInfo.TCP_ACK)) {
            active.remove(key);
            if (!c.reported) finished.add(c);
            c = null;
        }
        if (c == null) {
            if (active.size() >= maxActive) {
                untrackedBytes += p.totalLength;
                return null;
            }
            c = new Connection(p);
            active.put(key, c);
            totalConnections++;
        }

        c.lastSeenMs = Math.max(c.lastSeenMs, p.timestampMs);
        if (up) { c.bytesUp += p.totalLength; c.packetsUp++; }
        else { c.bytesDown += p.totalLength; c.packetsDown++; }

        if (p.isTcp()) {
            if (p.hasFlag(PacketInfo.TCP_RST)) c.closed = true;
            if (p.hasFlag(PacketInfo.TCP_FIN)) {
                if (up) c.finUp = true; else c.finDown = true;
                if (c.finUp && c.finDown) c.closed = true;
            }
        }
        return c;
    }

    /** Attach a domain name we actually observed (never guessed). */
    public void assignDomain(Connection c, String domain, String source) {
        if (domain == null || domain.isEmpty()) return;
        c.domain = domain;
        c.domainSource = source;
        domains.add(domain);
    }

    /**
     * Connections ready to report: closed, idle, or open for a long time. Each is returned ONCE.
     * Closed and idle ones are removed from memory.
     */
    public List<Connection> collectReportable(long nowMs) {
        List<Connection> out = new ArrayList<>();
        for (Connection c : finished) if (markReported(c)) out.add(c);
        finished.clear();

        Iterator<Connection> it = active.values().iterator();
        while (it.hasNext()) {
            Connection c = it.next();
            long idleLimit = "TCP".equals(c.protocol) ? TCP_IDLE_MS : UDP_IDLE_MS;
            boolean idle = nowMs - c.lastSeenMs > idleLimit;
            boolean longOpen = nowMs - c.firstSeenMs > REPORT_OPEN_AFTER_MS;
            if (c.closed || idle || longOpen) {
                if (markReported(c)) out.add(c);
            }
            if (c.closed || idle) it.remove();
        }
        out.sort((a, b) -> Long.compare(a.firstSeenMs, b.firstSeenMs));
        return out;
    }

    /** At STOP: every connection not yet reported, so nothing is lost. */
    public List<Connection> collectAll() {
        List<Connection> out = new ArrayList<>();
        for (Connection c : finished) if (markReported(c)) out.add(c);
        finished.clear();
        for (Connection c : active.values()) if (markReported(c)) out.add(c);
        out.sort((a, b) -> Long.compare(a.firstSeenMs, b.firstSeenMs));
        return out;
    }

    /** All connections still in memory (used by the detection rules). */
    public Iterable<Connection> activeConnections() { return active.values(); }

    private static boolean markReported(Connection c) {
        if (c.reported) return false;
        c.reported = true;
        return true;
    }

    private static String key(PacketInfo p) {
        return p.protocol + "|" + p.localIp() + "|" + p.localPort() + "|" + p.remoteIp() + "|" + p.remotePort();
    }

    // ---- statistics getters ----
    public long totalBytesUp() { return totalBytesUp; }
    public long totalBytesDown() { return totalBytesDown; }
    public long totalPacketsUp() { return totalPacketsUp; }
    public long totalPacketsDown() { return totalPacketsDown; }
    public long untrackedBytes() { return untrackedBytes; }
    public int totalConnections() { return totalConnections; }
    public int uniqueDomains() { return domains.size(); }
    public int activeCount() { return active.size(); }
}
