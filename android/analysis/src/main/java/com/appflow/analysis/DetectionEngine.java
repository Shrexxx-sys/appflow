package com.appflow.analysis;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Deterministic detection rules. Same input -> same alerts. No AI here.
 *
 * Rules (each fires at most once per destination, so alerts don't repeat every second):
 *   R01_HIGH_UPLOAD         much more data sent than received to one destination   (observed)
 *   R02_REPEATED_CONNECTIONS many new connections to one destination in a minute  (observed)
 *   R03_UNUSUAL_PORT        a server port outside the common list                  (observed)
 *   R04_PERIODIC_CONTACT    contact at very regular intervals (possibly background) (inferred:
 *                           metadata cannot show whether the app was in the foreground)
 *
 * Wording rule: alerts describe "unusual behavior worth reviewing", never "malware".
 */
public final class DetectionEngine {

    public static final long HIGH_UPLOAD_BYTES = 1_000_000;        // 1 MB -> medium
    public static final long VERY_HIGH_UPLOAD_BYTES = 5_000_000;   // 5 MB -> high
    public static final double UPLOAD_RATIO = 3.0;                 // sent >= 3x received
    public static final int REPEATED_COUNT = 10;
    public static final long REPEATED_WINDOW_MS = 60_000;
    public static final int PERIODIC_MIN_CONNECTIONS = 5;
    public static final long PERIODIC_MIN_INTERVAL_MS = 10_000;
    public static final double PERIODIC_MAX_VARIATION = 0.25;      // std-dev / mean of the gaps
    public static final Set<Integer> COMMON_PORTS = new HashSet<>(Arrays.asList(
            53, 80, 123, 443, 853, 5228, 5229, 5230, 8080, 8443));

    /** One finding. Field names mirror the backend's alert JSON. */
    public static final class Alert {
        public final String ruleId;
        public final String title;
        public final String description;
        public final String severity;       // low | medium | high
        public final String evidenceType;   // observed | inferred | potential_risk | not_observable
        public final Map<String, Object> evidence;
        public final String relatedDomain;
        public final String relatedIp;
        public final Integer relatedPort;
        public final long detectedAtMs;
        public int riskPoints;              // filled in by RiskScorer

        Alert(String ruleId, String title, String description, String severity, String evidenceType,
              Map<String, Object> evidence, String relatedDomain, String relatedIp, Integer relatedPort,
              long detectedAtMs) {
            this.ruleId = ruleId;
            this.title = title;
            this.description = description;
            this.severity = severity;
            this.evidenceType = evidenceType;
            this.evidence = evidence;
            this.relatedDomain = relatedDomain;
            this.relatedIp = relatedIp;
            this.relatedPort = relatedPort;
            this.detectedAtMs = detectedAtMs;
        }
    }

    /** Everything we track per destination IP. */
    private static final class Destination {
        final String ip;
        String domain;
        long bytesUp;
        long bytesDown;
        int lastPort;
        final ArrayDeque<Long> starts = new ArrayDeque<>();   // start times of recent connections

        Destination(String ip) { this.ip = ip; }

        String label() { return domain != null ? domain : ip; }
    }

    private static final int MAX_STARTS_KEPT = 50;

    private final Map<String, Destination> destinations = new HashMap<>();
    private final Set<String> fired = new HashSet<>();      // rule|target keys that already fired
    private final List<Alert> pending = new ArrayList<>();  // found but not yet handed out

    /** Feed every tracked packet (after domains were assigned). */
    public void onPacket(PacketInfo p, ConnectionManager.Connection c) {
        if (c == null) return;
        Destination d = destinations.computeIfAbsent(c.remoteIp, Destination::new);
        if (c.domain != null) d.domain = c.domain;
        d.lastPort = c.remotePort;
        if (p.direction == PacketInfo.Direction.UP) d.bytesUp += p.totalLength;
        else d.bytesDown += p.totalLength;

        boolean firstPacket = c.packetsUp + c.packetsDown == 1;
        if (firstPacket) {
            d.starts.addLast(c.firstSeenMs);
            if (d.starts.size() > MAX_STARTS_KEPT) d.starts.removeFirst();
            checkRepeated(d, p.timestampMs);
            checkPeriodic(d, p.timestampMs);
            checkUnusualPort(c, p.timestampMs);
        }
        checkHighUpload(d, p.timestampMs);
    }

    /** New alerts since the last call (each alert is returned exactly once). */
    public List<Alert> drainNewAlerts() {
        List<Alert> out = new ArrayList<>(pending);
        pending.clear();
        return out;
    }

    // ---------------------------------------------------------------- rules

    private void checkHighUpload(Destination d, long now) {
        if (d.bytesUp < HIGH_UPLOAD_BYTES || d.bytesUp < UPLOAD_RATIO * d.bytesDown) return;
        String severity = d.bytesUp >= VERY_HIGH_UPLOAD_BYTES ? "high" : "medium";
        if (!fire("R01|" + d.ip + "|" + severity)) return;
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("bytes_up", d.bytesUp);
        ev.put("bytes_down", d.bytesDown);
        ev.put("upload_to_download_ratio", round1(d.bytesDown == 0 ? d.bytesUp : (double) d.bytesUp / d.bytesDown));
        ev.put("threshold_bytes", severity.equals("high") ? VERY_HIGH_UPLOAD_BYTES : HIGH_UPLOAD_BYTES);
        pending.add(new Alert("R01_HIGH_UPLOAD", "High upload volume to " + d.label(),
                String.format(Locale.ROOT, "%.1f MB was sent to %s, at least %.0fx more than was received from it. "
                        + "The byte counts are observed; what data was sent cannot be observed because the "
                        + "traffic is encrypted. Unusual behavior worth reviewing.",
                        d.bytesUp / 1e6, d.label(), UPLOAD_RATIO),
                severity, "observed", ev, d.domain, d.ip, d.lastPort, now));
    }

    private void checkRepeated(Destination d, long now) {
        int recent = 0;
        for (long t : d.starts) if (now - t <= REPEATED_WINDOW_MS) recent++;
        if (recent < REPEATED_COUNT || !fire("R02|" + d.ip)) return;
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("new_connections", recent);
        ev.put("window_seconds", REPEATED_WINDOW_MS / 1000);
        ev.put("threshold", REPEATED_COUNT);
        pending.add(new Alert("R02_REPEATED_CONNECTIONS", "Repeated connections to " + d.label(),
                recent + " new connections to " + d.label() + " within " + (REPEATED_WINDOW_MS / 1000)
                        + " seconds. Frequent reconnecting is observed; the reason for it cannot be observed.",
                "medium", "observed", ev, d.domain, d.ip, d.lastPort, now));
    }

    private void checkUnusualPort(ConnectionManager.Connection c, long now) {
        boolean portBased = "TCP".equals(c.protocol) || "UDP".equals(c.protocol);
        if (!portBased || c.remotePort == 0 || COMMON_PORTS.contains(c.remotePort)) return;
        if (!fire("R03|" + c.remoteIp + "|" + c.remotePort)) return;
        String target = c.domain != null ? c.domain : c.remoteIp;
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("port", c.remotePort);
        ev.put("protocol", c.protocol);
        ev.put("domain_known", c.domain != null);
        pending.add(new Alert("R03_UNUSUAL_PORT", "Connection on an uncommon port (" + c.remotePort + ")",
                c.protocol + " connection to " + target + " on port " + c.remotePort
                        + ". Uncommon ports are not harmful by themselves but are worth reviewing.",
                "low", "observed", ev, c.domain, c.remoteIp, c.remotePort, now));
    }

    private void checkPeriodic(Destination d, long now) {
        if (d.starts.size() < PERIODIC_MIN_CONNECTIONS) return;
        Long[] t = d.starts.toArray(new Long[0]);
        int n = Math.min(t.length, 10);                       // look at the latest connections only
        double[] gaps = new double[n - 1];
        for (int i = 0; i < n - 1; i++) gaps[i] = t[t.length - n + i + 1] - t[t.length - n + i];
        double mean = 0;
        for (double g : gaps) mean += g;
        mean /= gaps.length;
        if (mean < PERIODIC_MIN_INTERVAL_MS) return;
        double var = 0;
        for (double g : gaps) var += (g - mean) * (g - mean);
        double variation = Math.sqrt(var / gaps.length) / mean;
        if (variation > PERIODIC_MAX_VARIATION || !fire("R04|" + d.ip)) return;
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("connections", n);
        ev.put("avg_interval_seconds", round1(mean / 1000));
        ev.put("interval_variation", round1(variation));
        pending.add(new Alert("R04_PERIODIC_CONTACT", "Regular repeated contact with " + d.label(),
                d.label() + " was contacted " + n + " times at regular ~" + Math.round(mean / 1000)
                        + "-second intervals. This pattern often means automatic background activity, but "
                        + "that is an INFERENCE: whether the app was in the foreground cannot be observed "
                        + "from network metadata.",
                "medium", "inferred", ev, d.domain, d.ip, d.lastPort, now));
    }

    private boolean fire(String key) {
        return fired.add(key);   // false if this rule already fired for this target
    }

    private static double round1(double v) {
        return Math.round(v * 10.0) / 10.0;
    }
}
