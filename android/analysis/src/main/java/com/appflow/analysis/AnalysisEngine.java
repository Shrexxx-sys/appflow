package com.appflow.analysis;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Glues everything together and keeps analysis OFF the VPN thread.
 *
 *   VPN thread --submit()--> [queue] --worker thread--> parse -> connections -> DNS/SNI -> rules
 *                                                       every 2 s: build JSON batch --> [sender thread] --> backend
 *
 * submit() only copies up to 2 KB of the packet (headers + enough for DNS / TLS server name) and
 * returns immediately. If the queue is full the copy is DROPPED and counted - forwarding is never
 * slowed down. Payload copies are used only to read names and are never stored or sent.
 */
public final class AnalysisEngine {

    public static final int QUEUE_CAPACITY = 20_000;
    public static final int COPY_LIMIT = 2048;
    public static final long EXPORT_INTERVAL_MS = 2000;
    private static final int MAX_PENDING_BATCHES = 30;

    /** Where finished JSON batches go (the backend in the app, a list in tests). Returns HTTP status. */
    public interface BatchSink {
        int send(String json) throws IOException;
    }

    /** Optional status callback for the UI (called from background threads). */
    public interface Listener {
        void onStatus(String message);
    }

    private static final class Raw {
        final byte[] data;
        final long ts;
        final PacketInfo.Direction dir;
        final int uid;

        Raw(byte[] data, long ts, PacketInfo.Direction dir, int uid) {
            this.data = data;
            this.ts = ts;
            this.dir = dir;
            this.uid = uid;
        }
    }

    private final long sessionId;
    private final boolean isMock;
    private final BatchSink sink;
    private final Listener listener;
    private final BlockingQueue<Raw> queue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);
    private final ConnectionManager connections = new ConnectionManager();
    private final DNSAnalyzer dns = new DNSAnalyzer();
    private final DetectionEngine detection = new DetectionEngine();
    private final RiskScorer scorer = new RiskScorer();
    private final List<DetectionEngine.Alert> allAlerts = new ArrayList<>();
    private final ArrayDeque<String> pendingBatches = new ArrayDeque<>();  // only touched by the sender thread
    private final ExecutorService sender = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "appflow-sender");
        t.setDaemon(true);
        return t;
    });

    private final AtomicLong submitted = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong processed = new AtomicLong();
    private final AtomicLong batchesAccepted = new AtomicLong();
    private volatile boolean running;
    private volatile String lastError;
    private Thread worker;
    private int lastScore;

    public AnalysisEngine(long sessionId, boolean isMock, BatchSink sink, Listener listener) {
        this.sessionId = sessionId;
        this.isMock = isMock;
        this.sink = sink;
        this.listener = listener;
    }

    // ------------------------------------------------------------- threading API

    public synchronized void start() {
        if (running) return;
        running = true;
        worker = new Thread(this::workLoop, "appflow-analysis");
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * Called by the VPN thread for every packet. Never blocks.
     * @return false if the analysis queue was full and this copy was dropped
     */
    public boolean submit(byte[] packet, int length, long timestampMs, PacketInfo.Direction dir, int uid) {
        if (!running || packet == null || length <= 0) return false;
        submitted.incrementAndGet();
        byte[] copy = Arrays.copyOf(packet, Math.min(length, Math.min(COPY_LIMIT, packet.length)));
        if (!queue.offer(new Raw(copy, timestampMs, dir, uid))) {
            dropped.incrementAndGet();
            return false;
        }
        return true;
    }

    /** Stop: analyse what is queued, send a final batch with ALL remaining connections, wait briefly. */
    public void stop() {
        Thread w;
        synchronized (this) {
            if (!running) return;
            running = false;
            w = worker;
        }
        try {
            w.join(5000);
            sender.shutdown();
            sender.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void workLoop() {
        long lastExport = System.currentTimeMillis();
        try {
            while (running || !queue.isEmpty()) {
                Raw r = queue.poll(200, TimeUnit.MILLISECONDS);
                if (r != null) process(r.data, r.data.length, r.ts, r.dir, r.uid);
                long now = System.currentTimeMillis();
                if (now - lastExport >= EXPORT_INTERVAL_MS) {
                    enqueueBatch(buildBatch(now, false));
                    lastExport = now;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException e) {
            lastError = "Analysis error: " + e;   // a bug must never take the VPN down with it
            status(lastError);
        }
        enqueueBatch(buildBatch(System.currentTimeMillis(), true));
    }

    private void enqueueBatch(String json) {
        try {
            sender.execute(() -> sendPending(json));
        } catch (RejectedExecutionException e) {
            lastError = "Final batch not sent (stop timed out)";
        }
    }

    /**
     * Runs on the sender thread. Failed batches stay queued (max 30) and are retried in order
     * with the next batch - so a Wi-Fi blip loses nothing. 4xx errors are not retried.
     */
    private void sendPending(String json) {
        pendingBatches.addLast(json);
        while (pendingBatches.size() > MAX_PENDING_BATCHES) pendingBatches.removeFirst();
        while (!pendingBatches.isEmpty()) {
            int status;
            try {
                status = sink.send(pendingBatches.peekFirst());
            } catch (IOException e) {
                lastError = "Backend unreachable: " + e.getMessage();
                status(lastError + " (will retry)");
                return;   // keep the batch; try again with the next one
            }
            if (status >= 200 && status < 300) {
                pendingBatches.removeFirst();
                batchesAccepted.incrementAndGet();
                lastError = null;
            } else if (status >= 500) {
                lastError = "Backend error HTTP " + status + " (will retry)";
                status(lastError);
                return;
            } else {
                // 4xx (bad key, invalid JSON, session stopped): retrying would not help.
                pendingBatches.removeFirst();
                lastError = "Backend rejected batch: HTTP " + status;
                status(lastError);
            }
        }
        status("Sent " + batchesAccepted.get() + " batches · " + processed.get() + " packets analysed"
                + (dropped.get() > 0 ? " · " + dropped.get() + " dropped" : ""));
    }

    private void status(String message) {
        if (listener != null) listener.onStatus(message);
    }

    // ------------------------------------------------------------- analysis core (single thread)

    /** Analyse one packet. Public for tests; in the app only the worker thread calls it. */
    public void process(byte[] data, int capturedLength, long ts, PacketInfo.Direction dir, int uid) {
        // Byte counts come from the IP header's length field, so a 2 KB copy still counts the real size.
        PacketInfo p = PacketParser.parse(data, capturedLength, ts, dir, uid);
        if (p == null) return;
        processed.incrementAndGet();

        // DNS answers coming back to the phone teach us IP -> name.
        if (p.isUdp() && p.direction == PacketInfo.Direction.DOWN && p.srcPort == 53 && p.payloadOffset >= 0) {
            dns.observeDnsResponse(data, p.payloadOffset, p.payloadLength);
        }

        ConnectionManager.Connection c = connections.onPacket(p);
        if (c == null) return;
        if (c.packetsUp + c.packetsDown == 1 && c.domain == null) {
            connections.assignDomain(c, dns.domainFor(c.remoteIp), "dns");
        }
        // The first data the phone sends on a TCP connection may be a TLS ClientHello with the server name.
        if (p.isTcp() && p.direction == PacketInfo.Direction.UP && !c.sniChecked && p.payloadLength > 0) {
            c.sniChecked = true;
            String sni = DNSAnalyzer.extractSni(data, p.payloadOffset, p.payloadLength);
            if (sni != null) connections.assignDomain(c, sni, "sni");   // SNI names THIS connection exactly
        }
        detection.onPacket(p, c);
    }

    /** Build one JSON batch: running totals + connections ready to report + new alerts. */
    public String buildBatch(long nowMs, boolean finalBatch) {
        List<ConnectionManager.Connection> ready =
                finalBatch ? connections.collectAll() : connections.collectReportable(nowMs);
        for (ConnectionManager.Connection c : ready) {
            if (c.domain == null) connections.assignDomain(c, dns.domainFor(c.remoteIp), "dns");
        }
        List<DetectionEngine.Alert> fresh = detection.drainNewAlerts();
        allAlerts.addAll(fresh);
        RiskScorer.Score score = scorer.score(allAlerts);   // also writes risk_points into each alert
        lastScore = score.score;
        return ObservationExporter.buildObservationJson(sessionId, nowMs, connections.totalBytesUp(),
                connections.totalBytesDown(), connections.totalConnections(), connections.uniqueDomains(),
                score.score, ready, fresh, isMock);
    }

    // ------------------------------------------------------------- read-only status
    public long submittedPackets() { return submitted.get(); }
    public long droppedPackets() { return dropped.get(); }
    public long processedPackets() { return processed.get(); }
    public long acceptedBatches() { return batchesAccepted.get(); }
    public String lastError() { return lastError; }
    public int lastRiskScore() { return lastScore; }
    public ConnectionManager connections() { return connections; }
}
