package com.appflow.app;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Forwards the monitored app's packets to the real internet and the answers back.
 *
 * Threads (deliberately simple):
 *   tun reader : reads packets from the VPN interface and queues them - nothing else
 *   forwarder  : the ONLY thread that touches connections: handles queued packets, socket events,
 *                writes answers to the VPN interface. One thread = no locks, no race conditions.
 *
 * Plain Java (no Android imports): the VPN interface and protect() are passed in as interfaces,
 * so this class is unit-tested on a laptop with a fake VPN interface and real local servers.
 * Supports IPv4 TCP and UDP. Other packets (e.g. ICMP ping) are counted and dropped.
 */
public final class PacketForwarder {

    /** The VPN interface: one read() returns one whole packet (0 = nothing within a short wait). */
    public interface Tun {
        int read(byte[] buf) throws IOException;
        void write(byte[] packet, int len) throws IOException;
    }

    /** VpnService.protect(): keeps OUR sockets out of the VPN (otherwise packets would loop). */
    public interface Protector {
        boolean protect(Socket socket);
        boolean protect(DatagramSocket socket);
    }

    /** Sees every packet in both directions (Phase 3: the analysis engine). Must return quickly. */
    public interface PacketTap {
        void onPacket(byte[] packet, int len, boolean fromApp);
    }

    private static final long UDP_IDLE_MS = 60_000;
    private static final long TCP_IDLE_MS = 5 * 60_000;

    /** A UDP "conversation" (e.g. DNS queries) relayed through one connected datagram socket. */
    private static final class UdpSession {
        final byte[] appIp;
        final int appPort;
        final byte[] remoteIp;
        final int remotePort;
        final DatagramChannel channel;
        long lastActiveMs = System.currentTimeMillis();

        UdpSession(byte[] appIp, int appPort, byte[] remoteIp, int remotePort, DatagramChannel channel) {
            this.appIp = appIp;
            this.appPort = appPort;
            this.remoteIp = remoteIp;
            this.remotePort = remotePort;
            this.channel = channel;
        }
    }

    private final Tun tun;
    private final Protector protector;
    private final PacketTap tap;
    private final Selector selector;
    private final BlockingQueue<byte[]> fromApp = new ArrayBlockingQueue<>(4096);
    private final Map<String, UdpSession> udp = new HashMap<>();
    private final Map<String, TcpProxy> tcp = new HashMap<>();
    private final ByteBuffer udpBuf = ByteBuffer.allocate(65535);
    private volatile boolean running;
    private volatile boolean resetRequested;
    private Thread readerThread;
    private Thread forwarderThread;

    final AtomicLong packetsFromApp = new AtomicLong();
    final AtomicLong packetsToApp = new AtomicLong();
    final AtomicLong packetsDropped = new AtomicLong();
    private volatile String lastError;

    public PacketForwarder(Tun tun, Protector protector, PacketTap tap) throws IOException {
        this.tun = tun;
        this.protector = protector;
        this.tap = tap;
        this.selector = Selector.open();
    }

    public void start() {
        running = true;
        readerThread = new Thread(this::readLoop, "tun-reader");
        forwarderThread = new Thread(this::forwardLoop, "forwarder");
        readerThread.start();
        forwarderThread.start();
    }

    public void stop() {
        running = false;
        selector.wakeup();
        try {
            if (readerThread != null) readerThread.join(1000);
            if (forwarderThread != null) forwarderThread.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Wi-Fi <-> mobile switch: old sockets are dead, so reset every connection; the app reconnects. */
    public void resetAllConnections() {
        resetRequested = true;
        selector.wakeup();
    }

    public long packetsFromApp() { return packetsFromApp.get(); }
    public long packetsToApp() { return packetsToApp.get(); }
    public long packetsDropped() { return packetsDropped.get(); }
    public int openConnections() { return tcp.size() + udp.size(); }
    public String lastError() { return lastError; }

    // ------------------------------------------------------------------ threads

    private void readLoop() {
        byte[] buf = new byte[32767];
        while (running) {
            try {
                int n = tun.read(buf);
                if (n <= 0) continue;
                packetsFromApp.incrementAndGet();
                if (tap != null) tap.onPacket(buf, n, true);
                if (!fromApp.offer(Arrays.copyOf(buf, n))) packetsDropped.incrementAndGet();
                selector.wakeup();
            } catch (IOException e) {
                if (running) lastError = "VPN read failed: " + e.getMessage();
                running = false;
            }
        }
        selector.wakeup();
    }

    private void forwardLoop() {
        long lastCleanup = System.currentTimeMillis();
        try {
            while (running) {
                byte[] p;
                while ((p = fromApp.poll()) != null) handleAppPacket(p);
                if (resetRequested) {
                    resetRequested = false;
                    resetAll();
                }
                selector.select(100);
                Iterator<SelectionKey> it = selector.selectedKeys().iterator();
                while (it.hasNext()) {
                    SelectionKey k = it.next();
                    it.remove();
                    if (k.isValid()) handleSocketEvent(k);
                }
                long now = System.currentTimeMillis();
                if (now - lastCleanup > 5000) {
                    cleanupIdle(now);
                    lastCleanup = now;
                }
            }
        } catch (IOException | RuntimeException e) {
            lastError = "Forwarder stopped: " + e;   // shown on screen; the VPN is then stopped
            running = false;
        } finally {
            resetAll();
            try {
                selector.close();
            } catch (IOException ignored) {
                // closing anyway
            }
        }
    }

    // ------------------------------------------------------------------ app -> internet

    private void handleAppPacket(byte[] p) {
        if (p.length < 20 || (p[0] >> 4 & 0x0F) != 4) {      // IPv4 only (IPv6 is blocked by the VPN setup)
            packetsDropped.incrementAndGet();
            return;
        }
        int ihl = (p[0] & 0x0F) * 4;
        int total = Math.min(p.length, PacketBuilder.u16(p, 2));
        int fragment = PacketBuilder.u16(p, 6) & 0x3FFF;      // MF flag or offset: fragmented
        int protocol = p[9] & 0xFF;
        if (ihl < 20 || total < ihl || fragment != 0) {
            packetsDropped.incrementAndGet();
            return;
        }
        byte[] src = Arrays.copyOfRange(p, 12, 16);
        byte[] dst = Arrays.copyOfRange(p, 16, 20);
        if (protocol == 17 && total >= ihl + 8) {
            handleUdp(p, ihl, total, src, dst);
        } else if (protocol == 6 && total >= ihl + 20) {
            handleTcp(p, ihl, total, src, dst);
        } else {
            packetsDropped.incrementAndGet();               // ICMP etc. are not forwarded
        }
    }

    private void handleUdp(byte[] p, int ihl, int total, byte[] src, byte[] dst) {
        int srcPort = PacketBuilder.u16(p, ihl);
        int dstPort = PacketBuilder.u16(p, ihl + 2);
        String key = key(src, srcPort, dst, dstPort);
        UdpSession s = udp.get(key);
        try {
            if (s == null) {
                DatagramChannel ch = DatagramChannel.open();
                if (!protector.protect(ch.socket())) throw new IOException("protect() failed");
                ch.connect(new InetSocketAddress(InetAddress.getByAddress(dst), dstPort));
                ch.configureBlocking(false);
                s = new UdpSession(src, srcPort, dst, dstPort, ch);
                ch.register(selector, SelectionKey.OP_READ, s);
                udp.put(key, s);
            }
            s.lastActiveMs = System.currentTimeMillis();
            s.channel.write(ByteBuffer.wrap(p, ihl + 8, total - ihl - 8));
        } catch (IOException e) {
            packetsDropped.incrementAndGet();
            if (s != null) closeUdp(key, s);
        }
    }

    private void handleTcp(byte[] p, int ihl, int total, byte[] src, byte[] dst) {
        int srcPort = PacketBuilder.u16(p, ihl);
        int dstPort = PacketBuilder.u16(p, ihl + 2);
        long seq = PacketBuilder.u32(p, ihl + 4);
        long ack = PacketBuilder.u32(p, ihl + 8);
        int headerLen = ((p[ihl + 12] >> 4) & 0x0F) * 4;
        int flags = p[ihl + 13] & 0x3F;
        int window = PacketBuilder.u16(p, ihl + 14);
        if (headerLen < 20 || ihl + headerLen > total) {
            packetsDropped.incrementAndGet();
            return;
        }
        int dataOff = ihl + headerLen;
        int dataLen = total - dataOff;
        String key = key(src, srcPort, dst, dstPort);
        TcpProxy c = tcp.get(key);

        boolean syn = (flags & PacketBuilder.SYN) != 0 && (flags & PacketBuilder.ACK) == 0;
        if (c == null) {
            if (syn) {
                c = new TcpProxy(this, key, src, srcPort, dst, dstPort);
                tcp.put(key, c);
                try {
                    c.open(seq, PacketBuilder.readMss(p, ihl, headerLen, 536), selector);
                } catch (IOException e) {
                    c.reset();
                }
            } else if ((flags & PacketBuilder.RST) == 0) {
                // A packet for a connection we don't know (e.g. after a reset): tell the app to give up.
                long rstSeq = (flags & PacketBuilder.ACK) != 0 ? ack : 0;
                long rstAck = (seq + dataLen + ((flags & PacketBuilder.FIN) != 0 ? 1 : 0)) & 0xFFFFFFFFL;
                writeToApp(PacketBuilder.tcp(dst, dstPort, src, srcPort, rstSeq, rstAck,
                        PacketBuilder.RST | PacketBuilder.ACK, 0, null, null, 0, 0));
            }
            return;
        }
        c.onAppPacket(flags, seq, ack, window, p, dataOff, dataLen);
    }

    // ------------------------------------------------------------------ internet -> app

    private void handleSocketEvent(SelectionKey k) {
        Object att = k.attachment();
        if (att instanceof TcpProxy) {
            TcpProxy c = (TcpProxy) att;
            if (k.isConnectable()) c.onConnectable();
            else {
                if (k.isValid() && k.isWritable()) c.onWritable();
                if (k.isValid() && k.isReadable()) c.onReadable();
            }
        } else if (att instanceof UdpSession) {
            UdpSession s = (UdpSession) att;
            try {
                udpBuf.clear();
                int n = s.channel.read(udpBuf);
                if (n > 0) {
                    s.lastActiveMs = System.currentTimeMillis();
                    writeToApp(PacketBuilder.udp(s.remoteIp, s.remotePort, s.appIp, s.appPort, udpBuf.array(), 0, n));
                }
            } catch (IOException e) {
                closeUdp(key(s.appIp, s.appPort, s.remoteIp, s.remotePort), s);
            }
        }
    }

    /** Called by TcpProxy and UDP code to deliver a packet to the app. */
    void writeToApp(byte[] packet) {
        try {
            tun.write(packet, packet.length);
            packetsToApp.incrementAndGet();
            if (tap != null) tap.onPacket(packet, packet.length, false);
        } catch (IOException e) {
            lastError = "VPN write failed: " + e.getMessage();
        }
    }

    boolean protect(Socket s) {
        return protector.protect(s);
    }

    void removeTcp(String key) {
        tcp.remove(key);
    }

    // ------------------------------------------------------------------ housekeeping

    private void cleanupIdle(long now) {
        for (Map.Entry<String, UdpSession> e : new ArrayList<>(udp.entrySet())) {
            if (now - e.getValue().lastActiveMs > UDP_IDLE_MS) closeUdp(e.getKey(), e.getValue());
        }
        for (TcpProxy c : new ArrayList<>(tcp.values())) {
            if (now - c.lastActiveMs > TCP_IDLE_MS) c.reset();
        }
    }

    private void resetAll() {
        for (TcpProxy c : new ArrayList<>(tcp.values())) c.reset();
        for (Map.Entry<String, UdpSession> e : new ArrayList<>(udp.entrySet())) closeUdp(e.getKey(), e.getValue());
    }

    private void closeUdp(String key, UdpSession s) {
        udp.remove(key);
        try {
            s.channel.close();
        } catch (IOException ignored) {
            // closing anyway
        }
    }

    private static String key(byte[] src, int srcPort, byte[] dst, int dstPort) {
        return (src[0] & 0xFF) + "." + (src[1] & 0xFF) + "." + (src[2] & 0xFF) + "." + (src[3] & 0xFF) + ":" + srcPort
                + ">" + (dst[0] & 0xFF) + "." + (dst[1] & 0xFF) + "." + (dst[2] & 0xFF) + "." + (dst[3] & 0xFF)
                + ":" + dstPort;
    }
}
