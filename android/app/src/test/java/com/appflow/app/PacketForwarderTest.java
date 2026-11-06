package com.appflow.app;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Runs the REAL forwarder on the laptop: a fake VPN interface (two queues) on one side and
 * real local TCP/UDP servers on the other. The test plays the role of the monitored app.
 */
class PacketForwarderTest {

    private static final byte[] APP = {10, 111, 0, 2};
    private static final byte[] LOCAL = {127, 0, 0, 1};

    /** Fake VPN interface: toForwarder = packets the "app" sends, toApp = packets the forwarder writes. */
    private final BlockingQueue<byte[]> toForwarder = new LinkedBlockingQueue<>();
    private final BlockingQueue<byte[]> toApp = new LinkedBlockingQueue<>();
    private final AtomicInteger tapUp = new AtomicInteger();
    private final AtomicInteger tapDown = new AtomicInteger();
    private PacketForwarder fwd;

    @BeforeEach
    void setUp() throws IOException {
        PacketForwarder.Tun tun = new PacketForwarder.Tun() {
            @Override
            public int read(byte[] buf) throws IOException {
                try {
                    byte[] p = toForwarder.poll(100, TimeUnit.MILLISECONDS);
                    if (p == null) return 0;
                    System.arraycopy(p, 0, buf, 0, p.length);
                    return p.length;
                } catch (InterruptedException e) {
                    throw new IOException(e);
                }
            }

            @Override
            public void write(byte[] packet, int len) {
                toApp.add(Arrays.copyOf(packet, len));
            }
        };
        PacketForwarder.Protector noProtect = new PacketForwarder.Protector() {
            @Override public boolean protect(Socket s) { return true; }
            @Override public boolean protect(DatagramSocket s) { return true; }
        };
        fwd = new PacketForwarder(tun, noProtect, (p, len, fromApp) -> (fromApp ? tapUp : tapDown).incrementAndGet());
        fwd.start();
    }

    @AfterEach
    void tearDown() {
        fwd.stop();
    }

    // ------------------------------------------------------------------ helpers

    private void appSendsTcp(int appPort, int serverPort, long seq, long ack, int flags, byte[] data) {
        byte[] opts = (flags & PacketBuilder.SYN) != 0 ? PacketBuilder.mssOption(1400) : null;
        toForwarder.add(PacketBuilder.tcp(APP, appPort, LOCAL, serverPort, seq, ack, flags, 65535, opts,
                data == null ? new byte[0] : data, 0, data == null ? 0 : data.length));
    }

    private byte[] nextToApp() throws InterruptedException {
        byte[] p = toApp.poll(5, TimeUnit.SECONDS);
        assertNotNull(p, "forwarder did not answer within 5 s");
        assertValidChecksums(p);
        return p;
    }

    private static void assertValidChecksums(byte[] p) {
        assertEquals(0, PacketBuilder.checksum(p, 0, 20, 0), "IPv4 header checksum");
        int proto = p[9] & 0xFF;
        assertEquals(0, PacketBuilder.transportChecksum(p, 20, p.length - 20, proto), "TCP/UDP checksum");
    }

    private static int flags(byte[] p) { return p[33] & 0x3F; }
    private static long seq(byte[] p) { return PacketBuilder.u32(p, 24); }
    private static long ack(byte[] p) { return PacketBuilder.u32(p, 28); }
    private static int dataOff(byte[] p) { return 20 + ((p[32] >> 4) & 0x0F) * 4; }
    private static int dataLen(byte[] p) { return p.length - dataOff(p); }

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    // ------------------------------------------------------------------ tests

    @Test
    void tcpEchoRoundTripAndCleanClose() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            Thread echo = new Thread(() -> {
                try (Socket s = server.accept(); InputStream in = s.getInputStream(); OutputStream out = s.getOutputStream()) {
                    byte[] b = new byte[1024];
                    int n;
                    while ((n = in.read(b)) > 0) out.write(b, 0, n);   // echo until the app closes
                } catch (IOException ignored) {
                    // test will fail on its own if this matters
                }
            });
            echo.start();
            int port = server.getLocalPort();

            appSendsTcp(40000, port, 1000, 0, PacketBuilder.SYN, null);
            byte[] synAck = nextToApp();
            assertEquals(PacketBuilder.SYN | PacketBuilder.ACK, flags(synAck));
            assertEquals(1001, ack(synAck));
            assertEquals(1360, PacketBuilder.readMss(synAck, 20, dataOff(synAck) - 20, -1));
            long serverSeq = seq(synAck) + 1;

            appSendsTcp(40000, port, 1001, serverSeq, PacketBuilder.ACK, null);
            byte[] hello = "hello world".getBytes();
            appSendsTcp(40000, port, 1001, serverSeq, PacketBuilder.ACK | PacketBuilder.PSH, hello);

            ByteArrayOutputStream echoed = new ByteArrayOutputStream();
            boolean ackedOurData = false;
            while (echoed.size() < hello.length) {
                byte[] p = nextToApp();
                if (ack(p) == 1001 + hello.length) ackedOurData = true;
                if (dataLen(p) > 0) {
                    assertEquals(serverSeq, seq(p));
                    echoed.write(p, dataOff(p), dataLen(p));
                    serverSeq += dataLen(p);
                    appSendsTcp(40000, port, 1001 + hello.length, serverSeq, PacketBuilder.ACK, null);
                }
            }
            assertTrue(ackedOurData, "our data must be acknowledged");
            assertArrayEquals(hello, echoed.toByteArray());

            // App closes -> server sees EOF and closes -> forwarder sends FIN to the app.
            appSendsTcp(40000, port, 1001 + hello.length, serverSeq, PacketBuilder.FIN | PacketBuilder.ACK, null);
            byte[] fin = null;
            for (int i = 0; i < 5 && fin == null; i++) {
                byte[] p = nextToApp();
                if ((flags(p) & PacketBuilder.FIN) != 0) fin = p;
            }
            assertNotNull(fin, "expected FIN from forwarder");
            appSendsTcp(40000, port, 1002 + hello.length, seq(fin) + 1, PacketBuilder.ACK, null);
            for (int i = 0; i < 50 && fwd.openConnections() > 0; i++) Thread.sleep(20);
            assertEquals(0, fwd.openConnections(), "connection must be released after close");
            echo.join(2000);
            assertTrue(tapUp.get() >= 5 && tapDown.get() >= 3, "tap sees both directions");
        }
    }

    @Test
    void largeDownloadArrivesCompleteAndRespectsWindow() throws Exception {
        byte[] payload = new byte[300_000];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i * 31 + 7);
        try (ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            Thread sender = new Thread(() -> {
                try (Socket s = server.accept()) {
                    s.getOutputStream().write(payload);
                } catch (IOException ignored) {
                    // checked by the assertions below
                }
            });
            sender.start();
            int port = server.getLocalPort();
            appSendsTcp(40001, port, 5000, 0, PacketBuilder.SYN, null);
            long next = seq(nextToApp()) + 1;
            appSendsTcp(40001, port, 5001, next, PacketBuilder.ACK, null);

            ByteArrayOutputStream got = new ByteArrayOutputStream();
            long acked = next;
            long maxInFlight = 0;
            boolean fin = false;
            while (!fin) {
                byte[] p = nextToApp();
                if (dataLen(p) > 0) {
                    assertEquals(next, seq(p), "segments must arrive in order");
                    got.write(p, dataOff(p), dataLen(p));
                    next += dataLen(p);
                    maxInFlight = Math.max(maxInFlight, next - acked);
                    if (got.size() % 8 == 0 || dataLen(p) < 1360) {     // ACK in bursts, like a real app
                        acked = next;
                        appSendsTcp(40001, port, 5001, acked, PacketBuilder.ACK, null);
                    } else if (next - acked > 32_000) {
                        acked = next;
                        appSendsTcp(40001, port, 5001, acked, PacketBuilder.ACK, null);
                    }
                }
                if ((flags(p) & PacketBuilder.FIN) != 0) fin = true;
            }
            assertArrayEquals(payload, got.toByteArray());
            assertTrue(maxInFlight <= 65535, "never more than the app's window in flight: " + maxInFlight);
            sender.join(2000);
        }
    }

    @Test
    void udpRoundTrip() throws Exception {
        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            Thread echo = new Thread(() -> {
                try {
                    DatagramPacket d = new DatagramPacket(new byte[512], 512);
                    server.receive(d);
                    server.send(new DatagramPacket(d.getData(), d.getLength(), d.getSocketAddress()));
                } catch (IOException ignored) {
                    // checked below
                }
            });
            echo.start();
            byte[] query = "fake-dns-query".getBytes();
            toForwarder.add(PacketBuilder.udp(APP, 53000, LOCAL, server.getLocalPort(), query, 0, query.length));
            byte[] reply = nextToApp();
            assertEquals(17, reply[9]);
            assertArrayEquals(LOCAL, Arrays.copyOfRange(reply, 12, 16));          // from the server
            assertArrayEquals(APP, Arrays.copyOfRange(reply, 16, 20));            // to the app
            assertEquals(53000, PacketBuilder.u16(reply, 22));
            assertArrayEquals(query, Arrays.copyOfRange(reply, 28, reply.length));
            echo.join(2000);
        }
    }

    @Test
    void refusedConnectionGetsRst() throws Exception {
        appSendsTcp(40002, freePort(), 1, 0, PacketBuilder.SYN, null);
        byte[] p = nextToApp();
        assertTrue((flags(p) & PacketBuilder.RST) != 0);
        assertEquals(2, ack(p));
    }

    @Test
    void unknownConnectionGetsRst() throws Exception {
        appSendsTcp(40003, 443, 77, 99, PacketBuilder.ACK | PacketBuilder.PSH, "x".getBytes());
        byte[] p = nextToApp();
        assertTrue((flags(p) & PacketBuilder.RST) != 0);
        assertEquals(99, seq(p));
    }

    @Test
    void ipv6AndIcmpAreDropped() throws Exception {
        byte[] v6 = new byte[60];
        v6[0] = 0x60;
        toForwarder.add(v6);
        byte[] icmp = PacketBuilder.udp(APP, 1, LOCAL, 2, new byte[0], 0, 0);
        icmp[9] = 1;                                                           // protocol ICMP
        toForwarder.add(icmp);
        for (int i = 0; i < 50 && fwd.packetsDropped() < 2; i++) Thread.sleep(20);
        assertEquals(2, fwd.packetsDropped());
        assertTrue(toApp.isEmpty());
    }

    @Test
    void networkChangeResetsOpenConnections() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            int port = server.getLocalPort();
            appSendsTcp(40004, port, 1, 0, PacketBuilder.SYN, null);
            byte[] synAck = nextToApp();
            appSendsTcp(40004, port, 2, seq(synAck) + 1, PacketBuilder.ACK, null);
            Thread.sleep(200);
            fwd.resetAllConnections();
            byte[] p = nextToApp();
            assertTrue((flags(p) & PacketBuilder.RST) != 0, "app must be told to reconnect");
            for (int i = 0; i < 50 && fwd.openConnections() > 0; i++) Thread.sleep(20);
            assertEquals(0, fwd.openConnections());
        }
    }
}
