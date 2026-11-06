package com.appflow.app;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Random;

/**
 * One TCP connection of the app, relayed through a real socket ("mini TCP stack").
 *
 *   app --SYN--> us        we connect a real socket to the server, then answer SYN-ACK
 *   app --data--> us       we ACK it and write it to the socket
 *   socket --data--> us    we cut it into segments, respecting the app's window, and send them to the app
 *   FIN / RST              closed in both directions, socket released
 *
 * Simplifications (fine for a demo, documented): IPv4 only, no window scaling (we never offer it, so
 * the app's window is plain 16-bit), no SACK/timestamps, and we do not retransmit to the app (the
 * VPN interface is local and does not lose packets in normal operation).
 * Runs ONLY on the forwarder's single thread, so no locks are needed.
 */
final class TcpProxy {

    static final int MY_MSS = 1360;          // fits in the VPN's 1500-byte MTU with headers to spare
    private static final int MY_WINDOW = 65535;
    private static final int MAX_BUFFER = 256 * 1024;
    private static final long MASK = 0xFFFFFFFFL;
    private static final Random RANDOM = new Random();

    enum State { CONNECTING, ESTABLISHED, CLOSED }

    final String key;
    final byte[] appIp;
    final int appPort;
    final byte[] remoteIp;
    final int remotePort;
    private final PacketForwarder forwarder;
    private SocketChannel channel;
    private SelectionKey selectionKey;
    State state = State.CONNECTING;

    private long appNext;        // next sequence number we expect from the app
    private long myNext;         // next sequence number we will send to the app
    private long appAcked;       // the app has received our bytes up to here
    private int appWindow = MY_WINDOW;
    private int sendMss = 536;   // the app's MSS (min. guaranteed value until told otherwise)
    private final ByteBuffer toRemote = ByteBuffer.allocate(MAX_BUFFER);
    private boolean appFinished;    // app sent FIN
    private boolean remoteFinished; // server closed its side
    private boolean finSentToApp;
    long lastActiveMs = System.currentTimeMillis();

    TcpProxy(PacketForwarder forwarder, String key, byte[] appIp, int appPort, byte[] remoteIp, int remotePort) {
        this.forwarder = forwarder;
        this.key = key;
        this.appIp = appIp;
        this.appPort = appPort;
        this.remoteIp = remoteIp;
        this.remotePort = remotePort;
    }

    /** The app sent SYN: start connecting a real (protected) socket to the server. */
    void open(long appSeq, int appMss, Selector selector) throws IOException {
        appNext = (appSeq + 1) & MASK;
        myNext = RANDOM.nextInt() & MASK;
        appAcked = myNext;
        sendMss = Math.max(64, Math.min(appMss, MY_MSS));
        channel = SocketChannel.open();
        if (!forwarder.protect(channel.socket())) throw new IOException("protect() failed");
        channel.configureBlocking(false);
        boolean connected = channel.connect(new InetSocketAddress(InetAddress.getByAddress(remoteIp), remotePort));
        selectionKey = channel.register(selector, connected ? 0 : SelectionKey.OP_CONNECT, this);
        if (connected) onConnected();
    }

    /** Selector says the connect finished (or failed). */
    void onConnectable() {
        try {
            if (channel.finishConnect()) onConnected();
        } catch (IOException e) {
            reset();   // e.g. connection refused / timeout -> tell the app with RST
        }
    }

    private void onConnected() {
        state = State.ESTABLISHED;
        send(PacketBuilder.SYN | PacketBuilder.ACK, PacketBuilder.mssOption(MY_MSS), null, 0, 0);
        myNext = (myNext + 1) & MASK;   // the SYN counts as one sequence number
        appAcked = myNext;
        selectionKey.interestOps(SelectionKey.OP_READ);
    }

    /** A packet from the app for this connection. */
    void onAppPacket(int flags, long seq, long ack, int window, byte[] p, int dataOff, int dataLen) {
        lastActiveMs = System.currentTimeMillis();
        if ((flags & PacketBuilder.RST) != 0) {
            close();
            return;
        }
        if (state == State.CONNECTING) return;              // SYN retransmit while we connect: ignore

        if ((flags & PacketBuilder.ACK) != 0) {
            if (after(ack, appAcked) && !after(ack, myNext)) appAcked = ack;
            appWindow = window;
            resumeReadingIfWindowOpen();
            if (finSentToApp && appFinished && ack == myNext) {   // our FIN was acknowledged: done
                close();
                return;
            }
        }

        if (dataLen > 0) {
            if (seq == appNext && toRemote.remaining() >= dataLen) {
                toRemote.put(p, dataOff, dataLen);
                appNext = (appNext + dataLen) & MASK;
                flushToRemote();
                if (state == State.CLOSED) return;            // the write failed and we reset
            }
            // In order -> acknowledges the new data. Out of order / no room -> repeats the last ACK,
            // so the app retransmits later. Either way the app learns where we are.
            sendAck();
        }

        if ((flags & PacketBuilder.FIN) != 0 && ((seq + dataLen) & MASK) == appNext && !appFinished) {
            appFinished = true;
            appNext = (appNext + 1) & MASK;
            sendAck();
            if (toRemote.position() == 0) shutdownRemoteOutput();
            if (remoteFinished && finSentToApp) close();
        }
    }

    /** The server sent data (or closed). */
    void onReadable() {
        lastActiveMs = System.currentTimeMillis();
        int inFlight = (int) ((myNext - appAcked) & MASK);
        int room = appWindow - inFlight;
        if (room <= 0) {                                    // the app's window is full: wait for its ACK
            selectionKey.interestOps(selectionKey.interestOps() & ~SelectionKey.OP_READ);
            return;
        }
        ByteBuffer buf = ByteBuffer.allocate(Math.min(room, 16 * 1024));
        int n;
        try {
            n = channel.read(buf);
        } catch (IOException e) {
            reset();
            return;
        }
        if (n < 0) {                                        // server closed: send FIN to the app
            remoteFinished = true;
            selectionKey.interestOps(selectionKey.interestOps() & ~SelectionKey.OP_READ);
            send(PacketBuilder.FIN | PacketBuilder.ACK, null, null, 0, 0);
            myNext = (myNext + 1) & MASK;
            finSentToApp = true;
            return;
        }
        byte[] data = buf.array();
        for (int off = 0; off < n; off += sendMss) {
            int len = Math.min(sendMss, n - off);
            send(PacketBuilder.ACK | PacketBuilder.PSH, null, data, off, len);
            myNext = (myNext + len) & MASK;
        }
    }

    /** The socket can take more data. */
    void onWritable() {
        flushToRemote();
    }

    private void flushToRemote() {
        toRemote.flip();
        try {
            channel.write(toRemote);
        } catch (IOException e) {
            toRemote.clear();
            reset();
            return;
        } finally {
            if (state != State.CLOSED) toRemote.compact();
        }
        int ops = selectionKey.interestOps();
        if (toRemote.position() > 0) {
            selectionKey.interestOps(ops | SelectionKey.OP_WRITE);      // wait until the socket drains
        } else {
            selectionKey.interestOps(ops & ~SelectionKey.OP_WRITE);
            if (appFinished) shutdownRemoteOutput();
        }
    }

    private void resumeReadingIfWindowOpen() {
        if (remoteFinished || selectionKey == null || !selectionKey.isValid()) return;
        int inFlight = (int) ((myNext - appAcked) & MASK);
        if (appWindow - inFlight > 0) selectionKey.interestOps(selectionKey.interestOps() | SelectionKey.OP_READ);
    }

    private void shutdownRemoteOutput() {
        try {
            channel.shutdownOutput();
        } catch (IOException ignored) {
            // the socket may already be closed
        }
    }

    private void sendAck() {
        send(PacketBuilder.ACK, null, null, 0, 0);
    }

    private void send(int flags, byte[] options, byte[] data, int off, int len) {
        forwarder.writeToApp(PacketBuilder.tcp(remoteIp, remotePort, appIp, appPort, myNext, appNext, flags,
                MY_WINDOW, options, data, off, len));
    }

    /** Abort: RST to the app and release everything. */
    void reset() {
        if (state == State.CLOSED) return;
        forwarder.writeToApp(PacketBuilder.tcp(remoteIp, remotePort, appIp, appPort, myNext, appNext,
                PacketBuilder.RST | PacketBuilder.ACK, 0, null, null, 0, 0));
        close();
    }

    void close() {
        if (state == State.CLOSED) return;
        state = State.CLOSED;
        if (selectionKey != null) selectionKey.cancel();
        try {
            if (channel != null) channel.close();
        } catch (IOException ignored) {
            // nothing useful to do
        }
        forwarder.removeTcp(key);
    }

    /** Sequence numbers wrap around at 2^32, so compare them "modulo 2^32". */
    private static boolean after(long a, long b) {
        return (int) ((a - b) & MASK) > 0;
    }
}
