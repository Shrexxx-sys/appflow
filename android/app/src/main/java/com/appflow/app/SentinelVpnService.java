package com.appflow.app;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import com.appflow.analysis.AnalysisEngine;
import com.appflow.analysis.ObservationExporter;
import com.appflow.analysis.PacketInfo;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Socket;

/**
 * Local VPN for ONE chosen app:
 *   1. creates a backend session (POST /sessions) - if the laptop is unreachable we stop with a clear error
 *   2. starts the VPN for that app only and forwards its packets (the app keeps its internet)
 *   3. copies every packet to the analysis engine (queue, never blocks forwarding), which sends
 *      a JSON batch to the backend every 2 seconds
 * Only metadata leaves the phone. Payloads are never stored or sent; HTTPS is never decrypted.
 */
public class SentinelVpnService extends VpnService {

    public static final String ACTION_START = "com.appflow.app.START";
    public static final String ACTION_STOP = "com.appflow.app.STOP";
    public static final String EXTRA_PACKAGE = "package";
    public static final String EXTRA_APP_NAME = "app_name";
    public static final String EXTRA_BACKEND_URL = "backend_url";
    public static final String EXTRA_API_KEY = "api_key";

    // Read by the screen once a second. volatile = always see the latest value across threads.
    private static volatile String status = "Stopped";
    private static volatile String error = "";
    private static volatile String analysisStatus = "";
    private static volatile PacketForwarder activeForwarder;

    private ParcelFileDescriptor tun;
    private volatile PacketForwarder forwarder;   // also read by the network-change callback thread
    private volatile AnalysisEngine engine;
    private ObservationExporter exporter;
    private long sessionId = -1;
    private ConnectivityManager.NetworkCallback networkCallback;
    private Network currentNetwork;

    public static String statusLine() {
        PacketForwarder f = activeForwarder;
        if (f == null) return status;
        String fwdError = f.lastError();
        if (fwdError != null) error = fwdError;
        return status + "\npackets: " + f.packetsFromApp() + " up / " + f.packetsToApp() + " down, "
                + f.openConnections() + " open connections\n" + analysisStatus;
    }

    public static String lastError() { return error; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_START.equals(action)) {
            String pkg = intent.getStringExtra(EXTRA_PACKAGE);
            String appName = intent.getStringExtra(EXTRA_APP_NAME);
            String url = intent.getStringExtra(EXTRA_BACKEND_URL);
            String key = intent.getStringExtra(EXTRA_API_KEY);
            status = "Connecting to backend " + url + " …";
            error = "";
            // Network calls are not allowed on the main thread -> start on a background thread.
            new Thread(() -> startMonitoring(pkg, appName, url, key), "start-monitoring").start();
        } else if (ACTION_STOP.equals(action)) {
            stopMonitoring();
            stopSelf();
        }
        return START_NOT_STICKY;   // if Android kills us, don't silently restart monitoring
    }

    private synchronized void startMonitoring(String pkg, String appName, String backendUrl, String apiKey) {
        stopMonitoring();
        int uid;
        try {
            uid = getPackageManager().getApplicationInfo(pkg, 0).uid;
        } catch (PackageManager.NameNotFoundException e) {
            fail("App not found: " + pkg);
            return;
        }

        // 1. Backend session first: without it there is nowhere to send the analysis.
        exporter = new ObservationExporter(backendUrl, apiKey);
        try {
            sessionId = exporter.startSession(pkg, appName, Build.MODEL, false);
        } catch (IOException e) {
            fail("Backend not reachable at " + backendUrl + " (" + e.getMessage() + "). "
                    + "Is the laptop on the same Wi-Fi, uvicorn started with --host 0.0.0.0, and the API key correct?");
            return;
        }
        final ObservationExporter ex = exporter;
        engine = new AnalysisEngine(sessionId, false, json -> ex.postObservation(json).status,
                message -> analysisStatus = "backend: " + message);
        engine.start();

        // 2. The VPN for this ONE app.
        try {
            Builder b = new Builder()
                    .setSession("AppFlow Sentinel")
                    .setMtu(1500)
                    .addAddress("10.111.0.2", 32)    // the VPN's own private address
                    .addRoute("0.0.0.0", 0)          // all IPv4 traffic of the chosen app
                    .addDnsServer("8.8.8.8");        // DNS goes through the VPN, so DNS answers are observable
            // No IPv6 address/route: Android then BLOCKS the app's IPv6, so everything uses IPv4 and is seen.
            b.addAllowedApplication(pkg);           // per-app: ONLY this app goes through the VPN
            tun = b.establish();
        } catch (PackageManager.NameNotFoundException e) {
            fail("App not found: " + pkg);
            stopMonitoring();
            return;
        }
        if (tun == null) {
            fail("VPN permission missing - press Start again and accept the dialog.");
            stopMonitoring();
            return;
        }

        // 3. Forwarding, with every packet copied to the analysis engine.
        final AnalysisEngine eng = engine;
        PacketForwarder.PacketTap tap = (packet, len, fromApp) -> eng.submit(packet, len,
                System.currentTimeMillis(), fromApp ? PacketInfo.Direction.UP : PacketInfo.Direction.DOWN, uid);
        try {
            forwarder = new PacketForwarder(new TunDevice(tun.getFileDescriptor()), new Protector(), tap);
        } catch (IOException e) {
            fail("Could not start forwarding: " + e.getMessage());
            stopMonitoring();
            return;
        }
        forwarder.start();
        activeForwarder = forwarder;
        watchNetworkChanges();
        status = "Monitoring " + appName + " · backend session #" + sessionId;
    }

    /** Wi-Fi <-> mobile data: tell Android which network we use, and reset connections on a switch. */
    private void watchNetworkChanges() {
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                setUnderlyingNetworks(new Network[] { network });
                if (currentNetwork != null && !currentNetwork.equals(network) && forwarder != null) {
                    forwarder.resetAllConnections();   // old sockets died with the old network
                    error = "Network changed - connections were reset; the app reconnects by itself.";
                }
                currentNetwork = network;
            }

            @Override
            public void onLost(Network network) {
                error = "Network lost - waiting for Wi-Fi or mobile data. (On mobile data the laptop backend "
                        + "is unreachable; batches are kept and retried.)";
            }
        };
        cm.registerDefaultNetworkCallback(networkCallback);
    }

    private void fail(String message) {
        error = message;
        status = "Stopped";
    }

    private synchronized void stopMonitoring() {
        activeForwarder = null;
        if (networkCallback != null) {
            try {
                getSystemService(ConnectivityManager.class).unregisterNetworkCallback(networkCallback);
            } catch (IllegalArgumentException ignored) {
                // already unregistered
            }
            networkCallback = null;
            currentNetwork = null;
        }
        if (forwarder != null) {
            forwarder.stop();
            forwarder = null;
        }
        if (tun != null) {
            try {
                tun.close();   // removes the VPN and the key icon
            } catch (IOException ignored) {
                // nothing useful to do
            }
            tun = null;
        }
        // Final batch + POST /stop involve the network: do them on a background thread.
        final AnalysisEngine eng = engine;
        final ObservationExporter ex = exporter;
        final long id = sessionId;
        engine = null;
        sessionId = -1;
        if (eng != null || id >= 0) {
            new Thread(() -> {
                if (eng != null) eng.stop();                     // analyse the rest, send the final batch
                if (ex != null && id >= 0) {
                    try {
                        ex.stopSession(id);
                    } catch (IOException e) {
                        error = "Could not tell the backend that monitoring stopped: " + e.getMessage();
                    }
                }
            }, "stop-monitoring").start();
        }
        status = "Stopped";
    }

    /** The user revoked the permission or started ANOTHER VPN app (only one VPN can run at a time). */
    @Override
    public void onRevoke() {
        stopMonitoring();
        error = "Android stopped the VPN (permission revoked or another VPN app started).";
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopMonitoring();
        super.onDestroy();
    }

    /** The VPN interface as a {@link PacketForwarder.Tun}: one read = one packet. */
    private static final class TunDevice implements PacketForwarder.Tun {
        private final FileDescriptor fd;
        private final FileInputStream in;
        private final FileOutputStream out;
        private final StructPollfd[] poll;

        TunDevice(FileDescriptor fd) {
            this.fd = fd;
            this.in = new FileInputStream(fd);
            this.out = new FileOutputStream(fd);
            StructPollfd p = new StructPollfd();
            p.fd = fd;
            p.events = (short) OsConstants.POLLIN;
            this.poll = new StructPollfd[] { p };
        }

        @Override
        public int read(byte[] buf) throws IOException {
            try {
                // Wait at most 200 ms, so STOP is noticed quickly even when the app is silent.
                if (Os.poll(poll, 200) <= 0) return 0;
            } catch (ErrnoException e) {
                if (!fd.valid()) throw new IOException("VPN interface closed");
                return 0;   // e.g. interrupted system call: just try again
            }
            return in.read(buf);
        }

        @Override
        public void write(byte[] packet, int len) throws IOException {
            out.write(packet, 0, len);   // one write = one packet
        }
    }

    /** VpnService.protect(): our own sockets must bypass the VPN, or packets would loop forever. */
    private final class Protector implements PacketForwarder.Protector {
        @Override
        public boolean protect(Socket socket) {
            return SentinelVpnService.this.protect(socket);
        }

        @Override
        public boolean protect(DatagramSocket socket) {
            return SentinelVpnService.this.protect(socket);
        }
    }
}
