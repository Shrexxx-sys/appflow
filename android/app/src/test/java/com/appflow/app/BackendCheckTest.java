package com.appflow.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.UnknownServiceException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class BackendCheckTest {

    // ---------------------------------------------------------------- URL clean-up

    @Test
    void acceptsLanAddressAndCleansIt() {
        assertEquals("http://192.168.1.20:8000", BackendCheck.normalizeUrl("  http://192.168.1.20:8000///  "));
        assertEquals("http://172.20.10.8:8000", BackendCheck.normalizeUrl("172.20.10.8:8000"));      // http:// added
        assertEquals("http://10.0.2.2:8000", BackendCheck.normalizeUrl("HTTP://10.0.2.2:8000"));     // emulator alias ok
    }

    @Test
    void refusesAddressesThatCannotWorkFromAPhone() {
        for (String bad : new String[] {"http://localhost:8000", "http://127.0.0.1:8000", "http://0.0.0.0:8000"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> BackendCheck.normalizeUrl(bad));
            assertTrue(e.getMessage().contains("this phone itself"), e.getMessage());
        }
        assertTrue(assertThrows(IllegalArgumentException.class, () -> BackendCheck.normalizeUrl("http://192.168.1.20"))
                .getMessage().contains(":8000"));                                                // port missing
        assertTrue(assertThrows(IllegalArgumentException.class, () -> BackendCheck.normalizeUrl("http://192.168.1.20:8000/docs"))
                .getMessage().contains("without /docs"));
        assertThrows(IllegalArgumentException.class, () -> BackendCheck.normalizeUrl("   "));
        assertThrows(IllegalArgumentException.class, () -> BackendCheck.normalizeUrl("ftp://192.168.1.20:8000"));
    }

    // ---------------------------------------------------------------- error reasons

    @Test
    void describesEachRealReasonWithTheUrl() {
        String u = "http://192.168.1.20:8000";
        assertTrue(BackendCheck.describe(new SocketTimeoutException("failed to connect after 5000ms"), u)
                .startsWith("No answer from " + u));
        assertTrue(BackendCheck.describe(new ConnectException("failed to connect: ECONNREFUSED (Connection refused)"), u)
                .startsWith("Connection refused by " + u));
        assertTrue(BackendCheck.describe(new NoRouteToHostException("EHOSTUNREACH"), u).startsWith("No route to " + u));
        assertTrue(BackendCheck.describe(new ConnectException("connect failed: ENETUNREACH (Network is unreachable)"), u)
                .startsWith("No route to " + u));
        assertTrue(BackendCheck.describe(new UnknownServiceException(
                "CLEARTEXT communication to 192.168.1.20 not permitted by network security policy"), u).contains("cleartext"));
        assertTrue(BackendCheck.describe(new UnknownHostException("laptop"), u).startsWith("Unknown host in " + u));
        assertTrue(BackendCheck.describe(new IOException("Start session failed: HTTP 401 {\"detail\":\"x\"}"), u)
                .contains("rejected the API key (HTTP 401)"));
    }

    // ---------------------------------------------------------------- the Test connection button

    /** A tiny fake backend: /health = 200, /reports/0/download = 404 with the right key, 401 otherwise. */
    private static HttpServer fakeBackend(String key, int healthStatus) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.createContext("/health", ex -> reply(ex, healthStatus, "{\"status\":\"ok\"}"));
        s.createContext("/reports/0/download", ex -> {
            String sent = ex.getRequestHeaders().getFirst("X-API-Key");
            reply(ex, key.equals(sent) ? 404 : 401, "{\"detail\":\"...\"}");
        });
        s.start();
        return s;
    }

    private static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    // The fake server can only listen on 127.0.0.1, which normalizeUrl() refuses for real users (on a phone it
    // means the phone itself). So these tests call checkNormalized(), the network part, directly.
    private static String loopbackUrl(int port) {
        return "http://127.0.0.1:" + port;
    }

    @Test
    void okWhenReachableAndKeyAccepted() throws Exception {
        HttpServer s = fakeBackend("right-key", 200);
        try {
            BackendCheck.Result r = BackendCheck.checkNormalized(loopbackUrl(s.getAddress().getPort()), "right-key");
            assertTrue(r.ok, r.message);
            assertTrue(r.message.startsWith("OK"));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void wrongKeyIsReportedAs401() throws Exception {
        HttpServer s = fakeBackend("right-key", 200);
        try {
            BackendCheck.Result r = BackendCheck.checkNormalized(loopbackUrl(s.getAddress().getPort()), "wrong-key");
            assertFalse(r.ok);
            assertTrue(r.message.contains("HTTP 401"), r.message);
        } finally {
            s.stop(0);
        }
    }

    @Test
    void refusedPortIsReportedWithTheUrl() throws Exception {
        int port;
        try (ServerSocket tmp = new ServerSocket(0)) {
            port = tmp.getLocalPort();                         // free port: nothing listens there
        }
        BackendCheck.Result r = BackendCheck.checkNormalized(loopbackUrl(port), "k");
        assertFalse(r.ok);
        assertTrue(r.message.startsWith("Connection refused by " + loopbackUrl(port)), r.message);
    }

    @Test
    void invalidUrlIsExplainedBeforeAnyNetworkCall() {
        BackendCheck.Result r = BackendCheck.check("http://localhost:8000", "k");
        assertFalse(r.ok);
        assertTrue(r.message.contains("this phone itself"));
    }

    /** Against a REAL running backend (only when APPFLOW_BACKEND_URL/APPFLOW_API_KEY are set). */
    @Test
    void realBackend() {
        String url = System.getenv("APPFLOW_BACKEND_URL");
        String key = System.getenv("APPFLOW_API_KEY");
        assumeTrue(url != null && key != null, "set APPFLOW_BACKEND_URL and APPFLOW_API_KEY to run");
        BackendCheck.Result ok = BackendCheck.check(url, key);
        assertTrue(ok.ok, ok.message);
        BackendCheck.Result bad = BackendCheck.check(url, key + "-wrong");
        assertTrue(!bad.ok && bad.message.contains("HTTP 401"), bad.message);
    }
}
