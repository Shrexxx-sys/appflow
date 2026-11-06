package com.appflow.app;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.net.UnknownServiceException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Everything about "can the phone reach the laptop backend?" (plain Java, unit-tested on a laptop):
 *   normalizeUrl() - clean up what the user typed, refuse addresses that cannot work from a phone
 *   describe()     - turn a Java network error into the REAL reason in plain words
 *   check()        - the "Test connection" button: GET /health, then verify the API key
 */
final class BackendCheck {

    static final int TIMEOUT_MS = 5000;
    private static final Pattern HTTP_STATUS = Pattern.compile("HTTP (\\d{3})");

    private BackendCheck() { }

    /** Result of the "Test connection" button. */
    static final class Result {
        final boolean ok;
        final String message;

        Result(boolean ok, String message) {
            this.ok = ok;
            this.message = message;
        }
    }

    /**
     * Clean up the backend URL: trims spaces, adds "http://" if missing, removes trailing slashes.
     * Refuses localhost/127.x (on a phone that means the PHONE itself), a missing port, and extra paths.
     * @return e.g. "http://172.20.10.8:8000"
     * @throws IllegalArgumentException with a message that says how to fix it
     */
    static String normalizeUrl(String raw) {
        String s = raw == null ? "" : raw.trim();
        if (s.isEmpty()) {
            throw new IllegalArgumentException("Enter the backend URL: your laptop's IPv4 address and port, "
                    + "for example http://192.168.1.20:8000");
        }
        if (!s.contains("://")) s = "http://" + s;
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        URI u;
        try {
            u = new URI(s);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("That is not a valid address: " + raw.trim());
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new IllegalArgumentException("The address must start with http:// (for example http://192.168.1.20:8000)");
        }
        String host = u.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("That is not a valid address: " + raw.trim());
        }
        String h = host.toLowerCase(Locale.ROOT);
        if (h.equals("localhost") || h.startsWith("127.") || h.equals("0.0.0.0") || h.equals("[::1]") || h.equals("::1")) {
            throw new IllegalArgumentException("\"" + host + "\" means this phone itself, not your laptop. Use the laptop's "
                    + "IPv4 address (run ipconfig on the laptop), for example http://192.168.1.20:8000");
        }
        if (u.getPort() == -1) {
            throw new IllegalArgumentException("Add the port at the end, for example " + scheme + "://" + host + ":8000");
        }
        String path = u.getRawPath() == null ? "" : u.getRawPath();
        if (!path.isEmpty() || u.getRawQuery() != null) {
            throw new IllegalArgumentException("Enter only the address and port, without " + path + " - for example "
                    + scheme + "://" + host + ":" + u.getPort());
        }
        return scheme + "://" + host + ":" + u.getPort();
    }

    /** The real reason a call to {@code url} failed, in plain words, always including the URL. */
    static String describe(Exception e, String url) {
        String msg = e.getMessage() == null ? "" : e.getMessage();
        String upper = msg.toUpperCase(Locale.ROOT);
        if (e instanceof UnknownServiceException || upper.contains("CLEARTEXT")) {
            return "Android blocked plain http:// to " + url + " (cleartext not permitted). This build allows it in "
                    + "its manifest - reinstall the latest version of the app.";
        }
        if (e instanceof SocketTimeoutException) {
            return "No answer from " + url + " within " + TIMEOUT_MS / 1000 + " s. Usually: the phone and laptop are on "
                    + "different networks, the laptop's IP address changed, or Windows Firewall blocks port 8000.";
        }
        if (e instanceof NoRouteToHostException || upper.contains("EHOSTUNREACH") || upper.contains("ENETUNREACH")) {
            return "No route to " + url + ": the phone cannot reach that address. Put both on the same Wi-Fi or "
                    + "hotspot and use the laptop's CURRENT IPv4 address.";
        }
        if (e instanceof ConnectException) {
            if (upper.contains("REFUSED")) {
                return "Connection refused by " + url + ": the laptop answered, but no backend is listening there. "
                        + "Start it with: uvicorn app.main:app --host 0.0.0.0 --port 8000";
            }
            return "Could not connect to " + url + " (" + msg + ").";
        }
        if (e instanceof UnknownHostException) {
            return "Unknown host in " + url + ". Type the laptop's IP address in numbers, for example http://192.168.1.20:8000";
        }
        Matcher m = HTTP_STATUS.matcher(msg);
        if (m.find()) return describeStatus(Integer.parseInt(m.group(1)), url);
        return "Request to " + url + " failed: " + e.getClass().getSimpleName() + (msg.isEmpty() ? "" : ": " + msg);
    }

    static String describeStatus(int status, String url) {
        if (status == 401) {
            return "The backend at " + url + " rejected the API key (HTTP 401). Copy API_KEY exactly from the "
                    + "laptop's .env file.";
        }
        return "The backend at " + url + " answered with an error (HTTP " + status + ").";
    }

    /**
     * "Test connection": 1) GET /health (no key needed) proves the phone reaches the backend;
     * 2) GET /reports/0/download with the key: report 0 never exists, so 404 = key accepted, 401 = key wrong.
     * Neither call changes anything on the backend. Must run on a background thread.
     */
    static Result check(String rawUrl, String apiKey) {
        String url;
        try {
            url = normalizeUrl(rawUrl);
        } catch (IllegalArgumentException e) {
            return new Result(false, e.getMessage());
        }
        return checkNormalized(url, apiKey);
    }

    /** The network part of check(), for an already-cleaned URL (tests call it with a local fake server). */
    static Result checkNormalized(String url, String apiKey) {
        try {
            int health = get(url + "/health", null);
            if (health != 200) return new Result(false, describeStatus(health, url + "/health"));
            if (apiKey == null || apiKey.trim().isEmpty()) {
                return new Result(false, "Backend reachable at " + url + ", but the API key is empty.");
            }
            int keyCheck = get(url + "/reports/0/download", apiKey.trim());
            if (keyCheck == 401) return new Result(false, describeStatus(401, url));
            if (keyCheck != 404) return new Result(false, describeStatus(keyCheck, url) + " while checking the API key.");
            return new Result(true, "OK: the phone reached the backend at " + url + " and the API key was accepted.");
        } catch (IOException e) {
            return new Result(false, describe(e, url));
        }
    }

    private static int get(String url, String apiKey) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        try {
            c.setConnectTimeout(TIMEOUT_MS);
            c.setReadTimeout(TIMEOUT_MS);
            if (apiKey != null) c.setRequestProperty("X-API-Key", apiKey);
            int status = c.getResponseCode();
            InputStream body = status >= 400 ? c.getErrorStream() : c.getInputStream();
            if (body != null) {
                // Drain the reply so the connection closes cleanly. (readAllBytes() needs Android 13+, so we loop.)
                try (InputStream b = body) {
                    byte[] buf = new byte[1024];
                    while (b.read(buf) != -1) { /* discard */ }
                }
            }
            return status;
        } finally {
            c.disconnect();
        }
    }
}
