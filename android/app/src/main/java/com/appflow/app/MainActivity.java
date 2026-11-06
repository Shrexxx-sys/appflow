package com.appflow.app;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The only screen: pick an app, Start / Stop, see status and errors.
 * The layout is built in code (no XML) to keep the file count low.
 */
public class MainActivity extends Activity {

    private static final int REQUEST_VPN_CONSENT = 1;
    private static final String PREFS = "appflow";

    private final List<String> labels = new ArrayList<>();
    private final List<String> packages = new ArrayList<>();
    private final List<String> names = new ArrayList<>();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private Spinner appPicker;
    private EditText backendUrl;
    private EditText apiKey;
    private TextView statusText;
    private TextView errorText;

    private final Runnable refresher = new Runnable() {
        @Override
        public void run() {
            statusText.setText(SentinelVpnService.statusLine());
            errorText.setText(SentinelVpnService.lastError());
            ui.postDelayed(this, 1000);   // simple: re-read the service status every second
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("AppFlow Sentinel");
        title.setTextSize(22);
        root.addView(title);

        TextView explain = new TextView(this);
        explain.setText("Watches WHO the chosen app talks to (IPs, domains, ports, bytes, timing). "
                + "It cannot read encrypted contents and never stores payloads. Android will ask for your "
                + "permission to start a local VPN. Only one VPN app can run at a time.");
        root.addView(explain);

        root.addView(label("App to monitor"));
        appPicker = new Spinner(this);
        loadLaunchableApps();
        appPicker.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, labels));
        root.addView(appPicker);

        // Saved on this phone (app-private storage) so you only type them once. Demo-level protection.
        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        root.addView(label("Backend URL (laptop's Wi-Fi IP, same network)"));
        backendUrl = new EditText(this);
        backendUrl.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        backendUrl.setText(prefs.getString("backend_url", "http://192.168.1.5:8000"));
        root.addView(backendUrl);
        root.addView(label("API key (API_KEY from the backend .env)"));
        apiKey = new EditText(this);
        apiKey.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        apiKey.setText(prefs.getString("api_key", ""));
        root.addView(apiKey);

        Button start = new Button(this);
        start.setText("Start monitoring");
        start.setOnClickListener(v -> onStartClicked());
        root.addView(start);

        Button stop = new Button(this);
        stop.setText("Stop");
        stop.setOnClickListener(v -> onStopClicked());
        root.addView(stop);

        statusText = new TextView(this);
        statusText.setPadding(0, dp(12), 0, 0);
        root.addView(statusText);

        errorText = new TextView(this);
        errorText.setTextColor(0xFFFF6B6B);
        root.addView(errorText);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.post(refresher);
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(refresher);
    }

    private void onStartClicked() {
        if (packages.isEmpty() || appPicker.getSelectedItemPosition() < 0) {
            errorText.setText("No app selected.");
            return;
        }
        String url = backendUrl.getText().toString().trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            errorText.setText("Backend URL must start with http:// (for example http://192.168.1.5:8000).");
            return;
        }
        if (apiKey.getText().toString().trim().isEmpty()) {
            errorText.setText("Enter the API key from the backend .env file.");
            return;
        }
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putString("backend_url", url)
                .putString("api_key", apiKey.getText().toString().trim())
                .apply();
        // Explicit user consent: Android shows its own VPN permission dialog the first time.
        Intent consent = VpnService.prepare(this);
        if (consent != null) {
            startActivityForResult(consent, REQUEST_VPN_CONSENT);
        } else {
            onActivityResult(REQUEST_VPN_CONSENT, RESULT_OK, null);   // permission already given
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_VPN_CONSENT) return;
        if (resultCode != RESULT_OK) {
            errorText.setText("VPN permission was not granted. Monitoring needs your explicit consent.");
            return;
        }
        int i = appPicker.getSelectedItemPosition();
        Intent start = new Intent(this, SentinelVpnService.class)
                .setAction(SentinelVpnService.ACTION_START)
                .putExtra(SentinelVpnService.EXTRA_PACKAGE, packages.get(i))
                .putExtra(SentinelVpnService.EXTRA_APP_NAME, names.get(i))
                .putExtra(SentinelVpnService.EXTRA_BACKEND_URL, backendUrl.getText().toString().trim())
                .putExtra(SentinelVpnService.EXTRA_API_KEY, apiKey.getText().toString().trim());
        startService(start);
    }

    private void onStopClicked() {
        startService(new Intent(this, SentinelVpnService.class).setAction(SentinelVpnService.ACTION_STOP));
    }

    /** All apps with a launcher icon, except this app itself, sorted by name. */
    private void loadLaunchableApps() {
        PackageManager pm = getPackageManager();
        Intent launcher = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        List<String[]> found = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (ResolveInfo r : pm.queryIntentActivities(launcher, 0)) {
            String pkg = r.activityInfo.packageName;
            if (pkg.equals(getPackageName()) || !seen.add(pkg)) continue;
            found.add(new String[] { String.valueOf(r.loadLabel(pm)), pkg });
        }
        Collections.sort(found, (a, b) -> a[0].compareToIgnoreCase(b[0]));
        for (String[] f : found) {
            labels.add(f[0] + "  (" + f[1] + ")");
            names.add(f[0]);
            packages.add(f[1]);
        }
    }

    private TextView label(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setPadding(0, dp(12), 0, 0);
        return t;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
