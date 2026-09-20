#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <esp_system.h>

#include "web_admin.h"
#include "storage.h"
#include "scanner.h"
#include "detector.h"
#include "text_utils.h"

namespace {
WebServer server(80);
String csrfToken;
bool restartPending = false;
uint32_t restartAtMs = 0;

String makeToken() {
  char out[33];
  snprintf(
    out,
    sizeof(out),
    "%08lX%08lX%08lX%08lX",
    static_cast<unsigned long>(esp_random()),
    static_cast<unsigned long>(esp_random()),
    static_cast<unsigned long>(esp_random()),
    static_cast<unsigned long>(esp_random())
  );
  return String(out);
}

bool csrfValid() {
  const String supplied = server.arg("csrf");
  return supplied.length() == 32 && supplied == csrfToken;
}

bool requireAdmin(bool allowSetup = false) {
  const String user = getAdminUser();
  const String pass = getAdminPassword();

  if (!server.authenticate(user.c_str(), pass.c_str())) {
    server.requestAuthentication(DIGEST_AUTH, "ESP32 Defense Lab");
    return false;
  }

  if (server.method() != HTTP_GET && !csrfValid()) {
    server.send(403, "text/plain", "Invalid or missing CSRF token.");
    return false;
  }

  if (!allowSetup && initialSetupRequired()) {
    server.sendHeader("Location", "/");
    server.send(303);
    return false;
  }

  return true;
}

void requestRestart() {
  restartPending = true;
  restartAtMs = millis();
}

String setupPage() {
  String html;
  html.reserve(4500);

  html =
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Defense Lab Setup</title><style>"
    "*{box-sizing:border-box}body{margin:0;background:#061019;color:#eef8ff;font-family:system-ui,sans-serif}"
    ".wrap{max-width:720px;margin:auto;padding:30px 18px}.card{padding:24px;border:1px solid #1d4057;border-radius:20px;background:#0a1a28}"
    "h1{font-size:clamp(2rem,7vw,3.3rem);margin:8px 0 12px}.tag{color:#42e5ff;font-weight:900;font-size:.75rem;letter-spacing:.12em}"
    "p{color:#9db2c2;line-height:1.6}label{display:block;margin:14px 0 6px;font-weight:700;color:#bdd3e1}"
    "input{width:100%;padding:12px;border-radius:10px;border:1px solid #29485c;background:#07141f;color:#fff}"
    "button{width:100%;margin-top:18px;padding:13px;border:0;border-radius:11px;background:linear-gradient(135deg,#20d8ff,#3d7bff);font-weight:900;color:#031019}"
    "</style></head><body><main class='wrap'><section class='card'>"
    "<div class='tag'>MANDATORY FIRST-BOOT SECURITY</div>"
    "<h1>Secure the defense lab.</h1>"
    "<p>Replace the public setup credentials before the normal monitoring dashboard is unlocked.</p>"
    "<form method='post' action='/setup/security'>"
    "<input type='hidden' name='csrf' value='" +
    csrfToken +
    "'><label>Management Wi-Fi name</label><input name='ssid' maxlength='32' value='" +
    DefenseText::htmlEscape(getApSsid()) +
    "' required><label>New Wi-Fi password (8-63 characters)</label>"
    "<input type='password' name='ap_password' minlength='8' maxlength='63' required>"
    "<label>Admin username</label><input name='admin_user' maxlength='32' value='admin' required>"
    "<label>New admin password (8-64 characters)</label>"
    "<input type='password' name='admin_password' minlength='8' maxlength='64' required>"
    "<button type='submit'>Save Security Settings & Restart</button></form>"
    "<p>Use different Wi-Fi and admin passwords. After restart, reconnect and open 192.168.4.1.</p>"
    "</section></main></body></html>";

  return html;
}

String dashboardPage() {
  String html;
  html.reserve(18000);

  html =
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>ESP32 Wireless Defense Lab</title><style>"
    ":root{--bg:#061019;--panel:#0a1926;--line:#1d3c50;--text:#edf8ff;--muted:#91aabc;--cyan:#28defe;--blue:#4b76ff}"
    "*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,#0d3350 0,transparent 30rem),var(--bg);color:var(--text);font-family:system-ui,sans-serif}"
    ".wrap{max-width:1150px;margin:auto;padding:20px}.top{display:flex;justify-content:space-between;gap:12px;align-items:center}.brand{display:flex;gap:10px;align-items:center}"
    ".logo{width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,var(--cyan),var(--blue));display:grid;place-items:center;color:#031019;font-weight:1000}"
    ".muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:14px}.card{background:#0a1926e8;border:1px solid var(--line);border-radius:16px;padding:16px}"
    ".metric b{display:block;font-size:1.55rem;margin-top:5px}.cols{display:grid;grid-template-columns:1.15fr .85fr;gap:13px;margin-top:13px}"
    ".actions{display:flex;gap:8px;flex-wrap:wrap}button{border:0;border-radius:10px;padding:10px 12px;font-weight:800;cursor:pointer;background:linear-gradient(135deg,var(--cyan),var(--blue));color:#031019}"
    ".secondary{background:#112c3d;color:#dff7ff;border:1px solid #27516a}.danger{background:#421d2a;color:#ffdce4;border:1px solid #6f2a40}"
    "input,select{background:#07141f;color:#fff;border:1px solid #29485c;border-radius:9px;padding:9px;margin:3px}"
    "table{width:100%;border-collapse:collapse;font-size:.84rem}th,td{text-align:left;padding:8px;border-bottom:1px solid #163146}th{color:#9dc0d2}.scroll{overflow:auto;max-height:380px}"
    ".pill{padding:3px 7px;border-radius:999px;font-size:.7rem;font-weight:900}.High{background:#4d1724;color:#ff91a5}.Warning{background:#4e3910;color:#ffd56e}"
    ".notice{margin-top:13px;padding:11px;border-left:3px solid var(--cyan);background:#071a28;color:#a4c6d6;border-radius:8px;font-size:.84rem}"
    "@media(max-width:800px){.grid{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}}"
    "</style></head><body><main class='wrap'>"
    "<div class='top'><div class='brand'><div class='logo'>DL</div><div><b>ESP32 Wireless Defense Lab</b><div class='muted'>Passive 2.4 GHz monitor - v1.0.0</div></div></div>"
    "<div class='actions'><button class='secondary' onclick='scanNow()'>Scan Nearby Wi-Fi</button><button class='danger' onclick='clearAlerts()'>Clear Alerts</button></div></div>"
    "<div class='notice'>Defensive-only: observes management traffic on the selected channel. No deauth transmission, Evil Twin, password capture, handshake/PMKID capture, Wi-Fi/BLE flooding or HID payloads.</div>"
    "<section class='grid'>"
    "<div class='card metric'><small>Monitor Channel</small><b id='channel'>-</b></div>"
    "<div class='card metric'><small>Nearby Networks</small><b id='networks'>-</b></div>"
    "<div class='card metric'><small>Suspicious Frames</small><b id='suspicious'>-</b></div>"
    "<div class='card metric'><small>Alerts</small><b id='alerts'>-</b></div></section>"
    "<section class='cols'><div class='card'><h3>Live Alerts</h3><div class='scroll'><table><thead><tr><th>Severity</th><th>Type</th><th>Source</th><th>CH</th><th>RSSI</th><th>Window</th></tr></thead><tbody id='alertsBody'></tbody></table></div></div>"
    "<div class='card'><h3>Monitor Channel</h3><p class='muted'>Single-radio ESP32 monitors one channel live. Network scan temporarily sweeps channels.</p>"
    "<form method='post' action='/settings/channel'><select name='channel'>";

  const uint8_t selected = getMonitorChannel();

  for (int ch = 1; ch <= 13; ++ch) {
    html += "<option value='" + String(ch) + "'";
    if (ch == selected) html += " selected";
    html += ">" + String(ch) + "</option>";
  }

  html +=
    "</select><button type='submit'>Apply Channel</button></form>"
    "<h3 style='margin-top:20px'>Management Security</h3>"
    "<form method='post' action='/settings/ap'><input name='ssid' maxlength='32' value='" +
    DefenseText::htmlEscape(getApSsid()) +
    "' required><input type='password' name='password' minlength='8' maxlength='63' placeholder='New Wi-Fi password' required><button type='submit'>Change Wi-Fi</button></form>"
    "<form method='post' action='/settings/admin'><input name='username' maxlength='32' value='" +
    DefenseText::htmlEscape(getAdminUser()) +
    "' required><input type='password' name='password' minlength='8' maxlength='64' placeholder='New admin password' required><button type='submit'>Change Admin</button></form>"
    "<form method='post' action='/system/factory-reset' onsubmit=\"return confirm('Erase Defense Lab settings?')\"><button class='danger'>Factory Reset</button></form>"
    "</div></section>"
    "<section class='cols'><div class='card'><h3>Nearby Wi-Fi Inventory</h3><div class='scroll'><table><thead><tr><th>SSID</th><th>BSSID</th><th>Security</th><th>CH</th><th>RSSI</th></tr></thead><tbody id='networksBody'></tbody></table></div></div>"
    "<div class='card'><h3>Channel Activity</h3><div class='scroll'><table><thead><tr><th>Channel</th><th>Mgmt</th><th>Suspicious</th></tr></thead><tbody id='channelsBody'></tbody></table></div></div></section>"
    "<section class='card' style='margin-top:13px'><h3>Device Health</h3><div id='health' class='muted'>Loading...</div></section>"
    "<script>const csrfToken='" +
    csrfToken +
    "';"
    "const esc=s=>String(s??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));"
    "document.addEventListener('submit',e=>{const f=e.target;if(f instanceof HTMLFormElement&&f.method.toLowerCase()==='post'&&!f.querySelector('[name=csrf]')){const i=document.createElement('input');i.type='hidden';i.name='csrf';i.value=csrfToken;f.prepend(i);}},true);"
    "async function j(u){const r=await fetch(u,{cache:'no-store'});if(!r.ok)throw new Error(await r.text());return r.json();}"
    "async function status(){const s=await j('/api/status');channel.textContent=s.channel;networks.textContent=s.networks;suspicious.textContent=s.suspiciousFrames.toLocaleString();alerts.textContent=s.alerts;health.innerHTML='Management frames: <b>'+s.managementFrames.toLocaleString()+'</b> - Free heap: <b>'+s.freeHeap.toLocaleString()+' B</b> - Uptime: <b>'+Math.floor(s.uptimeSeconds/60)+' min</b> - Last scan: <b>'+s.scanAgeSeconds+'s ago</b> - Dropped alerts: <b>'+s.droppedAlerts+'</b>';}"
    "async function nets(){const d=await j('/api/networks');let h='';d.forEach(n=>h+='<tr><td>'+esc(n.ssid)+'</td><td><code>'+esc(n.bssid)+'</code></td><td>'+esc(n.security)+'</td><td>'+n.channel+'</td><td>'+n.rssi+'</td></tr>');networksBody.innerHTML=h||'<tr><td colspan=5>No scan results yet.</td></tr>';}"
    "async function al(){const d=await j('/api/alerts');let h='';d.forEach(a=>h+='<tr><td><span class=\"pill '+esc(a.severity)+'\">'+esc(a.severity)+'</span></td><td>'+esc(a.type)+'</td><td><code>'+esc(a.source)+'</code></td><td>'+a.channel+'</td><td>'+a.rssi+'</td><td>'+a.frames+'</td></tr>');alertsBody.innerHTML=h||'<tr><td colspan=6>No burst alerts detected.</td></tr>';}"
    "async function chans(){const d=await j('/api/channels');let h='';d.forEach(c=>h+='<tr><td>'+c.channel+'</td><td>'+c.management.toLocaleString()+'</td><td>'+c.suspicious.toLocaleString()+'</td></tr>');channelsBody.innerHTML=h;}"
    "async function post(u){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:csrfToken})});if(!r.ok)throw new Error(await r.text());}"
    "async function scanNow(){await post('/scan');await Promise.all([status(),nets(),chans()]);}"
    "async function clearAlerts(){await post('/alerts/clear');await Promise.all([status(),al()]);}"
    "async function all(){try{await Promise.all([status(),nets(),al(),chans()]);}catch(e){health.textContent='Refresh failed: '+e.message;}}"
    "all();setInterval(status,3000);setInterval(al,3000);setInterval(chans,5000);setInterval(nets,15000);"
    "</script></main></body></html>";

  return html;
}

void restartManagementAp(uint8_t channel) {
  detectorPause();
  WiFi.softAPdisconnect(true);
  delay(150);

  WiFi.softAP(
    getApSsid().c_str(),
    getApPassword().c_str(),
    channel,
    false,
    4
  );

  detectorSetChannel(channel);
  detectorResume();
}
}

void webAdminBegin() {
  csrfToken = makeToken();

  server.on("/", HTTP_GET, []() {
    if (!requireAdmin(true)) return;

    server.send(
      200,
      "text/html; charset=utf-8",
      initialSetupRequired() ? setupPage() : dashboardPage()
    );
  });

  server.on("/setup/security", HTTP_POST, []() {
    if (!requireAdmin(true)) return;

    if (!initialSetupRequired()) {
      server.sendHeader("Location", "/");
      server.send(303);
      return;
    }

    const bool ok = setInitialCredentials(
      server.arg("ssid"),
      server.arg("ap_password"),
      server.arg("admin_user"),
      server.arg("admin_password")
    );

    if (!ok) {
      server.send(
        400,
        "text/plain",
        "Use valid Wi-Fi/admin credentials, keep both passwords different, and replace the factory passwords."
      );
      return;
    }

    server.send(
      200,
      "text/html",
      "<h2>Security setup complete.</h2><p>The ESP32 is restarting. Reconnect using the new management Wi-Fi credentials.</p>"
    );

    requestRestart();
  });

  server.on("/api/status", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(200, "application/json", detectorStatusJson());
  });

  server.on("/api/networks", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(200, "application/json", scannerNetworksJson());
  });

  server.on("/api/alerts", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(200, "application/json", detectorAlertsJson());
  });

  server.on("/api/channels", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(200, "application/json", detectorChannelsJson());
  });

  server.on("/scan", HTTP_POST, []() {
    if (!requireAdmin()) return;
    const bool ok = scannerScanNow();
    server.send(ok ? 200 : 500, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
  });

  server.on("/alerts/clear", HTTP_POST, []() {
    if (!requireAdmin()) return;
    detectorClearAlerts();
    server.send(200, "application/json", "{\"ok\":true}");
  });

  server.on("/settings/channel", HTTP_POST, []() {
    if (!requireAdmin()) return;

    const int channel = server.arg("channel").toInt();

    if (
      channel < 1 ||
      channel > 13 ||
      !setMonitorChannel(static_cast<uint8_t>(channel))
    ) {
      server.send(400, "text/plain", "Channel must be 1-13.");
      return;
    }

    restartManagementAp(static_cast<uint8_t>(channel));
    server.sendHeader("Location", "/");
    server.send(303);
  });

  server.on("/settings/ap", HTTP_POST, []() {
    if (!requireAdmin()) return;

    if (!setApCredentials(server.arg("ssid"), server.arg("password"))) {
      server.send(400, "text/plain", "Invalid management Wi-Fi settings.");
      return;
    }

    server.send(200, "text/html", "<h2>Wi-Fi updated.</h2><p>The ESP32 is restarting.</p>");
    requestRestart();
  });

  server.on("/settings/admin", HTTP_POST, []() {
    if (!requireAdmin()) return;

    if (!setAdminCredentials(server.arg("username"), server.arg("password"))) {
      server.send(400, "text/plain", "Invalid admin settings.");
      return;
    }

    server.send(200, "text/html", "<h2>Admin login updated.</h2><p>The ESP32 is restarting.</p>");
    requestRestart();
  });

  server.on("/system/factory-reset", HTTP_POST, []() {
    if (!requireAdmin()) return;

    factoryResetStorage();
    server.send(200, "text/html", "<h2>Factory reset complete.</h2><p>The ESP32 is restarting.</p>");
    requestRestart();
  });

  server.on("/health", HTTP_GET, []() {
    server.send(
      200,
      "application/json",
      "{\"status\":\"ok\",\"project\":\"ESP32 Wireless Defense Lab\"}"
    );
  });

  server.begin();
}

void webAdminLoop() {
  server.handleClient();

  if (restartPending && millis() - restartAtMs >= 1000) {
    ESP.restart();
  }
}
