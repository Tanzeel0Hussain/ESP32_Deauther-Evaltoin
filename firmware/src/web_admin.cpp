#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>

extern "C" {
#include "esp_system.h"
}

#include "web_admin.h"
#include "config.h"
#include "storage.h"
#include "wifi_scanner.h"
#include "frame_monitor.h"
#include "text_utils.h"

namespace {
WebServer server(80);

String csrfToken;
bool restartPending = false;
unsigned long restartRequestedAt = 0;

String makeCsrfToken() {
  char token[33];
  snprintf(
    token,
    sizeof(token),
    "%08lX%08lX%08lX%08lX",
    static_cast<unsigned long>(esp_random()),
    static_cast<unsigned long>(esp_random()),
    static_cast<unsigned long>(esp_random()),
    static_cast<unsigned long>(esp_random())
  );
  return String(token);
}

bool csrfValid() {
  const String supplied = server.arg("csrf");
  return
    csrfToken.length() == 32 &&
    supplied.length() == csrfToken.length() &&
    supplied == csrfToken;
}

bool requireCsrf() {
  if (csrfValid()) return true;
  server.send(403, "text/plain", "Invalid or missing CSRF token.");
  return false;
}

bool requireAdmin(bool allowSetup = false) {
  const String user = storageGetAdminUser();
  const String pass = storageGetAdminPassword();

  if (!server.authenticate(user.c_str(), pass.c_str())) {
    server.requestAuthentication(DIGEST_AUTH, "ESP32 Defense Lab");
    return false;
  }

  if (server.method() != HTTP_GET && !requireCsrf()) {
    return false;
  }

  if (!allowSetup && storageInitialSetupRequired()) {
    server.sendHeader("Location", "/");
    server.send(303);
    return false;
  }

  return true;
}

void scheduleRestart() {
  restartPending = true;
  restartRequestedAt = millis();
}

String setupPage() {
  String html;
  html.reserve(5200);

  html += R"HTML(<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32 Defense Lab Setup</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#06101b;color:#eef7ff;font-family:system-ui,sans-serif}
.wrap{max-width:720px;margin:auto;padding:28px 18px}.card{background:#0d1d2d;border:1px solid #20354a;border-radius:18px;padding:22px;box-shadow:0 28px 80px rgba(0,0,0,.35)}
.badge{display:inline-block;color:#49d3ff;font-size:.76rem;font-weight:800;letter-spacing:.08em;text-transform:uppercase}
h1{margin:9px 0 10px;font-size:clamp(1.8rem,6vw,3rem)}p{color:#9cb1c3;line-height:1.6}
label{display:block;margin-top:14px;color:#b9cedd;font-size:.82rem;font-weight:700}
input{width:100%;margin-top:6px;background:#091623;border:1px solid #294157;color:#fff;border-radius:11px;padding:12px}
button{width:100%;margin-top:18px;border:0;border-radius:11px;padding:13px;background:linear-gradient(135deg,#0b78ff,#20d9ff);color:#041019;font-weight:900}
.note{margin-top:15px;padding:12px;border-radius:11px;background:#0a2034;color:#8faabd;font-size:.8rem}
</style></head><body><main class="wrap"><section class="card"><div class="badge">)HTML";

  html += storageRecoveryRequired()
    ? "Credential recovery"
    : "Mandatory first-boot security";

  html += R"HTML(</div><h1>)HTML";

  html += storageRecoveryRequired()
    ? "Recover the Defense Lab securely."
    : "Secure the Defense Lab before monitoring.";

  html += R"HTML(</h1><p>)HTML";

  html += storageRecoveryRequired()
    ? "Stored credentials could not be decrypted. Random recovery credentials were printed to the physical serial console. Set fresh credentials now."
    : "Factory credentials are setup-only. Choose a new management Wi-Fi password and a different admin password before the dashboard unlocks.";

  html += R"HTML(</p><form method="post" action="/setup/security">
<input type="hidden" name="csrf" value=")HTML";
  html += csrfToken;
  html += R"HTML(">
<label>Management Wi-Fi name</label><input name="ssid" maxlength="32" value=")HTML";
  html += DefenseLabText::htmlEscape(storageGetApSsid());
  html += R"HTML(" required>
<label>New Wi-Fi password (8–63 characters)</label><input name="ap_password" type="password" minlength="8" maxlength="63" required>
<label>Admin username</label><input name="admin_user" maxlength="32" value="admin" required>
<label>New admin password (8–64 characters)</label><input name="admin_password" type="password" minlength="8" maxlength="64" required>
<button type="submit">Save Security Settings & Restart</button></form>
<div class="note">The Wi-Fi and admin passwords must be different and cannot remain the public setup defaults.</div>
</section></main></body></html>)HTML";

  return html;
}

String dashboardPage() {
  String html;
  html.reserve(24000);

  html += R"HTML(<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32 Wireless Defense Lab</title>
<style>
:root{--bg:#06101a;--panel:#0c1a28;--panel2:#102334;--line:#203a50;--text:#eef8ff;--muted:#91a9ba;--cyan:#3ddcff;--blue:#397dff;--green:#47e6a8;--amber:#ffcb67;--red:#ff6b7d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#0c2940 0,#06101a 34%,#030910 100%);color:var(--text);font-family:Inter,system-ui,sans-serif}
main{max-width:1180px;margin:auto;padding:20px}.top{display:flex;gap:16px;justify-content:space-between;align-items:center;flex-wrap:wrap;margin:10px 0 22px}
.badge{color:var(--cyan);font-weight:900;letter-spacing:.08em;text-transform:uppercase;font-size:.75rem}.muted,small{color:var(--muted)}
h1{font-size:clamp(2rem,6vw,4rem);margin:5px 0 4px;line-height:.95}h2,h3{margin-top:0}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card{background:linear-gradient(180deg,rgba(16,35,52,.96),rgba(8,20,31,.96));border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:0 16px 48px rgba(0,0,0,.24);margin-bottom:14px}
.stat strong{display:block;font-size:2rem;margin-top:7px}.ok{color:var(--green)}.warn{color:var(--amber)}.danger{color:var(--red)}
.two{display:grid;grid-template-columns:1.15fr .85fr;gap:14px}.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.btn,button{border:0;border-radius:10px;padding:10px 13px;background:linear-gradient(135deg,var(--blue),var(--cyan));color:#03101a;font-weight:900;cursor:pointer}.secondary{background:#152c40;color:var(--text);border:1px solid var(--line)}.dangerBtn{background:#4c1e29;color:#ffd6dd;border:1px solid #743343}
input,select{background:#071522;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:10px}table{width:100%;border-collapse:collapse;font-size:.86rem}th,td{text-align:left;padding:9px;border-bottom:1px solid rgba(32,58,80,.65)}th{color:#8fcfe5}
.bar{height:8px;border-radius:999px;background:#142638;overflow:hidden}.bar span{display:block;height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan))}
.alert{padding:12px;border-radius:12px;background:#171e2a;border:1px solid #493540;margin:8px 0}.alert b{color:#ff9bab}.safe{padding:12px;border:1px solid #204d40;background:#0b2b24;border-radius:12px;color:#a9f6d6}
form.inline{display:flex;gap:8px;flex-wrap:wrap;align-items:end}.field{display:flex;flex-direction:column;gap:5px}
@media(max-width:850px){.grid{grid-template-columns:repeat(2,1fr)}.two{grid-template-columns:1fr}}
@media(max-width:520px){.grid{grid-template-columns:1fr 1fr}main{padding:12px}.card{padding:14px}table{font-size:.76rem}}
</style></head><body><main>
<section class="top"><div><div class="badge">Passive wireless monitoring · v)HTML";
  html += DefenseLabConfig::VERSION;
  html += R"HTML(</div><h1>ESP32 Wireless<br>Defense Lab</h1><div class="muted">Observe. Detect. Understand. No packet injection.</div></div>
<div class="safe">🛡 Defensive mode only<br><small>No deauthentication transmission, credential capture, or rogue AP impersonation.</small></div></section>

<section class="grid">
<div class="card stat"><small>Deauth frames observed</small><strong id="deauth">0</strong></div>
<div class="card stat"><small>Disassoc frames observed</small><strong id="disassoc">0</strong></div>
<div class="card stat"><small>Detection alerts</small><strong id="alerts">0</strong></div>
<div class="card stat"><small>Monitor channel</small><strong>)HTML";
  html += String(storageGetMonitorChannel());
  html += R"HTML(</strong></div>
</section>

<section class="two">
<div>
<section class="card"><div class="row" style="justify-content:space-between"><div><h3>Nearby Wi-Fi inventory</h3><small>Passive discovery only. Scanning briefly pauses fixed-channel monitoring.</small></div><button onclick="scanNow()">Scan Networks</button></div>
<div style="overflow:auto;margin-top:12px"><table><thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>Security</th></tr></thead><tbody id="networks"><tr><td colspan="5" class="muted">Run a scan to populate nearby networks.</td></tr></tbody></table></div></section>

<section class="card"><h3>Channel occupancy</h3><div id="channels" class="muted">Run a scan to calculate channel occupancy.</div></section>
</div>

<div>
<section class="card"><div class="row" style="justify-content:space-between"><div><h3>Detection alerts</h3><small>Threshold: )HTML";
  html += String(storageGetAlertThreshold());
  html += R"HTML( frames / 10 seconds / source</small></div>
<form method="post" action="/alerts/clear"><button class="secondary">Clear</button></form></div><div id="alert-list"><div class="muted">No alerts loaded.</div></div></section>

<section class="card"><h3>Monitor settings</h3>
<form class="inline" method="post" action="/settings/monitor">
<div class="field"><small>Channel</small><input name="channel" type="number" min="1" max="13" value=")HTML";
  html += String(storageGetMonitorChannel());
  html += R"HTML(" required></div>
<div class="field"><small>Alert threshold</small><input name="threshold" type="number" min="5" max="200" value=")HTML";
  html += String(storageGetAlertThreshold());
  html += R"HTML(" required></div>
<button>Save & Restart</button></form></section>
</div></section>

<section class="two">
<section class="card"><h3>Management Wi-Fi</h3>
<form class="inline" method="post" action="/settings/ap">
<div class="field"><small>SSID</small><input name="ssid" maxlength="32" value=")HTML";
  html += DefenseLabText::htmlEscape(storageGetApSsid());
  html += R"HTML(" required></div>
<div class="field"><small>New password</small><input name="password" type="password" minlength="8" maxlength="63" required></div>
<button>Save & Restart</button></form></section>

<section class="card"><h3>Administrator</h3>
<form class="inline" method="post" action="/settings/admin">
<div class="field"><small>Username</small><input name="username" maxlength="32" value=")HTML";
  html += DefenseLabText::htmlEscape(storageGetAdminUser());
  html += R"HTML(" required></div>
<div class="field"><small>New password</small><input name="password" type="password" minlength="8" maxlength="64" required></div>
<button>Save & Restart</button></form></section>
</section>

<section class="card"><h3>System</h3><div class="row">
<form method="post" action="/system/restart"><button class="secondary">Restart ESP32</button></form>
<form method="post" action="/system/factory-reset" onsubmit="return confirm('Erase Defense Lab settings and restart?')"><button class="dangerBtn">Factory Reset</button></form>
</div><p><small>Management IP: <b>192.168.4.1</b> · Free heap: <span id="heap">—</span> · Uptime: <span id="uptime">—</span></small></p></section>

<script>
const csrfToken=')HTML";
  html += csrfToken;
  html += R"HTML(';
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

document.addEventListener('submit',event=>{
  const form=event.target;
  if(form instanceof HTMLFormElement && form.method.toLowerCase()==='post' && !form.querySelector('input[name="csrf"]')){
    const input=document.createElement('input');
    input.type='hidden';input.name='csrf';input.value=csrfToken;form.prepend(input);
  }
},true);

async function json(url,options){const r=await fetch(url,options);if(!r.ok)throw new Error(await r.text());return r.json()}

async function loadStatus(){
  try{
    const s=await json('/api/status');
    deauth.textContent=s.deauth;disassoc.textContent=s.disassoc;alerts.textContent=s.alerts;
    heap.textContent=Math.round(s.freeHeap/1024)+' KB';
    uptime.textContent=Math.floor(s.uptime/60)+' min';
  }catch(e){}
}

async function loadNetworks(){
  const rows=await json('/api/networks');
  networks.innerHTML=rows.length?rows.map(n=>`<tr><td>${esc(n.ssid||'(hidden)')}</td><td>${esc(n.bssid)}</td><td>${n.channel}</td><td>${n.rssi} dBm</td><td>${esc(n.security)}</td></tr>`).join(''):'<tr><td colspan="5">No networks found.</td></tr>';
}

async function loadChannels(){
  const rows=await json('/api/channels');
  const max=Math.max(1,...rows.map(x=>x.networks));
  channels.innerHTML=rows.map(x=>`<div style="display:grid;grid-template-columns:42px 1fr 84px;gap:8px;align-items:center;margin:8px 0"><b>CH ${x.channel}</b><div class="bar"><span style="width:${Math.round(x.networks/max*100)}%"></span></div><small>${x.networks} AP${x.networks===1?'':'s'}</small></div>`).join('');
}

async function loadAlerts(){
  const rows=await json('/api/alerts');
  alert-list.innerHTML=rows.length?rows.map(a=>`<div class="alert"><b>${esc(a.type)}</b> · CH ${a.channel} · ${a.rssi} dBm<br><small>Source ${esc(a.source)} · BSSID ${esc(a.bssid)} · ${a.windowCount} frames in window · uptime ${a.uptime}s</small></div>`).join(''):'<div class="muted">No threshold alerts recorded.</div>';
}

async function scanNow(){
  try{
    const r=await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:csrfToken})});
    if(!r.ok)throw new Error(await r.text());
    await Promise.all([loadNetworks(),loadChannels()]);
  }catch(e){alert(e.message)}
}

loadStatus();loadNetworks();loadChannels();loadAlerts();
setInterval(loadStatus,3000);setInterval(loadAlerts,5000);
</script></main></body></html>)HTML";

  return html;
}

void sendJson(const String& body) {
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "application/json", body);
}
}

void webAdminBegin() {
  csrfToken = makeCsrfToken();

  server.on("/", HTTP_GET, []() {
    if (!requireAdmin(true)) return;

    server.sendHeader("Cache-Control", "no-store");

    if (storageInitialSetupRequired()) {
      server.send(200, "text/html; charset=utf-8", setupPage());
      return;
    }

    server.send(200, "text/html; charset=utf-8", dashboardPage());
  });

  server.on("/setup/security", HTTP_POST, []() {
    if (!requireAdmin(true)) return;

    if (!storageInitialSetupRequired()) {
      server.sendHeader("Location", "/");
      server.send(303);
      return;
    }

    const bool ok = storageSetInitialCredentials(
      server.arg("ssid"),
      server.arg("ap_password"),
      server.arg("admin_user"),
      server.arg("admin_password")
    );

    if (!ok) {
      server.send(400, "text/plain", "Invalid credentials. Use different non-default Wi-Fi/admin passwords and valid lengths.");
      return;
    }

    server.send(
      200,
      "text/html",
      "<h2>Security setup complete.</h2><p>The ESP32 is restarting. Reconnect using your new management Wi-Fi credentials.</p>"
    );
    scheduleRestart();
  });

  server.on("/api/status", HTTP_GET, []() {
    if (!requireAdmin()) return;

    String json = frameMonitorStatusJson();
    json.remove(json.length() - 1);
    json +=
      ",\"channel\":" + String(storageGetMonitorChannel()) +
      ",\"networks\":" + String(wifiScannerNetworkCount()) +
      ",\"freeHeap\":" + String(ESP.getFreeHeap()) +
      ",\"uptime\":" + String(millis() / 1000UL) +
      "}";

    sendJson(json);
  });

  server.on("/api/networks", HTTP_GET, []() {
    if (!requireAdmin()) return;
    sendJson(wifiScannerNetworksJson());
  });

  server.on("/api/channels", HTTP_GET, []() {
    if (!requireAdmin()) return;
    sendJson(wifiScannerChannelsJson());
  });

  server.on("/api/alerts", HTTP_GET, []() {
    if (!requireAdmin()) return;
    sendJson(frameMonitorAlertsJson());
  });

  server.on("/scan", HTTP_POST, []() {
    if (!requireAdmin()) return;

    frameMonitorPause();
    const bool ok = wifiScannerScan();
    frameMonitorResume();

    if (!ok) {
      server.send(500, "text/plain", "Wi-Fi scan failed.");
      return;
    }

    server.send(200, "text/plain", "OK");
  });

  server.on("/alerts/clear", HTTP_POST, []() {
    if (!requireAdmin()) return;
    frameMonitorClearAlerts();
    server.sendHeader("Location", "/");
    server.send(303);
  });

  server.on("/settings/monitor", HTTP_POST, []() {
    if (!requireAdmin()) return;

    const int channel = server.arg("channel").toInt();
    const int threshold = server.arg("threshold").toInt();

    if (
      !storageSetMonitorChannel(static_cast<uint8_t>(channel)) ||
      !storageSetAlertThreshold(static_cast<uint16_t>(threshold))
    ) {
      server.send(400, "text/plain", "Invalid channel or threshold.");
      return;
    }

    server.send(200, "text/html", "<h2>Monitor settings saved.</h2><p>Restarting ESP32…</p>");
    scheduleRestart();
  });

  server.on("/settings/ap", HTTP_POST, []() {
    if (!requireAdmin()) return;

    if (!storageSetApCredentials(server.arg("ssid"), server.arg("password"))) {
      server.send(400, "text/plain", "Use a 1–32 character SSID and 8–63 character password different from the admin password.");
      return;
    }

    server.send(200, "text/html", "<h2>Management Wi-Fi updated.</h2><p>Restarting ESP32…</p>");
    scheduleRestart();
  });

  server.on("/settings/admin", HTTP_POST, []() {
    if (!requireAdmin()) return;

    if (!storageSetAdminCredentials(server.arg("username"), server.arg("password"))) {
      server.send(400, "text/plain", "Use a 1–32 character username and 8–64 character password different from the Wi-Fi password.");
      return;
    }

    server.send(200, "text/html", "<h2>Administrator updated.</h2><p>Restarting ESP32…</p>");
    scheduleRestart();
  });

  server.on("/system/restart", HTTP_POST, []() {
    if (!requireAdmin()) return;
    server.send(200, "text/html", "<h2>Restarting ESP32…</h2>");
    scheduleRestart();
  });

  server.on("/system/factory-reset", HTTP_POST, []() {
    if (!requireAdmin()) return;
    storageFactoryReset();
    server.send(200, "text/html", "<h2>Factory reset complete.</h2><p>Restarting with setup credentials…</p>");
    scheduleRestart();
  });

  server.onNotFound([]() {
    if (!requireAdmin()) return;
    server.send(404, "text/plain", "Not found");
  });

  server.begin();
  Serial.println("Protected local dashboard started.");
}

void webAdminLoop() {
  server.handleClient();

  if (
    restartPending &&
    millis() - restartRequestedAt > 900
  ) {
    ESP.restart();
  }
}
