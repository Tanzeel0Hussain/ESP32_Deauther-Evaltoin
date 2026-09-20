#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <esp_system.h>

#include "config.h"
#include "detector.h"
#include "storage.h"
#include "text_utils.h"
#include "web_admin.h"
#include "wifi_scanner.h"

namespace {
WebServer server(80);
String csrfToken;
bool restartPending = false;
unsigned long restartAt = 0;

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
  return
    csrfToken.length() == 32 &&
    server.arg("csrf") == csrfToken;
}

bool requireAdmin(bool allowSetup = false) {
  if (!server.authenticate(getAdminUser().c_str(), getAdminPassword().c_str())) {
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

void scheduleRestart() {
  restartPending = true;
  restartAt = millis();
}

String setupPage() {
  String html;
  html.reserve(6000);

  html += R"HTML(<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32 Wireless Defense Lab · Security Setup</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#06111d;color:#eff8ff;font-family:system-ui,sans-serif}
main{max-width:720px;margin:auto;padding:28px 18px}.card{background:#0c1d2d;border:1px solid #213a50;border-radius:20px;padding:24px;box-shadow:0 30px 90px rgba(0,0,0,.35)}
.badge{color:#56dcff;font-size:.78rem;font-weight:900;letter-spacing:.09em;text-transform:uppercase}
h1{font-size:clamp(2rem,7vw,3.3rem);margin:9px 0 10px}p{color:#9cb1c3;line-height:1.6}
label{display:block;margin-top:14px;color:#c6dae8;font-size:.84rem;font-weight:700}
input{width:100%;margin-top:6px;background:#071521;border:1px solid #29475f;color:#fff;border-radius:11px;padding:12px}
button{width:100%;margin-top:19px;border:0;border-radius:11px;padding:14px;background:linear-gradient(135deg,#1479ff,#29d9ff);font-weight:900;color:#04111a}
.note{margin-top:15px;background:#082238;border:1px solid #173d59;border-radius:11px;padding:12px;color:#9db7ca;font-size:.82rem}
</style></head><body><main><section class="card">
<div class="badge">)HTML";
  html += credentialRecoveryRequired()
    ? "Credential recovery"
    : "Mandatory first-boot security";
  html += R"HTML(</div>
<h1>)HTML";
  html += credentialRecoveryRequired()
    ? "Recover the defense dashboard securely."
    : "Secure the defense dashboard.";
  html += R"HTML(</h1>
<p>)HTML";
  html += credentialRecoveryRequired()
    ? "Stored credentials could not be decrypted. Random recovery credentials were printed to the physical serial console; public factory passwords are not used as a fallback. Set fresh credentials now."
    : "Replace the public setup credentials before monitoring. The management Wi-Fi password and admin password must be different.";
  html += R"HTML(</p>
<form method="post" action="/setup">
<input type="hidden" name="csrf" value=")HTML";
  html += csrfToken;
  html += R"HTML(">
<label>Management Wi-Fi name</label>
<input name="ssid" maxlength="32" value=")HTML";
  html += DefenseText::htmlEscape(getApSsid());
  html += R"HTML(" required>
<label>New Wi-Fi password (8–63 characters)</label>
<input name="ap_password" type="password" minlength="8" maxlength="63" required>
<label>Admin username</label>
<input name="admin_user" maxlength="32" value="admin" required>
<label>New admin password (8–64 characters)</label>
<input name="admin_password" type="password" minlength="8" maxlength="64" required>
<button>Save & Restart</button>
</form>
<div class="note">This firmware is passive-only. It monitors management frames and nearby network metadata; it does not inject frames, clone access points, or collect Wi-Fi credentials.</div>
</section></main></body></html>)HTML";
  return html;
}

String dashboardPage() {
  String html;
  html.reserve(26000);

  html += R"HTML(<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32 Wireless Defense Lab</title>
<style>
:root{--bg:#050d17;--panel:#0b1a28;--panel2:#0e2233;--line:#1c384e;--text:#eff8ff;--muted:#8ca8bb;--cyan:#43d9ff;--blue:#2c7dff;--green:#50e6a7;--amber:#ffd166;--red:#ff637d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 70% -20%,#12375a 0,transparent 42%),var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}
main{max-width:1220px;margin:auto;padding:22px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:20px}
.brand small{display:block;color:var(--cyan);font-weight:900;letter-spacing:.1em}.brand h1{margin:4px 0;font-size:clamp(1.6rem,4vw,2.7rem)}
.pill{padding:8px 12px;border:1px solid #1d4962;border-radius:999px;background:#071c2a;color:var(--green);font-size:.82rem}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card{background:linear-gradient(180deg,#0c1e2e,#081522);border:1px solid var(--line);border-radius:17px;padding:17px;box-shadow:0 20px 60px rgba(0,0,0,.22)}
.metric b{display:block;font-size:1.8rem;margin-top:6px}.muted{color:var(--muted)}.two{display:grid;grid-template-columns:1.15fr .85fr;gap:14px;margin-top:14px}
h2,h3{margin:0 0 12px}.actions{display:flex;flex-wrap:wrap;gap:8px}.btn,button{border:0;border-radius:10px;padding:10px 13px;font-weight:800;cursor:pointer;background:linear-gradient(135deg,var(--blue),var(--cyan));color:#041019}.secondary{background:#132a3d;color:#dcefff;border:1px solid #244a65}.danger{background:#4a1822;color:#ffdce2;border:1px solid #763040}
table{width:100%;border-collapse:collapse;font-size:.86rem}th,td{text-align:left;padding:9px;border-bottom:1px solid #173247}th{color:#8fb4c9}.table-wrap{overflow:auto;max-height:420px}
input,select{width:100%;background:#071520;color:#fff;border:1px solid #29465c;border-radius:9px;padding:10px;margin:5px 0 10px}
.status-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 15px var(--green);margin-right:7px}
.warn{color:var(--amber)}.alert{color:var(--red)}code{color:#91e8ff}
canvas{width:100%;height:180px;background:#06131f;border-radius:12px}
@media(max-width:850px){.grid{grid-template-columns:repeat(2,1fr)}.two{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}}
@media(max-width:480px){main{padding:14px}.grid{grid-template-columns:1fr 1fr}.metric b{font-size:1.35rem}}
</style></head><body><main>
<div class="top"><div class="brand"><small>PASSIVE WIRELESS DEFENSE</small><h1>ESP32 Wireless Defense Lab</h1><div class="muted">Local monitor · no frame injection · no credential capture</div></div><div class="pill"><span class="status-dot"></span>Monitor active</div></div>
<div class="grid">
<section class="card metric"><span class="muted">Deauth frames</span><b id="deauth">0</b></section>
<section class="card metric"><span class="muted">Disassoc frames</span><b id="disassoc">0</b></section>
<section class="card metric"><span class="muted">Alerts</span><b id="alertCount">0</b></section>
<section class="card metric"><span class="muted">Nearby networks</span><b id="networkCount">0</b></section>
</div>
<div class="two">
<section class="card"><h3>Threat Alerts</h3><div class="actions"><button class="secondary" onclick="refreshAll()">Refresh</button><button class="danger" onclick="post('/detector/reset')">Clear Detector</button></div><div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>BSSID / Source</th><th>Ch</th><th>RSSI</th><th>Burst</th><th>Reason</th></tr></thead><tbody id="alerts"></tbody></table></div></section>
<section class="card"><h3>Monitor Settings</h3>
<label class="muted">Monitor / management channel (1–13)</label><input id="channel" type="number" min="1" max="13">
<label class="muted">Burst alert threshold (3–200 frames / 5 sec)</label><input id="threshold" type="number" min="3" max="200">
<div class="actions"><button onclick="saveSettings()">Save & Restart if Channel Changed</button></div>
<p class="muted">Because classic ESP32 has one 2.4 GHz radio, the management AP and passive monitor share one selected channel.</p>
<hr style="border:0;border-top:1px solid #173247;margin:18px 0">
<h3>Device</h3><div id="device" class="muted"></div>
</section>
</div>
<div class="two">
<section class="card"><h3>Nearby Wi-Fi Inventory</h3><div class="actions"><button onclick="scan()">Scan Networks</button></div><div class="table-wrap"><table><thead><tr><th>SSID</th><th>BSSID</th><th>RSSI</th><th>Channel</th><th>Security</th></tr></thead><tbody id="networks"></tbody></table></div></section>
<section class="card"><h3>Channel Event Activity</h3><canvas id="chart" width="600" height="220"></canvas><p class="muted">Counts only observed deauthentication/disassociation management frames. It is not a full spectrum analyzer.</p></section>
</div>
<div class="two">
<section class="card"><h3>System Event Log</h3><div class="actions"><button class="secondary" onclick="loadLogs()">Refresh Logs</button><button class="danger" onclick="post('/logs/clear')">Clear Logs</button></div><div id="logs" class="muted" style="margin-top:12px"></div></section>
<section class="card"><h3>Management Credentials</h3>
<label class="muted">Management Wi-Fi name</label><input id="apSsid" maxlength="32" value=")HTML";
  html += DefenseText::htmlEscape(getApSsid());
  html += R"HTML(">
<label class="muted">New Wi-Fi password (8–63)</label><input id="apPass" type="password" minlength="8" maxlength="63" placeholder="Leave unchanged unless updating">
<label class="muted">Admin username</label><input id="adminUser" maxlength="32" value=")HTML";
  html += DefenseText::htmlEscape(getAdminUser());
  html += R"HTML(">
<label class="muted">New admin password (8–64)</label><input id="adminPass" type="password" minlength="8" maxlength="64" placeholder="Required to change credentials">
<div class="actions"><button onclick="saveCredentials()">Change Credentials & Restart</button></div>
</section>
</div>
<div class="two">
<section class="card"><h3>System Controls</h3><p class="muted">Management AP: <code>)HTML";
  html += DefenseText::htmlEscape(getApSsid());
  html += R"HTML(</code> · Dashboard: <code>192.168.4.1</code></p>
<div class="actions"><button class="secondary" onclick="post('/system/restart')">Restart ESP32</button><button class="danger" onclick="factoryReset()">Factory Reset</button></div>
<p class="muted" style="margin-top:14px">Firmware version )HTML";
  html += DefenseConfig::VERSION;
  html += R"HTML( · Built for defensive monitoring and authorized lab observation.</p></section>
</div>
<script>
const csrf=')HTML";
  html += csrfToken;
  html += R"HTML(';
const $=id=>document.getElementById(id);
const esc=s=>String(s??'');
async function api(path){const r=await fetch(path,{cache:'no-store'});if(!r.ok)throw new Error(await r.text());return r.json()}
async function post(path,data={}){data.csrf=csrf;const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(data)});if(!r.ok){alert(await r.text());return false}if(r.redirected)location.href=r.url;return true}
function td(tr,text,cls=''){const d=document.createElement('td');d.textContent=esc(text);if(cls)d.className=cls;tr.appendChild(d)}
async function loadStatus(){const s=await api('/api/status');$('deauth').textContent=s.deauth;$('disassoc').textContent=s.disassoc;$('alertCount').textContent=s.alerts;$('networkCount').textContent=s.networks;$('channel').value=s.monitorChannel;$('threshold').value=s.threshold;$('device').textContent=s.chip+' · rev '+s.revision+' · free heap '+s.freeHeap+' B · uptime '+s.uptimeSeconds+'s · IP '+s.ip;}
async function loadAlerts(){const data=await api('/api/alerts');const body=$('alerts');body.textContent='';data.forEach(a=>{const tr=document.createElement('tr');td(tr,a.seconds+'s');td(tr,a.type,'alert');td(tr,a.bssid+' / '+a.source);td(tr,a.channel);td(tr,a.rssi+' dBm');td(tr,a.burst);td(tr,a.reason);body.appendChild(tr)})}
async function loadNetworks(){const data=await api('/api/networks');const body=$('networks');body.textContent='';data.sort((a,b)=>b.rssi-a.rssi).forEach(n=>{const tr=document.createElement('tr');td(tr,n.ssid||'(hidden)');td(tr,n.bssid);td(tr,n.rssi+' dBm');td(tr,n.channel);td(tr,n.security,n.security==='Open'?'warn':'');body.appendChild(tr)})}
async function loadChannels(){const data=await api('/api/channels');const c=$('chart'),x=c.getContext('2d'),w=c.width,h=c.height;x.clearRect(0,0,w,h);const max=Math.max(1,...data.map(v=>v.events));data.forEach((v,i)=>{const bw=w/13-7,bh=(v.events/max)*(h-35),left=i*(w/13)+4;x.fillStyle='#2c7dff';x.fillRect(left,h-bh-22,bw,bh);x.fillStyle='#9fc3d7';x.font='12px system-ui';x.fillText(String(v.channel),left+bw/3,h-6)});}
async function loadLogs(){const data=await api('/api/logs');const box=$('logs');box.textContent='';[...data].reverse().forEach(l=>{const p=document.createElement('div');p.style.padding='7px 0';p.style.borderBottom='1px solid #173247';p.textContent='boot '+l.boot+' · +'+l.seconds+'s · '+l.type+': '+l.message;box.appendChild(p)})}
async function scan(){const ok=await post('/scan');if(ok){await loadNetworks();await loadStatus()}}
async function saveSettings(){const ok=await post('/settings',{channel:$('channel').value,threshold:$('threshold').value});if(ok)alert('Settings saved. If the channel changed, reconnect after restart.')}
async function saveCredentials(){
  if(!$('apPass').value||!$('adminPass').value){alert('Enter both a new Wi-Fi password and a new admin password.');return}
  await post('/settings/credentials',{
    ssid:$('apSsid').value,
    ap_password:$('apPass').value,
    admin_user:$('adminUser').value,
    admin_password:$('adminPass').value
  })
}
async function factoryReset(){if(confirm('Erase dashboard settings, passwords and logs?'))await post('/system/factory-reset')}
async function refreshAll(){await Promise.all([loadStatus(),loadAlerts(),loadNetworks(),loadChannels(),loadLogs()])}
refreshAll();setInterval(()=>Promise.all([loadStatus(),loadAlerts(),loadChannels()]),4000);
</script></main></body></html>)HTML";

  return html;
}

String statusJson() {
  String json = "{";
  json += "\"project\":\"" + String(DefenseConfig::PROJECT_NAME) + "\"";
  json += ",\"version\":\"" + String(DefenseConfig::VERSION) + "\"";
  json += ",\"ip\":\"" + WiFi.softAPIP().toString() + "\"";
  json += ",\"chip\":\"" + DefenseText::jsonEscape(ESP.getChipModel()) + "\"";
  json += ",\"revision\":" + String(ESP.getChipRevision());
  json += ",\"freeHeap\":" + String(ESP.getFreeHeap());
  json += ",\"uptimeSeconds\":" + String(millis() / 1000UL);
  json += ",\"monitorChannel\":" + String(getMonitorChannel());
  json += ",\"threshold\":" + String(getAlertThreshold());
  json += ",\"networks\":" + String(wifiScannerCount());
  json += ",\"openNetworks\":" + String(wifiScannerOpenCount());
  json += ",\"strongestRssi\":" + String(wifiScannerStrongestRssi());
  json += ",\"deauth\":" + String(detectorTotalDeauth());
  json += ",\"disassoc\":" + String(detectorTotalDisassoc());
  json += ",\"alerts\":" + String(detectorAlertCount());
  json += ",\"lastRssi\":" + String(detectorLastRssi());
  json += ",\"lastChannel\":" + String(detectorLastChannel());
  json += "}";
  return json;
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

  server.on("/setup", HTTP_POST, []() {
    if (!requireAdmin(true)) return;
    if (!initialSetupRequired()) {
      server.sendHeader("Location", "/");
      server.send(303);
      return;
    }

    if (!setInitialCredentials(
      server.arg("ssid"),
      server.arg("ap_password"),
      server.arg("admin_user"),
      server.arg("admin_password")
    )) {
      server.send(
        400,
        "text/plain",
        "Invalid credentials. Use a 1-32 character SSID, 8-63 character Wi-Fi password, 1-32 character admin user, 8-64 character admin password, keep both passwords different, and replace the factory defaults."
      );
      return;
    }

    appendEventLog("security", "First-boot credentials changed");
    server.send(
      200,
      "text/html",
      "<h2>Security setup complete.</h2><p>The ESP32 is restarting. Reconnect using your new management Wi-Fi password.</p>"
    );
    scheduleRestart();
  });

  server.on("/api/status", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(200, "application/json", statusJson());
  });

  server.on("/api/networks", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(200, "application/json", wifiScannerJson());
  });

  server.on("/api/alerts", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(200, "application/json", detectorAlertsJson());
  });

  server.on("/api/channels", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(200, "application/json", detectorChannelJson());
  });

  server.on("/api/logs", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(200, "application/json", getEventLogJson());
  });

  server.on("/scan", HTTP_POST, []() {
    if (!requireAdmin()) return;
    const bool ok = wifiScannerRun();
    appendEventLog("scan", ok ? "Nearby Wi-Fi scan completed" : "Wi-Fi scan failed");
    server.send(
      ok ? 200 : 500,
      "application/json",
      ok ? wifiScannerJson() : "{\"error\":\"scan failed\"}"
    );
  });

  server.on("/settings", HTTP_POST, []() {
    if (!requireAdmin()) return;

    const int channel = server.arg("channel").toInt();
    const int threshold = server.arg("threshold").toInt();

    if (channel < 1 || channel > 13 || threshold < 3 || threshold > 200) {
      server.send(400, "text/plain", "Channel must be 1-13 and threshold 3-200.");
      return;
    }

    const uint8_t oldChannel =
      getMonitorChannel();

    const uint16_t oldThreshold =
      getAlertThreshold();

    const bool channelChanged =
      static_cast<uint8_t>(channel) !=
      oldChannel;

    const bool channelSaved =
      setMonitorChannel(
        static_cast<uint8_t>(channel)
      );

    const bool thresholdSaved =
      channelSaved &&
      setAlertThreshold(
        static_cast<uint16_t>(threshold)
      );

    if (!thresholdSaved) {
      if (channelSaved) {
        setMonitorChannel(oldChannel);
      }

      setAlertThreshold(oldThreshold);

      server.send(
        500,
        "text/plain",
        "Could not persist settings; previous values were restored."
      );
      return;
    }

    detectorUpdateThreshold(
      static_cast<uint16_t>(threshold)
    );
    appendEventLog("settings", "Monitor channel/threshold updated");
    server.send(200, "application/json", "{\"ok\":true}");

    if (channelChanged) scheduleRestart();
  });

  server.on("/settings/credentials", HTTP_POST, []() {
    if (!requireAdmin()) return;

    if (!setInitialCredentials(
      server.arg("ssid"),
      server.arg("ap_password"),
      server.arg("admin_user"),
      server.arg("admin_password")
    )) {
      server.send(
        400,
        "text/plain",
        "Invalid credentials. Use a 1-32 character SSID, 8-63 character Wi-Fi password, 1-32 character admin user, 8-64 character admin password, and keep the Wi-Fi/admin passwords different."
      );
      return;
    }

    appendEventLog("security", "Management credentials updated");
    server.send(200, "application/json", "{\"ok\":true}");
    scheduleRestart();
  });

  server.on("/detector/reset", HTTP_POST, []() {
    if (!requireAdmin()) return;
    detectorReset();
    appendEventLog("detector", "Passive detector counters cleared");
    server.send(200, "application/json", "{\"ok\":true}");
  });

  server.on("/logs/clear", HTTP_POST, []() {
    if (!requireAdmin()) return;
    clearEventLogs();
    appendEventLog("system", "Event log cleared");
    server.send(200, "application/json", "{\"ok\":true}");
  });

  server.on("/system/restart", HTTP_POST, []() {
    if (!requireAdmin()) return;
    appendEventLog("system", "Manual restart requested");
    server.send(200, "application/json", "{\"ok\":true}");
    scheduleRestart();
  });

  server.on("/system/factory-reset", HTTP_POST, []() {
    if (!requireAdmin()) return;
    factoryResetStorage();
    server.send(200, "application/json", "{\"ok\":true}");
    scheduleRestart();
  });

  server.on("/health", HTTP_GET, []() {
    server.send(200, "application/json", "{\"status\":\"ok\",\"mode\":\"passive-defense\"}");
  });

  server.onNotFound([]() {
    server.send(404, "text/plain", "Not found");
  });

  server.begin();
}

void webAdminLoop() {
  server.handleClient();

  if (restartPending && millis() - restartAt >= 1000) {
    ESP.restart();
  }
}
