#include <Arduino.h>
#include <WebServer.h>

extern "C" {
#include "esp_system.h"
}

#include "web_admin.h"
#include "config.h"
#include "detector.h"
#include "scanner.h"
#include "storage.h"
#include "text_utils.h"

namespace {
WebServer server(80);
String csrfToken;
bool restartPending = false;
unsigned long restartAt = 0;

String makeToken() {
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
  const String value = server.arg("csrf");
  return
    csrfToken.length() == 32 &&
    value.length() == csrfToken.length() &&
    value == csrfToken;
}

bool requireAdmin(bool allowInitialSetup = false) {
  const String user = defenseAdminUser();
  const String password = defenseAdminPassword();

  if (
    !server.authenticate(
      user.c_str(),
      password.c_str()
    )
  ) {
    server.requestAuthentication(
      DIGEST_AUTH,
      "ESP32 Defense Lab"
    );
    return false;
  }

  if (
    server.method() != HTTP_GET &&
    !csrfValid()
  ) {
    server.send(
      403,
      "text/plain",
      "Invalid or missing CSRF token."
    );
    return false;
  }

  if (
    !allowInitialSetup &&
    defenseInitialSetupRequired()
  ) {
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
  html.reserve(5600);

  html = R"HTML(<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>ESP32 Defense Lab Setup</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#06111c;color:#eef8ff;font-family:Inter,system-ui,sans-serif}
.wrap{max-width:720px;margin:auto;padding:32px 18px}.card{background:#0c1d2c;border:1px solid #1e3e53;border-radius:20px;padding:24px;box-shadow:0 28px 90px #0007}
.badge{display:inline-block;color:#4fe2ff;font-size:.76rem;font-weight:900;letter-spacing:.12em;text-transform:uppercase}
h1{margin:10px 0 8px;font-size:clamp(2rem,7vw,3.4rem)}p{color:#9eb7c8;line-height:1.65}
label{display:block;margin-top:14px;color:#c8deeb;font-size:.82rem;font-weight:800}
input{width:100%;margin-top:6px;background:#071522;border:1px solid #29475b;color:#fff;border-radius:12px;padding:13px}
button{width:100%;margin-top:19px;border:0;border-radius:12px;padding:14px;background:linear-gradient(135deg,#0a7cff,#38e5ff);color:#03111b;font-weight:950;cursor:pointer}
.note{margin-top:16px;padding:13px;border-radius:12px;background:#09243a;color:#9ab5c7;font-size:.82rem}
</style></head><body><main class="wrap"><section class="card">
<div class="badge">Mandatory first-boot security</div>
<h1>Secure the Defense Lab.</h1>
<p>The factory credentials are setup-only. Choose a new management Wi-Fi password and a different administrator password before the monitoring dashboard is unlocked.</p>
<form method="post" action="/setup/security">
<input type="hidden" name="csrf" value=")HTML";

  html += csrfToken;

  html += R"HTML(">
<label>Management Wi-Fi name</label>
<input name="ssid" maxlength="32" value=")HTML";

  html +=
    DefenseText::htmlEscape(
      defenseApSsid()
    );

  html += R"HTML(" required>
<label>New Wi-Fi password (8–63 characters)</label>
<input name="ap_password" type="password" minlength="8" maxlength="63" autocomplete="new-password" required>
<label>Admin username</label>
<input name="admin_user" maxlength="32" value="admin" required>
<label>New admin password (8–64 characters)</label>
<input name="admin_password" type="password" minlength="8" maxlength="64" autocomplete="new-password" required>
<button type="submit">Save Security Settings & Restart</button>
</form>
<div class="note">The two passwords must be different. After restart, reconnect to the new management Wi-Fi and open <b>192.168.4.1</b>.</div>
</section></main></body></html>)HTML";

  return html;
}

String dashboardPage() {
  String html;
  html.reserve(25000);

  html = R"HTML(<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>ESP32 Wireless Defense Lab</title>
<style>
:root{--bg:#050d16;--panel:#0b1926;--panel2:#0d2233;--line:#1d394b;--text:#edf8ff;--muted:#88a6ba;--cyan:#44e5ff;--blue:#348cff;--green:#49e7a6;--amber:#ffca5b;--red:#ff6578}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 85% -10%,#0b3e66 0,transparent 34%),var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}
main{max-width:1180px;margin:auto;padding:18px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;padding:10px 0 18px}.brand b{font-size:1.12rem}.brand small{display:block;color:var(--muted);margin-top:3px}
.pill{border:1px solid var(--line);border-radius:999px;padding:8px 12px;color:var(--cyan);background:#081a28}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card{background:linear-gradient(180deg,#0d1d2b,#081520);border:1px solid var(--line);border-radius:18px;padding:17px;box-shadow:0 18px 55px #0004;margin-bottom:13px}
.metric small,.muted,small{color:var(--muted)}.metric strong{display:block;font-size:1.55rem;margin-top:7px}.span2{grid-column:span 2}h1,h2,h3{margin-top:0}h2{font-size:1.08rem}
.actions{display:flex;flex-wrap:wrap;gap:8px}.btn,button{border:1px solid #27617d;border-radius:10px;background:#0b3048;color:#dff8ff;padding:10px 13px;font-weight:800;cursor:pointer}.btn.primary,button.primary{background:linear-gradient(135deg,#087aff,#38e4ff);color:#03111a;border:0}.danger{border-color:#663343;background:#35151e;color:#ff9eaa}
input,select{background:#06131e;border:1px solid #274355;color:#fff;border-radius:10px;padding:10px;max-width:100%}form.inline{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.row{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:11px 0;border-bottom:1px solid #122b3a}.row:last-child{border-bottom:0}.network-main{min-width:0}.network-main b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.meta{color:var(--muted);font-size:.8rem;margin-top:4px}
.status{font-weight:900}.Normal{color:var(--green)}.Warning{color:var(--amber)}.Critical{color:var(--red)}
table{width:100%;border-collapse:collapse;font-size:.83rem}th,td{text-align:left;padding:9px;border-bottom:1px solid #153044}th{color:#9fc3d7}.scroll{overflow:auto}.empty{color:var(--muted);padding:10px 0}
@media(max-width:850px){.grid{grid-template-columns:repeat(2,1fr)}.span2{grid-column:span 2}}
@media(max-width:560px){main{padding:12px}.top{align-items:flex-start;flex-direction:column}.grid{grid-template-columns:1fr}.span2{grid-column:span 1}.metric strong{font-size:1.35rem}.row{align-items:flex-start;flex-direction:column}}
</style></head><body><main>
<div class="top">
<div class="brand"><b>🛡️ ESP32 Wireless Defense Lab</b><small>Passive 2.4 GHz management-frame monitor · v)HTML";

  html += DefenseConfig::VERSION;

  html += R"HTML(</small></div>
<div class="pill">Management: )HTML";

  html +=
    DefenseText::htmlEscape(
      defenseApSsid()
    );

  html += R"HTML( · 192.168.4.1</div>
</div>

<div class="grid">
<section class="card metric"><small>Threat level</small><strong id="level" class="Normal">Normal</strong></section>
<section class="card metric"><small>Monitor channel</small><strong id="channel">—</strong></section>
<section class="card metric"><small>Deauth frames</small><strong id="deauth">0</strong></section>
<section class="card metric"><small>Disassoc frames</small><strong id="disassoc">0</strong></section>

<section class="card span2">
<h2>Live Detection</h2>
<div class="row"><div><b>Current 10-second window</b><div class="meta">Passive observation only. No frames are transmitted to third-party networks.</div></div><div id="window">0</div></div>
<div class="row"><div><b>Strongest active source</b><div class="meta">Source MAC seen in recent deauth/disassociation frames.</div></div><div id="source">—</div></div>
<div class="row"><div><b>Last observed RSSI</b></div><div id="rssi">—</div></div>
<div class="row"><div><b>Free heap</b></div><div id="heap">—</div></div>
</section>

<section class="card span2">
<h2>Monitor Settings</h2>
<form class="inline" method="post" action="/settings/monitor">
<label>Channel <select name="channel">)HTML";

  for (uint8_t ch = 1; ch <= 13; ++ch) {
    html += "<option value='" + String(ch) + "'";

    if (ch == defenseMonitorChannel()) {
      html += " selected";
    }

    html += ">" + String(ch) + "</option>";
  }

  html += R"HTML(</select></label>
<label>Warning threshold <input name="threshold" type="number" min="3" max="200" value=")HTML";

  html += String(defenseAlertThreshold());

  html += R"HTML("></label>
<button class="primary">Apply</button>
</form>
<p><small>Threshold counts deauthentication + disassociation frames inside each 10-second detection window. Critical = 3× warning threshold.</small></p>
</section>
</div>

<section class="card">
<div class="row"><div><h2 style="margin:0">Nearby Wi-Fi Inventory</h2><div class="meta">A manual scan briefly pauses channel monitoring, then returns to the selected channel.</div></div><button class="primary" type="button" onclick="runScan()">Scan Networks</button></div>
<div id="networks" class="empty">No scan yet.</div>
</section>

<section class="card">
<div class="row"><div><h2 style="margin:0">Threat Alerts</h2><div class="meta">Recent passive deauth/disassociation bursts.</div></div>
<form method="post" action="/alerts/clear"><button>Clear Alerts</button></form></div>
<div class="scroll"><table><thead><tr><th>Age</th><th>Level</th><th>Source</th><th>CH</th><th>RSSI</th><th>Deauth</th><th>Disassoc</th></tr></thead><tbody id="alerts"><tr><td colspan="7" class="empty">No alerts.</td></tr></tbody></table></div>
</section>

<section class="card">
<div class="row"><div><h2 style="margin:0">Event Log</h2><div class="meta">Local device events and detector alerts.</div></div>
<form method="post" action="/logs/clear"><button>Clear Log</button></form></div>
<div class="scroll"><table><thead><tr><th>Age</th><th>Type</th><th>Message</th></tr></thead><tbody id="logs"><tr><td colspan="3" class="empty">No events.</td></tr></tbody></table></div>
</section>

<section class="card">
<h2>Security & Device</h2>
<form class="inline" method="post" action="/settings/security">
<input name="ssid" maxlength="32" value=")HTML";

  html +=
    DefenseText::htmlEscape(
      defenseApSsid()
    );

  html += R"HTML(" placeholder="Management SSID" required>
<input name="ap_password" type="password" minlength="8" maxlength="63" placeholder="New Wi-Fi password" required>
<input name="admin_user" maxlength="32" value=")HTML";

  html +=
    DefenseText::htmlEscape(
      defenseAdminUser()
    );

  html += R"HTML(" placeholder="Admin user" required>
<input name="admin_password" type="password" minlength="8" maxlength="64" placeholder="New admin password" required>
<button>Change Credentials</button>
</form>
<div class="actions" style="margin-top:14px">
<form method="post" action="/system/restart"><button>Restart ESP32</button></form>
<form method="post" action="/system/factory-reset" onsubmit="return confirm('Erase Defense Lab settings and restart?')"><button class="danger">Factory Reset</button></form>
</div>
</section>

<script>
const csrfToken=')HTML";

  html += csrfToken;

  html += R"HTML(';
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

document.addEventListener('submit',event=>{
  const form=event.target;
  if(
    form instanceof HTMLFormElement &&
    form.method.toLowerCase()==='post' &&
    !form.querySelector('input[name="csrf"]')
  ){
    const input=document.createElement('input');
    input.type='hidden';
    input.name='csrf';
    input.value=csrfToken;
    form.prepend(input);
  }
},true);

const age=s=>{
  const n=Number(s||0);
  if(n<60)return n+'s';
  if(n<3600)return Math.floor(n/60)+'m';
  return Math.floor(n/3600)+'h';
};

async function loadStatus(){
  const s=await fetch('/api/status').then(r=>r.json());
  const level=document.getElementById('level');
  level.textContent=s.level;
  level.className='status '+s.level;
  document.getElementById('channel').textContent=s.channel;
  document.getElementById('deauth').textContent=s.deauthFrames.toLocaleString();
  document.getElementById('disassoc').textContent=s.disassocFrames.toLocaleString();
  document.getElementById('window').textContent=(s.windowDeauth+s.windowDisassoc)+' disconnect / '+s.windowTotal+' management';
  document.getElementById('source').textContent=s.topSource||'—';
  document.getElementById('rssi').textContent=s.lastRssi+' dBm';
  document.getElementById('heap').textContent=Math.round(s.freeHeap/1024)+' KB';
}

async function loadAlerts(){
  const data=await fetch('/api/alerts').then(r=>r.json());
  const now=Math.floor(performance.now()/1000);
  document.getElementById('alerts').innerHTML=data.length?data.map(a=>`
    <tr>
      <td>${age(Math.max(0,now-a.seconds))}</td>
      <td class="${esc(a.level)}"><b>${esc(a.level)}</b></td>
      <td>${esc(a.source)}</td>
      <td>${a.channel}</td>
      <td>${a.rssi} dBm</td>
      <td>${a.deauth}</td>
      <td>${a.disassoc}</td>
    </tr>`).join(''):'<tr><td colspan="7" class="empty">No alerts.</td></tr>';
}

async function loadLogs(){
  const data=await fetch('/api/logs').then(r=>r.json());
  const now=Math.floor(performance.now()/1000);
  document.getElementById('logs').innerHTML=data.length?data.map(l=>`
    <tr><td>${age(Math.max(0,now-l.seconds))}</td><td>${esc(l.type)}</td><td>${esc(l.message)}</td></tr>`).join(''):'<tr><td colspan="3" class="empty">No events.</td></tr>';
}

async function loadNetworks(){
  const data=await fetch('/api/networks').then(r=>r.json());
  const box=document.getElementById('networks');

  box.innerHTML=data.length?data.map(n=>`
    <div class="row">
      <div class="network-main">
        <b>${esc(n.ssid||'(hidden SSID)')}</b>
        <div class="meta">${esc(n.bssid)} · CH ${n.channel} · ${n.rssi} dBm · ${n.secure?'Secured':'Open'}</div>
      </div>
      <form method="post" action="/settings/channel">
        <input type="hidden" name="csrf" value="${csrfToken}">
        <input type="hidden" name="channel" value="${n.channel}">
        <button>Monitor CH ${n.channel}</button>
      </form>
    </div>`).join(''):'<div class="empty">No networks found.</div>';
}

async function runScan(){
  const button=event.currentTarget;
  button.disabled=true;
  button.textContent='Scanning…';

  try{
    const body=new URLSearchParams({csrf:csrfToken});
    const response=await fetch('/scan',{
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body
    });

    if(!response.ok)throw new Error('scan failed');
    await loadNetworks();
  }catch(e){
    alert('Wi-Fi scan failed.');
  }finally{
    button.disabled=false;
    button.textContent='Scan Networks';
  }
}

loadStatus();
loadAlerts();
loadLogs();
loadNetworks();

setInterval(loadStatus,2000);
setInterval(loadAlerts,5000);
setInterval(loadLogs,7000);
</script>
</main></body></html>)HTML";

  return html;
}
}

void defenseWebBegin() {
  csrfToken = makeToken();

  server.on("/", HTTP_GET, []() {
    if (!requireAdmin(true)) return;

    if (defenseInitialSetupRequired()) {
      server.send(
        200,
        "text/html; charset=utf-8",
        setupPage()
      );
      return;
    }

    server.send(
      200,
      "text/html; charset=utf-8",
      dashboardPage()
    );
  });

  server.on("/setup/security", HTTP_POST, []() {
    if (!requireAdmin(true)) return;

    if (!defenseInitialSetupRequired()) {
      server.sendHeader("Location", "/");
      server.send(303);
      return;
    }

    const bool ok =
      defenseSaveInitialCredentials(
        server.arg("ssid"),
        server.arg("ap_password"),
        server.arg("admin_user"),
        server.arg("admin_password")
      );

    if (!ok) {
      server.send(
        400,
        "text/plain",
        "Invalid credentials. Use a 1-32 character SSID, 8-63 character Wi-Fi password, 1-32 character username, 8-64 character admin password, keep the two passwords different, and replace the factory passwords."
      );
      return;
    }

    defenseAppendLog(
      "security",
      "Mandatory first-boot credentials changed"
    );

    server.send(
      200,
      "text/html",
      "<h2>Security setup complete.</h2><p>The ESP32 is restarting. Reconnect using the new management Wi-Fi credentials.</p>"
    );

    scheduleRestart();
  });

  server.on("/api/status", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(
      200,
      "application/json",
      detectorStatsJson()
    );
  });

  server.on("/api/alerts", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(
      200,
      "application/json",
      detectorAlertsJson()
    );
  });

  server.on("/api/networks", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(
      200,
      "application/json",
      scannerNetworksJson()
    );
  });

  server.on("/api/logs", HTTP_GET, []() {
    if (!requireAdmin()) return;
    server.send(
      200,
      "application/json",
      defenseLogsJson()
    );
  });

  server.on("/scan", HTTP_POST, []() {
    if (!requireAdmin()) return;

    const bool ok = scannerRun();

    server.send(
      ok ? 200 : 500,
      "application/json",
      ok
        ? "{\"ok\":true}"
        : "{\"ok\":false}"
    );
  });

  server.on("/settings/channel", HTTP_POST, []() {
    if (!requireAdmin()) return;

    const int channel =
      server.arg("channel").toInt();

    if (channel < 1 || channel > 13) {
      server.send(
        400,
        "text/plain",
        "Channel must be 1-13."
      );
      return;
    }

    detectorSetChannel(
      static_cast<uint8_t>(channel)
    );

    server.sendHeader("Location", "/");
    server.send(303);
  });

  server.on("/settings/monitor", HTTP_POST, []() {
    if (!requireAdmin()) return;

    const int channel =
      server.arg("channel").toInt();

    const int threshold =
      server.arg("threshold").toInt();

    if (
      channel < 1 ||
      channel > 13 ||
      threshold < 3 ||
      threshold > 200
    ) {
      server.send(
        400,
        "text/plain",
        "Channel must be 1-13 and threshold 3-200."
      );
      return;
    }

    if (
      !defenseSetAlertThreshold(
        static_cast<uint16_t>(threshold)
      )
    ) {
      server.send(
        500,
        "text/plain",
        "Could not save threshold."
      );
      return;
    }

    detectorSetChannel(
      static_cast<uint8_t>(channel)
    );

    server.sendHeader("Location", "/");
    server.send(303);
  });

  server.on("/settings/security", HTTP_POST, []() {
    if (!requireAdmin()) return;

    const bool ok =
      defenseSaveCredentials(
        server.arg("ssid"),
        server.arg("ap_password"),
        server.arg("admin_user"),
        server.arg("admin_password")
      );

    if (!ok) {
      server.send(
        400,
        "text/plain",
        "Invalid security settings. Passwords must meet length rules and be different."
      );
      return;
    }

    defenseAppendLog(
      "security",
      "Management credentials changed"
    );

    server.send(
      200,
      "text/html",
      "<h2>Credentials changed.</h2><p>The ESP32 is restarting. Reconnect using the new management Wi-Fi credentials.</p>"
    );

    scheduleRestart();
  });

  server.on("/alerts/clear", HTTP_POST, []() {
    if (!requireAdmin()) return;
    detectorClearAlerts();
    server.sendHeader("Location", "/");
    server.send(303);
  });

  server.on("/logs/clear", HTTP_POST, []() {
    if (!requireAdmin()) return;
    defenseClearLogs();
    defenseAppendLog("system", "Event log cleared");
    server.sendHeader("Location", "/");
    server.send(303);
  });

  server.on("/system/restart", HTTP_POST, []() {
    if (!requireAdmin()) return;

    defenseAppendLog(
      "system",
      "Restart requested from dashboard"
    );

    server.send(
      200,
      "text/html",
      "<h2>Restarting ESP32…</h2>"
    );

    scheduleRestart();
  });

  server.on("/system/factory-reset", HTTP_POST, []() {
    if (!requireAdmin()) return;

    defenseFactoryReset();

    server.send(
      200,
      "text/html",
      "<h2>Factory reset complete.</h2><p>The ESP32 is restarting into first-boot setup.</p>"
    );

    scheduleRestart();
  });

  server.onNotFound([]() {
    if (!requireAdmin()) return;

    server.send(
      404,
      "text/plain",
      "Not found"
    );
  });

  server.begin();

  defenseAppendLog(
    "web",
    "Secure local dashboard started"
  );
}

void defenseWebLoop() {
  server.handleClient();

  if (
    restartPending &&
    millis() - restartAt > 1200
  ) {
    ESP.restart();
  }
}
