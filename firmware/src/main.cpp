#include <Arduino.h>
#include <WiFi.h>

extern "C" {
#include "esp_wifi.h"
}

#include "config.h"
#include "detector.h"
#include "display.h"
#include "storage.h"
#include "web_admin.h"
#include "wifi_scanner.h"

void setup() {
  Serial.begin(115200);
  delay(400);

  storageBegin();

  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect(true, true);
  delay(100);

  IPAddress ip(
    DefenseConfig::AP_IP_A,
    DefenseConfig::AP_IP_B,
    DefenseConfig::AP_IP_C,
    DefenseConfig::AP_IP_D
  );

  WiFi.softAPConfig(ip, ip, IPAddress(255, 255, 255, 0));
  WiFi.softAP(
    getApSsid().c_str(),
    getApPassword().c_str(),
    getMonitorChannel(),
    false,
    4
  );

  detectorUpdateThreshold(getAlertThreshold());
  detectorBegin();
  wifiScannerBegin();
  displayBegin();
  webAdminBegin();

  appendEventLog(
    "system",
    "Booted passive defense monitor on channel " +
      String(getMonitorChannel())
  );

  Serial.println();
  Serial.println(DefenseConfig::PROJECT_NAME);
  Serial.print("Management AP: ");
  Serial.println(getApSsid());
  Serial.print("Dashboard: http://");
  Serial.println(WiFi.softAPIP());
  Serial.println("Passive-only firmware: no frame injection or credential capture.");
}

void loop() {
  webAdminLoop();
  detectorLoop();
  wifiScannerLoop();
  displayLoop();
  delay(2);
}
