#include <Arduino.h>
#include <WiFi.h>

#include "config.h"
#include "detector.h"
#include "display.h"
#include "storage.h"
#include "system_monitor.h"
#include "web_admin.h"
#include "wifi_scanner.h"

void setup() {
  Serial.begin(115200);
  delay(400);

  Serial.println();
  Serial.println("==============================");
  Serial.println("ESP32 Wireless Defense Lab");
  Serial.println("Passive monitoring firmware");
  Serial.println("==============================");

  storageBegin();

  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect(false, true);
  delay(100);

  IPAddress apIp(
    DefenseConfig::AP_IP_A,
    DefenseConfig::AP_IP_B,
    DefenseConfig::AP_IP_C,
    DefenseConfig::AP_IP_D
  );

  WiFi.softAPConfig(
    apIp,
    apIp,
    IPAddress(255, 255, 255, 0)
  );

  const bool apReady = WiFi.softAP(
    getApSsid().c_str(),
    getApPassword().c_str(),
    getMonitorChannel(),
    false,
    4
  );

  detectorUpdateThreshold(
    getAlertThreshold()
  );

  detectorBegin();
  wifiScannerBegin();
  displayBegin();
  systemMonitorBegin();
  webAdminBegin();

  appendEventLog(
    "system",
    String("Firmware v") +
      DefenseConfig::VERSION +
      " ready on channel " +
      String(getMonitorChannel())
  );

  Serial.print("Management AP: ");
  Serial.println(getApSsid());
  Serial.print("Dashboard: http://");
  Serial.println(WiFi.softAPIP());
  Serial.println(
    "Passive-only: no frame injection or credential capture."
  );

  if (!apReady) {
    Serial.println(
      "WARNING: management AP failed to start."
    );
  }
}

void loop() {
  webAdminLoop();
  detectorLoop();
  wifiScannerLoop();
  displayLoop();
  systemMonitorLoop();
  delay(2);
}
