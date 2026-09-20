#include <Arduino.h>
#include <WiFi.h>

#include "storage.h"
#include "scanner.h"
#include "detector.h"
#include "display.h"
#include "web_admin.h"

namespace {
void startManagementAp() {
  IPAddress ip(192, 168, 4, 1);
  IPAddress mask(255, 255, 255, 0);

  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);
  WiFi.softAPConfig(ip, ip, mask);

  WiFi.softAP(
    getApSsid().c_str(),
    getApPassword().c_str(),
    getMonitorChannel(),
    false,
    4
  );
}
}

void setup() {
  Serial.begin(115200);
  delay(300);

  Serial.println();
  Serial.println("ESP32 Wireless Defense Lab");
  Serial.println("Defensive passive monitor");

  storageBegin();
  startManagementAp();

  detectorSetChannel(getMonitorChannel());

  scannerBegin();
  detectorBegin();
  displayBegin();
  webAdminBegin();

  Serial.print("Management Wi-Fi: ");
  Serial.println(getApSsid());
  Serial.println("Dashboard: http://192.168.4.1");

  if (initialSetupRequired()) {
    Serial.println("First boot: change setup credentials before normal use.");
  }
}

void loop() {
  detectorLoop();
  scannerLoop();
  displayLoop();
  webAdminLoop();
  delay(2);
}
