#include <Arduino.h>

#include "storage.h"
#include "wifi_scanner.h"
#include "frame_monitor.h"
#include "oled_display.h"
#include "web_admin.h"

void setup() {
  Serial.begin(115200);
  delay(300);

  Serial.println();
  Serial.println("ESP32 Wireless Defense Lab");
  Serial.println("Passive monitoring firmware");

  storageBegin();
  wifiScannerBegin();
  frameMonitorBegin();
  oledDisplayBegin();
  webAdminBegin();

  Serial.println(
    "No packet injection, credential capture, or rogue AP features are enabled."
  );
}

void loop() {
  frameMonitorLoop();
  oledDisplayLoop();
  webAdminLoop();
  delay(2);
}
