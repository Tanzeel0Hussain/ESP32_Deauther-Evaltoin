#include <Arduino.h>
#include <WiFi.h>

#include "config.h"
#include "storage.h"
#include "detector.h"
#include "scanner.h"
#include "display.h"
#include "system_monitor.h"
#include "web_admin.h"

void setup() {
  Serial.begin(115200);
  delay(350);

  Serial.println();
  Serial.println("==============================");
  Serial.println("ESP32 Wireless Defense Lab");
  Serial.println("Passive monitoring firmware");
  Serial.println("==============================");

  defenseStorageBegin();

  WiFi.persistent(false);
  WiFi.mode(WIFI_AP);

  const uint8_t channel =
    defenseMonitorChannel();

  const bool apReady =
    WiFi.softAP(
      defenseApSsid().c_str(),
      defenseApPassword().c_str(),
      channel,
      false,
      4
    );

  Serial.print("Management AP: ");
  Serial.println(defenseApSsid());
  Serial.print("Dashboard: http://");
  Serial.println(WiFi.softAPIP());

  if (!apReady) {
    Serial.println(
      "WARNING: management AP failed to start."
    );
  }

  scannerBegin();
  detectorBegin();
  defenseDisplayBegin();
  defenseSystemBegin();
  defenseWebBegin();

  defenseAppendLog(
    "system",
    String("Firmware v") +
    DefenseConfig::VERSION +
    " ready"
  );
}

void loop() {
  detectorLoop();
  defenseDisplayLoop();
  defenseWebLoop();
  defenseSystemLoop();
  delay(2);
}
