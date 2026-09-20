#include <Arduino.h>
#include <WiFi.h>

#include "scanner.h"
#include "detector.h"
#include "models.h"
#include "config.h"
#include "text_utils.h"
#include "storage.h"

namespace {
NetworkRecord networks[DefenseConfig::MAX_NETWORKS];
size_t networkCount = 0;
uint32_t lastScanMs = 0;
bool firstScanDone = false;

String securityText(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2 Enterprise";
    default: return "Secured";
  }
}
}

void scannerBegin() {
  networkCount = 0;
  lastScanMs = 0;
}

bool scannerScanNow() {
  detectorPause();

  const int found = WiFi.scanNetworks(false, true);
  networkCount = 0;

  if (found >= 0) {
    const int capped =
      found > static_cast<int>(DefenseConfig::MAX_NETWORKS)
        ? static_cast<int>(DefenseConfig::MAX_NETWORKS)
        : found;

    for (int i = 0; i < capped; ++i) {
      NetworkRecord record;
      record.ssid = WiFi.SSID(i);
      record.bssid = WiFi.BSSIDstr(i);
      record.rssi = WiFi.RSSI(i);
      record.channel = static_cast<uint8_t>(WiFi.channel(i));
      record.hidden = record.ssid.length() == 0;
      record.security = securityText(WiFi.encryptionType(i));

      networks[networkCount++] = record;
    }
  }

  WiFi.scanDelete();
  detectorSetChannel(getMonitorChannel());
  detectorResume();

  firstScanDone = true;
  lastScanMs = millis();

  return found >= 0;
}

void scannerLoop() {
  if (
    !firstScanDone ||
    millis() - lastScanMs >= DefenseConfig::AUTO_SCAN_INTERVAL_MS
  ) {
    scannerScanNow();
  }
}

String scannerNetworksJson() {
  String json;
  json.reserve(128 + networkCount * 160);
  json = "[";

  for (size_t i = 0; i < networkCount; ++i) {
    if (i) json += ",";

    const NetworkRecord& n = networks[i];

    json +=
      "{\"ssid\":\"" +
      DefenseText::jsonEscape(n.hidden ? String("<hidden>") : n.ssid) +
      "\",\"bssid\":\"" +
      DefenseText::jsonEscape(n.bssid) +
      "\",\"security\":\"" +
      DefenseText::jsonEscape(n.security) +
      "\",\"rssi\":" +
      String(n.rssi) +
      ",\"channel\":" +
      String(n.channel) +
      ",\"hidden\":" +
      String(n.hidden ? "true" : "false") +
      "}";
  }

  json += "]";
  return json;
}

size_t scannerNetworkCount() {
  return networkCount;
}

uint32_t scannerLastScanAgeSeconds() {
  if (!firstScanDone) return 0;
  return (millis() - lastScanMs) / 1000UL;
}
