#include <Arduino.h>
#include <WiFi.h>

#include "scanner.h"
#include "config.h"
#include "detector.h"
#include "models.h"
#include "storage.h"
#include "text_utils.h"

namespace {
NetworkRecord networks[DefenseConfig::MAX_SCAN_RESULTS];
size_t networkCount = 0;

const char* securityLabel(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN:
      return "Open";
    case WIFI_AUTH_WEP:
      return "WEP";
    case WIFI_AUTH_WPA_PSK:
      return "WPA";
    case WIFI_AUTH_WPA2_PSK:
      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:
      return "WPA/WPA2";
#if defined(WIFI_AUTH_WPA3_PSK)
    case WIFI_AUTH_WPA3_PSK:
      return "WPA3";
#endif
#if defined(WIFI_AUTH_WPA2_WPA3_PSK)
    case WIFI_AUTH_WPA2_WPA3_PSK:
      return "WPA2/WPA3";
#endif
    default:
      return "Secured";
  }
}
}

void scannerBegin() {
  networkCount = 0;
}

bool scannerRun() {
  const uint8_t monitorChannel = detectorChannel();

  detectorPause();

  const int count =
    WiFi.scanNetworks(
      false,
      true,
      false,
      120
    );

  networkCount = 0;

  if (count < 0) {
    detectorResume();
    defenseAppendLog(
      "scan",
      "Wi-Fi scan failed"
    );
    return false;
  }

  const int limit =
    count >
      DefenseConfig::MAX_SCAN_RESULTS
      ? DefenseConfig::MAX_SCAN_RESULTS
      : count;

  for (int i = 0; i < limit; ++i) {
    NetworkRecord record;
    record.ssid = WiFi.SSID(i);
    record.bssid = WiFi.BSSIDstr(i);
    record.rssi = WiFi.RSSI(i);
    record.channel = WiFi.channel(i);
    record.secure =
      WiFi.encryptionType(i) != WIFI_AUTH_OPEN;

    networks[networkCount++] = record;
  }

  WiFi.scanDelete();
  detectorResume();

  defenseAppendLog(
    "scan",
    "Passive inventory scan found " +
    String(networkCount) +
    " networks; monitor returned to channel " +
    String(monitorChannel)
  );

  return true;
}

String scannerNetworksJson() {
  String json = "[";
  json.reserve(200 + networkCount * 180);

  for (size_t i = 0; i < networkCount; ++i) {
    if (i) json += ",";

    const auto& network = networks[i];

    json +=
      "{\"ssid\":\"" +
      DefenseText::jsonEscape(network.ssid) +
      "\",\"bssid\":\"" +
      DefenseText::jsonEscape(network.bssid) +
      "\",\"rssi\":" +
      String(network.rssi) +
      ",\"channel\":" +
      String(network.channel) +
      ",\"secure\":" +
      String(network.secure ? "true" : "false") +
      "}";
  }

  json += "]";
  return json;
}

size_t scannerCount() {
  return networkCount;
}
