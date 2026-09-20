#include <Arduino.h>
#include <WiFi.h>

extern "C" {
#include "esp_wifi.h"
}

#include "config.h"
#include "models.h"
#include "text_utils.h"
#include "storage.h"
#include "wifi_scanner.h"

namespace {
NetworkRecord networks[DefenseConfig::MAX_NETWORKS];
size_t networkCount = 0;
int32_t strongest = -127;
uint8_t openNetworks = 0;
unsigned long lastScanMs = 0;

String authName(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Enterprise";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default: return "Unknown";
  }
}
}

void wifiScannerBegin() {
  wifiScannerRun();
}

void wifiScannerLoop() {}

bool wifiScannerRun() {
  const int found = WiFi.scanNetworks(false, true);
  if (found < 0) return false;

  networkCount = 0;
  strongest = -127;
  openNetworks = 0;

  for (
    int i = 0;
    i < found &&
    networkCount < DefenseConfig::MAX_NETWORKS;
    ++i
  ) {
    NetworkRecord& n = networks[networkCount++];
    n.ssid = WiFi.SSID(i);
    n.bssid = WiFi.BSSIDstr(i);
    n.rssi = WiFi.RSSI(i);
    n.channel = WiFi.channel(i);
    n.security = authName(WiFi.encryptionType(i));

    if (n.rssi > strongest) strongest = n.rssi;
    if (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) ++openNetworks;
  }

  WiFi.scanDelete();

  const uint8_t channel = getMonitorChannel();
  if (channel >= 1 && channel <= 13) {
    esp_wifi_set_channel(
      channel,
      WIFI_SECOND_CHAN_NONE
    );
  }

  lastScanMs = millis();
  return true;
}

String wifiScannerJson() {
  String json;
  json.reserve(256 + networkCount * 140);
  json = "[";

  for (size_t i = 0; i < networkCount; ++i) {
    if (i) json += ",";
    const NetworkRecord& n = networks[i];

    json += "{\"ssid\":\"" + DefenseText::jsonEscape(n.ssid) + "\"";
    json += ",\"bssid\":\"" + DefenseText::jsonEscape(n.bssid) + "\"";
    json += ",\"rssi\":" + String(n.rssi);
    json += ",\"channel\":" + String(n.channel);
    json += ",\"security\":\"" + DefenseText::jsonEscape(n.security) + "\"}";
  }

  return json + "]";
}

size_t wifiScannerCount() {
  return networkCount;
}

int32_t wifiScannerStrongestRssi() {
  return strongest;
}

uint8_t wifiScannerOpenCount() {
  return openNetworks;
}
