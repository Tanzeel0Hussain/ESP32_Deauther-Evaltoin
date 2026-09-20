#include <Arduino.h>
#include <WiFi.h>

extern "C" {
#include "esp_wifi.h"
}

#include "wifi_scanner.h"
#include "config.h"
#include "models.h"
#include "storage.h"
#include "text_utils.h"

namespace {
NetworkRecord networks[DefenseLabConfig::MAX_SCAN_RESULTS];
size_t networkCount = 0;

String securityLabel(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
#ifdef WIFI_AUTH_WPA3_PSK
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
#endif
#ifdef WIFI_AUTH_WPA2_WPA3_PSK
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
#endif
    default: return "Secured";
  }
}
}

void wifiScannerBegin() {
  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);

  IPAddress ip(
    DefenseLabConfig::AP_IP_A,
    DefenseLabConfig::AP_IP_B,
    DefenseLabConfig::AP_IP_C,
    DefenseLabConfig::AP_IP_D
  );

  IPAddress mask(255, 255, 255, 0);
  WiFi.softAPConfig(ip, ip, mask);

  const uint8_t channel = storageGetMonitorChannel();

  WiFi.softAP(
    storageGetApSsid().c_str(),
    storageGetApPassword().c_str(),
    channel,
    false,
    4
  );

  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  Serial.print("Management AP: ");
  Serial.println(storageGetApSsid());
  Serial.print("Dashboard: http://");
  Serial.println(WiFi.softAPIP());
  Serial.print("Monitor channel: ");
  Serial.println(channel);
}

bool wifiScannerScan() {
  networkCount = 0;

  const int found = WiFi.scanNetworks(false, true);

  if (found < 0) {
    WiFi.scanDelete();
    wifiScannerRestoreMonitorChannel();
    return false;
  }

  const size_t count =
    static_cast<size_t>(found) > DefenseLabConfig::MAX_SCAN_RESULTS
      ? DefenseLabConfig::MAX_SCAN_RESULTS
      : static_cast<size_t>(found);

  for (size_t i = 0; i < count; ++i) {
    NetworkRecord record;
    record.ssid = WiFi.SSID(static_cast<int>(i));
    record.bssid = WiFi.BSSIDstr(static_cast<int>(i));
    record.rssi = WiFi.RSSI(static_cast<int>(i));
    record.channel = static_cast<uint8_t>(WiFi.channel(static_cast<int>(i)));
    record.security = securityLabel(WiFi.encryptionType(static_cast<int>(i)));
    networks[networkCount++] = record;
  }

  WiFi.scanDelete();
  wifiScannerRestoreMonitorChannel();
  return true;
}

void wifiScannerRestoreMonitorChannel() {
  esp_wifi_set_channel(
    storageGetMonitorChannel(),
    WIFI_SECOND_CHAN_NONE
  );
}

size_t wifiScannerNetworkCount() {
  return networkCount;
}

uint8_t wifiScannerCurrentChannel() {
  return storageGetMonitorChannel();
}

String wifiScannerNetworksJson() {
  String json;
  json.reserve(128 + networkCount * 170);
  json = "[";

  for (size_t i = 0; i < networkCount; ++i) {
    if (i) json += ",";
    const NetworkRecord& network = networks[i];

    json +=
      "{\"ssid\":\"" + DefenseLabText::jsonEscape(network.ssid) +
      "\",\"bssid\":\"" + DefenseLabText::jsonEscape(network.bssid) +
      "\",\"rssi\":" + String(network.rssi) +
      ",\"channel\":" + String(network.channel) +
      ",\"security\":\"" + DefenseLabText::jsonEscape(network.security) +
      "\"}";
  }

  return json + "]";
}

String wifiScannerChannelsJson() {
  uint16_t counts[14] = {};
  int32_t rssiSum[14] = {};

  for (size_t i = 0; i < networkCount; ++i) {
    const uint8_t channel = networks[i].channel;
    if (channel >= 1 && channel <= 13) {
      ++counts[channel];
      rssiSum[channel] += networks[i].rssi;
    }
  }

  String json = "[";

  for (uint8_t channel = 1; channel <= 13; ++channel) {
    if (channel > 1) json += ",";

    const int32_t average =
      counts[channel] ? rssiSum[channel] / counts[channel] : -127;

    json +=
      "{\"channel\":" + String(channel) +
      ",\"networks\":" + String(counts[channel]) +
      ",\"avgRssi\":" + String(average) +
      "}";
  }

  return json + "]";
}
