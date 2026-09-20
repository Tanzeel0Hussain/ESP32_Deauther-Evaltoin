#include <Arduino.h>
#include <WiFi.h>

extern "C" {
#include "esp_wifi.h"
}

#include "config.h"
#include "detector.h"
#include "models.h"
#include "scanner_logic.h"
#include "storage.h"
#include "text_utils.h"
#include "wifi_scanner.h"

namespace {
NetworkRecord networks[
  DefenseConfig::MAX_NETWORKS
];

size_t networkCount = 0;
int32_t strongest = -127;
uint8_t openNetworks = 0;

bool scanning = false;
bool lastScanOk = false;
int32_t lastScanError = 0;
uint32_t lastScanMs = 0;

String authName(
  wifi_auth_mode_t mode
) {
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
    case WIFI_AUTH_WPA2_ENTERPRISE:
      return "WPA2-Enterprise";
    case WIFI_AUTH_WPA3_PSK:
      return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:
      return "WPA2/WPA3";
    default:
      return "Unknown";
  }
}

bool restoreRadio(
  bool detectorWasPaused
) {
  const auto action =
    ScannerLogic::restoreAction(
      detectorWasPaused
    );

  if (
    action ==
    ScannerLogic::RestoreAction::
      RestoreChannelOnly
  ) {
    const esp_err_t error =
      esp_wifi_set_channel(
        getMonitorChannel(),
        WIFI_SECOND_CHAN_NONE
      );

    if (error != ESP_OK) {
      lastScanError =
        static_cast<int32_t>(
          error
        );
      return false;
    }

    return true;
  }

  if (!detectorResume()) {
    lastScanError =
      detectorLastError();

    if (
      lastScanError == ESP_OK
    ) {
      lastScanError = -1001;
    }

    return false;
  }

  return true;
}

void finishScan(
  int found,
  bool restored
) {
  lastScanOk =
    ScannerLogic::scanSucceeded(
      found,
      restored
    );

  if (
    found < 0 &&
    lastScanError == 0
  ) {
    lastScanError = found;
  }

  if (lastScanOk) {
    lastScanError = 0;
  }

  lastScanMs = millis();
  scanning = false;
}
}

void wifiScannerBegin() {
  wifiScannerRun();
}

void wifiScannerLoop() {}

bool wifiScannerRun() {
  if (scanning) {
    lastScanError = -1002;
    return false;
  }

  scanning = true;
  lastScanError = 0;

  const bool wasPaused =
    detectorPaused();

  if (
    !wasPaused &&
    !detectorPause()
  ) {
    lastScanError =
      detectorLastError();

    if (
      lastScanError == ESP_OK
    ) {
      lastScanError = -1003;
    }

    finishScan(
      -1,
      false
    );

    return false;
  }

  const int found =
    WiFi.scanNetworks(
      false,
      true,
      true,
      180
    );

  if (found >= 0) {
    networkCount = 0;
    strongest = -127;
    openNetworks = 0;

    for (
      int i = 0;
      i < found &&
      networkCount <
        DefenseConfig::
          MAX_NETWORKS;
      ++i
    ) {
      NetworkRecord& n =
        networks[
          networkCount++
        ];

      n.ssid =
        WiFi.SSID(i);

      n.bssid =
        WiFi.BSSIDstr(i);

      n.rssi =
        WiFi.RSSI(i);

      n.channel =
        WiFi.channel(i);

      n.security =
        authName(
          WiFi.encryptionType(i)
        );

      if (
        n.rssi > strongest
      ) {
        strongest = n.rssi;
      }

      if (
        WiFi.encryptionType(i) ==
        WIFI_AUTH_OPEN
      ) {
        ++openNetworks;
      }
    }
  }

  WiFi.scanDelete();

  const bool restored =
    restoreRadio(
      wasPaused
    );

  finishScan(
    found,
    restored
  );

  return lastScanOk;
}

String wifiScannerJson() {
  String json;

  json.reserve(
    256 +
    networkCount * 140
  );

  json = "[";

  for (
    size_t i = 0;
    i < networkCount;
    ++i
  ) {
    if (i) {
      json += ",";
    }

    const NetworkRecord& n =
      networks[i];

    json +=
      "{\"ssid\":\"" +
      DefenseText::jsonEscape(
        n.ssid
      ) +
      "\"";

    json +=
      ",\"bssid\":\"" +
      DefenseText::jsonEscape(
        n.bssid
      ) +
      "\"";

    json +=
      ",\"rssi\":" +
      String(n.rssi);

    json +=
      ",\"channel\":" +
      String(n.channel);

    json +=
      ",\"security\":\"" +
      DefenseText::jsonEscape(
        n.security
      ) +
      "\"}";
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

bool wifiScannerScanning() {
  return scanning;
}

bool wifiScannerLastOk() {
  return lastScanOk;
}

int32_t wifiScannerLastError() {
  return lastScanError;
}

uint32_t wifiScannerLastScanMs() {
  return lastScanMs;
}

String wifiScannerStatus() {
  if (scanning) {
    return "scanning";
  }

  if (!lastScanMs) {
    return "not-run";
  }

  return lastScanOk
    ? "ok"
    : "error";
}
