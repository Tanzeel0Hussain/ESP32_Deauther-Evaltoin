#pragma once
#include <Arduino.h>

struct NetworkRecord {
  String ssid;
  String bssid;
  int32_t rssi = -127;
  uint8_t channel = 1;
  bool secure = false;
};

struct ThreatStats {
  uint64_t managementFrames = 0;
  uint64_t deauthFrames = 0;
  uint64_t disassocFrames = 0;
  uint32_t windowDeauth = 0;
  uint32_t windowDisassoc = 0;
  uint32_t windowTotal = 0;
  int32_t lastRssi = -127;
  uint8_t currentChannel = 1;
  String topSource = "";
  String level = "Normal";
  unsigned long uptimeSeconds = 0;
};

struct AlertRecord {
  unsigned long createdAtMs = 0;
  String source;
  uint8_t channel = 1;
  int32_t rssi = -127;
  uint32_t deauthCount = 0;
  uint32_t disassocCount = 0;
  String level;
};
