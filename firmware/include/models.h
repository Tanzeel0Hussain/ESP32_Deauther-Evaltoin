#pragma once
#include <Arduino.h>

struct NetworkRecord {
  String ssid;
  String bssid;
  int32_t rssi = -127;
  uint8_t channel = 0;
  String security;
};

struct DefenseAlert {
  uint32_t sequence = 0;
  uint32_t uptimeSeconds = 0;
  String source;
  String bssid;
  int32_t rssi = -127;
  uint8_t channel = 0;
  uint8_t subtype = 0;
  uint16_t windowCount = 0;
};
