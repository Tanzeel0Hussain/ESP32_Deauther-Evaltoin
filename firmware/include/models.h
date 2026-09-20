#pragma once
#include <Arduino.h>

struct NetworkRecord {
  String ssid;
  String bssid;
  int32_t rssi = -127;
  uint8_t channel = 0;
  String security;
};

struct AlertRecord {
  uint32_t id = 0;
  uint32_t uptimeMs = 0;
  char bssid[18] = {};
  char source[18] = {};
  char destination[18] = {};
  uint16_t reason = 0;
  uint16_t burstCount = 0;
  int8_t rssi = -127;
  uint8_t channel = 0;
  uint8_t subtype = 0;
  bool protectedFrame = false;
};
