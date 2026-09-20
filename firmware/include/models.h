#pragma once
#include <Arduino.h>

struct NetworkRecord {
  String ssid;
  String bssid;
  String security;
  int32_t rssi = -127;
  uint8_t channel = 0;
  bool hidden = false;
};

struct AlertRecord {
  uint32_t id = 0;
  uint32_t uptimeSeconds = 0;
  String source;
  String frameType;
  String severity;
  int32_t rssi = -127;
  uint8_t channel = 0;
  uint16_t framesInWindow = 0;
  bool broadcastDestination = false;
};

struct ChannelRecord {
  uint32_t managementFrames = 0;
  uint32_t suspiciousFrames = 0;
};
