#pragma once
#include <Arduino.h>

namespace DefenseLabConfig {
constexpr char PROJECT_NAME[] = "ESP32 Wireless Defense Lab";
constexpr char VERSION[] = "1.0.0";
constexpr char DEFAULT_AP_SSID[] = "ESP32-Defense-Lab";
constexpr char DEFAULT_AP_PASSWORD[] = "defenselab32";
constexpr char DEFAULT_ADMIN_USER[] = "admin";
constexpr char DEFAULT_ADMIN_PASSWORD[] = "change-me-32";
constexpr uint8_t DEFAULT_MONITOR_CHANNEL = 6;
constexpr uint16_t DEFAULT_ALERT_THRESHOLD = 15;
constexpr uint8_t MIN_MONITOR_CHANNEL = 1;
constexpr uint8_t MAX_MONITOR_CHANNEL = 13;
constexpr uint16_t MIN_ALERT_THRESHOLD = 5;
constexpr uint16_t MAX_ALERT_THRESHOLD = 200;
constexpr uint16_t ALERT_WINDOW_MS = 10000;
constexpr size_t MAX_SCAN_RESULTS = 32;
constexpr size_t MAX_ALERTS = 30;
constexpr size_t RAW_EVENT_QUEUE = 64;
constexpr uint8_t AP_IP_A = 192;
constexpr uint8_t AP_IP_B = 168;
constexpr uint8_t AP_IP_C = 4;
constexpr uint8_t AP_IP_D = 1;
}
