#pragma once
#include <Arduino.h>

namespace DefenseConfig {
constexpr char PROJECT_NAME[] = "ESP32 Wireless Defense Lab";
constexpr char VERSION[] = "1.0.0";

constexpr char DEFAULT_AP_SSID[] = "ESP32-Defense-Lab";
constexpr char DEFAULT_AP_PASSWORD[] = "defenselab32";
constexpr char DEFAULT_ADMIN_USER[] = "admin";
constexpr char DEFAULT_ADMIN_PASSWORD[] = "defenseadmin32";

constexpr uint8_t DEFAULT_CHANNEL = 1;
constexpr uint16_t DEFAULT_ALERT_THRESHOLD = 12;
constexpr uint16_t CRITICAL_MULTIPLIER = 3;

constexpr uint8_t MAX_SCAN_RESULTS = 32;
constexpr uint8_t MAX_SOURCES = 16;
constexpr uint8_t MAX_ALERTS = 24;

constexpr unsigned long DETECTION_WINDOW_MS = 10000;
constexpr unsigned long DISPLAY_REFRESH_MS = 1000;
}
