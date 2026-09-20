#pragma once
#include <Arduino.h>

namespace DefenseConfig {
constexpr char PROJECT_NAME[] = "ESP32 Wireless Defense Lab";
constexpr char VERSION[] = "1.0.0";

constexpr char DEFAULT_AP_SSID[] = "ESP32-Defense-Lab";
constexpr char DEFAULT_AP_PASSWORD[] = "defenselab";
constexpr char DEFAULT_ADMIN_USER[] = "admin";
constexpr char DEFAULT_ADMIN_PASSWORD[] = "changeme32";

constexpr uint8_t AP_IP_A = 192;
constexpr uint8_t AP_IP_B = 168;
constexpr uint8_t AP_IP_C = 4;
constexpr uint8_t AP_IP_D = 1;

constexpr uint8_t DEFAULT_MONITOR_CHANNEL = 1;
constexpr uint16_t DEFAULT_ALERT_THRESHOLD = 10;
constexpr uint32_t DETECTION_WINDOW_MS = 5000;
constexpr uint32_t ALERT_COOLDOWN_MS = 10000;

constexpr size_t MAX_NETWORKS = 40;
constexpr size_t MAX_ALERTS = 32;
constexpr size_t MAX_SOURCES = 16;
constexpr size_t MAX_PENDING_ALERTS = 16;
constexpr size_t MAX_LOGS = 24;
}
