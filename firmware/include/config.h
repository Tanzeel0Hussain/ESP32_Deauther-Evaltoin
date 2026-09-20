#pragma once
#include <Arduino.h>

namespace DefenseConfig {
constexpr char PRODUCT_NAME[] = "ESP32 Wireless Defense Lab";
constexpr char VERSION[] = "1.0.0";
constexpr char DEFAULT_AP_SSID[] = "ESP32-Defense-Lab";
constexpr char DEFAULT_AP_PASSWORD[] = "defenselab";
constexpr char DEFAULT_ADMIN_USER[] = "admin";
constexpr char DEFAULT_ADMIN_PASSWORD[] = "changeme32";
constexpr uint8_t DEFAULT_MONITOR_CHANNEL = 1;
constexpr size_t MAX_NETWORKS = 32;
constexpr size_t MAX_ALERTS = 32;
constexpr size_t MAX_TRACKERS = 20;
constexpr size_t MAX_PENDING_ALERTS = 10;
constexpr uint32_t DETECTION_WINDOW_MS = 2000;
constexpr uint16_t ALERT_THRESHOLD = 12;
constexpr uint16_t HIGH_ALERT_THRESHOLD = 30;
constexpr uint32_t ALERT_COOLDOWN_MS = 5000;
constexpr uint32_t AUTO_SCAN_INTERVAL_MS = 60000;
}
