#include <Arduino.h>
#include <Preferences.h>

#include "config.h"
#include "crypto_store.h"
#include "storage.h"
#include "text_utils.h"

namespace {
Preferences prefs;
constexpr uint8_t LOG_COUNT = DefenseConfig::MAX_LOGS;
uint32_t bootSequence = 0;

String logKey(uint8_t index) {
  return "log" + String(index);
}

String readProtected(const char* key, const char* fallback) {
  const String stored = prefs.getString(key, "");
  if (!stored.length()) return String(fallback);

  const String plain = unprotectSecret(stored);
  return plain.length() ? plain : String(fallback);
}
}

void storageBegin() {
  prefs.begin("def-lab", false);
  bootSequence = prefs.getUInt("boot_seq", 0) + 1;
  prefs.putUInt("boot_seq", bootSequence);

  const char* secretKeys[] = {"ap_pass", "admin_pass"};
  for (const char* key : secretKeys) {
    const String value = prefs.getString(key, "");
    if (value.length() && !isProtectedSecret(value)) {
      const String protectedValue = protectSecret(value);
      if (protectedValue.length()) prefs.putString(key, protectedValue);
    }
  }
}

String getApSsid() {
  return prefs.getString("ap_ssid", DefenseConfig::DEFAULT_AP_SSID);
}

String getApPassword() {
  return readProtected("ap_pass", DefenseConfig::DEFAULT_AP_PASSWORD);
}

String getAdminUser() {
  return prefs.getString("admin_user", DefenseConfig::DEFAULT_ADMIN_USER);
}

String getAdminPassword() {
  return readProtected("admin_pass", DefenseConfig::DEFAULT_ADMIN_PASSWORD);
}

uint8_t getMonitorChannel() {
  uint8_t channel = prefs.getUChar("channel", DefenseConfig::DEFAULT_MONITOR_CHANNEL);
  if (channel < 1 || channel > 13) channel = DefenseConfig::DEFAULT_MONITOR_CHANNEL;
  return channel;
}

uint16_t getAlertThreshold() {
  uint16_t value = prefs.getUShort("threshold", DefenseConfig::DEFAULT_ALERT_THRESHOLD);
  if (value < 3 || value > 200) value = DefenseConfig::DEFAULT_ALERT_THRESHOLD;
  return value;
}

bool initialSetupRequired() {
  return
    getApPassword() == DefenseConfig::DEFAULT_AP_PASSWORD ||
    getAdminPassword() == DefenseConfig::DEFAULT_ADMIN_PASSWORD;
}

bool setInitialCredentials(
  const String& apSsid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
) {
  if (
    apSsid.length() == 0 || apSsid.length() > 32 ||
    apPassword.length() < 8 || apPassword.length() > 63 ||
    adminUser.length() == 0 || adminUser.length() > 32 ||
    adminPassword.length() < 8 || adminPassword.length() > 64 ||
    apPassword == adminPassword ||
    apPassword == DefenseConfig::DEFAULT_AP_PASSWORD ||
    adminPassword == DefenseConfig::DEFAULT_ADMIN_PASSWORD
  ) {
    return false;
  }

  const String protectedAp = protectSecret(apPassword);
  const String protectedAdmin = protectSecret(adminPassword);
  if (!protectedAp.length() || !protectedAdmin.length()) return false;

  bool ok = true;
  ok &= prefs.putString("ap_ssid", apSsid) > 0;
  ok &= prefs.putString("ap_pass", protectedAp) > 0;
  ok &= prefs.putString("admin_user", adminUser) > 0;
  ok &= prefs.putString("admin_pass", protectedAdmin) > 0;
  return ok;
}

bool setMonitorChannel(uint8_t channel) {
  if (channel < 1 || channel > 13) return false;
  return prefs.putUChar("channel", channel) > 0;
}

bool setAlertThreshold(uint16_t threshold) {
  if (threshold < 3 || threshold > 200) return false;
  return prefs.putUShort("threshold", threshold) > 0;
}

void appendEventLog(const String& type, const String& message) {
  uint8_t head = prefs.getUChar("log_head", 0);
  uint8_t count = prefs.getUChar("log_count", 0);

  String safeType = type;
  String safeMessage = message;
  safeType.replace("|", "/");
  safeMessage.replace("|", "/");
  safeMessage.replace("\n", " ");
  safeMessage.replace("\r", " ");

  const String entry =
    String(bootSequence) + "|" +
    String(millis() / 1000UL) + "|" +
    safeType + "|" +
    safeMessage;

  prefs.putString(logKey(head).c_str(), entry);
  head = static_cast<uint8_t>((head + 1) % LOG_COUNT);
  if (count < LOG_COUNT) ++count;
  prefs.putUChar("log_head", head);
  prefs.putUChar("log_count", count);
}

String getEventLogJson() {
  const uint8_t head = prefs.getUChar("log_head", 0);
  const uint8_t count = prefs.getUChar("log_count", 0);

  String json = "[";
  for (uint8_t i = 0; i < count; ++i) {
    const int index = (head + LOG_COUNT - count + i) % LOG_COUNT;
    const String entry = prefs.getString(logKey(index).c_str(), "");

    int p1 = entry.indexOf('|');
    int p2 = entry.indexOf('|', p1 + 1);
    int p3 = entry.indexOf('|', p2 + 1);
    if (p1 < 0 || p2 < 0 || p3 < 0) continue;

    if (json.length() > 1) json += ",";
    json += "{\"boot\":" + entry.substring(0, p1);
    json += ",\"seconds\":" + entry.substring(p1 + 1, p2);
    json += ",\"type\":\"" + DefenseText::jsonEscape(entry.substring(p2 + 1, p3)) + "\"";
    json += ",\"message\":\"" + DefenseText::jsonEscape(entry.substring(p3 + 1)) + "\"}";
  }
  return json + "]";
}

void clearEventLogs() {
  for (uint8_t i = 0; i < LOG_COUNT; ++i) {
    prefs.remove(logKey(i).c_str());
  }
  prefs.putUChar("log_head", 0);
  prefs.putUChar("log_count", 0);
}

void factoryResetStorage() {
  prefs.clear();

  Preferences secure;
  if (secure.begin("def-sec", false)) {
    secure.clear();
    secure.end();
  }
}
