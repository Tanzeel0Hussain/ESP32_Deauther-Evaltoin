#include <Arduino.h>
#include <Preferences.h>

extern "C" {
#include "esp_system.h"
}

#include "storage.h"
#include "config.h"
#include "crypto_store.h"

namespace {
Preferences prefs;
bool recoveryMode = false;
String recoveryApSsid;
String recoveryApPassword;
String recoveryAdminPassword;

String randomPassword(size_t length) {
  static const char alphabet[] =
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
    "23456789";

  String value;
  value.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    value += alphabet[esp_random() % (sizeof(alphabet) - 1)];
  }
  return value;
}

void ensureRecovery() {
  if (recoveryApPassword.length() >= 12 && recoveryAdminPassword.length() >= 12) return;

  const uint64_t chipId = ESP.getEfuseMac();
  char suffix[9];
  snprintf(
    suffix,
    sizeof(suffix),
    "%08lX",
    static_cast<unsigned long>(chipId & 0xFFFFFFFFULL)
  );

  recoveryApSsid = "DefenseLab-Recovery-" + String(suffix).substring(4);
  recoveryApPassword = randomPassword(16);
  recoveryAdminPassword = randomPassword(18);
}

void enterRecovery(const char* reason) {
  if (recoveryMode) return;
  recoveryMode = true;
  ensureRecovery();

  Serial.println();
  Serial.println("=== ESP32 Defense Lab recovery ===");
  Serial.println(reason);
  Serial.print("Recovery Wi-Fi: ");
  Serial.println(recoveryApSsid);
  Serial.print("Recovery Wi-Fi password: ");
  Serial.println(recoveryApPassword);
  Serial.println("Recovery admin username: admin");
  Serial.print("Recovery admin password: ");
  Serial.println(recoveryAdminPassword);
  Serial.println("Open http://192.168.4.1");
  Serial.println("==================================");
}

String readProtected(const char* key) {
  const String stored = prefs.getString(key, "");
  return stored.length() ? unprotectSecret(stored) : "";
}
}

void storageBegin() {
  prefs.begin("deflab", false);

  if (!prefs.getString("ap_pass", "").length()) {
    prefs.putString("ap_pass", protectSecret(DefenseLabConfig::DEFAULT_AP_PASSWORD));
  }

  if (!prefs.getString("admin_pass", "").length()) {
    prefs.putString("admin_pass", protectSecret(DefenseLabConfig::DEFAULT_ADMIN_PASSWORD));
  }

  if (!readProtected("ap_pass").length() || !readProtected("admin_pass").length()) {
    enterRecovery("Stored credentials could not be decrypted.");
  }
}

String storageGetApSsid() {
  if (recoveryMode) {
    ensureRecovery();
    return recoveryApSsid;
  }
  return prefs.getString("ap_ssid", DefenseLabConfig::DEFAULT_AP_SSID);
}

String storageGetApPassword() {
  if (recoveryMode) {
    ensureRecovery();
    return recoveryApPassword;
  }

  const String value = readProtected("ap_pass");
  if (value.length()) return value;

  enterRecovery("Management Wi-Fi credential failure.");
  return recoveryApPassword;
}

String storageGetAdminUser() {
  return recoveryMode
    ? String("admin")
    : prefs.getString("admin_user", DefenseLabConfig::DEFAULT_ADMIN_USER);
}

String storageGetAdminPassword() {
  if (recoveryMode) {
    ensureRecovery();
    return recoveryAdminPassword;
  }

  const String value = readProtected("admin_pass");
  if (value.length()) return value;

  enterRecovery("Administrator credential failure.");
  return recoveryAdminPassword;
}

bool storageInitialSetupRequired() {
  if (recoveryMode) return true;
  return
    storageGetApPassword() == DefenseLabConfig::DEFAULT_AP_PASSWORD ||
    storageGetAdminPassword() == DefenseLabConfig::DEFAULT_ADMIN_PASSWORD;
}

bool storageRecoveryRequired() {
  return recoveryMode;
}

bool storageSetInitialCredentials(
  const String& ssid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
) {
  if (
    ssid.length() == 0 || ssid.length() > 32 ||
    apPassword.length() < 8 || apPassword.length() > 63 ||
    adminUser.length() == 0 || adminUser.length() > 32 ||
    adminPassword.length() < 8 || adminPassword.length() > 64 ||
    apPassword == adminPassword ||
    apPassword == DefenseLabConfig::DEFAULT_AP_PASSWORD ||
    adminPassword == DefenseLabConfig::DEFAULT_ADMIN_PASSWORD
  ) return false;

  const String protectedAp = protectSecret(apPassword);
  const String protectedAdmin = protectSecret(adminPassword);
  if (!protectedAp.length() || !protectedAdmin.length()) return false;

  const bool ok =
    prefs.putString("ap_ssid", ssid) > 0 &&
    prefs.putString("ap_pass", protectedAp) > 0 &&
    prefs.putString("admin_user", adminUser) > 0 &&
    prefs.putString("admin_pass", protectedAdmin) > 0;

  if (ok) {
    recoveryMode = false;
    recoveryApSsid = "";
    recoveryApPassword = "";
    recoveryAdminPassword = "";
  }

  return ok;
}

bool storageSetApCredentials(const String& ssid, const String& password) {
  if (
    ssid.length() == 0 || ssid.length() > 32 ||
    password.length() < 8 || password.length() > 63 ||
    password == storageGetAdminPassword()
  ) return false;

  const String protectedValue = protectSecret(password);
  if (!protectedValue.length()) return false;

  return
    prefs.putString("ap_ssid", ssid) > 0 &&
    prefs.putString("ap_pass", protectedValue) > 0;
}

bool storageSetAdminCredentials(const String& username, const String& password) {
  if (
    username.length() == 0 || username.length() > 32 ||
    password.length() < 8 || password.length() > 64 ||
    password == storageGetApPassword()
  ) return false;

  const String protectedValue = protectSecret(password);
  if (!protectedValue.length()) return false;

  return
    prefs.putString("admin_user", username) > 0 &&
    prefs.putString("admin_pass", protectedValue) > 0;
}

uint8_t storageGetMonitorChannel() {
  uint8_t channel = prefs.getUChar("channel", DefenseLabConfig::DEFAULT_MONITOR_CHANNEL);
  if (
    channel < DefenseLabConfig::MIN_MONITOR_CHANNEL ||
    channel > DefenseLabConfig::MAX_MONITOR_CHANNEL
  ) channel = DefenseLabConfig::DEFAULT_MONITOR_CHANNEL;
  return channel;
}

bool storageSetMonitorChannel(uint8_t channel) {
  if (
    channel < DefenseLabConfig::MIN_MONITOR_CHANNEL ||
    channel > DefenseLabConfig::MAX_MONITOR_CHANNEL
  ) return false;
  return prefs.putUChar("channel", channel) > 0;
}

uint16_t storageGetAlertThreshold() {
  uint16_t threshold = prefs.getUShort("threshold", DefenseLabConfig::DEFAULT_ALERT_THRESHOLD);
  if (
    threshold < DefenseLabConfig::MIN_ALERT_THRESHOLD ||
    threshold > DefenseLabConfig::MAX_ALERT_THRESHOLD
  ) threshold = DefenseLabConfig::DEFAULT_ALERT_THRESHOLD;
  return threshold;
}

bool storageSetAlertThreshold(uint16_t threshold) {
  if (
    threshold < DefenseLabConfig::MIN_ALERT_THRESHOLD ||
    threshold > DefenseLabConfig::MAX_ALERT_THRESHOLD
  ) return false;
  return prefs.putUShort("threshold", threshold) > 0;
}

void storageFactoryReset() {
  prefs.clear();

  Preferences secure;
  if (secure.begin("defsec", false)) {
    secure.clear();
    secure.end();
  }

  recoveryMode = false;
  recoveryApSsid = "";
  recoveryApPassword = "";
  recoveryAdminPassword = "";
}
