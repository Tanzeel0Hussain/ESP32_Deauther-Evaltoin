#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>

#include "storage.h"
#include "config.h"
#include "crypto_store.h"
#include "text_utils.h"

namespace {
Preferences prefs;
constexpr uint8_t MAX_LOGS = 24;

String logKey(uint8_t index) {
  return "log" + String(index);
}

bool validCredentials(
  const String& ssid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
) {
  return
    ssid.length() >= 1 &&
    ssid.length() <= 32 &&
    apPassword.length() >= 8 &&
    apPassword.length() <= 63 &&
    adminUser.length() >= 1 &&
    adminUser.length() <= 32 &&
    adminPassword.length() >= 8 &&
    adminPassword.length() <= 64 &&
    apPassword != adminPassword;
}

bool saveCredentialsInternal(
  const String& ssid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
) {
  if (!validCredentials(ssid, apPassword, adminUser, adminPassword)) {
    return false;
  }

  const String protectedAp = defenseProtectSecret(apPassword);
  const String protectedAdmin = defenseProtectSecret(adminPassword);

  if (!protectedAp.length() || !protectedAdmin.length()) {
    return false;
  }

  bool ok = true;
  ok &= prefs.putString("ap_ssid", ssid) > 0;
  ok &= prefs.putString("ap_pass", protectedAp) > 0;
  ok &= prefs.putString("admin_user", adminUser) > 0;
  ok &= prefs.putString("admin_pass", protectedAdmin) > 0;
  return ok;
}
}

void defenseStorageBegin() {
  prefs.begin("deflab", false);

  if (!prefs.isKey("ap_ssid")) {
    saveCredentialsInternal(
      DefenseConfig::DEFAULT_AP_SSID,
      DefenseConfig::DEFAULT_AP_PASSWORD,
      DefenseConfig::DEFAULT_ADMIN_USER,
      DefenseConfig::DEFAULT_ADMIN_PASSWORD
    );
  }

  if (!prefs.isKey("threshold")) {
    prefs.putUShort(
      "threshold",
      DefenseConfig::DEFAULT_ALERT_THRESHOLD
    );
  }

  if (!prefs.isKey("channel")) {
    prefs.putUChar(
      "channel",
      DefenseConfig::DEFAULT_CHANNEL
    );
  }

  const String apStored = prefs.getString("ap_pass", "");
  const String adminStored = prefs.getString("admin_pass", "");

  if (apStored.length() && !defenseSecretProtected(apStored)) {
    prefs.putString("ap_pass", defenseProtectSecret(apStored));
  }

  if (adminStored.length() && !defenseSecretProtected(adminStored)) {
    prefs.putString("admin_pass", defenseProtectSecret(adminStored));
  }
}

String defenseApSsid() {
  return prefs.getString(
    "ap_ssid",
    DefenseConfig::DEFAULT_AP_SSID
  );
}

String defenseApPassword() {
  const String value =
    defenseUnprotectSecret(
      prefs.getString("ap_pass", "")
    );

  return value.length()
    ? value
    : String(DefenseConfig::DEFAULT_AP_PASSWORD);
}

String defenseAdminUser() {
  return prefs.getString(
    "admin_user",
    DefenseConfig::DEFAULT_ADMIN_USER
  );
}

String defenseAdminPassword() {
  const String value =
    defenseUnprotectSecret(
      prefs.getString("admin_pass", "")
    );

  return value.length()
    ? value
    : String(DefenseConfig::DEFAULT_ADMIN_PASSWORD);
}

bool defenseInitialSetupRequired() {
  return
    defenseApPassword() == DefenseConfig::DEFAULT_AP_PASSWORD ||
    defenseAdminPassword() == DefenseConfig::DEFAULT_ADMIN_PASSWORD;
}

bool defenseSaveInitialCredentials(
  const String& ssid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
) {
  if (
    apPassword == DefenseConfig::DEFAULT_AP_PASSWORD ||
    adminPassword == DefenseConfig::DEFAULT_ADMIN_PASSWORD
  ) {
    return false;
  }

  return saveCredentialsInternal(
    ssid,
    apPassword,
    adminUser,
    adminPassword
  );
}

bool defenseSaveCredentials(
  const String& ssid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
) {
  return saveCredentialsInternal(
    ssid,
    apPassword,
    adminUser,
    adminPassword
  );
}

uint16_t defenseAlertThreshold() {
  uint16_t value =
    prefs.getUShort(
      "threshold",
      DefenseConfig::DEFAULT_ALERT_THRESHOLD
    );

  if (value < 3) value = 3;
  if (value > 200) value = 200;
  return value;
}

bool defenseSetAlertThreshold(uint16_t threshold) {
  if (threshold < 3 || threshold > 200) return false;
  return prefs.putUShort("threshold", threshold) > 0;
}

uint8_t defenseMonitorChannel() {
  uint8_t channel =
    prefs.getUChar(
      "channel",
      DefenseConfig::DEFAULT_CHANNEL
    );

  if (channel < 1 || channel > 13) {
    channel = DefenseConfig::DEFAULT_CHANNEL;
  }

  return channel;
}

bool defenseSetMonitorChannel(uint8_t channel) {
  if (channel < 1 || channel > 13) return false;
  return prefs.putUChar("channel", channel) > 0;
}

void defenseFactoryReset() {
  prefs.clear();

  Preferences secure;
  if (secure.begin("def-sec", false)) {
    secure.clear();
    secure.end();
  }
}

void defenseAppendLog(const String& type, const String& message) {
  uint8_t head = prefs.getUChar("log_head", 0);
  uint8_t count = prefs.getUChar("log_count", 0);

  String safeType = type;
  String safeMessage = message;
  safeType.replace("|", "/");
  safeMessage.replace("|", "/");
  safeMessage.replace("\n", " ");
  safeMessage.replace("\r", " ");

  const String entry =
    String(millis() / 1000UL) + "|" +
    safeType + "|" +
    safeMessage;

  prefs.putString(logKey(head).c_str(), entry);
  head = static_cast<uint8_t>((head + 1) % MAX_LOGS);
  if (count < MAX_LOGS) ++count;

  prefs.putUChar("log_head", head);
  prefs.putUChar("log_count", count);
}

String defenseLogsJson() {
  const uint8_t head = prefs.getUChar("log_head", 0);
  const uint8_t count = prefs.getUChar("log_count", 0);

  String json = "[";
  json.reserve(256 + count * 140);

  for (uint8_t n = 0; n < count; ++n) {
    const int index =
      (head + MAX_LOGS - 1 - n) % MAX_LOGS;

    const String entry =
      prefs.getString(logKey(index).c_str(), "");

    int first = entry.indexOf('|');
    int second = entry.indexOf('|', first + 1);

    if (first < 0 || second < 0) continue;

    if (json.length() > 1) json += ",";

    json +=
      "{\"seconds\":" +
      entry.substring(0, first) +
      ",\"type\":\"" +
      DefenseText::jsonEscape(
        entry.substring(first + 1, second)
      ) +
      "\",\"message\":\"" +
      DefenseText::jsonEscape(
        entry.substring(second + 1)
      ) +
      "\"}";
  }

  json += "]";
  return json;
}

void defenseClearLogs() {
  for (uint8_t i = 0; i < MAX_LOGS; ++i) {
    prefs.remove(logKey(i).c_str());
  }

  prefs.putUChar("log_head", 0);
  prefs.putUChar("log_count", 0);
}
