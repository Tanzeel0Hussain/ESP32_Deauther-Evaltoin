#include <Arduino.h>
#include <Preferences.h>
#include <esp_system.h>

#include "config.h"
#include "crypto_store.h"
#include "storage.h"
#include "text_utils.h"

namespace {
Preferences prefs;
constexpr uint8_t LOG_COUNT = DefenseConfig::MAX_LOGS;
uint32_t bootSequence = 0;
bool recoveryMode = false;
String recoveryApSsid;
String recoveryApPassword;
String recoveryAdminPassword;

String randomRecoveryPassword(size_t length) {
  static const char alphabet[] =
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
    "23456789";

  String value;
  value.reserve(length);

  for (size_t i = 0; i < length; ++i) {
    value += alphabet[
      esp_random() % (sizeof(alphabet) - 1)
    ];
  }

  return value;
}

void ensureRecoveryCredentials() {
  if (
    recoveryApPassword.length() >= 12 &&
    recoveryAdminPassword.length() >= 12
  ) {
    return;
  }

  const uint64_t chipId = ESP.getEfuseMac();
  char suffix[9];

  snprintf(
    suffix,
    sizeof(suffix),
    "%08lX",
    static_cast<unsigned long>(
      chipId & 0xFFFFFFFFULL
    )
  );

  recoveryApSsid =
    "DefenseLab-Recovery-" +
    String(suffix).substring(4);

  recoveryApPassword =
    randomRecoveryPassword(16);

  recoveryAdminPassword =
    randomRecoveryPassword(18);
}

void enterRecoveryMode(const char* reason) {
  if (recoveryMode) return;

  recoveryMode = true;
  ensureRecoveryCredentials();

  Serial.println();
  Serial.println(
    "=== ESP32 Defense Lab credential recovery ==="
  );
  Serial.println(reason);
  Serial.print("Recovery Wi-Fi: ");
  Serial.println(recoveryApSsid);
  Serial.print("Recovery Wi-Fi password: ");
  Serial.println(recoveryApPassword);
  Serial.println("Recovery admin username: admin");
  Serial.print("Recovery admin password: ");
  Serial.println(recoveryAdminPassword);
  Serial.println(
    "Open http://192.168.4.1 and set new credentials."
  );
  Serial.println(
    "============================================="
  );
}

String logKey(uint8_t index) {
  return "log" + String(index);
}

String readProtected(
  const char* key,
  const char* fallback,
  const char* failureReason
) {
  if (recoveryMode) {
    ensureRecoveryCredentials();

    if (String(key) == "ap_pass") {
      return recoveryApPassword;
    }

    if (String(key) == "admin_pass") {
      return recoveryAdminPassword;
    }
  }

  const String stored =
    prefs.getString(key, "");

  if (!stored.length()) {
    if (prefs.getBool("setup_done", false)) {
      enterRecoveryMode(failureReason);

      return String(key) == "ap_pass"
        ? recoveryApPassword
        : recoveryAdminPassword;
    }

    return String(fallback);
  }

  const String plain =
    unprotectSecret(stored);

  if (plain.length()) {
    return plain;
  }

  enterRecoveryMode(failureReason);

  return String(key) == "ap_pass"
    ? recoveryApPassword
    : recoveryAdminPassword;
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
      const String protectedValue =
        protectSecret(value);

      if (protectedValue.length()) {
        prefs.putString(
          key,
          protectedValue
        );
      }
    }
  }

  const String storedAp =
    prefs.getString("ap_pass", "");

  const String storedAdmin =
    prefs.getString("admin_pass", "");

  bool setupDone =
    prefs.getBool("setup_done", false);

  // Upgrade compatibility: releases before setup_done existed
  // always stored both passwords together after first setup.
  if (
    !setupDone &&
    storedAp.length() &&
    storedAdmin.length()
  ) {
    const String ap =
      unprotectSecret(storedAp);

    const String admin =
      unprotectSecret(storedAdmin);

    if (
      ap.length() &&
      admin.length() &&
      ap != DefenseConfig::DEFAULT_AP_PASSWORD &&
      admin != DefenseConfig::DEFAULT_ADMIN_PASSWORD
    ) {
      setupDone =
        prefs.putBool(
          "setup_done",
          true
        ) > 0;
    }
  }

  if (setupDone) {
    const bool protectedFormat =
      isProtectedSecret(storedAp) &&
      isProtectedSecret(storedAdmin);

    const bool decrypts =
      storedAp.length() &&
      storedAdmin.length() &&
      unprotectSecret(storedAp).length() &&
      unprotectSecret(storedAdmin).length();

    if (!protectedFormat || !decrypts) {
      enterRecoveryMode(
        "Provisioned management credentials are missing, unprotected, or could not be decrypted."
      );
    }
  } else {
    const bool hasAp =
      storedAp.length() > 0;

    const bool hasAdmin =
      storedAdmin.length() > 0;

    if (hasAp != hasAdmin) {
      // A partial credential write is not a valid first-boot state.
      enterRecoveryMode(
        "Incomplete management credential state detected."
      );
    }
  }
}

String getApSsid() {
  if (recoveryMode) {
    ensureRecoveryCredentials();
    return recoveryApSsid;
  }

  return prefs.getString(
    "ap_ssid",
    DefenseConfig::DEFAULT_AP_SSID
  );
}

String getApPassword() {
  return readProtected(
    "ap_pass",
    DefenseConfig::DEFAULT_AP_PASSWORD,
    "Stored management Wi-Fi credential could not be decrypted."
  );
}

String getAdminUser() {
  return recoveryMode
    ? String("admin")
    : prefs.getString(
        "admin_user",
        DefenseConfig::DEFAULT_ADMIN_USER
      );
}

String getAdminPassword() {
  return readProtected(
    "admin_pass",
    DefenseConfig::DEFAULT_ADMIN_PASSWORD,
    "Stored administrator credential could not be decrypted."
  );
}

bool credentialRecoveryRequired() {
  return recoveryMode;
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
  if (recoveryMode) return true;

  if (!prefs.getBool("setup_done", false)) {
    return true;
  }

  return
    getApPassword() ==
      DefenseConfig::DEFAULT_AP_PASSWORD ||
    getAdminPassword() ==
      DefenseConfig::DEFAULT_ADMIN_PASSWORD;
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

  if (ok) {
    ok &=
      prefs.putBool(
        "setup_done",
        true
      ) > 0;
  }

  if (ok) {
    recoveryMode = false;
    recoveryApSsid = "";
    recoveryApPassword = "";
    recoveryAdminPassword = "";
  } else {
    enterRecoveryMode(
      "Management credential update was incomplete."
    );
  }

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

  recoveryMode = false;
  recoveryApSsid = "";
  recoveryApPassword = "";
  recoveryAdminPassword = "";
}
