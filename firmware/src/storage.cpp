#include <Arduino.h>
#include <Preferences.h>

#include "storage.h"
#include "config.h"

namespace {
Preferences prefs;

bool validAp(const String& ssid, const String& password) {
  return
    ssid.length() >= 1 &&
    ssid.length() <= 32 &&
    password.length() >= 8 &&
    password.length() <= 63;
}

bool validAdmin(const String& user, const String& password) {
  return
    user.length() >= 1 &&
    user.length() <= 32 &&
    password.length() >= 8 &&
    password.length() <= 64;
}
}

void storageBegin() {
  prefs.begin("deflab", false);

  if (!prefs.isKey("ap_ssid")) {
    prefs.putString("ap_ssid", DefenseConfig::DEFAULT_AP_SSID);
  }

  if (!prefs.isKey("ap_pass")) {
    prefs.putString("ap_pass", DefenseConfig::DEFAULT_AP_PASSWORD);
  }

  if (!prefs.isKey("admin_user")) {
    prefs.putString("admin_user", DefenseConfig::DEFAULT_ADMIN_USER);
  }

  if (!prefs.isKey("admin_pass")) {
    prefs.putString("admin_pass", DefenseConfig::DEFAULT_ADMIN_PASSWORD);
  }

  if (!prefs.isKey("channel")) {
    prefs.putUChar("channel", DefenseConfig::DEFAULT_MONITOR_CHANNEL);
  }

  if (!prefs.isKey("setup_done")) {
    prefs.putBool("setup_done", false);
  }
}

String getApSsid() {
  return prefs.getString("ap_ssid", DefenseConfig::DEFAULT_AP_SSID);
}

String getApPassword() {
  return prefs.getString("ap_pass", DefenseConfig::DEFAULT_AP_PASSWORD);
}

String getAdminUser() {
  return prefs.getString("admin_user", DefenseConfig::DEFAULT_ADMIN_USER);
}

String getAdminPassword() {
  return prefs.getString("admin_pass", DefenseConfig::DEFAULT_ADMIN_PASSWORD);
}

bool initialSetupRequired() {
  return !prefs.getBool("setup_done", false);
}

bool setInitialCredentials(
  const String& apSsid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
) {
  if (
    !validAp(apSsid, apPassword) ||
    !validAdmin(adminUser, adminPassword) ||
    apPassword == adminPassword ||
    apPassword == DefenseConfig::DEFAULT_AP_PASSWORD ||
    adminPassword == DefenseConfig::DEFAULT_ADMIN_PASSWORD
  ) {
    return false;
  }

  const bool a = prefs.putString("ap_ssid", apSsid) > 0;
  const bool b = prefs.putString("ap_pass", apPassword) > 0;
  const bool c = prefs.putString("admin_user", adminUser) > 0;
  const bool d = prefs.putString("admin_pass", adminPassword) > 0;

  if (!(a && b && c && d)) return false;

  return prefs.putBool("setup_done", true) > 0;
}

bool setApCredentials(
  const String& apSsid,
  const String& apPassword
) {
  if (
    !validAp(apSsid, apPassword) ||
    apPassword == getAdminPassword()
  ) {
    return false;
  }

  const bool a = prefs.putString("ap_ssid", apSsid) > 0;
  const bool b = prefs.putString("ap_pass", apPassword) > 0;

  return a && b;
}

bool setAdminCredentials(
  const String& adminUser,
  const String& adminPassword
) {
  if (
    !validAdmin(adminUser, adminPassword) ||
    adminPassword == getApPassword()
  ) {
    return false;
  }

  const bool a = prefs.putString("admin_user", adminUser) > 0;
  const bool b = prefs.putString("admin_pass", adminPassword) > 0;

  return a && b;
}

uint8_t getMonitorChannel() {
  uint8_t channel =
    prefs.getUChar("channel", DefenseConfig::DEFAULT_MONITOR_CHANNEL);

  if (channel < 1 || channel > 13) {
    channel = DefenseConfig::DEFAULT_MONITOR_CHANNEL;
  }

  return channel;
}

bool setMonitorChannel(uint8_t channel) {
  if (channel < 1 || channel > 13) return false;
  return prefs.putUChar("channel", channel) > 0;
}

void factoryResetStorage() {
  prefs.clear();
}
