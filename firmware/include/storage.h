#pragma once
#include <Arduino.h>

void defenseStorageBegin();

String defenseApSsid();
String defenseApPassword();
String defenseAdminUser();
String defenseAdminPassword();

bool defenseInitialSetupRequired();
bool defenseSaveInitialCredentials(
  const String& ssid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
);
bool defenseSaveCredentials(
  const String& ssid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
);

uint16_t defenseAlertThreshold();
bool defenseSetAlertThreshold(uint16_t threshold);

uint8_t defenseMonitorChannel();
bool defenseSetMonitorChannel(uint8_t channel);

void defenseFactoryReset();

void defenseAppendLog(const String& type, const String& message);
String defenseLogsJson();
void defenseClearLogs();
