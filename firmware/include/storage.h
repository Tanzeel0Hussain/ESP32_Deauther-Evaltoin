#pragma once
#include <Arduino.h>

void storageBegin();
String storageGetApSsid();
String storageGetApPassword();
String storageGetAdminUser();
String storageGetAdminPassword();
bool storageInitialSetupRequired();
bool storageRecoveryRequired();

bool storageSetInitialCredentials(
  const String& ssid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
);

bool storageSetApCredentials(const String& ssid, const String& password);
bool storageSetAdminCredentials(const String& username, const String& password);

uint8_t storageGetMonitorChannel();
bool storageSetMonitorChannel(uint8_t channel);
uint16_t storageGetAlertThreshold();
bool storageSetAlertThreshold(uint16_t threshold);
void storageFactoryReset();
