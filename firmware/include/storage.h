#pragma once
#include <Arduino.h>

void storageBegin();

String getApSsid();
String getApPassword();
String getAdminUser();
String getAdminPassword();

bool initialSetupRequired();

bool setInitialCredentials(
  const String& apSsid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
);

bool setApCredentials(
  const String& apSsid,
  const String& apPassword
);

bool setAdminCredentials(
  const String& adminUser,
  const String& adminPassword
);

uint8_t getMonitorChannel();
bool setMonitorChannel(uint8_t channel);

void factoryResetStorage();
