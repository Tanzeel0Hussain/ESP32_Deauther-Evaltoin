#pragma once
#include <Arduino.h>

void storageBegin();

String getApSsid();
String getApPassword();
String getAdminUser();
String getAdminPassword();
uint8_t getMonitorChannel();
uint16_t getAlertThreshold();

bool initialSetupRequired();
bool setInitialCredentials(
  const String& apSsid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
);
bool setMonitorChannel(uint8_t channel);
bool setAlertThreshold(uint16_t threshold);

void appendEventLog(const String& type, const String& message);
String getEventLogJson();
void clearEventLogs();
void factoryResetStorage();
