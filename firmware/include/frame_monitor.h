#pragma once
#include <Arduino.h>

void frameMonitorBegin();
void frameMonitorLoop();
void frameMonitorPause();
void frameMonitorResume();
String frameMonitorStatusJson();
String frameMonitorAlertsJson();
void frameMonitorClearAlerts();
uint32_t frameMonitorTotalDeauth();
uint32_t frameMonitorTotalDisassoc();
uint32_t frameMonitorDroppedEvents();
uint32_t frameMonitorAlertCount();
