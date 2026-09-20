#pragma once
#include <Arduino.h>

void detectorBegin();
void detectorLoop();
void detectorPause();
void detectorResume();

bool detectorSetChannel(uint8_t channel);
uint8_t detectorChannel();

uint32_t detectorManagementFrames();
uint32_t detectorSuspiciousFrames();
uint32_t detectorAlertCount();
uint32_t detectorDroppedAlerts();

String detectorAlertsJson();
String detectorChannelsJson();
String detectorStatusJson();

void detectorClearAlerts();
