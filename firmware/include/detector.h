#pragma once
#include <Arduino.h>
#include "storage.h"

bool detectorBegin();
void detectorLoop();
void detectorReset();
void detectorUpdateThreshold(uint16_t threshold);
bool detectorPause();
bool detectorResume();
bool detectorPaused();
bool detectorHealthy();
String detectorStatus();
int32_t detectorLastError();

uint32_t detectorTotalDeauth();
uint32_t detectorTotalDisassoc();
uint32_t detectorAlertCount();
uint32_t detectorDroppedAlerts();
int8_t detectorLastRssi();
uint8_t detectorLastChannel();

String detectorAlertsJson();
String detectorChannelJson();
