#pragma once
#include <Arduino.h>
#include "models.h"

void detectorBegin();
void detectorLoop();
void detectorSetChannel(uint8_t channel);
uint8_t detectorChannel();
void detectorPause();
void detectorResume();
bool detectorPaused();

ThreatStats detectorStats();
String detectorStatsJson();
String detectorAlertsJson();
void detectorClearAlerts();
