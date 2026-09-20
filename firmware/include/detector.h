#pragma once
#include <Arduino.h>

void detectorBegin();
void detectorLoop();
void detectorReset();
void detectorUpdateThreshold(uint16_t threshold);

uint32_t detectorTotalDeauth();
uint32_t detectorTotalDisassoc();
uint32_t detectorAlertCount();
int8_t detectorLastRssi();
uint8_t detectorLastChannel();

String detectorAlertsJson();
String detectorChannelJson();
