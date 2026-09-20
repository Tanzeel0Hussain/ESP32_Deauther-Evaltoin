#pragma once
#include <Arduino.h>

void wifiScannerBegin();
bool wifiScannerScan();
void wifiScannerRestoreMonitorChannel();
String wifiScannerNetworksJson();
String wifiScannerChannelsJson();
size_t wifiScannerNetworkCount();
uint8_t wifiScannerCurrentChannel();
