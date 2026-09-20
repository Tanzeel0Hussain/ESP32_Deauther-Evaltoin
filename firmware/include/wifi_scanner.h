#pragma once
#include <Arduino.h>

void wifiScannerBegin();
void wifiScannerLoop();
bool wifiScannerRun();
String wifiScannerJson();
size_t wifiScannerCount();
int32_t wifiScannerStrongestRssi();
uint8_t wifiScannerOpenCount();

bool wifiScannerScanning();
bool wifiScannerLastOk();
int32_t wifiScannerLastError();
uint32_t wifiScannerLastScanMs();
String wifiScannerStatus();
