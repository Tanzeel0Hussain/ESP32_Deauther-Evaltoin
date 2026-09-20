#pragma once
#include <Arduino.h>

void scannerBegin();
void scannerLoop();
bool scannerScanNow();
String scannerNetworksJson();
size_t scannerNetworkCount();
uint32_t scannerLastScanAgeSeconds();
