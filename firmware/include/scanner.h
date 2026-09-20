#pragma once
#include <Arduino.h>

void scannerBegin();
bool scannerRun();
String scannerNetworksJson();
size_t scannerCount();
