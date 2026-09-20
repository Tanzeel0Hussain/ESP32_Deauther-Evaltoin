#pragma once
#include <Arduino.h>
String protectSecret(const String& plainText);
String unprotectSecret(const String& storedValue);
bool isProtectedSecret(const String& storedValue);
