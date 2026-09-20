#pragma once
#include <Arduino.h>

bool isProtectedSecret(const String& value);
String protectSecret(const String& plainText);
String unprotectSecret(const String& storedValue);
