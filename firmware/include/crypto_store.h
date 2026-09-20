#pragma once
#include <Arduino.h>

bool defenseSecretProtected(const String& storedValue);
String defenseProtectSecret(const String& plainText);
String defenseUnprotectSecret(const String& storedValue);
