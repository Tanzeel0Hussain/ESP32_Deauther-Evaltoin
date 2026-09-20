#pragma once
#include <stdint.h>

namespace DefenseValidation {
inline bool parseUnsignedDecimal(
  const char* text,
  uint32_t minimum,
  uint32_t maximum,
  uint32_t& value
) {
  if (!text || !*text || minimum > maximum) return false;

  uint32_t parsed = 0;
  for (const char* p = text; *p; ++p) {
    if (*p < '0' || *p > '9') return false;

    const uint32_t digit =
      static_cast<uint32_t>(*p - '0');

    if (
      parsed >
      (UINT32_MAX - digit) / 10U
    ) {
      return false;
    }

    parsed = parsed * 10U + digit;
  }

  if (parsed < minimum || parsed > maximum) {
    return false;
  }

  value = parsed;
  return true;
}
}
