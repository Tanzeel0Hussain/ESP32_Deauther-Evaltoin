#pragma once
#include <stdint.h>

namespace DefenseLogic {
inline bool isObservedThreatSubtype(uint8_t subtype) {
  return subtype == 0x0C || subtype == 0x0A;
}

inline bool validMonitorChannel(uint8_t channel) {
  return channel >= 1 && channel <= 13;
}

inline bool shouldRaiseAlert(
  uint16_t count,
  uint16_t threshold,
  uint32_t now,
  uint32_t lastAlert,
  uint32_t cooldownMs
) {
  if (count < threshold) return false;
  return lastAlert == 0 || now - lastAlert >= cooldownMs;
}
}
