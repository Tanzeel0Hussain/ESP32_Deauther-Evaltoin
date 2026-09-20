#pragma once
#include <stdint.h>

namespace DefenseThreatLogic {

enum class Level : uint8_t {
  Normal = 0,
  Warning = 1,
  Critical = 2
};

inline Level classify(
  uint32_t managementDisconnectFrames,
  uint16_t threshold,
  uint16_t criticalMultiplier
) {
  if (threshold == 0) return Level::Normal;

  const uint32_t critical =
    static_cast<uint32_t>(threshold) *
    static_cast<uint32_t>(criticalMultiplier);

  if (managementDisconnectFrames >= critical) {
    return Level::Critical;
  }

  if (managementDisconnectFrames >= threshold) {
    return Level::Warning;
  }

  return Level::Normal;
}

inline const char* label(Level level) {
  switch (level) {
    case Level::Warning:
      return "Warning";
    case Level::Critical:
      return "Critical";
    default:
      return "Normal";
  }
}

}  // namespace DefenseThreatLogic
