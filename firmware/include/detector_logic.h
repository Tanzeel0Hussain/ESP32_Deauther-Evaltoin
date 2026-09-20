#pragma once
#include <stdint.h>

namespace DefenseLogic {

enum class Severity : uint8_t {
  None = 0,
  Warning = 1,
  High = 2
};

inline Severity classifyBurst(
  uint16_t frames,
  bool broadcast,
  uint16_t threshold = 12,
  uint16_t highThreshold = 30
) {
  if (frames < threshold) return Severity::None;

  if (
    frames >= highThreshold ||
    (broadcast && frames >= static_cast<uint16_t>(threshold + threshold / 2))
  ) {
    return Severity::High;
  }

  return Severity::Warning;
}

inline const char* severityText(Severity severity) {
  switch (severity) {
    case Severity::Warning: return "Warning";
    case Severity::High: return "High";
    default: return "None";
  }
}

}
