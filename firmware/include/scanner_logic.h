#pragma once
#include <stdint.h>

namespace ScannerLogic {
enum class RestoreAction : uint8_t {
  RestoreChannelOnly,
  ResumeDetector
};

inline RestoreAction restoreAction(bool detectorWasPaused) {
  return detectorWasPaused
    ? RestoreAction::RestoreChannelOnly
    : RestoreAction::ResumeDetector;
}

inline bool scanSucceeded(int found, bool radioRestored) {
  return found >= 0 && radioRestored;
}
}
