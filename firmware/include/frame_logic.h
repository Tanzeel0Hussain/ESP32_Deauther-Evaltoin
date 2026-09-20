#pragma once
#include <stdint.h>

namespace DefenseFrameLogic {
inline uint8_t frameType(uint16_t fc) {
  return static_cast<uint8_t>((fc >> 2) & 0x03);
}
inline uint8_t frameSubtype(uint16_t fc) {
  return static_cast<uint8_t>((fc >> 4) & 0x0F);
}
inline bool isManagement(uint16_t fc) {
  return frameType(fc) == 0;
}
inline bool isDeauthentication(uint16_t fc) {
  return isManagement(fc) && frameSubtype(fc) == 12;
}
inline bool isDisassociation(uint16_t fc) {
  return isManagement(fc) && frameSubtype(fc) == 10;
}
inline bool isMonitoredThreat(uint16_t fc) {
  return isDeauthentication(fc) || isDisassociation(fc);
}
inline bool thresholdReached(uint16_t count, uint16_t threshold) {
  return threshold > 0 && count >= threshold;
}
}
