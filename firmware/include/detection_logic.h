#pragma once
#include <stddef.h>
#include <stdint.h>

namespace DefenseLogic {
inline bool isObservedThreatSubtype(uint8_t subtype) {
  return subtype == 0x0C || subtype == 0x0A;
}

inline bool validMonitorChannel(uint8_t channel) {
  return channel >= 1 && channel <= 13;
}

inline bool frameRetry(uint16_t frameControl) {
  return (frameControl & 0x0800U) != 0;
}

inline bool frameProtected(uint16_t frameControl) {
  return (frameControl & 0x4000U) != 0;
}

inline uint16_t sequenceNumber(uint16_t sequenceControl) {
  return static_cast<uint16_t>(sequenceControl >> 4);
}

inline uint8_t fragmentNumber(uint16_t sequenceControl) {
  return static_cast<uint8_t>(sequenceControl & 0x0FU);
}

inline bool isDuplicateRetry(
  bool retry,
  bool hasPrevious,
  uint16_t sequence,
  uint8_t fragment,
  uint8_t subtype,
  uint16_t lastSequence,
  uint8_t lastFragment,
  uint8_t lastSubtype
) {
  return
    retry &&
    hasPrevious &&
    sequence == lastSequence &&
    fragment == lastFragment &&
    subtype == lastSubtype;
}

template <typename Slot>
inline size_t selectLruSlot(
  const Slot* slots,
  size_t count,
  uint32_t now
) {
  for (size_t i = 0; i < count; ++i) {
    if (!slots[i].active) return i;
  }

  size_t oldest = 0;
  uint32_t oldestAge =
    now - slots[0].lastSeen;

  for (size_t i = 1; i < count; ++i) {
    const uint32_t age =
      now - slots[i].lastSeen;

    if (age > oldestAge) {
      oldest = i;
      oldestAge = age;
    }
  }

  return oldest;
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
