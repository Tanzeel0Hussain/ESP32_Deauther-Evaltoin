#pragma once
#include <stdint.h>

namespace CredentialLogic {
constexpr uint8_t NO_SLOT = 0xFF;

inline uint8_t selectCommittedSlot(
  uint8_t requestedSlot,
  bool slot0Valid,
  bool slot1Valid
) {
  if (requestedSlot == 0 && slot0Valid) return 0;
  if (requestedSlot == 1 && slot1Valid) return 1;
  if (slot0Valid) return 0;
  if (slot1Valid) return 1;
  return NO_SLOT;
}

inline uint8_t inactiveSlot(uint8_t activeSlot) {
  return activeSlot == 0 ? 1 : 0;
}
}
