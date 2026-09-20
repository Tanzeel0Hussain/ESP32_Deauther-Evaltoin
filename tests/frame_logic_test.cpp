#include <cassert>
#include <iostream>
#include "frame_logic.h"

int main() {
  using namespace DefenseFrameLogic;

  const uint16_t deauth = 0x00C0;
  const uint16_t disassoc = 0x00A0;
  const uint16_t beacon = 0x0080;
  const uint16_t data = 0x0008;

  assert(isManagement(deauth));
  assert(isDeauthentication(deauth));
  assert(!isDisassociation(deauth));
  assert(isManagement(disassoc));
  assert(isDisassociation(disassoc));
  assert(!isDeauthentication(disassoc));
  assert(!isMonitoredThreat(beacon));
  assert(!isManagement(data));
  assert(!thresholdReached(9, 10));
  assert(thresholdReached(10, 10));
  assert(thresholdReached(11, 10));
  assert(!thresholdReached(10, 0));

  std::cout << "Defense Lab frame logic tests passed\n";
  return 0;
}
