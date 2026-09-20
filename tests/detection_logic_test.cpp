#include <cassert>
#include <cstdint>
#include <iostream>

#include "credential_logic.h"
#include "detection_logic.h"
#include "fixed_ring_queue.h"
#include "input_validation.h"
#include "scanner_logic.h"

namespace {
struct TestSlot {
  bool active;
  uint32_t lastSeen;
};
}

int main() {
  using namespace DefenseLogic;

  assert(isObservedThreatSubtype(0x0C));
  assert(isObservedThreatSubtype(0x0A));
  assert(!isObservedThreatSubtype(0x08));

  assert(validMonitorChannel(1));
  assert(validMonitorChannel(13));
  assert(!validMonitorChannel(0));
  assert(!validMonitorChannel(14));

  assert(frameRetry(0x0800));
  assert(!frameRetry(0x0000));
  assert(frameProtected(0x4000));
  assert(!frameProtected(0x0000));
  assert(sequenceNumber(0x1234) == 0x0123);
  assert(fragmentNumber(0x1234) == 0x04);

  assert(isDuplicateRetry(
    true, true, 42, 0, 0x0C, 42, 0, 0x0C
  ));
  assert(!isDuplicateRetry(
    false, true, 42, 0, 0x0C, 42, 0, 0x0C
  ));
  assert(!isDuplicateRetry(
    true, true, 43, 0, 0x0C, 42, 0, 0x0C
  ));
  assert(!isDuplicateRetry(
    true, true, 42, 0, 0x0A, 42, 0, 0x0C
  ));

  TestSlot slots[] = {
    {true, 950},
    {true, 700},
    {true, 900}
  };
  assert(selectLruSlot(slots, 3, 1000) == 1);

  TestSlot withFree[] = {
    {true, 100},
    {false, 0},
    {true, 50}
  };
  assert(selectLruSlot(withFree, 3, 200) == 1);

  assert(!shouldRaiseAlert(9, 10, 5000, 0, 10000));
  assert(shouldRaiseAlert(10, 10, 5000, 0, 10000));
  assert(!shouldRaiseAlert(20, 10, 15000, 10000, 10000));
  assert(shouldRaiseAlert(20, 10, 20000, 10000, 10000));

  FixedRingQueue<int, 16> queue;
  for (int i = 0; i < 16; ++i) {
    assert(queue.push(i));
  }
  assert(queue.size() == 16);
  assert(queue.full());
  assert(!queue.push(16));

  for (int i = 0; i < 16; ++i) {
    int value = -1;
    assert(queue.pop(value));
    assert(value == i);
  }
  assert(queue.empty());

  using namespace CredentialLogic;
  assert(selectCommittedSlot(0, true, false) == 0);
  assert(selectCommittedSlot(1, true, false) == 0);
  assert(selectCommittedSlot(1, true, true) == 1);
  assert(selectCommittedSlot(NO_SLOT, false, true) == NO_SLOT);
  assert(selectCommittedSlot(NO_SLOT, false, false) == NO_SLOT);
  assert(inactiveSlot(0) == 1);
  assert(inactiveSlot(1) == 0);

  uint32_t parsed = 0;
  assert(DefenseValidation::parseUnsignedDecimal("6", 1, 13, parsed));
  assert(parsed == 6);
  assert(DefenseValidation::parseUnsignedDecimal("013", 1, 13, parsed));
  assert(parsed == 13);
  assert(!DefenseValidation::parseUnsignedDecimal("6abc", 1, 13, parsed));
  assert(!DefenseValidation::parseUnsignedDecimal("", 1, 13, parsed));
  assert(!DefenseValidation::parseUnsignedDecimal("14", 1, 13, parsed));
  assert(!DefenseValidation::parseUnsignedDecimal(
    "42949672960", 0, 200, parsed
  ));

  assert(
    ScannerLogic::restoreAction(true) ==
    ScannerLogic::RestoreAction::RestoreChannelOnly
  );
  assert(
    ScannerLogic::restoreAction(false) ==
    ScannerLogic::RestoreAction::ResumeDetector
  );
  assert(ScannerLogic::scanSucceeded(0, true));
  assert(!ScannerLogic::scanSucceeded(-1, true));
  assert(!ScannerLogic::scanSucceeded(3, false));

  std::cout
    << "ESP32 Wireless Defense Lab host tests passed\n";
  return 0;
}
