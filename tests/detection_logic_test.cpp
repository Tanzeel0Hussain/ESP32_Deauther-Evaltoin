#include <cassert>
#include <iostream>
#include "detection_logic.h"

int main() {
  using namespace DefenseLogic;

  assert(isObservedThreatSubtype(0x0C));
  assert(isObservedThreatSubtype(0x0A));
  assert(!isObservedThreatSubtype(0x08));

  assert(validMonitorChannel(1));
  assert(validMonitorChannel(13));
  assert(!validMonitorChannel(0));
  assert(!validMonitorChannel(14));

  assert(!shouldRaiseAlert(9, 10, 5000, 0, 10000));
  assert(shouldRaiseAlert(10, 10, 5000, 0, 10000));
  assert(!shouldRaiseAlert(20, 10, 15000, 10000, 10000));
  assert(shouldRaiseAlert(20, 10, 20000, 10000, 10000));

  std::cout << "ESP32 Wireless Defense Lab host tests passed\n";
  return 0;
}
