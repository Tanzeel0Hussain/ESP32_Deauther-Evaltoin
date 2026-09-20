#include <cassert>
#include <iostream>
#include <string>
#include "detector_logic.h"

int main() {
  using DefenseLogic::Severity;
  assert(DefenseLogic::classifyBurst(0, false) == Severity::None);
  assert(DefenseLogic::classifyBurst(11, false) == Severity::None);
  assert(DefenseLogic::classifyBurst(12, false) == Severity::Warning);
  assert(DefenseLogic::classifyBurst(29, false) == Severity::Warning);
  assert(DefenseLogic::classifyBurst(30, false) == Severity::High);
  assert(DefenseLogic::classifyBurst(18, true) == Severity::High);
  assert(std::string(DefenseLogic::severityText(Severity::High)) == "High");
  std::cout << "Defense Lab detector logic tests passed\n";
  return 0;
}
