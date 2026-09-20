#include <Arduino.h>

#include "display.h"
#include "detector.h"
#include "scanner.h"

#if DEFENSELAB_OLED
#include <Wire.h>
#include <U8g2lib.h>

namespace {
U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(U8G2_R0, U8X8_PIN_NONE);
uint32_t lastDrawMs = 0;
}

void displayBegin() {
  display.begin();
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tf);
  display.drawStr(0, 12, "ESP32 Defense Lab");
  display.drawStr(0, 28, "Passive monitor");
  display.sendBuffer();
}

void displayLoop() {
  if (millis() - lastDrawMs < 1000) return;
  lastDrawMs = millis();

  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tf);
  display.drawStr(0, 10, "Wireless Defense");

  display.setCursor(0, 24);
  display.print("CH ");
  display.print(detectorChannel());

  display.setCursor(0, 36);
  display.print("APs ");
  display.print(scannerNetworkCount());

  display.setCursor(0, 48);
  display.print("Sus ");
  display.print(detectorSuspiciousFrames());

  display.setCursor(0, 60);
  display.print("Alerts ");
  display.print(detectorAlertCount());

  display.sendBuffer();
}

#else

void displayBegin() {}
void displayLoop() {}

#endif
