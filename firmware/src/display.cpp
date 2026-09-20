#include <Arduino.h>
#include "config.h"
#include "detector.h"
#include "display.h"

#ifndef DEFENSE_ENABLE_OLED
#define DEFENSE_ENABLE_OLED 0
#endif

#if DEFENSE_ENABLE_OLED
#include <Wire.h>
#include <U8g2lib.h>

namespace {
U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(
  U8G2_R0,
  U8X8_PIN_NONE
);

unsigned long lastDraw = 0;
}
#endif

void defenseDisplayBegin() {
#if DEFENSE_ENABLE_OLED
  Wire.begin(21, 22);
  display.begin();
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tf);
  display.drawStr(0, 12, "ESP32 Defense Lab");
  display.drawStr(0, 28, "Passive monitor");
  display.sendBuffer();
#endif
}

void defenseDisplayLoop() {
#if DEFENSE_ENABLE_OLED
  if (
    millis() - lastDraw <
    DefenseConfig::DISPLAY_REFRESH_MS
  ) {
    return;
  }

  lastDraw = millis();

  const ThreatStats stats = detectorStats();

  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tf);

  display.drawStr(0, 10, "Wireless Defense Lab");

  String line =
    "CH " +
    String(stats.currentChannel) +
    "  " +
    stats.level;

  display.drawStr(0, 24, line.c_str());

  line =
    "Deauth " +
    String(
      static_cast<unsigned long>(
        stats.deauthFrames
      )
    );

  display.drawStr(0, 38, line.c_str());

  line =
    "Disassoc " +
    String(
      static_cast<unsigned long>(
        stats.disassocFrames
      )
    );

  display.drawStr(0, 52, line.c_str());
  display.sendBuffer();
#endif
}
