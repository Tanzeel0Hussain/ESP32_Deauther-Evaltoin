#include <Arduino.h>

#include "oled_display.h"
#include "frame_monitor.h"
#include "storage.h"

#if DEFENSELAB_ENABLE_OLED
#include <U8g2lib.h>

namespace {
U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(U8G2_R0, U8X8_PIN_NONE);
unsigned long lastDrawMs = 0;
}
#endif

void oledDisplayBegin() {
#if DEFENSELAB_ENABLE_OLED
  display.begin();
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tf);
  display.drawStr(0, 12, "ESP32 Defense Lab");
  display.drawStr(0, 28, "Passive monitor");
  display.sendBuffer();
#endif
}

void oledDisplayLoop() {
#if DEFENSELAB_ENABLE_OLED
  if (millis() - lastDrawMs < 1000) return;
  lastDrawMs = millis();

  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tf);

  display.setCursor(0, 12);
  display.print("CH ");
  display.print(storageGetMonitorChannel());

  display.setCursor(0, 28);
  display.print("Deauth ");
  display.print(frameMonitorTotalDeauth());

  display.setCursor(0, 44);
  display.print("Disassoc ");
  display.print(frameMonitorTotalDisassoc());

  display.setCursor(0, 60);
  display.print("Alerts ");
  display.print(frameMonitorAlertCount());

  display.sendBuffer();
#endif
}
