#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <U8g2lib.h>

#include "detector.h"
#include "display.h"
#include "storage.h"
#include "wifi_scanner.h"

namespace {
U8G2_SSD1306_128X64_NONAME_F_HW_I2C oled(U8G2_R0, U8X8_PIN_NONE);
bool oledPresent = false;
unsigned long lastDraw = 0;

bool detectOled() {
  Wire.begin(21, 22);
  Wire.beginTransmission(0x3C);
  return Wire.endTransmission() == 0;
}
}

void displayBegin() {
  oledPresent = detectOled();
  if (!oledPresent) return;

  oled.begin();
  oled.setFont(u8g2_font_6x10_tf);
}

void displayLoop() {
  if (!oledPresent || millis() - lastDraw < 1000) return;
  lastDraw = millis();

  oled.clearBuffer();
  oled.setFont(u8g2_font_6x10_tf);
  oled.drawStr(0, 9, "Wireless Defense Lab");

  const String ip = WiFi.softAPIP().toString();
  oled.drawStr(0, 23, ("IP " + ip).c_str());
  oled.drawStr(0, 34, ("Ch " + String(getMonitorChannel()) + "  APs " + String(wifiScannerCount())).c_str());
  oled.drawStr(0, 45, ("Deauth " + String(detectorTotalDeauth())).c_str());
  oled.drawStr(0, 56, ("Alerts " + String(detectorAlertCount())).c_str());
  oled.sendBuffer();
}
