# Hardware Guide

## Supported target

The default PlatformIO environment targets a classic ESP32 development board compatible with `esp32dev`, such as common ESP32-WROOM-32 DevKit boards.

### Required

- Classic ESP32 development board
- 4 MB flash recommended
- USB data/power cable
- 2.4 GHz Wi-Fi environment

### Optional OLED

An SSD1306/SH1106-style 128×64 I2C display can be used for local status.

Typical ESP32 I2C wiring:

| OLED | ESP32 |
|---|---:|
| VCC | 3.3 V |
| GND | GND |
| SDA | GPIO 21 |
| SCL | GPIO 22 |

OLED support is disabled by default. In `platformio.ini`, change:

`-D DEFENSELAB_ENABLE_OLED=0`

to:

`-D DEFENSELAB_ENABLE_OLED=1`

before building.

## Radio behavior

The firmware uses the ESP32 radio in AP+STA mode while passively listening for Wi-Fi management frames on the configured monitoring channel. A nearby-network scan temporarily pauses fixed-channel monitoring because the single radio must visit other channels.

This is a **single-radio passive monitor**, not a spectrum analyzer. It cannot continuously observe all 2.4 GHz channels at the same time.

## Hardware validation checklist

1. Flash the release firmware.
2. Join `ESP32-Defense-Lab`.
3. Complete mandatory first-boot credential replacement.
4. Confirm the dashboard opens at `192.168.4.1`.
5. Run a nearby-network scan.
6. Confirm the radio returns to the configured monitor channel.
7. In a controlled lab, generate legitimate disconnect/reconnect activity and verify observed management-frame counters.
8. Verify alert threshold behavior with authorized test traffic.
9. Power-cycle and confirm settings persist.
10. Run for 12–24 hours and record uptime/free-heap behavior.

Do not claim measured detection coverage, RF range, or long-duration stability until tested on the actual board.
