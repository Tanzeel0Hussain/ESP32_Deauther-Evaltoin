# Hardware Notes

## Supported target

The maintained PlatformIO environment targets `esp32dev`, suitable for classic ESP32 development boards such as common ESP32-WROOM-32 / DevKit-style hardware.

The firmware relies on classic ESP32 Wi-Fi promiscuous receive APIs. ESP32-S2/S3/C3/C6/H2 variants are not claimed as validated targets by this repository.

## Minimum hardware

- Classic ESP32 board
- 4 MB flash recommended
- USB data cable
- Stable 5 V USB power source
- 2.4 GHz Wi-Fi environment that you own or are authorized to monitor

## Optional OLED

SSD1306 128×64, I²C address `0x3C`:

| OLED | ESP32 |
|---|---|
| VCC | 3.3 V |
| GND | GND |
| SDA | GPIO 21 |
| SCL | GPIO 22 |

The firmware probes the display address at boot. If no display is present, normal operation continues without OLED support.

## Radio behavior

Classic ESP32 has a single 2.4 GHz radio. The management access point and passive monitor share the selected channel. Scanning nearby networks temporarily changes channels; after a scan the configured monitor channel is restored.

This project observes selected management frames. It is not a spectrum analyzer and cannot see 5 GHz/6 GHz traffic.

## Physical validation checklist

Before calling a release hardware-validated:

1. Flash the combined release binary or browser installer.
2. Confirm the management AP appears.
3. Complete mandatory credential replacement.
4. Confirm dashboard status updates for at least 30 minutes.
5. Run nearby-network scans and verify the monitor channel returns to the configured value.
6. In an isolated authorized lab, generate legitimate reconnect/disconnect activity and confirm receive-side counters/alerts behave as expected.
7. Confirm an optional SSD1306 display if used.
8. Power-cycle and verify settings persist.
9. Run a 12–24 hour soak test and record any watchdog/brownout resets.

Never validate the detector by disrupting third-party networks.
