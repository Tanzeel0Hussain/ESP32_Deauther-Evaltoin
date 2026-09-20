<div align="center">

# ESP32 Wireless Defense Lab

### Passive Wi-Fi visibility and management-frame anomaly detection for classic ESP32

[![Firmware CI](https://github.com/Tanzeel0Hussain/ESP32_Deauther-Evaltoin/actions/workflows/firmware.yml/badge.svg)](https://github.com/Tanzeel0Hussain/ESP32_Deauther-Evaltoin/actions/workflows/firmware.yml)
[![Live Site](https://img.shields.io/badge/Live-Project_Site-29d9ff)](https://tanzeel0hussain.github.io/ESP32_Deauther-Evaltoin/)
[![Firmware](https://img.shields.io/badge/Firmware-v1.0.0-50e6a7)](https://github.com/Tanzeel0Hussain/ESP32_Deauther-Evaltoin/releases/tag/v1.0.0)
[![ESP32](https://img.shields.io/badge/Target-Classic_ESP32-2c7dff)](docs/HARDWARE.md)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

## What this project is

**ESP32 Wireless Defense Lab** is a defensive, receive-only Wi-Fi monitoring project for classic ESP32 boards. It observes nearby 2.4 GHz Wi-Fi metadata and selected 802.11 management frames, then presents useful visibility through a secure local dashboard.

The maintained firmware is intentionally defensive. It does **not** include deauthentication transmission, Evil Twin access-point impersonation, credential collection, beacon flooding, handshake/PMKID harvesting, BLE spam, or HID payload modules.

## Core features

| Area | Capabilities |
|---|---|
| Passive detector | Observes deauthentication and disassociation management frames |
| Burst alerts | Per-source/BSSID burst tracking with configurable threshold and cooldown |
| Wi-Fi inventory | Nearby SSID, BSSID, RSSI, channel and security metadata |
| Channel analytics | Event activity for 2.4 GHz channels 1–13 |
| Local dashboard | Responsive dark dashboard at `192.168.4.1` |
| Security | WPA2 management AP, HTTP Digest admin auth, per-boot CSRF token |
| Credential storage | AES-256-GCM protected local management credentials |
| First boot | Mandatory replacement of public setup credentials |
| Event history | Reset reasons, scans, settings changes and detector events |
| OLED | Optional SSD1306 128×64 status display on GPIO 21/22 |
| Reliability | Task watchdog, NVS persistence, factory reset |
| Quality | PlatformIO build, host detector tests, flash-size budget in GitHub Actions |

## Start here

### Browser install

1. Open the [live project page](https://tanzeel0hussain.github.io/ESP32_Deauther-Evaltoin/).
2. Connect a supported classic ESP32 by USB.
3. Click **Install Firmware** in a Chromium-based desktop browser.
4. After flashing, join `ESP32-Defense-Lab`.
5. Open `http://192.168.4.1`.
6. Sign in with the setup credentials below.
7. Replace both public setup passwords before the dashboard unlocks.

### First-boot setup credentials

| Setting | Factory setup value |
|---|---|
| Management Wi-Fi | `ESP32-Defense-Lab` |
| Wi-Fi password | `defenselab` |
| Dashboard | `http://192.168.4.1` |
| Admin username | `admin` |
| Admin password | `changeme32` |

These are setup-only defaults. The Wi-Fi password and admin password must be changed and must remain different.

## How detection works

The ESP32 enables promiscuous **receive** mode with a management-frame filter. It watches for 802.11 deauthentication and disassociation subtypes, tracks bursts by source/BSSID, and creates an alert when the configured threshold is reached within the detection window.

An alert means **suspicious management-frame activity was observed**. It is not proof that a specific device is malicious, because MAC addresses can be spoofed and legitimate infrastructure may also emit management frames.

The firmware never calls an 802.11 transmit/injection routine for attack traffic.

## Single-radio limitation

Classic ESP32 has one 2.4 GHz Wi-Fi radio. The local management AP and passive monitor therefore share the configured channel. A nearby-network scan temporarily leaves the selected channel and the firmware restores the configured monitor channel afterward.

This is a compact lab/defensive visibility device, not a multi-radio enterprise WIDS.

## Optional OLED

A 128×64 SSD1306 I²C display at address `0x3C` is detected automatically.

| OLED | ESP32 |
|---|---|
| VCC | 3.3 V |
| GND | GND |
| SDA | GPIO 21 |
| SCL | GPIO 22 |

The display shows the local IP, monitor channel, network count, observed deauthentication count and alert count.

## Build from source

Requirements: Python, PlatformIO and a supported classic ESP32 development board.

```bash
git clone https://github.com/Tanzeel0Hussain/ESP32_Deauther-Evaltoin.git
cd ESP32_Deauther-Evaltoin
pio run -e esp32dev
```

Upload from PlatformIO:

```bash
pio run -e esp32dev -t upload
pio device monitor -b 115200
```

## Repository structure

```text
.
├── firmware/
│   ├── include/
│   │   ├── config.h
│   │   ├── crypto_store.h
│   │   ├── detection_logic.h
│   │   ├── detector.h
│   │   ├── display.h
│   │   ├── models.h
│   │   ├── storage.h
│   │   ├── system_monitor.h
│   │   ├── text_utils.h
│   │   ├── web_admin.h
│   │   └── wifi_scanner.h
│   └── src/
├── tests/
├── docs/
│   └── firmware/
├── assets/
├── .github/workflows/
├── index.html
├── manifest.json
├── platformio.ini
├── SECURITY.md
└── LICENSE
```

## Validation status

| Validation | Status |
|---|---|
| Host detector logic tests | Automated in CI |
| ESP32 firmware compile | Automated in CI |
| 90% flash budget | Enforced in CI |
| Offensive modules removed from maintained main branch | Yes |
| Browser firmware/release packaging | v1.0.0 pipeline |
| Physical ESP32 boot | Requires real hardware validation |
| Real RF detection sensitivity | Requires controlled lab validation |
| OLED hardware | Requires optional display hardware |

See [Hardware Notes](docs/HARDWARE.md) before testing.

## Responsible use

Use the device only where you own the equipment or have permission to monitor the radio environment. The project is designed for defensive visibility and education, not interference.

## Author

Built and maintained by **Tanzeel Hussain**.

## License

MIT — see [LICENSE](LICENSE).
