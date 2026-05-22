# 🔱 Hydra-ESP32 WiFi Security Tool

<div align="center">
<img src="https://img.shields.io/badge/ESP32-WiFi%20Security-red?style=for-the-badge&logo=espressif" alt="ESP32"/>
<img src="https://img.shields.io/badge/Arduino-IDE-blue?style=for-the-badge&logo=arduino" alt="Arduino"/>
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</div>

<div align="center">

[![Stars](https://img.shields.io/github/stars/yourusername/Hydra-ESP32?style=for-the-badge&color=yellow)](https://github.com/yourusername/Hydra-ESP32/stargazers)
[![Forks](https://img.shields.io/github/forks/yourusername/Hydra-ESP32?style=for-the-badge&color=orange)](https://github.com/yourusername/Hydra-ESP32/network/members)
[![Issues](https://img.shields.io/github/issues/yourusername/Hydra-ESP32?style=for-the-badge&color=red)](https://github.com/yourusername/Hydra-ESP32/issues)
[![License](https://img.shields.io/github/license/yourusername/Hydra-ESP32?style=for-the-badge&color=blue)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/yourusername/Hydra-ESP32?style=for-the-badge&color=brightgreen)](https://github.com/yourusername/Hydra-ESP32/commits)

</div>

A powerful wireless security research firmware for ESP32 microcontrollers. Features multi-target deauthentication attacks, Evil Twin captive portals, beacon spamming, BLE advertisement flooding, deauth detection, WPA handshake capture, and Bluetooth HID payloads. Built for authorized penetration testing and security research.

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized security testing and educational purposes only.** Unauthorized access to computer networks is illegal under the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), IT Act 2000, and equivalent legislation worldwide. The authors accept no liability for misuse. You are solely responsible for complying with all applicable laws.

---

## 📋 Table of Contents

- [Features](#-features)
- [Hardware Requirements](#-hardware-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Attack Modules](#-attack-modules)
- [Web Interface](#-web-interface)
- [API Reference](#-api-reference)
- [Troubleshooting](#-troubleshooting)
- [Credits](#-credits)
- [License](#-license)

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **Multi-Target Deauth** | Attack up to 16 WiFi networks simultaneously |
| **Evil Twin Portal** | Captive portal with automatic password verification |
| **Beacon Spam** | Generate up to 100 fake access points |
| **Ghost Mode** | Extract SSIDs from probe requests and clone them |
| **Deauth Detector** | Monitor and alert on active deauthentication attacks |
| **WPA Handshake** | Capture 4-way handshakes for offline cracking |
| **PMKID Capture** | Clientless WPA2 password hash extraction |
| **BSSID Clone** | Full AP impersonation (SSID + BSSID + Channel) |
| **BLE Spam** | Flood Apple, Samsung, and Google pairing popups |
| **HID Payloads** | Bluetooth keyboard injection attacks |
| **OLED Support** | Live status display on SSD1306 128x64 screen |

---

## 🛠️ Hardware Requirements

### Required

| Component | Specification |
|-----------|---------------|
| **Microcontroller** | ESP32 DevKit V1 / ESP32-WROOM-32 / ESP32-WROVER |
| **Chip** | Xtensa LX6 dual-core (240MHz) |
| **Flash** | Minimum 4MB |
| **USB** | Micro-USB or USB-C for programming |

> ⚠️ **Note:** ESP32-S2, S3, C3, and other variants are **not supported** due to different radio architectures.

### Optional

| Component | Purpose |
|-----------|---------|
| **SSD1306 OLED** | 128x64 I2C display for live attack status |
| **External Antenna** | Increased range for attacks |

### Pinout (OLED)

| OLED | ESP32 |
|------|-------|
| VCC | 3.3V |
| GND | GND |
| SDA | GPIO 21 |
| SCL | GPIO 22 |

---

## 📦 Installation

### Step 1: Arduino IDE Setup

Add ESP32 board support:
File → Preferences → Additional Board Manager URLs:
https://dl.espressif.com/dl/package_esp32_index.json

Tools → Board → Board Manager → Search "ESP32" → Install

### Step 2: Required Libraries

Install these libraries via Library Manager (`Sketch → Include Library → Manage Libraries`):

| Library | Version | Author |
|---------|---------|--------|
| `U8g2` | Latest | olikraus |
| `ArduinoJson` | 6.x | Benoit Blanchon |

For BLE features:
- `ESP32 BLE Arduino` (Built-in with ESP32 core)

### Step 3: Upload Firmware

1. Connect ESP32 to computer via USB
2. Select board: `Tools → Board → ESP32 Dev Module`
3. Select port: `Tools → Port → (Your COM Port)`
4. Upload speed: `921600`
5. Open `Hydra_ESP.ino` and click **Upload**

### Boot Mode (If Upload Fails)

Hold **BOOT** button → Click **Upload** → Release BOOT when "Connecting..." appears.

---

## 📱 Usage

### Initial Setup

| Parameter | Default Value |
|-----------|---------------|
| **AP SSID** | `Hydra-ESP` |
| **AP Password** | `12345678` |
| **Web Interface** | `http://192.168.4.1` |
| **Admin Page** | `http://192.168.4.1/admin` |

### Quick Start

1. **Power on** ESP32
2. **Connect** your phone/laptop to `Hydra-ESP` WiFi network
3. **Open browser** and navigate to `192.168.4.1`
4. **Scan** for target networks
5. **Select** a network and launch attack

---

## ⚔️ Attack Modules

### 1. Deauthentication Attack

Sends 802.11 deauthentication frames to disconnect clients from target AP.

```cpp
// Packet structure
Frame Control: 0xC0 (Deauth)
Reason Code: 0x0007 (Class 3 frame from non-associated STA)
```
# Supported Methods:

Broadcast deauth (all clients)
Directed deauth (specific MAC)
Deauth + Disassociation combo
**Effectiveness:** Bypassed by 802.11w (MFP). Use BSSID Clone for MFP-enabled networks.

## 2. Evil Twin Captive Portal
Creates an open clone of the target network with identical SSID.

# Workflow:

1. Clone target AP (same SSID, channel)
2. Run parallel deauth attack
3. Victims connect to open clone
4. Captive portal requests password
5. Automatic verification against real AP
6. Attack stops on successful verification
# Portal Features:

- Mobile-responsive design
- Router firmware update theme
- Real-time password validation
- Stores all attempts in memory
## 3. Beacon Spam
Floods the RF spectrum with fake beacon frames.

# Configuration:

- Count: 1-100 fake networks
- SSID: Random or custom list
- Interval: 100ms default
- Impact: Pollutes WiFi scan lists on all nearby devices.

## 4. Ghost Mode (Probe Request Sniffer)
# Mechanism:

1. Enters promiscuous mode
2. Captures probe request frames
3. Extracts SSIDs from saved networks
4. Immediately starts advertising those SSIDs
**Use Case:** Forces devices to connect to ESP32 instead of legitimate networks.

## 5. Deauth Attack Detector
**Detection Logic:**

- Monitors management frames in real-time
- Alerts when >10 deauth frames/sec from single BSSID
- Flags broadcast deauth (src: 00:00:00:00:00:00)
- Logs attacker BSSID, channel, and timestamp
**Display:** Live log table in web interface + OLED alerts.

## 6. WPA Handshake Capture
Forces re-authentication and captures the 4-way handshake.

# Output Formats:
```
- .pcap (Wireshark compatible)
- .hccapx (Hashcat compatible)
```
**Requirements:** At least one connected client on target network.

## 7. PMKID Capture (Clientless)
Extracts PMKID from RSN IE without requiring connected clients.

**Hash Mode:** 22000 (Hashcat)

**Success Rate:** ~80% on modern WPA2 networks. Some APs disable PMKID transmission.

## 8. BSSID Clone (Twin Deauth)
Creates exact AP duplicate including BSSID and channel.

**Advantage:** Bypasses 802.11w Management Frame Protection.

**Mechanism:** Conflicting beacon frames cause client disconnection.
## 9. BLE Spam
Broadcasts fake advertisement packets mimicking popular devices.

| Brand | Devices |
|---------|-------------|
| **Apple** | AirPods, AirPods Pro, AirPods Max, Apple TV, HomePod, Vision Pro |
| **Samsung** | Galaxy Buds, Galaxy Watch |
| **Google** | Pixel Buds, Fast Pair |
**Effect:** Continuous pairing popups on target devices.

## 10. Bluetooth HID Payloads
Advertises as Bluetooth keyboard (```Hydra-XXXX```).

**Capabilities:**

- Automatic pairing with Windows PCs
- Keystroke injection
- Pre-configured payloads (Reverse shell, Download & Execute, etc.)

## 🌐 Web Interface
Endpoints
| Endpoint | Function |
|---------|-------------|
| **/** | Main control panel |
| **/scan** | JSON API - scan networks |
| **/start** | Start attack |
| **/stop** | Stop attack |
| **/save** | Save captured password |
| **/admin** | 	View captured data |
| **/status** | Attack status JSON |

## Web UI Preview
- ┌─────────────────────────────────────┐
- │        🔱 Hydra-ESP32              │
- │    WiFi Security Tool              │
- ├─────────────────────────────────────┤
- │  [🔍 Scan Networks]               │
- │                                     │
- │  📶 TargetNetwork (WPA2)          │
- │  Signal: -45dBm | Ch: 6            │
- │  [🚀 Start Attack]                 │
- │                                     │
- │  Status: 🚨 ATTACKING              │
- │  Deauth: 150 packets sent          │
- │  Portal: 3 clients connected         │
- └─────────────────────────────────────┘

## 🔌 API Reference
Scan Networks
# Request:
```http GET /scan```
**Response:**
```json
{
  "networks": [
    {
      "ssid": "TargetNetwork",
      "bssid": "AA:BB:CC:DD:EE:FF",
      "channel": 6,
      "rssi": -45,
      "encrypted": true
    }
  ]
}
```
# Start Attack
# Request:

```http
GET /start?type=deauth&ssid=Target&bssid=AA:BB:CC:DD:EE:FF&ch=6
```
# Save Password
# Request:

```http
GET /save?pass=password123
```
# Response:

OK - Password correct, attack stopped
NO - Password incorrect

# 🖥️ OLED Display
If SSD1306 is connected, displays:
| Screen | Content |
|---------|-------------|
| **Boot** | Logo + Firmware version |
| **Idle** | IP address + Client count |
| **Scanning** | Progress + Networks found |
| **Attacking** | Target + Packets sent + Runtime |
| **Captured** | Password + Network name |

## 🐛 Troubleshooting
| Issue | Issue |
|---------|-------------|
| **Upload failed** | Hold BOOT button during upload |
| **Port not detected** | Install CH340/CP2102 drivers |
| **Deauth not working** | Target may have 802.11w enabled. Use BSSID Clone |
| **Web UI not loading** | Ensure connected to ```Hydra-ESP``` network |
| **OLED blank** | Check I2C wiring (SDA→GPIO21, SCL→GPIO22) |
| **BLE not working** | Restart ESP32, BLE stack may need reset |
| **Password verify fails** | Password verify fails |

## 📊 Performance

| Metric | Value |
|---------|-------------|
| **Deauth Rate** | ~20 packets/second per target |
| **Max Targets** | 16 simultaneous |
| **Web UI Response** | <100ms |
| **Scan Time** | ~3 seconds |
| **BLE Spam Range** | 	~10 meters |
| **WiFi Range** | ~50 meters (stock antenna) |

## 🔒 Security Features
- Automatic attack timeout (configurable)
- NVS encryption for stored credentials
- WPA2-PSK for management AP
- CSRF protection on web endpoints

## 🛡️ Defense Recommendations
To protect against these attacks:

1. **Enable WPA3** - Resists offline dictionary attacks
2. **Enable 802.11w** - Protected Management Frames
3. **Use hidden SSID** - Harder to target
4. **Strong passwords** - 12+ characters, mixed case
5. **Monitor rogue APs** - Use WiFi scanning tools
6. **Disable WPS** - Prevent brute force attacks
7. **BLE pairing** - Disable on unused devices
Input sanitization on all APIs
