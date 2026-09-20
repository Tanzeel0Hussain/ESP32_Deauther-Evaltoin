# Architecture

ESP32 Wireless Defense Lab is a defensive wireless visibility project for classic ESP32. Its detection path is receive-only and does not use raw 802.11 frame injection.

## Runtime data flow

```text
Nearby 2.4 GHz Wi-Fi
        │
        │ receive only
        ▼
ESP32 promiscuous management-frame filter
        │
        ├─ deauthentication
        └─ disassociation
        │
        ▼
source MAC + BSSID burst tracker
(Retry/sequence dedup + last-seen LRU)
        │
        ▼
bounded 16-entry fixed-size pending-alert queue
        │
        ▼
normal Arduino loop
        │
        ├─ alert history + JSON
        ├─ local protected dashboard
        └─ optional OLED status
```

The Wi-Fi callback performs bounded metadata parsing/copying only. Human-readable MAC formatting and dashboard alert records are produced outside the callback.

## Separate nearby-network scan

```text
dashboard request
      │
      ▼
pause promiscuous RX
      │
      ▼
WiFi.scanNetworks(passive=true)
      │
      ├─ SSID / BSSID
      ├─ RSSI
      ├─ channel
      └─ advertised security
      │
      ▼
restore configured monitor channel
      │
      ▼
resume promiscuous RX
```

Classic ESP32 has one 2.4 GHz radio, so the management AP and passive monitor share the configured channel. A full network scan temporarily interrupts fixed-channel monitoring.

## Local security

- WPA2-compatible management access point.
- Mandatory replacement of public first-boot credentials.
- HTTP Digest dashboard authentication.
- Per-boot CSRF token on state-changing requests.
- AES-256-GCM application-level credential storage with a random per-device master secret.
- Dual credential slots: new SSID/password/admin values are staged and verified in the inactive slot, then activated by one commit-pointer update; the previous committed slot remains available for rollback.
- Serial-assisted random recovery credentials if no complete committed credential set can be recovered or critical stored secrets cannot be decrypted.
- Factory reset clears both normal settings and the credential-master namespace.

## Defensive boundary

The maintained firmware does not implement deauthentication/disassociation transmission, access-point impersonation, credential capture, WPA/PMKID harvesting, beacon/BLE flooding, or HID injection.

CI scans relevant source-code extensions across the current repository checkout and fails if the ESP32 raw 802.11 transmit API `esp_wifi_80211_tx` or offensive credential-harvesting implementation markers appear.


## Radio-transmission scope

“Receive-only” describes the **detection path**. The ESP32 management access point still performs ordinary standards-compliant Wi-Fi transmissions required for local administration. The maintained firmware does not transmit forged deauthentication/disassociation frames or other attack traffic.
