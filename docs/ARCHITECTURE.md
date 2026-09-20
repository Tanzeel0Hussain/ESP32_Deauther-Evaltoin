# Architecture

```text
Nearby 2.4 GHz Wi-Fi
        │
        │ passive receive only
        ▼
┌──────────────────────────┐
│ ESP32 promiscuous RX     │
│ management frames only   │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ Frame classifier         │
│ deauth / disassociation  │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ Per-source time windows  │
│ threshold + alert ring   │
└──────┬───────────┬───────┘
       │           │
       ▼           ▼
  Local Web UI   Optional OLED

Separate scan path:
WiFi.scanNetworks → SSID/BSSID/channel/RSSI/security → channel occupancy
```

## Design principles

- Receive-only monitoring.
- No raw 802.11 frame transmission.
- No credential capture.
- Small bounded in-memory queues.
- Protected local administration.
- Input/output escaping for local web data.
- Fixed-channel monitoring with explicit scan interruptions.
- Compile/test/release automation through GitHub Actions.
