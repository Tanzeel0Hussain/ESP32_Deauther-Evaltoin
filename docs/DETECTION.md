# Detection Model

ESP32 Wireless Defense Lab is a passive observation tool. It does not transmit forged management frames or collect Wi-Fi credentials.

## What is observed

The receiver is limited to 802.11 management traffic and currently counts:

- deauthentication frames (management subtype 12);
- disassociation frames (management subtype 10).

The maintained detector records local metadata only: source MAC, BSSID, receive channel, RSSI, frame subtype, observed count and device uptime.

## Alert rule

The maintained default rule groups observations by source MAC:

- detection window: 10 seconds;
- default threshold: 15 observed deauth/disassociation frames;
- configurable threshold: 5–200 frames;
- tracked source windows: 8;
- in-memory alert history: 30 records;
- raw event queue: 64 entries.

One threshold alert is generated per tracked source in a detection window. The source window resets when the 10-second period expires.

## Channel coverage

Classic ESP32 has one 2.4 GHz radio. Normal monitoring therefore covers one configured channel at a time, shared with the local management AP.

A requested nearby-network scan temporarily pauses promiscuous monitoring, surveys nearby 2.4 GHz networks, restores the configured monitor channel and resumes passive monitoring.

## Interpreting an alert

An alert means the configured observation threshold was reached. It is **not proof of malicious intent** and is not reliable attribution to a person. Legitimate access-point/client behavior, roaming, unstable links and authorized lab equipment can also create management-frame bursts.

Use alerts as a signal to investigate with authorized network-management and packet-analysis tools.
