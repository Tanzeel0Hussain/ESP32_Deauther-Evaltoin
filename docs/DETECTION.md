# Detection Model

ESP32 Wireless Defense Lab is a passive observation tool. It does not transmit forged management frames or collect Wi-Fi credentials.

## What is observed

The receiver is limited to 802.11 management traffic and currently counts deauthentication and disassociation frames. Each observation records only metadata needed for local analysis: source, destination, BSSID, reason code, receive channel and RSSI.

## Burst rule

The default rule groups observations by source MAC and BSSID:

- detection window: 5 seconds
- default threshold: 10 frames
- configurable threshold: 3–200 frames
- per-source alert cooldown: 10 seconds
- tracked source/BSSID pairs: 16
- in-memory alert history: 32

The oldest source-tracking slot is reused when the table is full.

## Channel coverage

Classic ESP32 has one 2.4 GHz radio. Normal monitoring therefore covers one configured channel at a time, shared with the local management AP.

A manual nearby-network inventory scan temporarily pauses passive monitoring, surveys the 2.4 GHz channels, restores the configured monitor channel and resumes the detector.

## Interpreting an alert

An alert means the configured observation threshold was reached. It is not proof of malicious intent or reliable attribution to a person/device. Legitimate network administration, roaming, unstable links and lab equipment can also create management-frame bursts.

Use alerts as a signal to investigate with authorized network-management and packet-analysis tools.
