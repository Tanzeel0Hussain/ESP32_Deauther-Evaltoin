# Detection Model

ESP32 Wireless Defense Lab is a passive observation tool. It does not transmit forged management frames or collect Wi-Fi credentials.

## What is observed

The receiver is limited to 802.11 management traffic and currently counts deauthentication and disassociation frames. Retry retransmissions are deduplicated using the 802.11 Retry bit together with sequence, fragment and subtype metadata. Each observation records only metadata needed for local analysis: source, destination, BSSID, receive channel and RSSI. A reason code is recorded only when the management-frame body is not protected; PMF/protected frames report the reason as unavailable instead of interpreting encrypted bytes.

## Burst rule

The default rule groups observations by source MAC and BSSID:

- detection window: 5 seconds
- default threshold: 10 frames
- configurable threshold: 3–200 frames
- per-source alert cooldown: 10 seconds
- tracked source/BSSID pairs: 32
- in-memory alert history: 32

When the table is full, the least-recently-seen source/BSSID slot is reused. This reduces avoidable eviction of currently active sources in busy environments.

## Channel coverage

Classic ESP32 has one 2.4 GHz radio. Normal monitoring therefore covers one configured channel at a time, shared with the local management AP.

A manual nearby-network inventory scan temporarily pauses fixed-channel monitoring, performs a passive 2.4 GHz scan without active probe requests, restores the configured monitor channel and resumes the detector. Both restoration operations are checked; failures are surfaced through the dashboard/API instead of being silently treated as success.

## Interpreting an alert

An alert means the configured observation threshold was reached. It is not proof of malicious intent or reliable attribution to a person/device. Legitimate network administration, roaming, unstable links and lab equipment can also create management-frame bursts.

Use alerts as a signal to investigate with authorized network-management and packet-analysis tools.
