# Security Policy

## Maintained scope

ESP32 Wireless Defense Lab is a **defensive, receive-only wireless monitoring project**.

The maintained firmware provides:

- passive nearby Wi-Fi inventory;
- passive observation of 802.11 deauthentication and disassociation management frames;
- threshold-based local alerts;
- channel/RSSI visibility;
- a protected local dashboard;
- optional OLED status output.

The maintained project intentionally does **not** provide packet injection, deauthentication transmission, credential collection, Evil Twin impersonation, rogue captive portals, WPA/PMKID capture, beacon flooding, BLE flooding or HID payload injection.

## Local management security

The management access point is protected with WPA2-compatible credentials and the dashboard uses HTTP Digest authentication. Factory credentials are setup-only: the normal dashboard remains locked until both the management Wi-Fi password and administrator password are changed.

Passwords are stored using AES-GCM protected application storage with a random per-device master secret. A failure to decrypt critical credentials enters serial-assisted recovery rather than silently falling back to known factory credentials.

The dashboard is local HTTP, not TLS. Use the management network as a trusted local administration network.

## Reporting

Please report security issues privately to the repository owner rather than publishing exploit details in a public issue before a fix is available.
