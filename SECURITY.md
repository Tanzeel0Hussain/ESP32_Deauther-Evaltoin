# Security Policy

## Maintained security model

ESP32 Wireless Defense Lab is maintained as a defensive, receive-only wireless visibility project.

The main branch does not maintain functionality for:

- deauthentication/disassociation packet injection,
- Evil Twin or access-point impersonation,
- password/credential collection,
- beacon flooding,
- handshake or PMKID harvesting,
- BLE advertisement spam,
- HID/keystroke injection.

## Local management security

The local dashboard uses:

- WPA2-protected management Wi-Fi,
- mandatory first-boot replacement of public setup credentials,
- separate management-Wi-Fi and admin passwords,
- HTTP Digest authentication,
- per-boot CSRF tokens for state-changing requests,
- AES-256-GCM application-level at-rest protection for local passwords,
- serial-assisted random recovery credentials if critical stored credentials cannot be decrypted,
- factory reset of both settings and the per-device credential master key,
- bounded input lengths and escaped HTML/JSON output.

The dashboard is served over local HTTP rather than TLS. Keep the management Wi-Fi trusted and physically local. If encrypted management credentials are corrupted, the firmware does not silently fall back to the public factory passwords; random recovery credentials are printed to the physical serial console and mandatory setup is re-enabled.

## Responsible reporting

If you find a security issue in the maintained defensive firmware, open a GitHub issue without publishing active credentials, private network identifiers, or exploit details that would put third parties at risk.
