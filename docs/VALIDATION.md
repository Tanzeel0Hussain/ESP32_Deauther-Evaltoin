# Hardware Validation Checklist

CI verifies compilation and pure detector logic, but it cannot prove real RF behavior. Complete this checklist on the actual target board before calling a release hardware-validated.

| Test | Pass condition |
|---|---|
| Browser/USB install | ESP32 flashes and boots without a reset loop |
| Management AP | `ESP32-Defense-Lab` appears after first boot |
| First-boot security | Normal dashboard remains locked until both setup passwords are replaced |
| Dashboard | `192.168.4.1` loads and status updates repeatedly |
| Persistence | Credentials, channel and threshold survive a power cycle |
| Nearby scan | Authorized local networks show plausible SSID/BSSID/RSSI/channel/security |
| Scan recovery | Passive detector resumes on the configured channel after scanning |
| Channel change | Management AP and detector return on the selected channel after restart |
| Passive counters | Authorized lab disconnect/reconnect activity increments observed counters |
| Burst alert | Controlled authorized test traffic crossing the threshold creates an alert |
| Alert context | Source/BSSID/channel/RSSI/reason fields are populated |
| Cooldown | Repeated activity respects the configured alert cooldown |
| Detector reset | Counters and alerts clear without corrupting settings |
| Logs | Boot/scan/settings events persist and clear correctly |
| Factory reset | Settings and credential master secret clear; first-boot setup returns |
| OLED | Optional SSD1306 status displays correctly at address 0x3C |
| Heap stability | Repeated dashboard refreshes/scans do not progressively exhaust heap |
| Soak test | 12–24 hours of passive monitoring without watchdog reset or lock-up |

## Evidence

Keep a serial boot log, dashboard screenshots, known test timestamps, free-heap readings before/after repeated scans, final soak-test uptime, and hardware photos.

Never validate this project by disrupting third-party networks.
