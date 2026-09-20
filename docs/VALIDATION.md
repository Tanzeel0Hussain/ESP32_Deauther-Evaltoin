# Hardware Validation Checklist

CI verifies compilation and pure frame-classification logic, but it cannot prove real RF behavior. Complete this checklist on the actual target board before calling a release hardware-validated.

| Test | Pass condition |
|---|---|
| Browser/USB install | ESP32 flashes and boots without a reset loop |
| Management AP | `ESP32-Defense-Lab` appears after first boot |
| First-boot security | Normal dashboard remains locked until both setup passwords are replaced |
| Dashboard | `192.168.4.1` loads and status updates repeatedly |
| Persistence | Credentials, channel and threshold survive a power cycle |
| Nearby scan | Authorized local networks show plausible SSID/BSSID/RSSI/channel/security |
| Scan recovery | Passive monitor resumes on the configured channel after scanning |
| Channel change | Management AP and monitor return on the selected channel after restart |
| Passive counters | Controlled authorized disconnect/reconnect activity increments observed counters |
| Threshold alert | Authorized lab traffic reaching the configured threshold creates an alert |
| Alert context | Source/BSSID/channel/RSSI/window count are populated |
| Alert clear | Alert history clears without changing saved settings |
| Factory reset | Settings and credential master secret clear; first-boot setup returns |
| OLED | Optional 128×64 I2C status display works when enabled at build time |
| Heap stability | Repeated dashboard refreshes/scans do not progressively exhaust heap |
| Soak test | 12–24 hours of passive monitoring without reset loop or lock-up |

## Evidence to keep

1. Serial boot log.
2. Dashboard screenshots.
3. Known authorized test timestamps.
4. Free-heap readings before/after repeated scans.
5. 12–24 hour uptime record.
6. Exact ESP32 board/module and optional OLED details.

Never validate this project by disrupting third-party networks.
