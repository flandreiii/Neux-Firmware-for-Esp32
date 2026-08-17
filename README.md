# 🛰️ Neux-firmware

**Passive WiFi / BLE recon & network diagnostics toolkit for ESP32 — controllable over USB serial or WiFi.**

`#ESP32` `#WiFi` `#BLE` `#Bluetooth` `#CyberSecurity` `#NetworkSecurity` `#PenTesting` `#IoT` `#Arduino` `#OpenSource` `#InfoSec` `#WirelessSecurity` `#RedTeam` `#BlueTeam` `#Recon`

---

## ⚠️ Responsible Use

Neux-firmware is a **passive** recon and diagnostic tool. It does not contain deauthentication attacks, beacon/BLE spam, jamming, or packet injection of any kind — every mode only *listens*, it never transmits attacks against other devices.

**Only use this firmware on networks and devices you own, or where you have explicit written authorization to test.** Passive sniffing, LAN scanning, and port scanning of networks you do not control or do not have permission to test is illegal in most jurisdictions. You are solely responsible for how you use this tool.

---

## 📖 What is Neux-firmware?

Neux-firmware turns any ESP32 (DevKit V1, WROOM, S3, C3, M5Stick, etc.) into a compact wireless recon and network diagnostics station — no external modules required, just the WiFi + BLE (+ BT Classic, on supported chips) radios already built into the chip.

---

## 🔹 V1.0 — Serial Recon Base

The original release. Fully controlled over USB serial (e.g. from Termux, a serial terminal app, or the Arduino Serial Monitor).

**Features:**

- `WIFI_SCAN` — classic active WiFi network scan (SSID, BSSID, channel, RSSI, open/encrypted)
- `WIFI_SNIFF_START` / `WIFI_SNIFF_STOP` — passive 802.11 sniffer: logs beacons, probe requests, observed clients, and observed (not sent) deauth frames from surrounding traffic, with channel hopping across 1–13
- `WIFI_PCAP_START` / `WIFI_PCAP_STOP` — streams raw 802.11 frame headers over serial for capture/analysis on the connected computer/phone (e.g. via Wireshark)
- `BLE_SCAN <seconds>` — active BLE device scan (address, RSSI, name)
- `BT_SCAN` — Bluetooth Classic inquiry (on chips with BT Classic support)
- `STATUS` — chip model, core count, free heap, uptime, WiFi MAC
- `HELP` — full command list

No WiFi AP, no web dashboard — pure serial control.

---

## 🚀 V2.0 — Web Dashboard & Network Toolkit

Everything from V1.0, rebuilt into a firmware you can drive from your **phone's browser** over its own WiFi access point, on top of the original serial command set.

**New in V2.0:**

### 🌐 Web Dashboard
Self-hosted access point (`Neux-firmware` AP) serving a full control panel — live status, WiFi/BLE scanning, file browser, and downloads, no app required.

### 🛡️ Defensive / IDS-style Detection
- **Deauth & disassociation counter** — passively tallies deauth/disassoc management frames seen in the air, surfacing possible attacks nearby, without transmitting anything
- **Rogue AP / Evil Twin detector** — flags SSIDs seen broadcasting from multiple BSSIDs with mismatched security types

### 📡 Dual STA + AP Mode
Connect the ESP32 to a target WiFi network for diagnostics while keeping its own control AP alive — no need to disconnect your phone to test another network.

### 🔍 Network Diagnostics
- **Connectivity/DNS check** — resolve and reach a given host from the ESP32's network
- **LAN Scanner** — discover live hosts on the connected subnet ("who's on my network")
- **Port Scanner** — check common ports on a target IP for basic exposure auditing

### ⚙️ Administration
- Editable AP SSID/password and optional HTTP authentication on the whole dashboard, persisted to flash
- **OTA firmware updates** — flash new firmware straight from the browser, no USB cable needed after the first flash

### 🗂️ Data & Logging (carried over, expanded)
- All scan results, rogue AP reports, LAN scan results, and event logs saved to flash and downloadable

---

## 🧰 Requirements

- Any ESP32 board (DevKit V1 / WROOM / S3 / C3 / M5Stick)
- Arduino IDE or ArduinoDroid with the **ESP32 Arduino core** installed
- Built-in libraries only: `WiFi.h`, `esp_wifi.h`, `WebServer.h`, `SPIFFS.h`, `Update.h`, `BLEDevice.h`, `BLEScan.h`, `BLEAdvertisedDevice.h` — no third-party libraries needed

## 📲 Flashing

1. Open the `.ino` file in Arduino IDE or ArduinoDroid, inside a folder with the exact same name as the file.
2. Select an ESP32 board under **Tools → Board**.
3. Connect via USB and upload.
4. Connect to the `Neux-firmware` (V2.0) WiFi access point, or send serial commands at `115200` baud.

## 🖥️ Serial Commands (V2.0)

```
HELP
STATUS
AP_INFO
WIFI_SCAN
MONITOR_ON / MONITOR_OFF
BLE_SCAN 6
STA_CONNECT ssid pass
STA_DISCONNECT
STA_STATUS
NET_CHECK host
LAN_SCAN
PORT_SCAN ip
ROGUE_CHECK
FILES
SHOW WIFI / SHOW BLE / SHOW LOG
CLEAR
REBOOT
```

---

## 🗺️ Roadmap Ideas

- [ ] Scheduled/automatic scans with historical charts
- [ ] Export reports as PDF/CSV
- [ ] Multi-language dashboard

---

## ☕ Support the Project

If Neux-firmware saved you time or helped you learn, consider buying me a coffee:

**[buymeacoffee.com/flandreiii](https://buymeacoffee.com/flandreiii)**

---

## 📄 License

Add your preferred license here (MIT is a common choice for open hobbyist firmware — see [choosealicense.com](https://choosealicense.com/) if unsure).

---

## ⭐ Contributing

Issues and pull requests are welcome. Please keep any contributed features passive/diagnostic in nature — no active attack functionality (deauth injection, jamming, spam) will be merged.
