/*
 * ============================================================
 *   N E U X   F I R M W A R E
 * ============================================================
 * Firmware pasiv de recon WiFi / BLE / Bluetooth Classic pentru
 * orice placa cu chip ESP32 (DevKit V1, M5Stick, WROOM, S3, C3).
 * Control TOTAL din Termux, prin comenzi text pe Serial (USB).
 *
 * NU CONTINE: deauth, beacon spam, BLE spam/jamming, injectie de
 * pachete sau orice forma de atac activ. Toate modurile doar
 * ASCULTA eterul (promiscuous / scan), nu transmit catre alte
 * dispozitive. Foloseste-l doar pe reteaua/dispozitivele tale
 * sau cu autorizatie explicita.
 *
 * Nu necesita module externe (fara NRF24, fara nimic) - foloseste
 * doar radio-urile WiFi+BLE(+BT Classic) integrate in chip.
 *
 * Biblioteci necesare (deja incluse in ESP32 Arduino Core, nu
 * trebuie instalate separat): WiFi.h, esp_wifi.h, BLEDevice.h,
 * BluetoothSerial.h (doar pe chipuri cu BT Classic)
 * ============================================================
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

#if CONFIG_BT_CLASSIC_ENABLED
  #include <BluetoothSerial.h>
  BluetoothSerial SerialBT;
#endif

#define FW_NAME "Neux Firmware"
#define FW_VER  "1.0"

// ---------------- stare globala ----------------
bool wifiSniffing   = false;
bool wifiPcapMode   = false;
uint8_t currentChannel = 1;
unsigned long lastHop = 0;
const uint16_t HOP_INTERVAL_MS = 300;

// ================= UTILITARE SERIAL =================
void printHelp() {
  Serial.println(F("---- Neux Firmware :: comenzi ----"));
  Serial.println(F("HELP                 - lista comenzi"));
  Serial.println(F("STATUS               - info placa/chip"));
  Serial.println(F("WIFI_SCAN            - scaneaza retele WiFi din jur"));
  Serial.println(F("WIFI_SNIFF_START     - pornit sniffer pasiv (beacons/probe/clienti)"));
  Serial.println(F("WIFI_SNIFF_STOP      - opreste sniffer-ul"));
  Serial.println(F("WIFI_PCAP_START      - stream .pcap live (pt Wireshark, via Termux)"));
  Serial.println(F("WIFI_PCAP_STOP       - opreste stream-ul pcap"));
  Serial.println(F("BLE_SCAN <secunde>   - scaneaza dispozitive BLE din jur"));
  #if CONFIG_BT_CLASSIC_ENABLED
  Serial.println(F("BT_SCAN              - inquiry Bluetooth Classic (doar cu BT Classic)"));
  #endif
  Serial.println(F("-----------------------------------"));
}

void printStatus() {
  Serial.println(F("---- STATUS ----"));
  Serial.print(F("Firmware : ")); Serial.print(FW_NAME); Serial.print(F(" v")); Serial.println(FW_VER);
  Serial.print(F("Chip     : ")); Serial.println(ESP.getChipModel());
  Serial.print(F("Cores    : ")); Serial.println(ESP.getChipCores());
  Serial.print(F("Heap lib : ")); Serial.print(ESP.getFreeHeap()); Serial.println(F(" bytes"));
  Serial.print(F("Uptime   : ")); Serial.print(millis() / 1000); Serial.println(F(" s"));
  Serial.print(F("MAC WiFi : ")); Serial.println(WiFi.macAddress());
  Serial.println(F("----------------"));
}

// ================= WIFI: SCAN CLASIC =================
void wifiScan() {
  Serial.println(F("[wifi] scanare in curs..."));
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  int n = WiFi.scanNetworks();
  Serial.print(F("[wifi] retele gasite: ")); Serial.println(n);
  for (int i = 0; i < n; i++) {
    Serial.printf("%2d | %-32s | %s | ch:%2d | %4ddBm | %s\n",
      i,
      WiFi.SSID(i).c_str(),
      WiFi.BSSIDstr(i).c_str(),
      WiFi.channel(i),
      WiFi.RSSI(i),
      (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) ? "OPEN" : "ENC"
    );
  }
  Serial.println(F("[wifi] scanare terminata"));
  WiFi.scanDelete();
}

// ================= WIFI: SNIFFER PASIV (text) =================
// Extrage doar antetul 802.11 (adrese MAC, tip cadru), NU continutul
// pachetelor de date - scop: recon pasiv (beacons, probe, clienti vazuti).
void IRAM_ATTR wifiSniffCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!wifiSniffing) return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload = pkt->payload;
  uint16_t frameCtrl = payload[0] | (payload[1] << 8);
  uint8_t frameType    = (frameCtrl >> 2) & 0x3;
  uint8_t frameSubtype  = (frameCtrl >> 4) & 0xF;

  char macBuf[18];
  uint8_t *addr2 = &payload[10]; // adresa sursa (de obicei transmitatorul)
  snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
           addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5]);

  if (frameType == 0) { // management
    if (frameSubtype == 8) {
      Serial.printf("[beacon] mac:%s ch:%d rssi:%d\n", macBuf, currentChannel, pkt->rx_ctrl.rssi);
    } else if (frameSubtype == 4) {
      Serial.printf("[probe_req] mac:%s ch:%d rssi:%d\n", macBuf, currentChannel, pkt->rx_ctrl.rssi);
    } else if (frameSubtype == 12) {
      Serial.printf("[deauth_seen] mac:%s ch:%d rssi:%d (doar observat, nu trimis de noi)\n",
                    macBuf, currentChannel, pkt->rx_ctrl.rssi);
    }
  } else if (frameType == 2) { // data - doar semnalam clientul, fara continut
    Serial.printf("[client_seen] mac:%s ch:%d rssi:%d\n", macBuf, currentChannel, pkt->rx_ctrl.rssi);
  }
}

void wifiSniffStart() {
  WiFi.mode(WIFI_MODE_NULL);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiSniffCallback);
  currentChannel = 1;
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  wifiSniffing = true;
  lastHop = millis();
  Serial.println(F("[wifi] sniffer pasiv PORNIT (Ctrl: WIFI_SNIFF_STOP)"));
}

void wifiSniffStop() {
  wifiSniffing = false;
  esp_wifi_set_promiscuous(false);
  Serial.println(F("[wifi] sniffer OPRIT"));
}

// ================= WIFI: STREAM PCAP LIVE =================
// Trimite fiecare cadru brut 802.11 catre Termux, incadrat cu
// sync+lungime+checksum, pt conversie in .pcap (DLT 105) pe telefon.
void IRAM_ATTR wifiPcapCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!wifiPcapMode) return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len > 1400) len = 1400; // limitam pt siguranta buffer serial

  uint8_t chk = 0xAA ^ 0x55 ^ (len & 0xFF) ^ ((len >> 8) & 0xFF);
  Serial.write(0xAA);
  Serial.write(0x55);
  Serial.write(len & 0xFF);
  Serial.write((len >> 8) & 0xFF);
  for (int i = 0; i < len; i++) {
    Serial.write(pkt->payload[i]);
    chk ^= pkt->payload[i];
  }
  Serial.write(chk);
}

void wifiPcapStart() {
  WiFi.mode(WIFI_MODE_NULL);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiPcapCallback);
  currentChannel = 1;
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  wifiPcapMode = true;
  lastHop = millis();
  Serial.println(F("[wifi] pcap stream PORNIT"));
}

void wifiPcapStop() {
  wifiPcapMode = false;
  esp_wifi_set_promiscuous(false);
  Serial.println(F("[wifi] pcap stream OPRIT"));
}

// ================= BLE SCAN =================
void bleScan(int seconds) {
  Serial.print(F("[ble] scanare ")); Serial.print(seconds); Serial.println(F("s..."));
  BLEDevice::init("");
  BLEScan *scan = BLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(100);
  scan->setWindow(99);
  BLEScanResults* results = scan->start(seconds, false);
int count = results->getCount();
Serial.print(F("[ble] dispozitive gasite: ")); Serial.println(count);
for (int i = 0; i < count; i++) {
  BLEAdvertisedDevice d = results->getDevice(i);
  Serial.printf("%2d | %s | rssi:%4d | %s\n",
    i,
    d.getAddress().toString().c_str(),
    d.getRSSI(),
    d.haveName() ? d.getName().c_str() : "(fara nume)"
  );
}
scan->clearResults();
  scan->clearResults();
  Serial.println(F("[ble] scanare terminata"));
}

// ================= BT CLASSIC SCAN =================
#if CONFIG_BT_CLASSIC_ENABLED
void btScan() {
  Serial.println(F("[bt] pornesc discovery Bluetooth Classic..."));
  SerialBT.begin("neux-scanner");
  BTScanResults *results = SerialBT.discover(10000); // 10s
  if (results) {
    Serial.print(F("[bt] dispozitive gasite: ")); Serial.println(results->getCount());
    for (int i = 0; i < results->getCount(); i++) {
      BTAdvertisedDevice *d = results->getDevice(i);
      Serial.printf("%2d | %s | %s | rssi:%4d\n",
        i, d->getAddress().toString().c_str(),
        d->getName().c_str(), d->getRSSI());
    }
  } else {
    Serial.println(F("[bt] niciun dispozitiv gasit"));
  }
  SerialBT.end();
  Serial.println(F("[bt] discovery terminat"));
}
#endif

// ================= COMMAND PARSER =================
void handleCommand(String cmd) {
  cmd.trim();
  if (cmd.length() == 0) return;

  if (cmd == "HELP") printHelp();
  else if (cmd == "STATUS") printStatus();
  else if (cmd == "WIFI_SCAN") wifiScan();
  else if (cmd == "WIFI_SNIFF_START") wifiSniffStart();
  else if (cmd == "WIFI_SNIFF_STOP") wifiSniffStop();
  else if (cmd == "WIFI_PCAP_START") wifiPcapStart();
  else if (cmd == "WIFI_PCAP_STOP") wifiPcapStop();
  else if (cmd.startsWith("BLE_SCAN")) {
    int secs = 8;
    int spaceIdx = cmd.indexOf(' ');
    if (spaceIdx > 0) secs = cmd.substring(spaceIdx + 1).toInt();
    if (secs <= 0) secs = 8;
    bleScan(secs);
  }
  #if CONFIG_BT_CLASSIC_ENABLED
  else if (cmd == "BT_SCAN") btScan();
  #endif
  else {
    Serial.print(F("[!] comanda necunoscuta: "));
    Serial.println(cmd);
    Serial.println(F("Scrie HELP pentru lista de comenzi."));
  }
}

// ================= SETUP / LOOP =================
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println();
  Serial.print(F("=== ")); Serial.print(FW_NAME); Serial.print(F(" v")); Serial.print(FW_VER); Serial.println(F(" ==="));
  Serial.println(F("Scrie HELP pentru comenzi."));
}

void loop() {
  // channel hopping cand suntem in sniff/pcap mode
  if ((wifiSniffing || wifiPcapMode) && millis() - lastHop > HOP_INTERVAL_MS) {
    currentChannel = (currentChannel % 13) + 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastHop = millis();
  }

  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    handleCommand(line);
  }
}
