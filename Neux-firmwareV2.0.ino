#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <SPIFFS.h>
#include <Update.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include "esp_wifi.h"

#define FW_NAME    "Neux-firmware"
#define FW_VERSION "2.0"
#define SERIAL_BAUD 115200

#define DEFAULT_AP_SSID "ESP32-TOOL"
#define DEFAULT_AP_PASS "esp32tool"

WebServer server(80);

// ------------------------------------------------------------
// STATE
// ------------------------------------------------------------

bool monitorRunning = false;
uint8_t monitorChannel = 1;

unsigned long bootMillis = 0;
unsigned long lastHopMillis = 0;

volatile uint32_t frameCounter   = 0;
volatile uint32_t deauthCounter  = 0;
volatile uint32_t disassocCounter = 0;
volatile uint32_t channelActivity[15]; // index 1..14 used

String serialBuffer = "";

bool staConnecting = false;
unsigned long staConnectStart = 0;

// config (loaded from /config.txt)
String cfgApSsid   = DEFAULT_AP_SSID;
String cfgApPass    = DEFAULT_AP_PASS;
bool   cfgAuthOn    = false;
String cfgAuthUser  = "admin";
String cfgAuthPass  = "admin";
String cfgStaSsid   = "";
String cfgStaPass   = "";

#define WIFI_FILE   "/wifi.txt"
#define BLE_FILE    "/ble.json"
#define LOG_FILE    "/events.txt"
#define ROGUE_FILE  "/rogue.json"
#define LAN_FILE    "/lan.json"
#define CONFIG_FILE "/config.txt"


// ============================================================
// FORWARD DECLARATIONS
// ============================================================

String readFile(const char *filename);
void writeFile(const char *filename, const String &data);
void appendFile(const char *filename, const String &data);
void deleteFile(const char *filename);
void logEvent(const String &event);

String jsonEscape(String value);
String securityName(wifi_auth_mode_t mode);

void loadConfig();
void saveConfig();
bool checkAuth();

String scanWiFi();
void startWiFiMonitor();
void stopWiFiMonitor();
void updateWiFiMonitor();
void IRAM_ATTR wifiPacketCallback(void *buffer, wifi_promiscuous_pkt_type_t type);

String scanBLE(uint32_t seconds);

String getStatusJSON();

bool staConnect(const String &ssid, const String &pass);
void staDisconnect();
String getStaStatusJSON();

String netCheck(const String &host, uint16_t port);
String scanLAN();
String portScan(const String &ipStr);

void handleRoot();
void handleStatus();
void handleWiFi();
void handleBLE();
void handleMonitorOn();
void handleMonitorOff();
void handleFile();
void handleClear();
void handleDownload();
void handleGetConfig();
void handleSetConfig();
void handleStaConnect();
void handleStaDisconnect();
void handleStaStatus();
void handleNetCheck();
void handleLanScan();
void handlePortScan();
void handleRogue();
void handleUpdatePage();
void handleUpdateUpload();
void handleNotFound();

void printHelp();
void printStatus();
void serialCommand(String command);


// ============================================================
// FILESYSTEM
// ============================================================

String readFile(const char *filename)
{
  if (!SPIFFS.exists(filename)) return "";
  File file = SPIFFS.open(filename, "r");
  if (!file) return "";
  String result = file.readString();
  file.close();
  return result;
}

void writeFile(const char *filename, const String &data)
{
  File file = SPIFFS.open(filename, "w");
  if (!file) return;
  file.print(data);
  file.close();
}

void appendFile(const char *filename, const String &data)
{
  File file = SPIFFS.open(filename, "a");
  if (!file) return;
  file.print(data);
  file.close();
}

void deleteFile(const char *filename)
{
  if (SPIFFS.exists(filename)) SPIFFS.remove(filename);
}

void logEvent(const String &event)
{
  String line;
  line += String(millis());
  line += " | ";
  line += event;
  line += "\n";
  appendFile(LOG_FILE, line);
}


// ============================================================
// CONFIG
// ============================================================

void loadConfig()
{
  if (!SPIFFS.exists(CONFIG_FILE))
  {
    saveConfig();
    return;
  }

  String data = readFile(CONFIG_FILE);
  int start = 0;

  while (start < (int) data.length())
  {
    int nl = data.indexOf('\n', start);
    if (nl == -1) nl = data.length();

    String line = data.substring(start, nl);
    line.trim();
    start = nl + 1;

    if (line.length() == 0 || line.startsWith("#")) continue;

    int eq = line.indexOf('=');
    if (eq == -1) continue;

    String key = line.substring(0, eq);
    String val = line.substring(eq + 1);

    if (key == "ap_ssid")   cfgApSsid = val;
    else if (key == "ap_pass")   cfgApPass = val;
    else if (key == "auth_on")   cfgAuthOn = (val == "1");
    else if (key == "auth_user") cfgAuthUser = val;
    else if (key == "auth_pass") cfgAuthPass = val;
    else if (key == "sta_ssid")  cfgStaSsid = val;
    else if (key == "sta_pass")  cfgStaPass = val;
  }
}

void saveConfig()
{
  String out;
  out += "ap_ssid=" + cfgApSsid + "\n";
  out += "ap_pass=" + cfgApPass + "\n";
  out += "auth_on=" + String(cfgAuthOn ? "1" : "0") + "\n";
  out += "auth_user=" + cfgAuthUser + "\n";
  out += "auth_pass=" + cfgAuthPass + "\n";
  out += "sta_ssid=" + cfgStaSsid + "\n";
  out += "sta_pass=" + cfgStaPass + "\n";

  writeFile(CONFIG_FILE, out);
}

bool checkAuth()
{
  if (!cfgAuthOn) return true;

  if (!server.authenticate(cfgAuthUser.c_str(), cfgAuthPass.c_str()))
  {
    server.requestAuthentication();
    return false;
  }

  return true;
}


// ============================================================
// STRING HELPERS
// ============================================================

String jsonEscape(String value)
{
  value.replace("\\", "\\\\");
  value.replace("\"", "\\\"");
  value.replace("\r", " ");
  value.replace("\n", " ");
  return value;
}

String securityName(wifi_auth_mode_t mode)
{
  switch (mode)
  {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default: return "OTHER";
  }
}


// ============================================================
// WIFI SCANNER (+ rogue AP / evil-twin heuristic)
// ============================================================

String scanWiFi()
{
  bool oldMonitorState = monitorRunning;

  if (oldMonitorState)
  {
    monitorRunning = false;
    esp_wifi_set_promiscuous(false);
  }

  WiFi.mode(WIFI_AP_STA);

  Serial.println();
  Serial.println("[WIFI] Scan started...");

  int count = WiFi.scanNetworks(false, true);

  if (count < 0)
  {
    Serial.println("[WIFI] Scan failed.");
    if (oldMonitorState) startWiFiMonitor();
    return "[]";
  }

  String json = "[";
  String text = "";

  // for rogue AP detection: track first-seen bssid+security per SSID
  const int MAXNET = 64;
  String seenSsid[MAXNET];
  String seenBssid[MAXNET];
  String seenSec[MAXNET];
  bool rogueFlag[MAXNET];
  int seenCount = 0;

  for (int i = 0; i < count; i++)
  {
    String ssid = WiFi.SSID(i);
    String bssid = WiFi.BSSIDstr(i);
    int channel = WiFi.channel(i);
    int rssi = WiFi.RSSI(i);
    String security = securityName(WiFi.encryptionType(i));

    if (i > 0) json += ",";

    json += "{";
    json += "\"ssid\":\"" + jsonEscape(ssid) + "\",";
    json += "\"bssid\":\"" + bssid + "\",";
    json += "\"channel\":" + String(channel) + ",";
    json += "\"rssi\":" + String(rssi) + ",";
    json += "\"security\":\"" + security + "\"";
    json += "}";

    text += ssid + " | " + bssid + " | CH" + String(channel) +
            " | " + String(rssi) + " dBm | " + security + "\n";

    Serial.println(
      String(i) + " | " + ssid + " | " + bssid +
      " | CH" + String(channel) + " | " + String(rssi) +
      " dBm | " + security
    );

    // rogue AP heuristic: same SSID, different BSSID/security already seen
    if (ssid.length() > 0)
    {
      bool found = false;

      for (int k = 0; k < seenCount; k++)
      {
        if (seenSsid[k] == ssid)
        {
          found = true;

          if (seenBssid[k] != bssid || seenSec[k] != security)
          {
            rogueFlag[k] = true;
          }
        }
      }

      if (!found && seenCount < MAXNET)
      {
        seenSsid[seenCount] = ssid;
        seenBssid[seenCount] = bssid;
        seenSec[seenCount] = security;
        rogueFlag[seenCount] = false;
        seenCount++;
      }
    }
  }

  json += "]";

  writeFile(WIFI_FILE, text);

  // build rogue AP report
  String rogueJson = "[";
  bool firstRogue = true;

  for (int k = 0; k < seenCount; k++)
  {
    if (!rogueFlag[k]) continue;

    if (!firstRogue) rogueJson += ",";
    firstRogue = false;

    rogueJson += "{\"ssid\":\"" + jsonEscape(seenSsid[k]) + "\"}";
  }

  rogueJson += "]";
  writeFile(ROGUE_FILE, rogueJson);

  if (firstRogue == false)
  {
    logEvent("ROGUE_AP_SUSPECTED");
  }

  WiFi.scanDelete();

  logEvent("WIFI_SCAN");

  if (oldMonitorState) startWiFiMonitor();

  Serial.print("[WIFI] Found: ");
  Serial.println(count);

  return json;
}


// ============================================================
// WIFI PASSIVE MONITOR (frame counting + deauth/disassoc IDS)
// ============================================================

typedef struct
{
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t seq_ctrl;
} wifi_mgmt_hdr_t;

void IRAM_ATTR wifiPacketCallback(
  void *buffer,
  wifi_promiscuous_pkt_type_t type)
{
  if (!monitorRunning) return;
  if (buffer == nullptr) return;

  frameCounter++;

  if (monitorChannel >= 1 && monitorChannel <= 14)
  {
    channelActivity[monitorChannel]++;
  }

  if (type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *) buffer;
  uint8_t *payload = pkt->payload;

  uint8_t frameType    = (payload[0] & 0x0C) >> 2;
  uint8_t frameSubtype  = (payload[0] & 0xF0) >> 4;

  if (frameType == 0) // management
  {
    if (frameSubtype == 0x0C) deauthCounter++;      // deauthentication
    else if (frameSubtype == 0x0A) disassocCounter++; // disassociation
  }
}

void startWiFiMonitor()
{
  if (monitorRunning) return;

  WiFi.mode(WIFI_AP_STA);

  monitorChannel = 1;
  esp_wifi_set_channel(monitorChannel, WIFI_SECOND_CHAN_NONE);

  esp_wifi_set_promiscuous_rx_cb(wifiPacketCallback);
  esp_wifi_set_promiscuous(true);

  monitorRunning = true;
  lastHopMillis = millis();

  logEvent("WIFI_MONITOR_ON");
  Serial.println("[WIFI] Passive monitor ON");
}

void stopWiFiMonitor()
{
  if (!monitorRunning) return;

  monitorRunning = false;
  esp_wifi_set_promiscuous(false);

  logEvent("WIFI_MONITOR_OFF");
  Serial.println("[WIFI] Passive monitor OFF");
}

void updateWiFiMonitor()
{
  if (!monitorRunning) return;

  unsigned long now = millis();
  if (now - lastHopMillis < 400) return;

  lastHopMillis = now;
  monitorChannel++;
  if (monitorChannel > 13) monitorChannel = 1;

  esp_wifi_set_channel(monitorChannel, WIFI_SECOND_CHAN_NONE);
}


// ============================================================
// BLE SCANNER
// ============================================================

class MyBLECallbacks : public BLEAdvertisedDeviceCallbacks
{
public:
  String result;
  String text;
  bool first;

  MyBLECallbacks() { result = "["; text = ""; first = true; }

  void onResult(BLEAdvertisedDevice device) override
  {
    String address = device.getAddress().toString().c_str();
    String name = "";
    if (device.haveName()) name = device.getName().c_str();
    int rssi = device.getRSSI();

    if (!first) result += ",";
    first = false;

    result += "{";
    result += "\"address\":\"" + jsonEscape(address) + "\",";
    result += "\"name\":\"" + jsonEscape(name) + "\",";
    result += "\"rssi\":" + String(rssi);
    result += "}";

    text += address + " | " + (name.length() > 0 ? name : "(unknown)") +
            " | " + String(rssi) + " dBm\n";
  }

  String getJSON()
  {
    String output = result;
    output += "]";
    return output;
  }
};

MyBLECallbacks bleCallbacks;
bool bleInitialized = false;

String scanBLE(uint32_t seconds)
{
  if (seconds < 1) seconds = 1;
  if (seconds > 20) seconds = 20;

  Serial.println();
  Serial.print("[BLE] Scanning ");
  Serial.print(seconds);
  Serial.println(" seconds...");

  if (!bleInitialized)
  {
    BLEDevice::init("");
    bleInitialized = true;
  }

  BLEScan *scanner = BLEDevice::getScan();
  if (scanner == nullptr)
  {
    Serial.println("[BLE] Scanner unavailable.");
    return "[]";
  }

  bleCallbacks.result = "[";
  bleCallbacks.text = "";
  bleCallbacks.first = true;

  scanner->setAdvertisedDeviceCallbacks(&bleCallbacks, false);
  scanner->setActiveScan(true);
  scanner->setInterval(100);
  scanner->setWindow(80);

  scanner->start(seconds, false);

  String output = bleCallbacks.getJSON();
  writeFile(BLE_FILE, output);
  scanner->clearResults();

  logEvent("BLE_SCAN");
  Serial.println("[BLE] Scan finished.");

  return output;
}


// ============================================================
// STA (client) CONNECTIVITY — dual AP+STA, diagnostics only
// ============================================================

bool staConnect(const String &ssid, const String &pass)
{
  if (ssid.length() == 0) return false;

  WiFi.mode(WIFI_AP_STA);
  WiFi.begin(ssid.c_str(), pass.c_str());

  staConnecting = true;
  staConnectStart = millis();

  logEvent("STA_CONNECT_ATTEMPT:" + ssid);

  return true;
}

void staDisconnect()
{
  WiFi.disconnect(false, true);
  staConnecting = false;
  logEvent("STA_DISCONNECT");
}

String getStaStatusJSON()
{
  bool connected = (WiFi.status() == WL_CONNECTED);

  String json = "{";
  json += "\"connected\":" + String(connected ? "true" : "false") + ",";
  json += "\"connecting\":" + String(staConnecting && !connected ? "true" : "false") + ",";
  json += "\"ssid\":\"" + jsonEscape(WiFi.SSID()) + "\",";
  json += "\"ip\":\"" + (connected ? WiFi.localIP().toString() : String("")) + "\",";
  json += "\"rssi\":" + String(connected ? WiFi.RSSI() : 0);
  json += "}";

  return json;
}


// ============================================================
// NETWORK DIAGNOSTICS
// ============================================================

String netCheck(const String &host, uint16_t port)
{
  String json = "{";
  json += "\"host\":\"" + jsonEscape(host) + "\",";

  IPAddress resolved;
  bool dnsOk = WiFi.hostByName(host.c_str(), resolved);

  json += "\"dns_ok\":" + String(dnsOk ? "true" : "false") + ",";
  json += "\"resolved_ip\":\"" + (dnsOk ? resolved.toString() : String("")) + "\",";

  bool reachable = false;

  if (dnsOk)
  {
    WiFiClient client;
    client.setTimeout(2000);
    reachable = client.connect(resolved, port);
    client.stop();
  }

  json += "\"reachable\":" + String(reachable ? "true" : "false") + ",";
  json += "\"port\":" + String(port);
  json += "}";

  logEvent("NET_CHECK:" + host);

  return json;
}


// ============================================================
// LAN SCANNER — discover live hosts on the connected STA subnet
// ============================================================

String scanLAN()
{
  if (WiFi.status() != WL_CONNECTED)
  {
    return "{\"error\":\"not connected to a network (STA)\"}";
  }

  IPAddress local = WiFi.localIP();
  IPAddress mask = WiFi.subnetMask();

  uint32_t localInt = (uint32_t) local;
  uint32_t maskInt = (uint32_t) mask;
  uint32_t network = localInt & maskInt;
  uint32_t broadcast = network | (~maskInt);

  uint32_t startHost = network + 1;
  uint32_t endHost = broadcast - 1;

  // safety cap: never scan more than 254 hosts
  if (endHost - startHost > 254) endHost = startHost + 254;

  String json = "[";
  bool first = true;
  int found = 0;

  Serial.println("[LAN] Scanning subnet...");

  for (uint32_t h = startHost; h <= endHost; h++)
  {
    IPAddress ip(h);

    WiFiClient client;
    client.setTimeout(150);

    bool up = client.connect(ip, 80);
    client.stop();

    if (!up)
    {
      // also try 443 as a fallback check
      WiFiClient client2;
      client2.setTimeout(150);
      up = client2.connect(ip, 443);
      client2.stop();
    }

    if (up)
    {
      if (!first) json += ",";
      first = false;

      json += "{\"ip\":\"" + ip.toString() + "\"}";
      found++;

      Serial.println("[LAN] Host up: " + ip.toString());
    }

    // yield periodically so the web server / watchdog stay responsive
    if ((h - startHost) % 8 == 0) yield();
  }

  json += "]";

  writeFile(LAN_FILE, json);
  logEvent("LAN_SCAN:found=" + String(found));

  return json;
}


// ============================================================
// TCP PORT SCANNER — common ports on a single target IP
// ============================================================

String portScan(const String &ipStr)
{
  IPAddress ip;

  if (!ip.fromString(ipStr))
  {
    return "{\"error\":\"invalid ip\"}";
  }

  const uint16_t ports[] = {
    21, 22, 23, 25, 53, 80, 110, 143,
    443, 445, 993, 995, 3306, 3389, 5900, 8080
  };

  const int portCount = sizeof(ports) / sizeof(ports[0]);

  String json = "{\"ip\":\"" + ipStr + "\",\"open_ports\":[";
  bool first = true;

  for (int i = 0; i < portCount; i++)
  {
    WiFiClient client;
    client.setTimeout(300);

    bool open = client.connect(ip, ports[i]);
    client.stop();

    if (open)
    {
      if (!first) json += ",";
      first = false;
      json += String(ports[i]);
    }

    yield();
  }

  json += "]}";

  logEvent("PORT_SCAN:" + ipStr);

  return json;
}


// ============================================================
// DEVICE STATUS
// ============================================================

String getStatusJSON()
{
  String json = "{";
  json += "\"name\":\"" FW_NAME "\",";
  json += "\"firmware\":\"" FW_VERSION "\",";
  json += "\"chip\":\"" + String(ESP.getChipModel()) + "\",";
  json += "\"heap\":" + String(ESP.getFreeHeap()) + ",";
  json += "\"uptime\":" + String((millis() - bootMillis) / 1000) + ",";
  json += "\"channel\":" + String(monitorChannel) + ",";
  json += "\"frames\":" + String(frameCounter) + ",";
  json += "\"deauth\":" + String(deauthCounter) + ",";
  json += "\"disassoc\":" + String(disassocCounter) + ",";
  json += "\"monitor\":" + String(monitorRunning ? "true" : "false") + ",";
  json += "\"ip\":\"" + WiFi.softAPIP().toString() + "\",";
  json += "\"sta_connected\":" + String(WiFi.status() == WL_CONNECTED ? "true" : "false");
  json += "}";

  return json;
}


// ============================================================
// WEB PAGE
// ============================================================

const char MAIN_PAGE[] PROGMEM = R"HTML(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Neux-firmware</title>
<style>
body{margin:0;background:#080b10;color:#eeeeee;font-family:Arial,sans-serif;}
header{background:#121821;padding:18px;border-bottom:1px solid #2b3542;}
header h1{margin:0;}
header p{opacity:.6;}
main{max-width:900px;margin:auto;padding:12px;}
.card{background:#121821;border:1px solid #293442;border-radius:12px;padding:15px;margin-bottom:12px;}
button{border:0;border-radius:8px;padding:11px 14px;margin:3px;background:#26384b;color:white;}
button.danger{background:#762c2c;}
input{background:#05070a;border:1px solid #293442;color:#eee;border-radius:6px;padding:8px;margin:3px;}
pre{background:#05070a;border-radius:8px;padding:12px;white-space:pre-wrap;overflow:auto;max-height:420px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;}
.stat{background:#080d13;border-radius:8px;padding:12px;}
.stat b{display:block;font-size:18px;}
.stat span{opacity:.6;font-size:12px;}
a{color:#80c7ff;}
label{display:block;font-size:12px;opacity:.7;margin-top:6px;}
</style>
</head>
<body>
<header>
<h1>Neux-firmware <span style="opacity:.5;font-size:14px;">V2.0</span></h1>
<p>WiFi / BLE / Monitor / Network Toolkit</p>
</header>
<main>

<div class="card">
<h2>Status</h2>
<div id="status" class="grid"></div>
<button onclick="refreshStatus()">Refresh</button>
</div>

<div class="card">
<h2>WiFi Recon</h2>
<button onclick="wifiScan()">WiFi Scan</button>
<button onclick="monitor(1)">Monitor ON</button>
<button onclick="monitor(0)">Monitor OFF</button>
<button onclick="getRogue()">Check Rogue AP</button>
<pre id="wifi">Ready.</pre>
</div>

<div class="card">
<h2>Bluetooth Low Energy</h2>
<button onclick="bleScan()">BLE Scan</button>
<pre id="ble">Ready.</pre>
</div>

<div class="card">
<h2>Connect to WiFi (STA)</h2>
<label>SSID</label>
<input id="staSsid" placeholder="Network name">
<label>Password</label>
<input id="staPass" type="password" placeholder="Password">
<br>
<button onclick="staConnect()">Connect</button>
<button class="danger" onclick="staDisconnect()">Disconnect</button>
<pre id="sta">Not connected.</pre>
</div>

<div class="card">
<h2>Network Diagnostics</h2>
<label>Host</label>
<input id="netHost" placeholder="example.com or 192.168.1.1" value="google.com">
<br>
<button onclick="netCheck()">Test Connectivity</button>
<pre id="net">Ready.</pre>
</div>

<div class="card">
<h2>LAN Scanner</h2>
<p style="opacity:.6;font-size:12px;">Scans devices on the network you're connected to (STA). May take a few minutes.</p>
<button onclick="lanScan()">Scan LAN</button>
<pre id="lan">Ready.</pre>
</div>

<div class="card">
<h2>Port Scanner</h2>
<label>Target IP</label>
<input id="portIp" placeholder="192.168.1.1">
<br>
<button onclick="portScan()">Scan Common Ports</button>
<pre id="ports">Ready.</pre>
</div>

<div class="card">
<h2>Saved Data</h2>
<button onclick="showFile('wifi')">WiFi</button>
<button onclick="showFile('ble')">BLE</button>
<button onclick="showFile('log')">Log</button>
<button class="danger" onclick="clearData()">Delete collected data</button>
<pre id="files">Ready.</pre>
</div>

<div class="card">
<h2>Downloads</h2>
<a href="/download?file=wifi">WiFi results</a><br><br>
<a href="/download?file=ble">BLE results</a><br><br>
<a href="/download?file=log">Event log</a>
</div>

<div class="card">
<h2>Settings</h2>
<label>AP SSID</label>
<input id="cfgApSsid" placeholder="AP SSID">
<label>AP Password</label>
<input id="cfgApPass" placeholder="AP Password">
<label>Dashboard auth</label>
<select id="cfgAuthOn"><option value="0">Off</option><option value="1">On</option></select>
<label>Auth user</label>
<input id="cfgAuthUser" placeholder="username">
<label>Auth password</label>
<input id="cfgAuthPass" type="password" placeholder="password">
<br>
<button onclick="loadConfigForm()">Load Current</button>
<button onclick="saveConfigForm()">Save (reboot required for AP change)</button>
<pre id="cfgResult"></pre>
</div>

<div class="card">
<h2>Firmware Update (OTA)</h2>
<form method="POST" action="/update" enctype="multipart/form-data">
<input type="file" name="firmware">
<button type="submit">Upload &amp; Flash</button>
</form>
</div>

<div class="card">
<h2>USB Serial commands</h2>
<pre>
HELP
STATUS
WIFI_SCAN
MONITOR_ON / MONITOR_OFF
BLE_SCAN 6
STA_CONNECT ssid pass
STA_STATUS
NET_CHECK host
LAN_SCAN
PORT_SCAN ip
ROGUE_CHECK
FILES
SHOW WIFI / SHOW BLE / SHOW LOG
CLEAR
REBOOT
</pre>
</div>

</main>

<script>
async function getText(url, opts){
  let response = await fetch(url, opts);
  return await response.text();
}

async function refreshStatus(){
  try{
    let data = JSON.parse(await getText("/api/status"));
    document.getElementById("status").innerHTML =
      "<div class=stat><b>"+data.name+"</b><span>Device</span></div>" +
      "<div class=stat><b>v"+data.firmware+"</b><span>Firmware</span></div>" +
      "<div class=stat><b>"+data.chip+"</b><span>Chip</span></div>" +
      "<div class=stat><b>"+data.heap+"</b><span>Free heap</span></div>" +
      "<div class=stat><b>"+data.uptime+" s</b><span>Uptime</span></div>" +
      "<div class=stat><b>"+data.channel+"</b><span>Channel</span></div>" +
      "<div class=stat><b>"+data.frames+"</b><span>Frames</span></div>" +
      "<div class=stat><b>"+data.deauth+"</b><span>Deauth frames</span></div>" +
      "<div class=stat><b>"+data.disassoc+"</b><span>Disassoc frames</span></div>" +
      "<div class=stat><b>"+data.ip+"</b><span>AP IP</span></div>" +
      "<div class=stat><b>"+(data.sta_connected?"Yes":"No")+"</b><span>STA connected</span></div>";
  }catch(error){
    document.getElementById("status").innerText = "Status error: " + error;
  }
}

async function wifiScan(){
  document.getElementById("wifi").innerText = "Scanning...";
  try{
    let data = JSON.parse(await getText("/api/wifi"));
    document.getElementById("wifi").innerText = JSON.stringify(data, null, 2);
  }catch(error){ document.getElementById("wifi").innerText = "Error: " + error; }
}

async function getRogue(){
  try{
    let data = JSON.parse(await getText("/api/rogue"));
    document.getElementById("wifi").innerText = "Rogue AP check:\n" + JSON.stringify(data, null, 2);
  }catch(error){ document.getElementById("wifi").innerText = "Error: " + error; }
}

async function monitor(state){
  let url = state ? "/api/monitor/on" : "/api/monitor/off";
  document.getElementById("wifi").innerText = await getText(url);
  refreshStatus();
}

async function bleScan(){
  document.getElementById("ble").innerText = "Scanning BLE...";
  try{
    let data = JSON.parse(await getText("/api/ble"));
    document.getElementById("ble").innerText = JSON.stringify(data, null, 2);
  }catch(error){ document.getElementById("ble").innerText = "Error: " + error; }
}

async function staConnect(){
  let ssid = document.getElementById("staSsid").value;
  let pass = document.getElementById("staPass").value;
  document.getElementById("sta").innerText = "Connecting...";
  let data = await getText("/api/sta/connect?ssid=" + encodeURIComponent(ssid) + "&pass=" + encodeURIComponent(pass));
  document.getElementById("sta").innerText = data;
  setTimeout(staStatus, 4000);
}

async function staDisconnect(){
  document.getElementById("sta").innerText = await getText("/api/sta/disconnect");
  refreshStatus();
}

async function staStatus(){
  try{
    let data = JSON.parse(await getText("/api/sta/status"));
    document.getElementById("sta").innerText = JSON.stringify(data, null, 2);
  }catch(error){ document.getElementById("sta").innerText = "Error: " + error; }
  refreshStatus();
}

async function netCheck(){
  let host = document.getElementById("netHost").value;
  document.getElementById("net").innerText = "Testing...";
  try{
    let data = JSON.parse(await getText("/api/netcheck?host=" + encodeURIComponent(host)));
    document.getElementById("net").innerText = JSON.stringify(data, null, 2);
  }catch(error){ document.getElementById("net").innerText = "Error: " + error; }
}

async function lanScan(){
  document.getElementById("lan").innerText = "Scanning LAN, this can take a few minutes...";
  try{
    let data = JSON.parse(await getText("/api/lanscan"));
    document.getElementById("lan").innerText = JSON.stringify(data, null, 2);
  }catch(error){ document.getElementById("lan").innerText = "Error: " + error; }
}

async function portScan(){
  let ip = document.getElementById("portIp").value;
  document.getElementById("ports").innerText = "Scanning...";
  try{
    let data = JSON.parse(await getText("/api/portscan?ip=" + encodeURIComponent(ip)));
    document.getElementById("ports").innerText = JSON.stringify(data, null, 2);
  }catch(error){ document.getElementById("ports").innerText = "Error: " + error; }
}

async function showFile(name){
  document.getElementById("files").innerText = await getText("/api/file?file=" + name);
}

async function clearData(){
  if(!confirm("Delete all collected data?")) return;
  document.getElementById("files").innerText = await getText("/api/clear");
}

async function loadConfigForm(){
  try{
    let data = JSON.parse(await getText("/api/config"));
    document.getElementById("cfgApSsid").value = data.ap_ssid;
    document.getElementById("cfgApPass").value = data.ap_pass;
    document.getElementById("cfgAuthOn").value = data.auth_on ? "1" : "0";
    document.getElementById("cfgAuthUser").value = data.auth_user;
    document.getElementById("cfgAuthPass").value = "";
  }catch(error){ document.getElementById("cfgResult").innerText = "Error: " + error; }
}

async function saveConfigForm(){
  let params = new URLSearchParams();
  params.set("ap_ssid", document.getElementById("cfgApSsid").value);
  params.set("ap_pass", document.getElementById("cfgApPass").value);
  params.set("auth_on", document.getElementById("cfgAuthOn").value);
  params.set("auth_user", document.getElementById("cfgAuthUser").value);
  params.set("auth_pass", document.getElementById("cfgAuthPass").value);

  document.getElementById("cfgResult").innerText = await getText("/api/config", {
    method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: params.toString()
  });
}

refreshStatus();
setInterval(refreshStatus, 3000);
</script>

</body>
</html>
)HTML";


// ============================================================
// WEB HANDLERS
// ============================================================

void handleRoot()
{
  if (!checkAuth()) return;
  server.send(200, "text/html", MAIN_PAGE);
}

void handleStatus()
{
  if (!checkAuth()) return;
  server.send(200, "application/json", getStatusJSON());
}

void handleWiFi()
{
  if (!checkAuth()) return;
  server.send(200, "application/json", scanWiFi());
}

void handleBLE()
{
  if (!checkAuth()) return;
  server.send(200, "application/json", scanBLE(6));
}

void handleMonitorOn()
{
  if (!checkAuth()) return;
  startWiFiMonitor();
  server.send(200, "text/plain", "Passive monitor ON");
}

void handleMonitorOff()
{
  if (!checkAuth()) return;
  stopWiFiMonitor();
  server.send(200, "text/plain", "Passive monitor OFF");
}

void handleFile()
{
  if (!checkAuth()) return;

  if (!server.hasArg("file"))
  {
    server.send(400, "text/plain", "Missing file");
    return;
  }

  String requested = server.arg("file");
  const char *filename = nullptr;

  if (requested == "wifi") filename = WIFI_FILE;
  else if (requested == "ble") filename = BLE_FILE;
  else if (requested == "log") filename = LOG_FILE;
  else
  {
    server.send(400, "text/plain", "Invalid file");
    return;
  }

  server.send(200, "text/plain", readFile(filename));
}

void handleClear()
{
  if (!checkAuth()) return;

  deleteFile(WIFI_FILE);
  deleteFile(BLE_FILE);

  logEvent("DATA_CLEARED");
  server.send(200, "text/plain", "Collected data deleted.");
}

void handleDownload()
{
  if (!checkAuth()) return;

  if (!server.hasArg("file"))
  {
    server.send(400, "text/plain", "Missing file");
    return;
  }

  String requested = server.arg("file");
  const char *filename = nullptr;
  String downloadName;

  if (requested == "wifi") { filename = WIFI_FILE; downloadName = "wifi.txt"; }
  else if (requested == "ble") { filename = BLE_FILE; downloadName = "ble.json"; }
  else if (requested == "log") { filename = LOG_FILE; downloadName = "events.txt"; }
  else
  {
    server.send(400, "text/plain", "Invalid file");
    return;
  }

  if (!SPIFFS.exists(filename))
  {
    server.send(404, "text/plain", "File not found");
    return;
  }

  File file = SPIFFS.open(filename, "r");
  if (!file)
  {
    server.send(500, "text/plain", "Cannot open file");
    return;
  }

  server.sendHeader("Content-Disposition", "attachment; filename=\"" + downloadName + "\"");
  server.streamFile(file, "text/plain");
  file.close();
}

void handleGetConfig()
{
  if (!checkAuth()) return;

  String json = "{";
  json += "\"ap_ssid\":\"" + jsonEscape(cfgApSsid) + "\",";
  json += "\"ap_pass\":\"" + jsonEscape(cfgApPass) + "\",";
  json += "\"auth_on\":" + String(cfgAuthOn ? "true" : "false") + ",";
  json += "\"auth_user\":\"" + jsonEscape(cfgAuthUser) + "\"";
  json += "}";

  server.send(200, "application/json", json);
}

void handleSetConfig()
{
  if (!checkAuth()) return;

  if (server.hasArg("ap_ssid") && server.arg("ap_ssid").length() > 0)
    cfgApSsid = server.arg("ap_ssid");

  if (server.hasArg("ap_pass") && server.arg("ap_pass").length() >= 8)
    cfgApPass = server.arg("ap_pass");

  if (server.hasArg("auth_on"))
    cfgAuthOn = (server.arg("auth_on") == "1");

  if (server.hasArg("auth_user") && server.arg("auth_user").length() > 0)
    cfgAuthUser = server.arg("auth_user");

  if (server.hasArg("auth_pass") && server.arg("auth_pass").length() > 0)
    cfgAuthPass = server.arg("auth_pass");

  saveConfig();
  logEvent("CONFIG_UPDATED");

  server.send(200, "text/plain", "Config saved. Reboot to apply AP SSID/password changes.");
}

void handleStaConnect()
{
  if (!checkAuth()) return;

  String ssid = server.hasArg("ssid") ? server.arg("ssid") : "";
  String pass = server.hasArg("pass") ? server.arg("pass") : "";

  if (staConnect(ssid, pass))
  {
    server.send(200, "text/plain", "Connecting to " + ssid + "...");
  }
  else
  {
    server.send(400, "text/plain", "Missing SSID.");
  }
}

void handleStaDisconnect()
{
  if (!checkAuth()) return;
  staDisconnect();
  server.send(200, "text/plain", "Disconnected.");
}

void handleStaStatus()
{
  if (!checkAuth()) return;
  server.send(200, "application/json", getStaStatusJSON());
}

void handleNetCheck()
{
  if (!checkAuth()) return;

  String host = server.hasArg("host") ? server.arg("host") : "";
  uint16_t port = server.hasArg("port") ? (uint16_t) server.arg("port").toInt() : 80;

  if (host.length() == 0)
  {
    server.send(400, "application/json", "{\"error\":\"missing host\"}");
    return;
  }

  server.send(200, "application/json", netCheck(host, port));
}

void handleLanScan()
{
  if (!checkAuth()) return;
  server.send(200, "application/json", scanLAN());
}

void handlePortScan()
{
  if (!checkAuth()) return;

  String ip = server.hasArg("ip") ? server.arg("ip") : "";

  if (ip.length() == 0)
  {
    server.send(400, "application/json", "{\"error\":\"missing ip\"}");
    return;
  }

  server.send(200, "application/json", portScan(ip));
}

void handleRogue()
{
  if (!checkAuth()) return;
  server.send(200, "application/json", readFile(ROGUE_FILE));
}

void handleUpdatePage()
{
  if (!checkAuth()) return;
  server.send(200, "text/html",
    "<html><body style='background:#080b10;color:#eee;font-family:sans-serif'>"
    "<h2>Neux-firmware OTA Update</h2>"
    "<form method='POST' action='/update' enctype='multipart/form-data'>"
    "<input type='file' name='firmware'>"
    "<input type='submit' value='Upload'>"
    "</form></body></html>"
  );
}

void handleUpdateUpload()
{
  HTTPUpload &upload = server.upload();

  if (upload.status == UPLOAD_FILE_START)
  {
    Serial.println("[OTA] Update start: " + upload.filename);

    if (!Update.begin(UPDATE_SIZE_UNKNOWN))
    {
      Update.printError(Serial);
    }
  }
  else if (upload.status == UPLOAD_FILE_WRITE)
  {
    if (Update.write(upload.buf, upload.currentSize) != upload.currentSize)
    {
      Update.printError(Serial);
    }
  }
  else if (upload.status == UPLOAD_FILE_END)
  {
    if (Update.end(true))
    {
      Serial.println("[OTA] Update success: " + String(upload.totalSize) + " bytes");
      logEvent("OTA_UPDATE_OK");
    }
    else
    {
      Update.printError(Serial);
      logEvent("OTA_UPDATE_FAILED");
    }
  }
}

void handleUpdateResult()
{
  if (!checkAuth()) return;

  server.sendHeader("Connection", "close");

  if (Update.hasError())
  {
    server.send(500, "text/plain", "Update failed. Check serial log.");
  }
  else
  {
    server.send(200, "text/plain", "Update successful! Rebooting...");
    delay(500);
    ESP.restart();
  }
}

void handleNotFound()
{
  server.send(404, "text/plain", "Not found");
}


// ============================================================
// SERIAL
// ============================================================

void printHelp()
{
  Serial.println();
  Serial.println("==============================");
  Serial.println("   " FW_NAME " V" FW_VERSION);
  Serial.println("==============================");
  Serial.println("HELP");
  Serial.println("STATUS");
  Serial.println("AP_INFO");
  Serial.println("WIFI_SCAN");
  Serial.println("MONITOR_ON");
  Serial.println("MONITOR_OFF");
  Serial.println("BLE_SCAN 6");
  Serial.println("STA_CONNECT ssid pass");
  Serial.println("STA_DISCONNECT");
  Serial.println("STA_STATUS");
  Serial.println("NET_CHECK host");
  Serial.println("LAN_SCAN");
  Serial.println("PORT_SCAN ip");
  Serial.println("ROGUE_CHECK");
  Serial.println("FILES");
  Serial.println("SHOW WIFI");
  Serial.println("SHOW BLE");
  Serial.println("SHOW LOG");
  Serial.println("CLEAR");
  Serial.println("REBOOT");
  Serial.println("==============================");
  Serial.println();
}

void printStatus()
{
  Serial.println();
  Serial.println("==============================");
  Serial.println("Firmware: " FW_NAME " V" FW_VERSION);
  Serial.println("Chip: " + String(ESP.getChipModel()));
  Serial.println("Free heap: " + String(ESP.getFreeHeap()));
  Serial.println("Uptime: " + String((millis() - bootMillis) / 1000) + " sec");
  Serial.println("AP SSID: " + cfgApSsid);
  Serial.println("AP IP: " + WiFi.softAPIP().toString());
  Serial.println("Monitor: " + String(monitorRunning ? "ON" : "OFF"));
  Serial.println("Channel: " + String(monitorChannel));
  Serial.println("Frames: " + String(frameCounter));
  Serial.println("Deauth frames: " + String(deauthCounter));
  Serial.println("Disassoc frames: " + String(disassocCounter));
  Serial.println("STA connected: " + String(WiFi.status() == WL_CONNECTED ? "Yes" : "No"));
  Serial.println("==============================");
  Serial.println();
}

void printFilesList()
{
  Serial.println();
  Serial.println("==============================");
  Serial.println("FILES");
  Serial.println("wifi.txt : " + String(SPIFFS.exists(WIFI_FILE) ? "present" : "missing"));
  Serial.println("ble.json : " + String(SPIFFS.exists(BLE_FILE) ? "present" : "missing"));
  Serial.println("events.txt : " + String(SPIFFS.exists(LOG_FILE) ? "present" : "missing"));
  Serial.println("rogue.json : " + String(SPIFFS.exists(ROGUE_FILE) ? "present" : "missing"));
  Serial.println("lan.json : " + String(SPIFFS.exists(LAN_FILE) ? "present" : "missing"));
  Serial.println("==============================");
  Serial.println();
}

void serialCommand(String command)
{
  command.trim();
  if (command.length() == 0) return;

  if (command.equalsIgnoreCase("HELP")) { printHelp(); return; }
  if (command.equalsIgnoreCase("STATUS")) { printStatus(); return; }

  if (command.equalsIgnoreCase("AP_INFO"))
  {
    Serial.println("SSID: " + cfgApSsid);
    Serial.println("Password: " + cfgApPass);
    Serial.println("IP: " + WiFi.softAPIP().toString());
    return;
  }

  if (command.equalsIgnoreCase("WIFI_SCAN")) { Serial.println(scanWiFi()); return; }
  if (command.equalsIgnoreCase("MONITOR_ON")) { startWiFiMonitor(); return; }
  if (command.equalsIgnoreCase("MONITOR_OFF")) { stopWiFiMonitor(); return; }

  if (command.startsWith("BLE_SCAN"))
  {
    uint32_t seconds = 6;
    int spaceIndex = command.indexOf(' ');

    if (spaceIndex != -1)
    {
      String arg = command.substring(spaceIndex + 1);
      arg.trim();
      if (arg.length() > 0)
      {
        seconds = (uint32_t) arg.toInt();
        if (seconds == 0) seconds = 6;
      }
    }

    Serial.println(scanBLE(seconds));
    return;
  }

  if (command.startsWith("STA_CONNECT"))
  {
    // format: STA_CONNECT ssid pass
    String rest = command.substring(String("STA_CONNECT").length());
    rest.trim();

    int spaceIndex = rest.indexOf(' ');
    String ssid = (spaceIndex == -1) ? rest : rest.substring(0, spaceIndex);
    String pass = (spaceIndex == -1) ? "" : rest.substring(spaceIndex + 1);

    ssid.trim();
    pass.trim();

    if (staConnect(ssid, pass))
    {
      Serial.println("Connecting to " + ssid + "...");
    }
    else
    {
      Serial.println("Usage: STA_CONNECT <ssid> <pass>");
    }

    return;
  }

  if (command.equalsIgnoreCase("STA_DISCONNECT")) { staDisconnect(); Serial.println("Disconnected."); return; }
  if (command.equalsIgnoreCase("STA_STATUS")) { Serial.println(getStaStatusJSON()); return; }

  if (command.startsWith("NET_CHECK"))
  {
    String rest = command.substring(String("NET_CHECK").length());
    rest.trim();

    if (rest.length() == 0)
    {
      Serial.println("Usage: NET_CHECK <host>");
    }
    else
    {
      Serial.println(netCheck(rest, 80));
    }

    return;
  }

  if (command.equalsIgnoreCase("LAN_SCAN")) { Serial.println(scanLAN()); return; }

  if (command.startsWith("PORT_SCAN"))
  {
    String rest = command.substring(String("PORT_SCAN").length());
    rest.trim();

    if (rest.length() == 0)
    {
      Serial.println("Usage: PORT_SCAN <ip>");
    }
    else
    {
      Serial.println(portScan(rest));
    }

    return;
  }

  if (command.equalsIgnoreCase("ROGUE_CHECK")) { Serial.println(readFile(ROGUE_FILE)); return; }
  if (command.equalsIgnoreCase("FILES")) { printFilesList(); return; }
  if (command.equalsIgnoreCase("SHOW WIFI")) { Serial.println(readFile(WIFI_FILE)); return; }
  if (command.equalsIgnoreCase("SHOW BLE")) { Serial.println(readFile(BLE_FILE)); return; }
  if (command.equalsIgnoreCase("SHOW LOG")) { Serial.println(readFile(LOG_FILE)); return; }

  if (command.equalsIgnoreCase("CLEAR"))
  {
    deleteFile(WIFI_FILE);
    deleteFile(BLE_FILE);
    logEvent("DATA_CLEARED");
    Serial.println("Collected data deleted.");
    return;
  }

  if (command.equalsIgnoreCase("REBOOT"))
  {
    Serial.println("Rebooting...");
    Serial.flush();
    delay(200);
    ESP.restart();
    return;
  }

  Serial.println("Unknown command. Type HELP for the command list.");
}


// ============================================================
// SETUP / LOOP
// ============================================================

void setup()
{
  Serial.begin(SERIAL_BAUD);
  delay(200);

  bootMillis = millis();

  if (!SPIFFS.begin(true))
  {
    Serial.println("[FS] SPIFFS mount failed.");
  }
  else
  {
    Serial.println("[FS] SPIFFS mounted.");
  }

  loadConfig();

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(cfgApSsid.c_str(), cfgApPass.c_str());

  Serial.println();
  Serial.println("==============================");
  Serial.println("   " FW_NAME " V" FW_VERSION);
  Serial.println("==============================");
  Serial.println("AP SSID: " + cfgApSsid);
  Serial.println("AP IP: " + WiFi.softAPIP().toString());
  Serial.println("Type HELP for serial commands.");
  Serial.println("==============================");
  Serial.println();

  server.on("/", HTTP_GET, handleRoot);
  server.on("/api/status", HTTP_GET, handleStatus);
  server.on("/api/wifi", HTTP_GET, handleWiFi);
  server.on("/api/ble", HTTP_GET, handleBLE);
  server.on("/api/monitor/on", HTTP_GET, handleMonitorOn);
  server.on("/api/monitor/off", HTTP_GET, handleMonitorOff);
  server.on("/api/file", HTTP_GET, handleFile);
  server.on("/api/clear", HTTP_GET, handleClear);
  server.on("/download", HTTP_GET, handleDownload);

  server.on("/api/config", HTTP_GET, handleGetConfig);
  server.on("/api/config", HTTP_POST, handleSetConfig);

  server.on("/api/sta/connect", HTTP_GET, handleStaConnect);
  server.on("/api/sta/disconnect", HTTP_GET, handleStaDisconnect);
  server.on("/api/sta/status", HTTP_GET, handleStaStatus);

  server.on("/api/netcheck", HTTP_GET, handleNetCheck);
  server.on("/api/lanscan", HTTP_GET, handleLanScan);
  server.on("/api/portscan", HTTP_GET, handlePortScan);
  server.on("/api/rogue", HTTP_GET, handleRogue);

  server.on("/update", HTTP_GET, handleUpdatePage);
  server.on("/update", HTTP_POST, handleUpdateResult, handleUpdateUpload);

  server.onNotFound(handleNotFound);

  server.begin();

  Serial.println("[WEB] Server started.");
  logEvent("BOOT");
}

void loop()
{
  server.handleClient();
  updateWiFiMonitor();

  while (Serial.available() > 0)
  {
    char c = (char) Serial.read();

    if (c == '\n' || c == '\r')
    {
      if (serialBuffer.length() > 0)
      {
        serialCommand(serialBuffer);
        serialBuffer = "";
      }
    }
    else
    {
      serialBuffer += c;
      if (serialBuffer.length() > 200) serialBuffer = "";
    }
  }
}
