#include <Arduino.h>
#include <WiFi.h>

extern "C" {
#include "esp_wifi.h"
}

#include "detector.h"
#include "config.h"
#include "storage.h"
#include "text_utils.h"
#include "threat_logic.h"

namespace {
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

struct SourceCounter {
  uint8_t mac[6] = {};
  uint32_t deauth = 0;
  uint32_t disassoc = 0;
  int32_t rssi = -127;
  bool used = false;
};

volatile uint64_t totalManagement = 0;
volatile uint64_t totalDeauth = 0;
volatile uint64_t totalDisassoc = 0;
volatile uint32_t windowDeauth = 0;
volatile uint32_t windowDisassoc = 0;
volatile uint32_t windowManagement = 0;
volatile int32_t lastRssi = -127;

SourceCounter sources[DefenseConfig::MAX_SOURCES];
ThreatStats currentStats;
AlertRecord alerts[DefenseConfig::MAX_ALERTS];
size_t alertCount = 0;
size_t alertHead = 0;

unsigned long windowStartedAt = 0;
uint8_t channel = DefenseConfig::DEFAULT_CHANNEL;
bool paused = false;

bool sameMac(const uint8_t a[6], const uint8_t b[6]) {
  for (uint8_t i = 0; i < 6; ++i) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

int sourceSlot(const uint8_t mac[6]) {
  for (uint8_t i = 0; i < DefenseConfig::MAX_SOURCES; ++i) {
    if (sources[i].used && sameMac(sources[i].mac, mac)) {
      return i;
    }
  }

  for (uint8_t i = 0; i < DefenseConfig::MAX_SOURCES; ++i) {
    if (!sources[i].used) {
      sources[i].used = true;
      memcpy(sources[i].mac, mac, 6);
      return i;
    }
  }

  return -1;
}

void IRAM_ATTR promiscuousCallback(
  void* buffer,
  wifi_promiscuous_pkt_type_t type
) {
  if (type != WIFI_PKT_MGMT || !buffer) return;

  const wifi_promiscuous_pkt_t* packet =
    static_cast<wifi_promiscuous_pkt_t*>(buffer);

  if (packet->rx_ctrl.sig_len < 24) return;

  const uint8_t* payload = packet->payload;
  const uint8_t frameType = (payload[0] >> 2) & 0x03;
  const uint8_t subtype = (payload[0] >> 4) & 0x0F;

  if (frameType != 0) return;

  portENTER_CRITICAL_ISR(&mux);

  ++totalManagement;
  ++windowManagement;
  lastRssi = packet->rx_ctrl.rssi;

  if (subtype == 0x0C || subtype == 0x0A) {
    const uint8_t* source = payload + 10;
    const int slot = sourceSlot(source);

    if (subtype == 0x0C) {
      ++totalDeauth;
      ++windowDeauth;
      if (slot >= 0) ++sources[slot].deauth;
    } else {
      ++totalDisassoc;
      ++windowDisassoc;
      if (slot >= 0) ++sources[slot].disassoc;
    }

    if (slot >= 0) {
      sources[slot].rssi = packet->rx_ctrl.rssi;
    }
  }

  portEXIT_CRITICAL_ISR(&mux);
}

void resetWindowSources() {
  for (auto& source : sources) {
    source = SourceCounter();
  }
}

void addAlert(
  const String& source,
  int32_t rssi,
  uint32_t deauth,
  uint32_t disassoc,
  const String& level
) {
  AlertRecord record;
  record.createdAtMs = millis();
  record.source = source;
  record.channel = channel;
  record.rssi = rssi;
  record.deauthCount = deauth;
  record.disassocCount = disassoc;
  record.level = level;

  alerts[alertHead] = record;
  alertHead =
    (alertHead + 1) % DefenseConfig::MAX_ALERTS;

  if (alertCount < DefenseConfig::MAX_ALERTS) {
    ++alertCount;
  }
}

void evaluateWindow() {
  uint32_t deauth = 0;
  uint32_t disassoc = 0;
  uint32_t management = 0;
  int32_t rssi = -127;
  uint64_t allManagement = 0;
  uint64_t allDeauth = 0;
  uint64_t allDisassoc = 0;

  SourceCounter sourceCopy[DefenseConfig::MAX_SOURCES];

  portENTER_CRITICAL(&mux);

  deauth = windowDeauth;
  disassoc = windowDisassoc;
  management = windowManagement;
  rssi = lastRssi;
  allManagement = totalManagement;
  allDeauth = totalDeauth;
  allDisassoc = totalDisassoc;

  memcpy(sourceCopy, sources, sizeof(sources));

  windowDeauth = 0;
  windowDisassoc = 0;
  windowManagement = 0;
  resetWindowSources();

  portEXIT_CRITICAL(&mux);

  const uint32_t disconnectFrames =
    deauth + disassoc;

  const auto level =
    DefenseThreatLogic::classify(
      disconnectFrames,
      defenseAlertThreshold(),
      DefenseConfig::CRITICAL_MULTIPLIER
    );

  String topSource;
  uint32_t topCount = 0;
  int32_t topRssi = rssi;

  for (const auto& source : sourceCopy) {
    if (!source.used) continue;

    const uint32_t count =
      source.deauth + source.disassoc;

    if (count > topCount) {
      topCount = count;
      topSource =
        DefenseText::macToString(source.mac);
      topRssi = source.rssi;
    }
  }

  currentStats.managementFrames = allManagement;
  currentStats.deauthFrames = allDeauth;
  currentStats.disassocFrames = allDisassoc;
  currentStats.windowDeauth = deauth;
  currentStats.windowDisassoc = disassoc;
  currentStats.windowTotal = management;
  currentStats.lastRssi = rssi;
  currentStats.currentChannel = channel;
  currentStats.topSource = topSource;
  currentStats.level =
    DefenseThreatLogic::label(level);
  currentStats.uptimeSeconds =
    millis() / 1000UL;

  if (level != DefenseThreatLogic::Level::Normal) {
    const String sourceLabel =
      topSource.length()
        ? topSource
        : String("Unknown source");

    addAlert(
      sourceLabel,
      topRssi,
      deauth,
      disassoc,
      currentStats.level
    );

    defenseAppendLog(
      "alert",
      currentStats.level +
      " disconnect-frame burst on channel " +
      String(channel) +
      ": " +
      String(disconnectFrames) +
      " frames / " +
      String(DefenseConfig::DETECTION_WINDOW_MS / 1000UL) +
      "s, source " +
      sourceLabel
    );
  }
}
}

void detectorBegin() {
  channel = defenseMonitorChannel();
  windowStartedAt = millis();

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_channel(
    channel,
    WIFI_SECOND_CHAN_NONE
  );
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(
    promiscuousCallback
  );
  esp_wifi_set_promiscuous(true);

  paused = false;

  defenseAppendLog(
    "monitor",
    "Passive detector started on channel " +
    String(channel)
  );
}

void detectorLoop() {
  if (paused) return;

  if (
    millis() - windowStartedAt >=
    DefenseConfig::DETECTION_WINDOW_MS
  ) {
    evaluateWindow();
    windowStartedAt = millis();
  }
}

void detectorSetChannel(uint8_t newChannel) {
  if (newChannel < 1 || newChannel > 13) return;

  esp_wifi_set_promiscuous(false);

  channel = newChannel;
  defenseSetMonitorChannel(channel);

  esp_wifi_set_channel(
    channel,
    WIFI_SECOND_CHAN_NONE
  );

  esp_wifi_set_promiscuous(true);

  portENTER_CRITICAL(&mux);
  windowDeauth = 0;
  windowDisassoc = 0;
  windowManagement = 0;
  resetWindowSources();
  portEXIT_CRITICAL(&mux);

  windowStartedAt = millis();

  defenseAppendLog(
    "monitor",
    "Monitoring channel changed to " +
    String(channel)
  );
}

uint8_t detectorChannel() {
  return channel;
}

void detectorPause() {
  if (paused) return;
  esp_wifi_set_promiscuous(false);
  paused = true;
}

void detectorResume() {
  if (!paused) return;

  esp_wifi_set_channel(
    channel,
    WIFI_SECOND_CHAN_NONE
  );
  esp_wifi_set_promiscuous(true);
  paused = false;
  windowStartedAt = millis();
}

bool detectorPaused() {
  return paused;
}

ThreatStats detectorStats() {
  ThreatStats stats = currentStats;

  portENTER_CRITICAL(&mux);
  stats.managementFrames = totalManagement;
  stats.deauthFrames = totalDeauth;
  stats.disassocFrames = totalDisassoc;
  stats.lastRssi = lastRssi;
  portEXIT_CRITICAL(&mux);

  stats.currentChannel = channel;
  stats.uptimeSeconds = millis() / 1000UL;
  return stats;
}

String detectorStatsJson() {
  const ThreatStats stats = detectorStats();

  String json;
  json.reserve(420);

  json =
    "{\"version\":\"" +
    String(DefenseConfig::VERSION) +
    "\",\"channel\":" +
    String(stats.currentChannel) +
    ",\"level\":\"" +
    DefenseText::jsonEscape(stats.level) +
    "\",\"managementFrames\":" +
    String(
      static_cast<unsigned long long>(
        stats.managementFrames
      )
    ) +
    ",\"deauthFrames\":" +
    String(
      static_cast<unsigned long long>(
        stats.deauthFrames
      )
    ) +
    ",\"disassocFrames\":" +
    String(
      static_cast<unsigned long long>(
        stats.disassocFrames
      )
    ) +
    ",\"windowDeauth\":" +
    String(stats.windowDeauth) +
    ",\"windowDisassoc\":" +
    String(stats.windowDisassoc) +
    ",\"windowTotal\":" +
    String(stats.windowTotal) +
    ",\"lastRssi\":" +
    String(stats.lastRssi) +
    ",\"topSource\":\"" +
    DefenseText::jsonEscape(stats.topSource) +
    "\",\"threshold\":" +
    String(defenseAlertThreshold()) +
    ",\"uptime\":" +
    String(stats.uptimeSeconds) +
    ",\"freeHeap\":" +
    String(ESP.getFreeHeap()) +
    ",\"paused\":" +
    String(paused ? "true" : "false") +
    "}";

  return json;
}

String detectorAlertsJson() {
  String json = "[";
  json.reserve(320 + alertCount * 180);

  for (size_t n = 0; n < alertCount; ++n) {
    const size_t index =
      (alertHead + DefenseConfig::MAX_ALERTS - 1 - n) %
      DefenseConfig::MAX_ALERTS;

    const AlertRecord& alert = alerts[index];

    if (n) json += ",";

    json +=
      "{\"seconds\":" +
      String(alert.createdAtMs / 1000UL) +
      ",\"source\":\"" +
      DefenseText::jsonEscape(alert.source) +
      "\",\"channel\":" +
      String(alert.channel) +
      ",\"rssi\":" +
      String(alert.rssi) +
      ",\"deauth\":" +
      String(alert.deauthCount) +
      ",\"disassoc\":" +
      String(alert.disassocCount) +
      ",\"level\":\"" +
      DefenseText::jsonEscape(alert.level) +
      "\"}";
  }

  json += "]";
  return json;
}

void detectorClearAlerts() {
  alertCount = 0;
  alertHead = 0;
  defenseAppendLog("alert", "In-memory alerts cleared");
}
