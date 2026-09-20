#include <Arduino.h>
#include <cstring>

extern "C" {
#include "esp_wifi.h"
}

#include "config.h"
#include "detection_logic.h"
#include "detector.h"
#include "models.h"
#include "storage.h"
#include "text_utils.h"

namespace {
struct BurstSlot {
  bool active = false;
  uint8_t source[6] = {};
  uint8_t bssid[6] = {};
  uint32_t windowStart = 0;
  uint32_t lastAlert = 0;
  uint16_t count = 0;
};

BurstSlot sources[DefenseConfig::MAX_SOURCES];
AlertRecord alerts[DefenseConfig::MAX_ALERTS];

uint32_t totalDeauth = 0;
uint32_t totalDisassoc = 0;
uint32_t alertSequence = 0;
uint32_t alertCount = 0;
int8_t lastRssi = -127;
uint8_t lastChannel = 0;
uint32_t channelEvents[14] = {};
uint16_t alertThreshold = DefenseConfig::DEFAULT_ALERT_THRESHOLD;
bool paused = false;

portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

void macToText(const uint8_t mac[6], char out[18]) {
  snprintf(
    out,
    18,
    "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
  );
}

int findOrCreateSource(const uint8_t source[6], const uint8_t bssid[6], uint32_t now) {
  for (size_t i = 0; i < DefenseConfig::MAX_SOURCES; ++i) {
    if (
      sources[i].active &&
      memcmp(sources[i].source, source, 6) == 0 &&
      memcmp(sources[i].bssid, bssid, 6) == 0
    ) {
      return static_cast<int>(i);
    }
  }

  for (size_t i = 0; i < DefenseConfig::MAX_SOURCES; ++i) {
    if (!sources[i].active) {
      sources[i] = BurstSlot();
      sources[i].active = true;
      memcpy(sources[i].source, source, 6);
      memcpy(sources[i].bssid, bssid, 6);
      sources[i].windowStart = now;
      return static_cast<int>(i);
    }
  }

  size_t oldest = 0;
  for (size_t i = 1; i < DefenseConfig::MAX_SOURCES; ++i) {
    if (sources[i].windowStart < sources[oldest].windowStart) oldest = i;
  }

  sources[oldest] = BurstSlot();
  sources[oldest].active = true;
  memcpy(sources[oldest].source, source, 6);
  memcpy(sources[oldest].bssid, bssid, 6);
  sources[oldest].windowStart = now;
  return static_cast<int>(oldest);
}

void pushAlert(
  const uint8_t source[6],
  const uint8_t bssid[6],
  const uint8_t destination[6],
  uint8_t subtype,
  uint16_t reason,
  uint16_t burst,
  int8_t rssi,
  uint8_t channel,
  uint32_t now
) {
  AlertRecord record;
  record.id = ++alertSequence;
  record.uptimeMs = now;
  macToText(source, record.source);
  macToText(bssid, record.bssid);
  macToText(destination, record.destination);
  record.subtype = subtype;
  record.reason = reason;
  record.burstCount = burst;
  record.rssi = rssi;
  record.channel = channel;

  alerts[record.id % DefenseConfig::MAX_ALERTS] = record;
  ++alertCount;
}

void promiscuousCallback(void* buffer, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || !buffer) return;

  const auto* packet = static_cast<wifi_promiscuous_pkt_t*>(buffer);
  const uint16_t length = packet->rx_ctrl.sig_len;
  if (length < 26) return;

  const uint8_t* frame = packet->payload;
  const uint16_t fc = frame[0] | (static_cast<uint16_t>(frame[1]) << 8);
  const uint8_t frameType = (fc >> 2) & 0x03;
  const uint8_t subtype = (fc >> 4) & 0x0F;

  if (
    frameType != 0 ||
    !DefenseLogic::isObservedThreatSubtype(subtype)
  ) return;

  const uint8_t* destination = frame + 4;
  const uint8_t* source = frame + 10;
  const uint8_t* bssid = frame + 16;
  const uint16_t reason = frame[24] | (static_cast<uint16_t>(frame[25]) << 8);

  const uint32_t now = millis();
  const int8_t rssi = packet->rx_ctrl.rssi;
  const uint8_t channel = packet->rx_ctrl.channel;

  portENTER_CRITICAL_ISR(&mux);

  if (subtype == 0x0C) ++totalDeauth;
  else ++totalDisassoc;

  lastRssi = rssi;
  lastChannel = channel;
  if (channel >= 1 && channel <= 13) ++channelEvents[channel];

  const int index = findOrCreateSource(source, bssid, now);
  if (index >= 0) {
    BurstSlot& slot = sources[index];

    if (now - slot.windowStart > DefenseConfig::DETECTION_WINDOW_MS) {
      slot.windowStart = now;
      slot.count = 0;
    }

    ++slot.count;

    if (
      DefenseLogic::shouldRaiseAlert(
        slot.count,
        alertThreshold,
        now,
        slot.lastAlert,
        DefenseConfig::ALERT_COOLDOWN_MS
      )
    ) {
      pushAlert(
        source,
        bssid,
        destination,
        subtype,
        reason,
        slot.count,
        rssi,
        channel,
        now
      );
      slot.lastAlert = now;
      slot.count = 0;
      slot.windowStart = now;
    }
  }

  portEXIT_CRITICAL_ISR(&mux);
}
}

void detectorBegin() {
  alertThreshold = getAlertThreshold();

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_channel(
    getMonitorChannel(),
    WIFI_SECOND_CHAN_NONE
  );
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
  esp_wifi_set_promiscuous(true);
  paused = false;
}

void detectorLoop() {}

void detectorPause() {
  if (paused) return;
  esp_wifi_set_promiscuous(false);
  paused = true;
}

void detectorResume() {
  if (!paused) return;

  esp_wifi_set_channel(
    getMonitorChannel(),
    WIFI_SECOND_CHAN_NONE
  );

  esp_wifi_set_promiscuous(true);
  paused = false;
}

bool detectorPaused() {
  return paused;
}

void detectorReset() {
  portENTER_CRITICAL(&mux);
  memset(sources, 0, sizeof(sources));
  memset(alerts, 0, sizeof(alerts));
  memset(channelEvents, 0, sizeof(channelEvents));
  totalDeauth = 0;
  totalDisassoc = 0;
  alertCount = 0;
  alertSequence = 0;
  lastRssi = -127;
  lastChannel = 0;
  portEXIT_CRITICAL(&mux);
}

void detectorUpdateThreshold(uint16_t threshold) {
  if (threshold < 3) threshold = 3;
  if (threshold > 200) threshold = 200;

  portENTER_CRITICAL(&mux);
  alertThreshold = threshold;
  portEXIT_CRITICAL(&mux);
}

uint32_t detectorTotalDeauth() {
  portENTER_CRITICAL(&mux);
  const uint32_t value = totalDeauth;
  portEXIT_CRITICAL(&mux);
  return value;
}

uint32_t detectorTotalDisassoc() {
  portENTER_CRITICAL(&mux);
  const uint32_t value = totalDisassoc;
  portEXIT_CRITICAL(&mux);
  return value;
}

uint32_t detectorAlertCount() {
  portENTER_CRITICAL(&mux);
  const uint32_t value = alertCount;
  portEXIT_CRITICAL(&mux);
  return value;
}

int8_t detectorLastRssi() {
  portENTER_CRITICAL(&mux);
  const int8_t value = lastRssi;
  portEXIT_CRITICAL(&mux);
  return value;
}

uint8_t detectorLastChannel() {
  portENTER_CRITICAL(&mux);
  const uint8_t value = lastChannel;
  portEXIT_CRITICAL(&mux);
  return value;
}

String detectorAlertsJson() {
  AlertRecord snapshot[DefenseConfig::MAX_ALERTS];
  uint32_t count = 0;
  uint32_t sequence = 0;

  portENTER_CRITICAL(&mux);
  memcpy(snapshot, alerts, sizeof(alerts));
  count = alertCount > DefenseConfig::MAX_ALERTS ? DefenseConfig::MAX_ALERTS : alertCount;
  sequence = alertSequence;
  portEXIT_CRITICAL(&mux);

  String json = "[";
  for (uint32_t offset = 0; offset < count; ++offset) {
    const uint32_t id = sequence - offset;
    const AlertRecord& a = snapshot[id % DefenseConfig::MAX_ALERTS];
    if (!a.id) continue;
    if (json.length() > 1) json += ",";

    json += "{\"id\":" + String(a.id);
    json += ",\"seconds\":" + String(a.uptimeMs / 1000UL);
    json += ",\"type\":\"" + String(a.subtype == 0x0C ? "Deauthentication" : "Disassociation") + "\"";
    json += ",\"bssid\":\"" + String(a.bssid) + "\"";
    json += ",\"source\":\"" + String(a.source) + "\"";
    json += ",\"destination\":\"" + String(a.destination) + "\"";
    json += ",\"reason\":" + String(a.reason);
    json += ",\"burst\":" + String(a.burstCount);
    json += ",\"rssi\":" + String(a.rssi);
    json += ",\"channel\":" + String(a.channel) + "}";
  }
  return json + "]";
}

String detectorChannelJson() {
  uint32_t snapshot[14] = {};
  portENTER_CRITICAL(&mux);
  memcpy(snapshot, channelEvents, sizeof(channelEvents));
  portEXIT_CRITICAL(&mux);

  String json = "[";
  for (uint8_t channel = 1; channel <= 13; ++channel) {
    if (channel > 1) json += ",";
    json += "{\"channel\":" + String(channel) + ",\"events\":" + String(snapshot[channel]) + "}";
  }
  return json + "]";
}
