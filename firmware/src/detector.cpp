#include <Arduino.h>
#include <cstring>

extern "C" {
#include "esp_timer.h"
#include "esp_wifi.h"
}

#include "detector.h"
#include "detector_logic.h"
#include "models.h"
#include "config.h"
#include "text_utils.h"
#include "scanner.h"

namespace {

struct SourceTracker {
  uint8_t mac[6] = {};
  bool active = false;
  uint32_t windowStartMs = 0;
  uint32_t lastSeenMs = 0;
  uint32_t lastAlertMs = 0;
  uint16_t framesInWindow = 0;
};

struct PendingAlert {
  uint8_t source[6] = {};
  uint8_t subtype = 0;
  uint8_t channel = 0;
  int8_t rssi = -127;
  uint16_t framesInWindow = 0;
  bool broadcastDestination = false;
  DefenseLogic::Severity severity = DefenseLogic::Severity::None;
};

SourceTracker trackers[DefenseConfig::MAX_TRACKERS];
PendingAlert pending[DefenseConfig::MAX_PENDING_ALERTS];
AlertRecord alerts[DefenseConfig::MAX_ALERTS];
ChannelRecord channels[13];

size_t pendingHead = 0;
size_t pendingTail = 0;
size_t pendingCount = 0;
size_t alertCount = 0;
size_t alertHead = 0;

uint32_t nextAlertId = 1;
volatile uint32_t managementFrames = 0;
volatile uint32_t suspiciousFrames = 0;
volatile uint32_t droppedAlerts = 0;

uint8_t currentChannel = DefenseConfig::DEFAULT_MONITOR_CHANNEL;
bool promiscuousEnabled = false;

portMUX_TYPE detectorMux = portMUX_INITIALIZER_UNLOCKED;

uint32_t nowMs() {
  return static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
}

bool isBroadcast(const uint8_t mac[6]) {
  for (int i = 0; i < 6; ++i) {
    if (mac[i] != 0xFF) return false;
  }
  return true;
}

int findTracker(const uint8_t mac[6]) {
  for (size_t i = 0; i < DefenseConfig::MAX_TRACKERS; ++i) {
    if (trackers[i].active && memcmp(trackers[i].mac, mac, 6) == 0) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

int findOrCreateTracker(const uint8_t mac[6], uint32_t now) {
  const int existing = findTracker(mac);
  if (existing >= 0) return existing;

  size_t candidate = 0;
  uint32_t oldest = UINT32_MAX;

  for (size_t i = 0; i < DefenseConfig::MAX_TRACKERS; ++i) {
    if (!trackers[i].active) {
      candidate = i;
      oldest = 0;
      break;
    }

    if (trackers[i].lastSeenMs < oldest) {
      oldest = trackers[i].lastSeenMs;
      candidate = i;
    }
  }

  trackers[candidate] = SourceTracker();
  memcpy(trackers[candidate].mac, mac, 6);
  trackers[candidate].active = true;
  trackers[candidate].windowStartMs = now;
  trackers[candidate].lastSeenMs = now;

  return static_cast<int>(candidate);
}

void queueAlert(
  const uint8_t source[6],
  uint8_t subtype,
  uint8_t channel,
  int8_t rssi,
  uint16_t count,
  bool broadcast,
  DefenseLogic::Severity severity
) {
  if (pendingCount >= DefenseConfig::MAX_PENDING_ALERTS) {
    ++droppedAlerts;
    return;
  }

  PendingAlert& item = pending[pendingHead];

  memcpy(item.source, source, 6);
  item.subtype = subtype;
  item.channel = channel;
  item.rssi = rssi;
  item.framesInWindow = count;
  item.broadcastDestination = broadcast;
  item.severity = severity;

  pendingHead = (pendingHead + 1) % DefenseConfig::MAX_PENDING_ALERTS;
  ++pendingCount;
}

void promiscuousCallback(void* buffer, wifi_promiscuous_pkt_type_t type) {
  if (!buffer || type != WIFI_PKT_MGMT) return;

  const auto* packet = reinterpret_cast<wifi_promiscuous_pkt_t*>(buffer);
  const uint16_t length = packet->rx_ctrl.sig_len;

  if (length < 24) return;

  const uint8_t* frame = packet->payload;
  const uint8_t subtype = (frame[0] >> 4) & 0x0F;

  uint8_t channel = packet->rx_ctrl.channel;
  if (channel < 1 || channel > 13) channel = currentChannel;

  portENTER_CRITICAL(&detectorMux);

  ++managementFrames;

  if (channel >= 1 && channel <= 13) {
    ++channels[channel - 1].managementFrames;
  }

  const bool suspicious = subtype == 10 || subtype == 12;

  if (!suspicious) {
    portEXIT_CRITICAL(&detectorMux);
    return;
  }

  ++suspiciousFrames;

  if (channel >= 1 && channel <= 13) {
    ++channels[channel - 1].suspiciousFrames;
  }

  const uint8_t* destination = frame + 4;
  const uint8_t* source = frame + 10;
  const bool broadcast = isBroadcast(destination);
  const uint32_t now = nowMs();

  const int index = findOrCreateTracker(source, now);
  SourceTracker& tracker = trackers[index];

  if (now - tracker.windowStartMs > DefenseConfig::DETECTION_WINDOW_MS) {
    tracker.windowStartMs = now;
    tracker.framesInWindow = 0;
  }

  tracker.lastSeenMs = now;
  ++tracker.framesInWindow;

  const auto severity =
    DefenseLogic::classifyBurst(
      tracker.framesInWindow,
      broadcast,
      DefenseConfig::ALERT_THRESHOLD,
      DefenseConfig::HIGH_ALERT_THRESHOLD
    );

  if (
    severity != DefenseLogic::Severity::None &&
    (
      tracker.lastAlertMs == 0 ||
      now - tracker.lastAlertMs >= DefenseConfig::ALERT_COOLDOWN_MS
    )
  ) {
    tracker.lastAlertMs = now;

    queueAlert(
      source,
      subtype,
      channel,
      packet->rx_ctrl.rssi,
      tracker.framesInWindow,
      broadcast,
      severity
    );
  }

  portEXIT_CRITICAL(&detectorMux);
}

void storeAlert(const PendingAlert& item) {
  AlertRecord record;

  record.id = nextAlertId++;
  record.uptimeSeconds = millis() / 1000UL;
  record.source = DefenseText::macToString(item.source);
  record.frameType = item.subtype == 12 ? "Deauthentication" : "Disassociation";
  record.severity = DefenseLogic::severityText(item.severity);
  record.rssi = item.rssi;
  record.channel = item.channel;
  record.framesInWindow = item.framesInWindow;
  record.broadcastDestination = item.broadcastDestination;

  alerts[alertHead] = record;
  alertHead = (alertHead + 1) % DefenseConfig::MAX_ALERTS;

  if (alertCount < DefenseConfig::MAX_ALERTS) ++alertCount;

  Serial.print("[");
  Serial.print(record.severity);
  Serial.print("] ");
  Serial.print(record.frameType);
  Serial.print(" burst from ");
  Serial.print(record.source);
  Serial.print(" on ch ");
  Serial.print(record.channel);
  Serial.print(" (");
  Serial.print(record.framesInWindow);
  Serial.println(" frames/window)");
}

}

void detectorBegin() {
  memset(trackers, 0, sizeof(trackers));
  memset(channels, 0, sizeof(channels));
  detectorSetChannel(currentChannel);
  detectorResume();
}

void detectorLoop() {
  while (true) {
    PendingAlert item;
    bool haveAlert = false;

    portENTER_CRITICAL(&detectorMux);

    if (pendingCount > 0) {
      item = pending[pendingTail];
      pendingTail = (pendingTail + 1) % DefenseConfig::MAX_PENDING_ALERTS;
      --pendingCount;
      haveAlert = true;
    }

    portEXIT_CRITICAL(&detectorMux);

    if (!haveAlert) break;
    storeAlert(item);
  }
}

void detectorPause() {
  if (!promiscuousEnabled) return;
  esp_wifi_set_promiscuous(false);
  promiscuousEnabled = false;
}

void detectorResume() {
  if (promiscuousEnabled) return;

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;

  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
  esp_wifi_set_promiscuous(true);

  promiscuousEnabled = true;
}

bool detectorSetChannel(uint8_t channel) {
  if (channel < 1 || channel > 13) return false;

  currentChannel = channel;
  return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) == ESP_OK;
}

uint8_t detectorChannel() {
  return currentChannel;
}

uint32_t detectorManagementFrames() {
  portENTER_CRITICAL(&detectorMux);
  const uint32_t value = managementFrames;
  portEXIT_CRITICAL(&detectorMux);
  return value;
}

uint32_t detectorSuspiciousFrames() {
  portENTER_CRITICAL(&detectorMux);
  const uint32_t value = suspiciousFrames;
  portEXIT_CRITICAL(&detectorMux);
  return value;
}

uint32_t detectorAlertCount() {
  return static_cast<uint32_t>(alertCount);
}

uint32_t detectorDroppedAlerts() {
  portENTER_CRITICAL(&detectorMux);
  const uint32_t value = droppedAlerts;
  portEXIT_CRITICAL(&detectorMux);
  return value;
}

String detectorAlertsJson() {
  String json;
  json.reserve(128 + alertCount * 180);
  json = "[";

  for (size_t i = 0; i < alertCount; ++i) {
    if (i) json += ",";

    const size_t index =
      (alertHead + DefenseConfig::MAX_ALERTS - 1 - i) %
      DefenseConfig::MAX_ALERTS;

    const AlertRecord& a = alerts[index];

    json +=
      "{\"id\":" + String(a.id) +
      ",\"uptime\":" + String(a.uptimeSeconds) +
      ",\"source\":\"" + DefenseText::jsonEscape(a.source) +
      "\",\"type\":\"" + DefenseText::jsonEscape(a.frameType) +
      "\",\"severity\":\"" + DefenseText::jsonEscape(a.severity) +
      "\",\"rssi\":" + String(a.rssi) +
      ",\"channel\":" + String(a.channel) +
      ",\"frames\":" + String(a.framesInWindow) +
      ",\"broadcast\":" + String(a.broadcastDestination ? "true" : "false") +
      "}";
  }

  json += "]";
  return json;
}

String detectorChannelsJson() {
  String json = "[";

  for (int i = 0; i < 13; ++i) {
    if (i) json += ",";

    uint32_t mgmt = 0;
    uint32_t suspicious = 0;

    portENTER_CRITICAL(&detectorMux);
    mgmt = channels[i].managementFrames;
    suspicious = channels[i].suspiciousFrames;
    portEXIT_CRITICAL(&detectorMux);

    json +=
      "{\"channel\":" + String(i + 1) +
      ",\"management\":" + String(mgmt) +
      ",\"suspicious\":" + String(suspicious) +
      "}";
  }

  json += "]";
  return json;
}

String detectorStatusJson() {
  return
    "{\"product\":\"" + String(DefenseConfig::PRODUCT_NAME) +
    "\",\"version\":\"" + String(DefenseConfig::VERSION) +
    "\",\"channel\":" + String(detectorChannel()) +
    ",\"networks\":" + String(scannerNetworkCount()) +
    ",\"managementFrames\":" + String(detectorManagementFrames()) +
    ",\"suspiciousFrames\":" + String(detectorSuspiciousFrames()) +
    ",\"alerts\":" + String(detectorAlertCount()) +
    ",\"droppedAlerts\":" + String(detectorDroppedAlerts()) +
    ",\"uptimeSeconds\":" + String(millis() / 1000UL) +
    ",\"freeHeap\":" + String(ESP.getFreeHeap()) +
    ",\"scanAgeSeconds\":" + String(scannerLastScanAgeSeconds()) +
    "}";
}

void detectorClearAlerts() {
  alertCount = 0;
  alertHead = 0;

  portENTER_CRITICAL(&detectorMux);
  pendingCount = 0;
  pendingHead = 0;
  pendingTail = 0;
  portEXIT_CRITICAL(&detectorMux);
}
