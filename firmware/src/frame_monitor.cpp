#include <Arduino.h>
#include <cstring>

extern "C" {
#include "esp_wifi.h"
}

#include "frame_monitor.h"
#include "frame_logic.h"
#include "config.h"
#include "models.h"
#include "storage.h"
#include "text_utils.h"

namespace {

struct RawThreatEvent {
  uint8_t source[6] = {};
  uint8_t bssid[6] = {};
  int8_t rssi = -127;
  uint8_t channel = 0;
  uint8_t subtype = 0;
};

struct SourceWindow {
  bool active = false;
  uint8_t source[6] = {};
  uint32_t startedAtMs = 0;
  uint16_t count = 0;
};

RawThreatEvent eventQueue[DefenseLabConfig::RAW_EVENT_QUEUE];
volatile uint8_t queueHead = 0;
volatile uint8_t queueTail = 0;

volatile uint32_t totalDeauth = 0;
volatile uint32_t totalDisassoc = 0;
volatile uint32_t droppedEvents = 0;

DefenseAlert alerts[DefenseLabConfig::MAX_ALERTS];
size_t storedAlertCount = 0;
size_t alertHead = 0;
uint32_t totalAlerts = 0;

SourceWindow sourceWindows[8];
portMUX_TYPE monitorMux = portMUX_INITIALIZER_UNLOCKED;

String macToString(const uint8_t mac[6]) {
  char output[18];
  snprintf(
    output,
    sizeof(output),
    "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2],
    mac[3], mac[4], mac[5]
  );
  return String(output);
}

bool sameMac(const uint8_t a[6], const uint8_t b[6]) {
  return memcmp(a, b, 6) == 0;
}

SourceWindow& windowFor(const uint8_t source[6]) {
  SourceWindow* oldest = &sourceWindows[0];

  for (SourceWindow& window : sourceWindows) {
    if (window.active && sameMac(window.source, source)) {
      return window;
    }

    if (!window.active) {
      memcpy(window.source, source, 6);
      window.active = true;
      window.startedAtMs = millis();
      window.count = 0;
      return window;
    }

    if (window.startedAtMs < oldest->startedAtMs) {
      oldest = &window;
    }
  }

  memcpy(oldest->source, source, 6);
  oldest->active = true;
  oldest->startedAtMs = millis();
  oldest->count = 0;
  return *oldest;
}

void addAlert(const RawThreatEvent& event, uint16_t count) {
  DefenseAlert alert;
  alert.sequence = ++totalAlerts;
  alert.uptimeSeconds = millis() / 1000UL;
  alert.source = macToString(event.source);
  alert.bssid = macToString(event.bssid);
  alert.rssi = event.rssi;
  alert.channel = event.channel;
  alert.subtype = event.subtype;
  alert.windowCount = count;

  alerts[alertHead] = alert;
  alertHead = (alertHead + 1) % DefenseLabConfig::MAX_ALERTS;

  if (storedAlertCount < DefenseLabConfig::MAX_ALERTS) {
    ++storedAlertCount;
  }

  Serial.print("Defense alert: ");
  Serial.print(event.subtype == 12 ? "deauth" : "disassoc");
  Serial.print(" source=");
  Serial.print(alert.source);
  Serial.print(" channel=");
  Serial.print(alert.channel);
  Serial.print(" count=");
  Serial.println(alert.windowCount);
}

bool popEvent(RawThreatEvent& event) {
  bool available = false;

  portENTER_CRITICAL(&monitorMux);

  if (queueTail != queueHead) {
    event = eventQueue[queueTail];
    queueTail = static_cast<uint8_t>(
      (queueTail + 1) % DefenseLabConfig::RAW_EVENT_QUEUE
    );
    available = true;
  }

  portEXIT_CRITICAL(&monitorMux);
  return available;
}

void promiscuousCallback(
  void* buffer,
  wifi_promiscuous_pkt_type_t type
) {
  if (type != WIFI_PKT_MGMT || !buffer) return;

  const auto* packet =
    static_cast<const wifi_promiscuous_pkt_t*>(buffer);

  if (packet->rx_ctrl.sig_len < 24) return;

  const uint8_t* payload = packet->payload;
  const uint16_t frameControl =
    static_cast<uint16_t>(payload[0] | (payload[1] << 8));

  if (!DefenseFrameLogic::isMonitoredThreat(frameControl)) return;

  RawThreatEvent event;
  memcpy(event.source, payload + 10, 6);
  memcpy(event.bssid, payload + 16, 6);
  event.rssi = packet->rx_ctrl.rssi;
  event.channel = packet->rx_ctrl.channel;
  event.subtype = DefenseFrameLogic::frameSubtype(frameControl);

  portENTER_CRITICAL(&monitorMux);

  if (event.subtype == 12) {
    ++totalDeauth;
  } else {
    ++totalDisassoc;
  }

  const uint8_t next = static_cast<uint8_t>(
    (queueHead + 1) % DefenseLabConfig::RAW_EVENT_QUEUE
  );

  if (next == queueTail) {
    ++droppedEvents;
  } else {
    eventQueue[queueHead] = event;
    queueHead = next;
  }

  portEXIT_CRITICAL(&monitorMux);
}

}

void frameMonitorBegin() {
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);
  esp_wifi_set_promiscuous(true);

  Serial.println("Passive deauth/disassociation monitor active.");
}

void frameMonitorLoop() {
  RawThreatEvent event;

  while (popEvent(event)) {
    SourceWindow& window = windowFor(event.source);
    const uint32_t now = millis();

    if (
      now - window.startedAtMs >=
      DefenseLabConfig::ALERT_WINDOW_MS
    ) {
      window.startedAtMs = now;
      window.count = 0;
    }

    ++window.count;

    const uint16_t threshold = storageGetAlertThreshold();

    // One alert per source per configured window.
    if (
      window.count == threshold &&
      DefenseFrameLogic::thresholdReached(window.count, threshold)
    ) {
      addAlert(event, window.count);
    }
  }
}

void frameMonitorPause() {
  esp_wifi_set_promiscuous(false);
}

void frameMonitorResume() {
  esp_wifi_set_promiscuous(true);
}

uint32_t frameMonitorTotalDeauth() {
  portENTER_CRITICAL(&monitorMux);
  const uint32_t value = totalDeauth;
  portEXIT_CRITICAL(&monitorMux);
  return value;
}

uint32_t frameMonitorTotalDisassoc() {
  portENTER_CRITICAL(&monitorMux);
  const uint32_t value = totalDisassoc;
  portEXIT_CRITICAL(&monitorMux);
  return value;
}

uint32_t frameMonitorDroppedEvents() {
  portENTER_CRITICAL(&monitorMux);
  const uint32_t value = droppedEvents;
  portEXIT_CRITICAL(&monitorMux);
  return value;
}

uint32_t frameMonitorAlertCount() {
  return totalAlerts;
}

String frameMonitorStatusJson() {
  String json;
  json.reserve(260);

  json =
    "{\"deauth\":" + String(frameMonitorTotalDeauth()) +
    ",\"disassoc\":" + String(frameMonitorTotalDisassoc()) +
    ",\"alerts\":" + String(totalAlerts) +
    ",\"dropped\":" + String(frameMonitorDroppedEvents()) +
    ",\"threshold\":" + String(storageGetAlertThreshold()) +
    ",\"windowMs\":" + String(DefenseLabConfig::ALERT_WINDOW_MS) +
    "}";

  return json;
}

String frameMonitorAlertsJson() {
  String json;
  json.reserve(64 + storedAlertCount * 180);
  json = "[";

  for (size_t i = 0; i < storedAlertCount; ++i) {
    if (i) json += ",";

    const size_t index =
      (alertHead + DefenseLabConfig::MAX_ALERTS - 1 - i) %
      DefenseLabConfig::MAX_ALERTS;

    const DefenseAlert& alert = alerts[index];

    json +=
      "{\"id\":" + String(alert.sequence) +
      ",\"uptime\":" + String(alert.uptimeSeconds) +
      ",\"type\":\"" +
      String(alert.subtype == 12 ? "Deauthentication" : "Disassociation") +
      "\",\"source\":\"" + DefenseLabText::jsonEscape(alert.source) +
      "\",\"bssid\":\"" + DefenseLabText::jsonEscape(alert.bssid) +
      "\",\"rssi\":" + String(alert.rssi) +
      ",\"channel\":" + String(alert.channel) +
      ",\"windowCount\":" + String(alert.windowCount) +
      "}";
  }

  return json + "]";
}

void frameMonitorClearAlerts() {
  storedAlertCount = 0;
  alertHead = 0;
  totalAlerts = 0;

  for (DefenseAlert& alert : alerts) {
    alert = DefenseAlert();
  }

  for (SourceWindow& window : sourceWindows) {
    window = SourceWindow();
  }
}
