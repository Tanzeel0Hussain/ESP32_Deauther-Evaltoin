#include <Arduino.h>
#include <cstring>

extern "C" {
#include "esp_wifi.h"
}

#include "config.h"
#include "detection_logic.h"
#include "detector.h"
#include "fixed_ring_queue.h"
#include "models.h"
#include "storage.h"
#include "text_utils.h"

namespace {
enum class DetectorState : uint8_t {
  Stopped,
  Active,
  Paused,
  Error
};

struct BurstSlot {
  bool active = false;
  uint8_t source[6] = {};
  uint8_t bssid[6] = {};
  uint32_t windowStart = 0;
  uint32_t lastAlert = 0;
  uint32_t lastSeen = 0;
  uint16_t count = 0;
  bool hasSequence = false;
  uint16_t lastSequence = 0;
  uint8_t lastFragment = 0;
  uint8_t lastSubtype = 0;
};

struct PendingAlert {
  uint8_t source[6] = {};
  uint8_t bssid[6] = {};
  uint8_t destination[6] = {};
  uint8_t subtype = 0;
  uint16_t reason = 0;
  uint16_t burst = 0;
  int8_t rssi = -127;
  uint8_t channel = 0;
  uint32_t uptimeMs = 0;
  bool protectedFrame = false;
};

BurstSlot sources[DefenseConfig::MAX_SOURCES];
FixedRingQueue<
  PendingAlert,
  DefenseConfig::MAX_PENDING_ALERTS
> pendingQueue;
volatile uint32_t droppedAlerts = 0;
AlertRecord alerts[DefenseConfig::MAX_ALERTS];

uint32_t totalDeauth = 0;
uint32_t totalDisassoc = 0;
uint32_t alertSequence = 0;
uint32_t alertCount = 0;
int8_t lastRssi = -127;
uint8_t lastChannel = 0;
uint32_t channelEvents[14] = {};
uint16_t alertThreshold =
  DefenseConfig::DEFAULT_ALERT_THRESHOLD;
DetectorState detectorState =
  DetectorState::Stopped;
int32_t detectorError = ESP_OK;

portMUX_TYPE mux =
  portMUX_INITIALIZER_UNLOCKED;

void setDetectorState(
  DetectorState state,
  int32_t error = ESP_OK
) {
  portENTER_CRITICAL(&mux);
  detectorState = state;
  detectorError = error;
  portEXIT_CRITICAL(&mux);
}

bool detectorStepOk(
  const char* step,
  esp_err_t error
) {
  if (error == ESP_OK) return true;

  setDetectorState(
    DetectorState::Error,
    static_cast<int32_t>(error)
  );

  Serial.print("Detector error at ");
  Serial.print(step);
  Serial.print(": ");
  Serial.println(static_cast<int32_t>(error));
  return false;
}

void macToText(
  const uint8_t mac[6],
  char out[18]
) {
  snprintf(
    out,
    18,
    "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0],
    mac[1],
    mac[2],
    mac[3],
    mac[4],
    mac[5]
  );
}

int findOrCreateSource(
  const uint8_t source[6],
  const uint8_t bssid[6],
  uint32_t now
) {
  for (
    size_t i = 0;
    i < DefenseConfig::MAX_SOURCES;
    ++i
  ) {
    if (
      sources[i].active &&
      memcmp(
        sources[i].source,
        source,
        6
      ) == 0 &&
      memcmp(
        sources[i].bssid,
        bssid,
        6
      ) == 0
    ) {
      return static_cast<int>(i);
    }
  }

  const size_t slotIndex =
    DefenseLogic::selectLruSlot(
      sources,
      DefenseConfig::MAX_SOURCES,
      now
    );

  BurstSlot& slot =
    sources[slotIndex];

  slot = BurstSlot();
  slot.active = true;

  memcpy(
    slot.source,
    source,
    6
  );

  memcpy(
    slot.bssid,
    bssid,
    6
  );

  slot.windowStart = now;
  slot.lastSeen = now;

  return static_cast<int>(
    slotIndex
  );
}

void queueAlert(
  const uint8_t source[6],
  const uint8_t bssid[6],
  const uint8_t destination[6],
  uint8_t subtype,
  uint16_t reason,
  uint16_t burst,
  int8_t rssi,
  uint8_t channel,
  uint32_t now,
  bool protectedFrame
) {
  PendingAlert item;

  memcpy(
    item.source,
    source,
    6
  );

  memcpy(
    item.bssid,
    bssid,
    6
  );

  memcpy(
    item.destination,
    destination,
    6
  );

  item.subtype = subtype;
  item.reason = reason;
  item.burst = burst;
  item.rssi = rssi;
  item.channel = channel;
  item.uptimeMs = now;
  item.protectedFrame = protectedFrame;

  if (!pendingQueue.push(item)) {
    droppedAlerts =
      static_cast<uint32_t>(
        droppedAlerts
      ) + 1U;
  }
}

bool popPendingAlert(
  PendingAlert& item
) {
  bool available = false;

  portENTER_CRITICAL(&mux);
  available =
    pendingQueue.pop(item);
  portEXIT_CRITICAL(&mux);

  return available;
}

void storeAlert(
  const PendingAlert& item
) {
  AlertRecord record;
  record.id = ++alertSequence;
  record.uptimeMs = item.uptimeMs;

  macToText(
    item.source,
    record.source
  );

  macToText(
    item.bssid,
    record.bssid
  );

  macToText(
    item.destination,
    record.destination
  );

  record.subtype = item.subtype;
  record.reason = item.reason;
  record.burstCount = item.burst;
  record.rssi = item.rssi;
  record.channel = item.channel;
  record.protectedFrame =
    item.protectedFrame;

  alerts[
    (record.id - 1U) %
    DefenseConfig::MAX_ALERTS
  ] = record;

  ++alertCount;

  Serial.print("Defense alert: ");
  Serial.print(
    item.subtype == 0x0C
      ? "deauth"
      : "disassoc"
  );
  Serial.print(" source=");
  Serial.print(record.source);
  Serial.print(" bssid=");
  Serial.print(record.bssid);
  Serial.print(" channel=");
  Serial.print(record.channel);
  Serial.print(" burst=");
  Serial.print(record.burstCount);

  if (record.protectedFrame) {
    Serial.println(
      " reason=protected"
    );
  } else {
    Serial.print(" reason=");
    Serial.println(record.reason);
  }
}

void promiscuousCallback(
  void* buffer,
  wifi_promiscuous_pkt_type_t type
) {
  if (
    type != WIFI_PKT_MGMT ||
    !buffer
  ) {
    return;
  }

  const auto* packet =
    static_cast<wifi_promiscuous_pkt_t*>(
      buffer
    );

  const uint16_t length =
    packet->rx_ctrl.sig_len;

  if (length < 24) return;

  const uint8_t* frame =
    packet->payload;

  const uint16_t fc =
    frame[0] |
    (
      static_cast<uint16_t>(
        frame[1]
      ) << 8
    );

  const uint8_t frameType =
    (fc >> 2) & 0x03;

  const uint8_t subtype =
    (fc >> 4) & 0x0F;

  if (
    frameType != 0 ||
    !DefenseLogic::
      isObservedThreatSubtype(
        subtype
      )
  ) {
    return;
  }

  const bool protectedFrame =
    DefenseLogic::frameProtected(
      fc
    );

  if (
    !protectedFrame &&
    length < 26
  ) {
    return;
  }

  const uint8_t* destination =
    frame + 4;

  const uint8_t* source =
    frame + 10;

  const uint8_t* bssid =
    frame + 16;

  const uint16_t sequenceControl =
    frame[22] |
    (
      static_cast<uint16_t>(
        frame[23]
      ) << 8
    );

  const uint16_t sequence =
    DefenseLogic::sequenceNumber(
      sequenceControl
    );

  const uint8_t fragment =
    DefenseLogic::fragmentNumber(
      sequenceControl
    );

  const bool retry =
    DefenseLogic::frameRetry(fc);

  const uint16_t reason =
    protectedFrame
      ? 0
      : static_cast<uint16_t>(
          frame[24] |
          (
            static_cast<uint16_t>(
              frame[25]
            ) << 8
          )
        );

  const uint32_t now = millis();
  const int8_t rssi =
    packet->rx_ctrl.rssi;
  const uint8_t channel =
    packet->rx_ctrl.channel;

  portENTER_CRITICAL_ISR(&mux);

  const int index =
    findOrCreateSource(
      source,
      bssid,
      now
    );

  if (index >= 0) {
    BurstSlot& slot =
      sources[index];

    slot.lastSeen = now;

    const bool duplicate =
      DefenseLogic::isDuplicateRetry(
        retry,
        slot.hasSequence,
        sequence,
        fragment,
        subtype,
        slot.lastSequence,
        slot.lastFragment,
        slot.lastSubtype
      );

    if (duplicate) {
      portEXIT_CRITICAL_ISR(&mux);
      return;
    }

    slot.hasSequence = true;
    slot.lastSequence = sequence;
    slot.lastFragment = fragment;
    slot.lastSubtype = subtype;

    if (subtype == 0x0C) {
      totalDeauth =
        static_cast<uint32_t>(
          totalDeauth
        ) + 1U;
    } else {
      totalDisassoc =
        static_cast<uint32_t>(
          totalDisassoc
        ) + 1U;
    }

    lastRssi = rssi;
    lastChannel = channel;

    if (
      channel >= 1 &&
      channel <= 13
    ) {
      channelEvents[channel] =
        channelEvents[channel] + 1U;
    }

    if (
      now - slot.windowStart >
      DefenseConfig::
        DETECTION_WINDOW_MS
    ) {
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
        DefenseConfig::
          ALERT_COOLDOWN_MS
      )
    ) {
      queueAlert(
        source,
        bssid,
        destination,
        subtype,
        reason,
        slot.count,
        rssi,
        channel,
        now,
        protectedFrame
      );

      slot.lastAlert = now;
      slot.count = 0;
      slot.windowStart = now;
    }
  }

  portEXIT_CRITICAL_ISR(&mux);
}
}

bool detectorBegin() {
  alertThreshold =
    getAlertThreshold();

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask =
    WIFI_PROMIS_FILTER_MASK_MGMT;

  setDetectorState(
    DetectorState::Stopped
  );

  if (
    !detectorStepOk(
      "disable promiscuous mode",
      esp_wifi_set_promiscuous(false)
    )
  ) {
    return false;
  }

  if (
    !detectorStepOk(
      "set monitor channel",
      esp_wifi_set_channel(
        getMonitorChannel(),
        WIFI_SECOND_CHAN_NONE
      )
    )
  ) {
    return false;
  }

  if (
    !detectorStepOk(
      "set promiscuous filter",
      esp_wifi_set_promiscuous_filter(
        &filter
      )
    )
  ) {
    return false;
  }

  if (
    !detectorStepOk(
      "register receive callback",
      esp_wifi_set_promiscuous_rx_cb(
        &promiscuousCallback
      )
    )
  ) {
    return false;
  }

  if (
    !detectorStepOk(
      "enable promiscuous mode",
      esp_wifi_set_promiscuous(true)
    )
  ) {
    esp_wifi_set_promiscuous(false);
    return false;
  }

  setDetectorState(
    DetectorState::Active
  );

  return true;
}

void detectorLoop() {
  PendingAlert item;

  while (
    popPendingAlert(item)
  ) {
    storeAlert(item);
  }
}

bool detectorPause() {
  DetectorState state;

  portENTER_CRITICAL(&mux);
  state = detectorState;
  portEXIT_CRITICAL(&mux);

  if (
    state ==
    DetectorState::Paused
  ) {
    return true;
  }

  if (
    state !=
    DetectorState::Active
  ) {
    return false;
  }

  if (
    !detectorStepOk(
      "pause promiscuous mode",
      esp_wifi_set_promiscuous(false)
    )
  ) {
    return false;
  }

  setDetectorState(
    DetectorState::Paused
  );

  return true;
}

bool detectorResume() {
  DetectorState state;

  portENTER_CRITICAL(&mux);
  state = detectorState;
  portEXIT_CRITICAL(&mux);

  if (
    state ==
    DetectorState::Active
  ) {
    return true;
  }

  if (
    state !=
    DetectorState::Paused
  ) {
    return false;
  }

  if (
    !detectorStepOk(
      "restore monitor channel",
      esp_wifi_set_channel(
        getMonitorChannel(),
        WIFI_SECOND_CHAN_NONE
      )
    )
  ) {
    return false;
  }

  if (
    !detectorStepOk(
      "resume promiscuous mode",
      esp_wifi_set_promiscuous(true)
    )
  ) {
    return false;
  }

  setDetectorState(
    DetectorState::Active
  );

  return true;
}

bool detectorPaused() {
  portENTER_CRITICAL(&mux);
  const bool value =
    detectorState ==
    DetectorState::Paused;
  portEXIT_CRITICAL(&mux);

  return value;
}

bool detectorHealthy() {
  portENTER_CRITICAL(&mux);
  const bool value =
    detectorState ==
      DetectorState::Active ||
    detectorState ==
      DetectorState::Paused;
  portEXIT_CRITICAL(&mux);

  return value;
}

String detectorStatus() {
  DetectorState state;

  portENTER_CRITICAL(&mux);
  state = detectorState;
  portEXIT_CRITICAL(&mux);

  switch (state) {
    case DetectorState::Active:
      return "active";
    case DetectorState::Paused:
      return "paused";
    case DetectorState::Error:
      return "error";
    default:
      return "stopped";
  }
}

int32_t detectorLastError() {
  portENTER_CRITICAL(&mux);
  const int32_t value =
    detectorError;
  portEXIT_CRITICAL(&mux);

  return value;
}

void detectorReset() {
  portENTER_CRITICAL(&mux);

  memset(
    sources,
    0,
    sizeof(sources)
  );

  memset(
    alerts,
    0,
    sizeof(alerts)
  );

  memset(
    channelEvents,
    0,
    sizeof(channelEvents)
  );

  totalDeauth = 0;
  totalDisassoc = 0;
  alertCount = 0;
  alertSequence = 0;
  pendingQueue.clear();
  droppedAlerts = 0;
  lastRssi = -127;
  lastChannel = 0;

  portEXIT_CRITICAL(&mux);
}

void detectorUpdateThreshold(
  uint16_t threshold
) {
  if (threshold < 3) {
    threshold = 3;
  }

  if (threshold > 200) {
    threshold = 200;
  }

  portENTER_CRITICAL(&mux);
  alertThreshold = threshold;
  portEXIT_CRITICAL(&mux);
}

uint32_t detectorTotalDeauth() {
  portENTER_CRITICAL(&mux);
  const uint32_t value =
    totalDeauth;
  portEXIT_CRITICAL(&mux);
  return value;
}

uint32_t detectorTotalDisassoc() {
  portENTER_CRITICAL(&mux);
  const uint32_t value =
    totalDisassoc;
  portEXIT_CRITICAL(&mux);
  return value;
}

uint32_t detectorAlertCount() {
  portENTER_CRITICAL(&mux);
  const uint32_t value =
    alertCount;
  portEXIT_CRITICAL(&mux);
  return value;
}

uint32_t detectorDroppedAlerts() {
  portENTER_CRITICAL(&mux);
  const uint32_t value =
    droppedAlerts;
  portEXIT_CRITICAL(&mux);
  return value;
}

int8_t detectorLastRssi() {
  portENTER_CRITICAL(&mux);
  const int8_t value =
    lastRssi;
  portEXIT_CRITICAL(&mux);
  return value;
}

uint8_t detectorLastChannel() {
  portENTER_CRITICAL(&mux);
  const uint8_t value =
    lastChannel;
  portEXIT_CRITICAL(&mux);
  return value;
}

String detectorAlertsJson() {
  AlertRecord snapshot[
    DefenseConfig::MAX_ALERTS
  ];

  uint32_t count = 0;
  uint32_t sequence = 0;

  portENTER_CRITICAL(&mux);

  memcpy(
    snapshot,
    alerts,
    sizeof(alerts)
  );

  count =
    alertCount >
      DefenseConfig::MAX_ALERTS
      ? DefenseConfig::MAX_ALERTS
      : alertCount;

  sequence =
    alertSequence;

  portEXIT_CRITICAL(&mux);

  String json = "[";

  for (
    uint32_t offset = 0;
    offset < count;
    ++offset
  ) {
    const uint32_t id =
      sequence - offset;

    const AlertRecord& a =
      snapshot[
        (id - 1U) %
        DefenseConfig::MAX_ALERTS
      ];

    if (!a.id) continue;

    if (
      json.length() > 1
    ) {
      json += ",";
    }

    json +=
      "{\"id\":" +
      String(a.id);

    json +=
      ",\"seconds\":" +
      String(
        a.uptimeMs /
        1000UL
      );

    json +=
      ",\"type\":\"" +
      String(
        a.subtype == 0x0C
          ? "Deauthentication"
          : "Disassociation"
      ) +
      "\"";

    json +=
      ",\"bssid\":\"" +
      String(a.bssid) +
      "\"";

    json +=
      ",\"source\":\"" +
      String(a.source) +
      "\"";

    json +=
      ",\"destination\":\"" +
      String(a.destination) +
      "\"";

    if (a.protectedFrame) {
      json +=
        ",\"reason\":null";
    } else {
      json +=
        ",\"reason\":" +
        String(a.reason);
    }

    json +=
      ",\"protected\":" +
      String(
        a.protectedFrame
          ? "true"
          : "false"
      );

    json +=
      ",\"burst\":" +
      String(a.burstCount);

    json +=
      ",\"rssi\":" +
      String(a.rssi);

    json +=
      ",\"channel\":" +
      String(a.channel) +
      "}";
  }

  return json + "]";
}

String detectorChannelJson() {
  uint32_t snapshot[14] = {};

  portENTER_CRITICAL(&mux);

  memcpy(
    snapshot,
    channelEvents,
    sizeof(channelEvents)
  );

  portEXIT_CRITICAL(&mux);

  String json = "[";

  for (
    uint8_t channel = 1;
    channel <= 13;
    ++channel
  ) {
    if (channel > 1) {
      json += ",";
    }

    json +=
      "{\"channel\":" +
      String(channel) +
      ",\"events\":" +
      String(
        snapshot[channel]
      ) +
      "}";
  }

  return json + "]";
}
