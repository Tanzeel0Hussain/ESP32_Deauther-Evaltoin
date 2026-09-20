#include <Arduino.h>

extern "C" {
#include "esp_task_wdt.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
}

#include "system_monitor.h"
#include "storage.h"

namespace {
bool watchdogReady = false;

String resetReason(esp_reset_reason_t reason) {
  switch (reason) {
    case ESP_RST_POWERON:
      return "Power-on reset";
    case ESP_RST_SW:
      return "Software restart";
    case ESP_RST_PANIC:
      return "Panic reset";
    case ESP_RST_TASK_WDT:
      return "Task watchdog reset";
    case ESP_RST_INT_WDT:
      return "Interrupt watchdog reset";
    case ESP_RST_BROWNOUT:
      return "Brownout reset";
    default:
      return "Reset reason " +
        String(static_cast<int>(reason));
  }
}
}

void systemMonitorBegin() {
  appendEventLog(
    "system",
    resetReason(esp_reset_reason())
  );

  esp_task_wdt_config_t config = {
    .timeout_ms = 15000,
    .idle_core_mask =
      (1U << portNUM_PROCESSORS) - 1U,
    .trigger_panic = true
  };

  esp_err_t result =
    esp_task_wdt_reconfigure(&config);

  if (result == ESP_ERR_INVALID_STATE) {
    result = esp_task_wdt_init(&config);
  }

  if (
    result == ESP_OK ||
    result == ESP_ERR_INVALID_STATE
  ) {
    const esp_err_t addResult =
      esp_task_wdt_add(nullptr);

    watchdogReady =
      addResult == ESP_OK ||
      addResult == ESP_ERR_INVALID_STATE;
  }

  appendEventLog(
    "system",
    watchdogReady
      ? "Task watchdog active"
      : "Task watchdog unavailable"
  );
}

void systemMonitorLoop() {
  if (watchdogReady) {
    esp_task_wdt_reset();
  }
}
