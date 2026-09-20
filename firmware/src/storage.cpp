#include <Arduino.h>
#include <Preferences.h>
#include <esp_system.h>

#include "config.h"
#include "credential_logic.h"
#include "crypto_store.h"
#include "storage.h"
#include "text_utils.h"

namespace {
Preferences prefs;
constexpr uint8_t LOG_COUNT =
  DefenseConfig::MAX_LOGS;

constexpr uint32_t CREDENTIAL_COMMIT_MAGIC =
  0x43524544UL;

constexpr const char* SLOT_SSID_KEYS[2] = {
  "c0_ssid",
  "c1_ssid"
};

constexpr const char* SLOT_AP_KEYS[2] = {
  "c0_ap",
  "c1_ap"
};

constexpr const char* SLOT_USER_KEYS[2] = {
  "c0_user",
  "c1_user"
};

constexpr const char* SLOT_ADMIN_KEYS[2] = {
  "c0_admin",
  "c1_admin"
};

constexpr const char* SLOT_OK_KEYS[2] = {
  "c0_ok",
  "c1_ok"
};

uint32_t bootSequence = 0;
bool recoveryMode = false;
uint8_t activeCredentialSlot =
  CredentialLogic::NO_SLOT;

String recoveryApSsid;
String recoveryApPassword;
String recoveryAdminPassword;

String randomRecoveryPassword(
  size_t length
) {
  static const char alphabet[] =
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
    "23456789";

  String value;
  value.reserve(length);

  for (
    size_t i = 0;
    i < length;
    ++i
  ) {
    value += alphabet[
      esp_random() %
      (sizeof(alphabet) - 1)
    ];
  }

  return value;
}

void ensureRecoveryCredentials() {
  if (
    recoveryApPassword.length() >= 12 &&
    recoveryAdminPassword.length() >= 12
  ) {
    return;
  }

  const uint64_t chipId =
    ESP.getEfuseMac();

  char suffix[9];

  snprintf(
    suffix,
    sizeof(suffix),
    "%08lX",
    static_cast<unsigned long>(
      chipId & 0xFFFFFFFFULL
    )
  );

  recoveryApSsid =
    "DefenseLab-Recovery-" +
    String(suffix).substring(4);

  recoveryApPassword =
    randomRecoveryPassword(16);

  recoveryAdminPassword =
    randomRecoveryPassword(18);
}

void enterRecoveryMode(
  const char* reason
) {
  if (recoveryMode) return;

  recoveryMode = true;
  ensureRecoveryCredentials();

  Serial.println();
  Serial.println(
    "=== ESP32 Defense Lab credential recovery ==="
  );
  Serial.println(reason);
  Serial.print("Recovery Wi-Fi: ");
  Serial.println(recoveryApSsid);
  Serial.print(
    "Recovery Wi-Fi password: "
  );
  Serial.println(recoveryApPassword);
  Serial.println(
    "Recovery admin username: admin"
  );
  Serial.print(
    "Recovery admin password: "
  );
  Serial.println(
    recoveryAdminPassword
  );
  Serial.println(
    "Open http://192.168.4.1 and set new credentials."
  );
  Serial.println(
    "============================================="
  );
}

String logKey(uint8_t index) {
  return "log" + String(index);
}

bool validSlotNumber(
  uint8_t slot
) {
  return slot <= 1;
}

bool slotHasAnyData(
  uint8_t slot
) {
  if (!validSlotNumber(slot)) {
    return false;
  }

  return
    prefs.getUInt(
      SLOT_OK_KEYS[slot],
      0
    ) != 0 ||
    prefs.getString(
      SLOT_SSID_KEYS[slot],
      ""
    ).length() > 0 ||
    prefs.getString(
      SLOT_AP_KEYS[slot],
      ""
    ).length() > 0 ||
    prefs.getString(
      SLOT_USER_KEYS[slot],
      ""
    ).length() > 0 ||
    prefs.getString(
      SLOT_ADMIN_KEYS[slot],
      ""
    ).length() > 0;
}

bool slotValid(
  uint8_t slot
) {
  if (
    !validSlotNumber(slot) ||
    prefs.getUInt(
      SLOT_OK_KEYS[slot],
      0
    ) !=
      CREDENTIAL_COMMIT_MAGIC
  ) {
    return false;
  }

  const String ssid =
    prefs.getString(
      SLOT_SSID_KEYS[slot],
      ""
    );

  const String protectedAp =
    prefs.getString(
      SLOT_AP_KEYS[slot],
      ""
    );

  const String user =
    prefs.getString(
      SLOT_USER_KEYS[slot],
      ""
    );

  const String protectedAdmin =
    prefs.getString(
      SLOT_ADMIN_KEYS[slot],
      ""
    );

  if (
    ssid.length() == 0 ||
    ssid.length() > 32 ||
    user.length() == 0 ||
    user.length() > 32 ||
    !isProtectedSecret(protectedAp) ||
    !isProtectedSecret(
      protectedAdmin
    )
  ) {
    return false;
  }

  const String ap =
    unprotectSecret(
      protectedAp
    );

  const String admin =
    unprotectSecret(
      protectedAdmin
    );

  return
    ap.length() >= 8 &&
    ap.length() <= 63 &&
    admin.length() >= 8 &&
    admin.length() <= 64 &&
    ap != admin;
}

void resolveActiveCredentialSlot() {
  const bool slot0Valid =
    slotValid(0);

  const bool slot1Valid =
    slotValid(1);

  const uint8_t requested =
    prefs.getUChar(
      "cred_slot",
      CredentialLogic::NO_SLOT
    );

  activeCredentialSlot =
    CredentialLogic::
      selectCommittedSlot(
        requested,
        slot0Valid,
        slot1Valid
      );

  if (
    activeCredentialSlot !=
      CredentialLogic::NO_SLOT &&
    activeCredentialSlot !=
      requested
  ) {
    prefs.putUChar(
      "cred_slot",
      activeCredentialSlot
    );
  }
}

bool stageCredentialSlot(
  uint8_t slot,
  const String& apSsid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
) {
  if (!validSlotNumber(slot)) {
    return false;
  }

  const String protectedAp =
    protectSecret(apPassword);

  const String protectedAdmin =
    protectSecret(adminPassword);

  if (
    !protectedAp.length() ||
    !protectedAdmin.length()
  ) {
    return false;
  }

  prefs.remove(
    SLOT_OK_KEYS[slot]
  );

  if (
    prefs.getUInt(
      SLOT_OK_KEYS[slot],
      0
    ) != 0
  ) {
    return false;
  }

  bool ok = true;

  ok &=
    prefs.putString(
      SLOT_SSID_KEYS[slot],
      apSsid
    ) > 0;

  ok &=
    prefs.putString(
      SLOT_AP_KEYS[slot],
      protectedAp
    ) > 0;

  ok &=
    prefs.putString(
      SLOT_USER_KEYS[slot],
      adminUser
    ) > 0;

  ok &=
    prefs.putString(
      SLOT_ADMIN_KEYS[slot],
      protectedAdmin
    ) > 0;

  if (!ok) {
    return false;
  }

  const bool verified =
    prefs.getString(
      SLOT_SSID_KEYS[slot],
      ""
    ) == apSsid &&
    prefs.getString(
      SLOT_USER_KEYS[slot],
      ""
    ) == adminUser &&
    unprotectSecret(
      prefs.getString(
        SLOT_AP_KEYS[slot],
        ""
      )
    ) == apPassword &&
    unprotectSecret(
      prefs.getString(
        SLOT_ADMIN_KEYS[slot],
        ""
      )
    ) == adminPassword;

  if (!verified) {
    return false;
  }

  if (
    prefs.putUInt(
      SLOT_OK_KEYS[slot],
      CREDENTIAL_COMMIT_MAGIC
    ) == 0
  ) {
    return false;
  }

  return slotValid(slot);
}

bool activateCredentialSlot(
  uint8_t slot
) {
  if (
    !slotValid(slot) ||
    prefs.putUChar(
      "cred_slot",
      slot
    ) == 0
  ) {
    return false;
  }

  if (
    prefs.getUChar(
      "cred_slot",
      CredentialLogic::NO_SLOT
    ) != slot
  ) {
    return false;
  }

  activeCredentialSlot = slot;
  return true;
}

void clearLegacyCredentials() {
  prefs.remove("ap_ssid");
  prefs.remove("ap_pass");
  prefs.remove("admin_user");
  prefs.remove("admin_pass");
}

void protectLegacySecrets() {
  const char* secretKeys[] = {
    "ap_pass",
    "admin_pass"
  };

  for (
    const char* key :
    secretKeys
  ) {
    const String value =
      prefs.getString(key, "");

    if (
      value.length() &&
      !isProtectedSecret(value)
    ) {
      const String protectedValue =
        protectSecret(value);

      if (
        protectedValue.length()
      ) {
        prefs.putString(
          key,
          protectedValue
        );
      }
    }
  }
}

bool legacyHasAnyCredentials() {
  return
    prefs.getString(
      "ap_ssid",
      ""
    ).length() > 0 ||
    prefs.getString(
      "ap_pass",
      ""
    ).length() > 0 ||
    prefs.getString(
      "admin_user",
      ""
    ).length() > 0 ||
    prefs.getString(
      "admin_pass",
      ""
    ).length() > 0;
}

bool legacyBundleValid() {
  const String ssid =
    prefs.getString(
      "ap_ssid",
      ""
    );

  const String protectedAp =
    prefs.getString(
      "ap_pass",
      ""
    );

  const String user =
    prefs.getString(
      "admin_user",
      ""
    );

  const String protectedAdmin =
    prefs.getString(
      "admin_pass",
      ""
    );

  if (
    ssid.length() == 0 ||
    ssid.length() > 32 ||
    user.length() == 0 ||
    user.length() > 32 ||
    !isProtectedSecret(protectedAp) ||
    !isProtectedSecret(
      protectedAdmin
    )
  ) {
    return false;
  }

  const String ap =
    unprotectSecret(
      protectedAp
    );

  const String admin =
    unprotectSecret(
      protectedAdmin
    );

  return
    ap.length() >= 8 &&
    ap.length() <= 63 &&
    admin.length() >= 8 &&
    admin.length() <= 64 &&
    ap != admin;
}

bool migrateLegacyBundle() {
  if (!legacyBundleValid()) {
    return false;
  }

  const String ssid =
    prefs.getString(
      "ap_ssid",
      ""
    );

  const String ap =
    unprotectSecret(
      prefs.getString(
        "ap_pass",
        ""
      )
    );

  const String user =
    prefs.getString(
      "admin_user",
      ""
    );

  const String admin =
    unprotectSecret(
      prefs.getString(
        "admin_pass",
        ""
      )
    );

  if (
    !stageCredentialSlot(
      0,
      ssid,
      ap,
      user,
      admin
    ) ||
    !activateCredentialSlot(0)
  ) {
    return false;
  }

  prefs.putBool(
    "setup_done",
    true
  );

  clearLegacyCredentials();
  return true;
}

String readSlotSecret(
  const char* key,
  const char* failureReason
) {
  const String stored =
    prefs.getString(key, "");

  const String plain =
    unprotectSecret(stored);

  if (plain.length()) {
    return plain;
  }

  enterRecoveryMode(
    failureReason
  );

  ensureRecoveryCredentials();

  return String(key) ==
      SLOT_AP_KEYS[
        activeCredentialSlot
      ]
    ? recoveryApPassword
    : recoveryAdminPassword;
}

bool slotUsesFactoryDefaults(
  uint8_t slot
) {
  if (!slotValid(slot)) {
    return false;
  }

  const String ap =
    unprotectSecret(
      prefs.getString(
        SLOT_AP_KEYS[slot],
        ""
      )
    );

  const String admin =
    unprotectSecret(
      prefs.getString(
        SLOT_ADMIN_KEYS[slot],
        ""
      )
    );

  return
    ap ==
      DefenseConfig::
        DEFAULT_AP_PASSWORD ||
    admin ==
      DefenseConfig::
        DEFAULT_ADMIN_PASSWORD;
}
}

void storageBegin() {
  prefs.begin(
    "def-lab",
    false
  );

  bootSequence =
    prefs.getUInt(
      "boot_seq",
      0
    ) + 1;

  prefs.putUInt(
    "boot_seq",
    bootSequence
  );

  protectLegacySecrets();
  resolveActiveCredentialSlot();

  const bool setupDone =
    prefs.getBool(
      "setup_done",
      false
    );

  if (
    activeCredentialSlot ==
      CredentialLogic::NO_SLOT &&
    legacyBundleValid()
  ) {
    if (
      !migrateLegacyBundle()
    ) {
      enterRecoveryMode(
        "Legacy management credentials could not be migrated atomically."
      );
    }
  }

  resolveActiveCredentialSlot();

  if (
    activeCredentialSlot !=
      CredentialLogic::NO_SLOT
  ) {
    if (
      slotUsesFactoryDefaults(
        activeCredentialSlot
      )
    ) {
      enterRecoveryMode(
        "Committed management credentials still contain public factory passwords."
      );
      return;
    }

    if (!setupDone) {
      prefs.putBool(
        "setup_done",
        true
      );
    }

    return;
  }

  const bool partialSlotState =
    slotHasAnyData(0) ||
    slotHasAnyData(1);

  if (
    setupDone ||
    legacyHasAnyCredentials() ||
    partialSlotState
  ) {
    enterRecoveryMode(
      "No complete committed management credential set is available."
    );
  }
}

String getApSsid() {
  if (recoveryMode) {
    ensureRecoveryCredentials();
    return recoveryApSsid;
  }

  if (
    activeCredentialSlot !=
      CredentialLogic::NO_SLOT
  ) {
    return prefs.getString(
      SLOT_SSID_KEYS[
        activeCredentialSlot
      ],
      DefenseConfig::
        DEFAULT_AP_SSID
    );
  }

  return DefenseConfig::
    DEFAULT_AP_SSID;
}

String getApPassword() {
  if (recoveryMode) {
    ensureRecoveryCredentials();
    return recoveryApPassword;
  }

  if (
    activeCredentialSlot !=
      CredentialLogic::NO_SLOT
  ) {
    return readSlotSecret(
      SLOT_AP_KEYS[
        activeCredentialSlot
      ],
      "Stored management Wi-Fi credential could not be decrypted."
    );
  }

  return DefenseConfig::
    DEFAULT_AP_PASSWORD;
}

String getAdminUser() {
  if (recoveryMode) {
    return "admin";
  }

  if (
    activeCredentialSlot !=
      CredentialLogic::NO_SLOT
  ) {
    return prefs.getString(
      SLOT_USER_KEYS[
        activeCredentialSlot
      ],
      DefenseConfig::
        DEFAULT_ADMIN_USER
    );
  }

  return DefenseConfig::
    DEFAULT_ADMIN_USER;
}

String getAdminPassword() {
  if (recoveryMode) {
    ensureRecoveryCredentials();
    return recoveryAdminPassword;
  }

  if (
    activeCredentialSlot !=
      CredentialLogic::NO_SLOT
  ) {
    return readSlotSecret(
      SLOT_ADMIN_KEYS[
        activeCredentialSlot
      ],
      "Stored administrator credential could not be decrypted."
    );
  }

  return DefenseConfig::
    DEFAULT_ADMIN_PASSWORD;
}

bool credentialRecoveryRequired() {
  return recoveryMode;
}

uint8_t getMonitorChannel() {
  uint8_t channel =
    prefs.getUChar(
      "channel",
      DefenseConfig::
        DEFAULT_MONITOR_CHANNEL
    );

  if (
    channel < 1 ||
    channel > 13
  ) {
    channel =
      DefenseConfig::
        DEFAULT_MONITOR_CHANNEL;
  }

  return channel;
}

uint16_t getAlertThreshold() {
  uint16_t value =
    prefs.getUShort(
      "threshold",
      DefenseConfig::
        DEFAULT_ALERT_THRESHOLD
    );

  if (
    value < 3 ||
    value > 200
  ) {
    value =
      DefenseConfig::
        DEFAULT_ALERT_THRESHOLD;
  }

  return value;
}

bool initialSetupRequired() {
  if (recoveryMode) {
    return true;
  }

  if (
    activeCredentialSlot ==
      CredentialLogic::NO_SLOT
  ) {
    return true;
  }

  return
    getApPassword() ==
      DefenseConfig::
        DEFAULT_AP_PASSWORD ||
    getAdminPassword() ==
      DefenseConfig::
        DEFAULT_ADMIN_PASSWORD;
}

bool setInitialCredentials(
  const String& apSsid,
  const String& apPassword,
  const String& adminUser,
  const String& adminPassword
) {
  if (
    apSsid.length() == 0 ||
    apSsid.length() > 32 ||
    apPassword.length() < 8 ||
    apPassword.length() > 63 ||
    adminUser.length() == 0 ||
    adminUser.length() > 32 ||
    adminPassword.length() < 8 ||
    adminPassword.length() > 64 ||
    apPassword == adminPassword ||
    apPassword ==
      DefenseConfig::
        DEFAULT_AP_PASSWORD ||
    adminPassword ==
      DefenseConfig::
        DEFAULT_ADMIN_PASSWORD
  ) {
    return false;
  }

  const uint8_t previousSlot =
    activeCredentialSlot;

  const uint8_t targetSlot =
    CredentialLogic::
      inactiveSlot(
        previousSlot
      );

  if (
    !stageCredentialSlot(
      targetSlot,
      apSsid,
      apPassword,
      adminUser,
      adminPassword
    )
  ) {
    if (
      previousSlot ==
      CredentialLogic::NO_SLOT
    ) {
      enterRecoveryMode(
        "Initial management credentials could not be staged completely."
      );
    }

    return false;
  }

  if (
    !activateCredentialSlot(
      targetSlot
    )
  ) {
    activeCredentialSlot =
      previousSlot;

    if (
      previousSlot ==
      CredentialLogic::NO_SLOT
    ) {
      enterRecoveryMode(
        "Management credential commit pointer could not be updated."
      );
    }

    return false;
  }

  prefs.putBool(
    "setup_done",
    true
  );

  clearLegacyCredentials();

  recoveryMode = false;
  recoveryApSsid = "";
  recoveryApPassword = "";
  recoveryAdminPassword = "";

  return true;
}

bool setMonitorChannel(
  uint8_t channel
) {
  if (
    channel < 1 ||
    channel > 13
  ) {
    return false;
  }

  return prefs.putUChar(
    "channel",
    channel
  ) > 0;
}

bool setAlertThreshold(
  uint16_t threshold
) {
  if (
    threshold < 3 ||
    threshold > 200
  ) {
    return false;
  }

  return prefs.putUShort(
    "threshold",
    threshold
  ) > 0;
}

void appendEventLog(
  const String& type,
  const String& message
) {
  uint8_t head =
    prefs.getUChar(
      "log_head",
      0
    );

  uint8_t count =
    prefs.getUChar(
      "log_count",
      0
    );

  String safeType = type;
  String safeMessage = message;

  safeType.replace(
    "|",
    "/"
  );

  safeMessage.replace(
    "|",
    "/"
  );

  safeMessage.replace(
    "\n",
    " "
  );

  safeMessage.replace(
    "\r",
    " "
  );

  const String entry =
    String(bootSequence) +
    "|" +
    String(
      millis() / 1000UL
    ) +
    "|" +
    safeType +
    "|" +
    safeMessage;

  prefs.putString(
    logKey(head).c_str(),
    entry
  );

  head =
    static_cast<uint8_t>(
      (head + 1) %
      LOG_COUNT
    );

  if (
    count < LOG_COUNT
  ) {
    ++count;
  }

  prefs.putUChar(
    "log_head",
    head
  );

  prefs.putUChar(
    "log_count",
    count
  );
}

String getEventLogJson() {
  const uint8_t head =
    prefs.getUChar(
      "log_head",
      0
    );

  const uint8_t count =
    prefs.getUChar(
      "log_count",
      0
    );

  String json = "[";

  for (
    uint8_t i = 0;
    i < count;
    ++i
  ) {
    const int index =
      (
        head +
        LOG_COUNT -
        count +
        i
      ) %
      LOG_COUNT;

    const String entry =
      prefs.getString(
        logKey(index).c_str(),
        ""
      );

    int p1 =
      entry.indexOf('|');

    int p2 =
      entry.indexOf(
        '|',
        p1 + 1
      );

    int p3 =
      entry.indexOf(
        '|',
        p2 + 1
      );

    if (
      p1 < 0 ||
      p2 < 0 ||
      p3 < 0
    ) {
      continue;
    }

    if (
      json.length() > 1
    ) {
      json += ",";
    }

    json +=
      "{\"boot\":" +
      entry.substring(0, p1);

    json +=
      ",\"seconds\":" +
      entry.substring(
        p1 + 1,
        p2
      );

    json +=
      ",\"type\":\"" +
      DefenseText::jsonEscape(
        entry.substring(
          p2 + 1,
          p3
        )
      ) +
      "\"";

    json +=
      ",\"message\":\"" +
      DefenseText::jsonEscape(
        entry.substring(
          p3 + 1
        )
      ) +
      "\"}";
  }

  return json + "]";
}

void clearEventLogs() {
  for (
    uint8_t i = 0;
    i < LOG_COUNT;
    ++i
  ) {
    prefs.remove(
      logKey(i).c_str()
    );
  }

  prefs.putUChar(
    "log_head",
    0
  );

  prefs.putUChar(
    "log_count",
    0
  );
}

void factoryResetStorage() {
  prefs.clear();

  Preferences secure;

  if (
    secure.begin(
      "def-sec",
      false
    )
  ) {
    secure.clear();
    secure.end();
  }

  activeCredentialSlot =
    CredentialLogic::NO_SLOT;

  recoveryMode = false;
  recoveryApSsid = "";
  recoveryApPassword = "";
  recoveryAdminPassword = "";
}
