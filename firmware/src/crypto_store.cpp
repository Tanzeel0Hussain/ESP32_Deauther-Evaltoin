#include <Arduino.h>
#include <Preferences.h>
#include <vector>

extern "C" {
#include "esp_system.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
}

#include "crypto_store.h"

namespace {
constexpr char PREFIX[] = "enc2:";
constexpr uint8_t NONCE_SIZE = 12;
constexpr uint8_t TAG_SIZE = 16;
constexpr size_t MASTER_KEY_SIZE = 32;

bool loadOrCreateMasterSecret(uint8_t output[MASTER_KEY_SIZE]) {
  Preferences secure;
  if (!secure.begin("defsec", false)) return false;

  if (secure.getBytesLength("master") == MASTER_KEY_SIZE) {
    const size_t read = secure.getBytes("master", output, MASTER_KEY_SIZE);
    secure.end();
    return read == MASTER_KEY_SIZE;
  }

  esp_fill_random(output, MASTER_KEY_SIZE);
  const size_t written = secure.putBytes("master", output, MASTER_KEY_SIZE);
  secure.end();
  return written == MASTER_KEY_SIZE;
}

bool deriveKey(uint8_t key[32]) {
  uint8_t master[MASTER_KEY_SIZE];
  if (!loadOrCreateMasterSecret(master)) return false;

  const uint64_t chipId = ESP.getEfuseMac();
  const char context[] = "ESP32-Defense-Lab-credential-v1";
  uint8_t material[MASTER_KEY_SIZE + sizeof(chipId) + sizeof(context) - 1];

  memcpy(material, master, MASTER_KEY_SIZE);
  memcpy(material + MASTER_KEY_SIZE, &chipId, sizeof(chipId));
  memcpy(material + MASTER_KEY_SIZE + sizeof(chipId), context, sizeof(context) - 1);

  mbedtls_sha256(material, sizeof(material), key, 0);
  memset(master, 0, sizeof(master));
  memset(material, 0, sizeof(material));
  return true;
}

String hexEncode(const uint8_t* data, size_t length) {
  static const char hex[] = "0123456789abcdef";
  String output;
  output.reserve(length * 2);
  for (size_t i = 0; i < length; ++i) {
    output += hex[(data[i] >> 4) & 0x0F];
    output += hex[data[i] & 0x0F];
  }
  return output;
}

int fromHex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool hexDecode(const String& input, std::vector<uint8_t>& output) {
  if (input.length() % 2 != 0) return false;
  output.resize(input.length() / 2);
  for (size_t i = 0; i < output.size(); ++i) {
    const int high = fromHex(input[i * 2]);
    const int low = fromHex(input[i * 2 + 1]);
    if (high < 0 || low < 0) return false;
    output[i] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}
}

bool isProtectedSecret(const String& storedValue) {
  return storedValue.startsWith(PREFIX);
}

String protectSecret(const String& plainText) {
  if (!plainText.length()) return "";

  uint8_t key[32];
  if (!deriveKey(key)) return "";

  uint8_t nonce[NONCE_SIZE];
  uint8_t tag[TAG_SIZE];
  esp_fill_random(nonce, sizeof(nonce));
  std::vector<uint8_t> cipher(plainText.length());

  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);

  if (mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
    mbedtls_gcm_free(&context);
    memset(key, 0, sizeof(key));
    return "";
  }

  const int result = mbedtls_gcm_crypt_and_tag(
    &context,
    MBEDTLS_GCM_ENCRYPT,
    plainText.length(),
    nonce,
    sizeof(nonce),
    nullptr,
    0,
    reinterpret_cast<const unsigned char*>(plainText.c_str()),
    cipher.data(),
    sizeof(tag),
    tag
  );

  mbedtls_gcm_free(&context);
  memset(key, 0, sizeof(key));
  if (result != 0) return "";

  String output = PREFIX;
  output += hexEncode(nonce, sizeof(nonce));
  output += hexEncode(tag, sizeof(tag));
  output += hexEncode(cipher.data(), cipher.size());
  return output;
}

String unprotectSecret(const String& storedValue) {
  if (!isProtectedSecret(storedValue)) return "";

  std::vector<uint8_t> raw;
  if (!hexDecode(storedValue.substring(strlen(PREFIX)), raw)) return "";
  if (raw.size() < NONCE_SIZE + TAG_SIZE) return "";

  uint8_t key[32];
  if (!deriveKey(key)) return "";

  const uint8_t* nonce = raw.data();
  const uint8_t* tag = raw.data() + NONCE_SIZE;
  const uint8_t* cipher = raw.data() + NONCE_SIZE + TAG_SIZE;
  const size_t cipherLength = raw.size() - NONCE_SIZE - TAG_SIZE;
  std::vector<uint8_t> plain(cipherLength + 1, 0);

  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);

  if (mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
    mbedtls_gcm_free(&context);
    memset(key, 0, sizeof(key));
    return "";
  }

  const int result = mbedtls_gcm_auth_decrypt(
    &context,
    cipherLength,
    nonce,
    NONCE_SIZE,
    nullptr,
    0,
    tag,
    TAG_SIZE,
    cipher,
    plain.data()
  );

  mbedtls_gcm_free(&context);
  memset(key, 0, sizeof(key));
  if (result != 0) return "";

  return String(reinterpret_cast<char*>(plain.data()));
}
