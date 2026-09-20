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
constexpr char PREFIX[] = "enc1:";
constexpr uint8_t NONCE_SIZE = 12;
constexpr uint8_t TAG_SIZE = 16;
constexpr size_t MASTER_SIZE = 32;

bool loadOrCreateMaster(uint8_t out[MASTER_SIZE]) {
  Preferences secure;
  if (!secure.begin("def-sec", false)) return false;

  const size_t length = secure.getBytesLength("master");
  if (length == MASTER_SIZE) {
    const size_t read = secure.getBytes("master", out, MASTER_SIZE);
    secure.end();
    return read == MASTER_SIZE;
  }

  esp_fill_random(out, MASTER_SIZE);
  const size_t written = secure.putBytes("master", out, MASTER_SIZE);
  secure.end();
  return written == MASTER_SIZE;
}

bool deriveKey(uint8_t key[32]) {
  uint8_t master[MASTER_SIZE];
  if (!loadOrCreateMaster(master)) return false;

  const uint64_t chip = ESP.getEfuseMac();
  uint8_t material[MASTER_SIZE + sizeof(chip) + 28] = {};
  memcpy(material, master, MASTER_SIZE);
  memcpy(material + MASTER_SIZE, &chip, sizeof(chip));

  const char context[] = "ESP32-Wireless-Defense-Lab";
  memcpy(material + MASTER_SIZE + sizeof(chip), context, sizeof(context) - 1);

  mbedtls_sha256(material, sizeof(material), key, 0);
  memset(master, 0, sizeof(master));
  memset(material, 0, sizeof(material));
  return true;
}

String hexEncode(const uint8_t* data, size_t length) {
  static const char hex[] = "0123456789abcdef";
  String out;
  out.reserve(length * 2);
  for (size_t i = 0; i < length; ++i) {
    out += hex[(data[i] >> 4) & 0x0F];
    out += hex[data[i] & 0x0F];
  }
  return out;
}

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool hexDecode(const String& input, std::vector<uint8_t>& out) {
  if (input.length() % 2 != 0) return false;
  out.resize(input.length() / 2);

  for (size_t i = 0; i < out.size(); ++i) {
    const int hi = hexValue(input[i * 2]);
    const int lo = hexValue(input[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}
}

bool isProtectedSecret(const String& value) {
  return value.startsWith(PREFIX);
}

String protectSecret(const String& plainText) {
  if (!plainText.length()) return "";

  uint8_t key[32];
  if (!deriveKey(key)) return "";

  uint8_t nonce[NONCE_SIZE];
  uint8_t tag[TAG_SIZE];
  esp_fill_random(nonce, sizeof(nonce));

  std::vector<uint8_t> cipher(plainText.length());
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
    mbedtls_gcm_free(&ctx);
    memset(key, 0, sizeof(key));
    return "";
  }

  const int result = mbedtls_gcm_crypt_and_tag(
    &ctx,
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

  mbedtls_gcm_free(&ctx);
  memset(key, 0, sizeof(key));
  if (result != 0) return "";

  String out = PREFIX;
  out += hexEncode(nonce, sizeof(nonce));
  out += hexEncode(tag, sizeof(tag));
  out += hexEncode(cipher.data(), cipher.size());
  return out;
}

String unprotectSecret(const String& storedValue) {
  if (!storedValue.length()) return "";
  if (!isProtectedSecret(storedValue)) return storedValue;

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
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
    mbedtls_gcm_free(&ctx);
    memset(key, 0, sizeof(key));
    return "";
  }

  const int result = mbedtls_gcm_auth_decrypt(
    &ctx,
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

  mbedtls_gcm_free(&ctx);
  memset(key, 0, sizeof(key));
  if (result != 0) return "";

  return String(reinterpret_cast<char*>(plain.data()));
}
