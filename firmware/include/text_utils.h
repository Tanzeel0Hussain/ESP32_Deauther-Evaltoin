#pragma once
#include <Arduino.h>

namespace DefenseText {

inline String jsonEscape(const String& input) {
  String output;
  output.reserve(input.length() + 8);
  static const char hex[] = "0123456789ABCDEF";

  for (size_t i = 0; i < input.length(); ++i) {
    const uint8_t c = static_cast<uint8_t>(input[i]);

    switch (c) {
      case '"': output += "\\\""; break;
      case '\\': output += "\\\\"; break;
      case '\b': output += "\\b"; break;
      case '\f': output += "\\f"; break;
      case '\n': output += "\\n"; break;
      case '\r': output += "\\r"; break;
      case '\t': output += "\\t"; break;
      default:
        if (c < 0x20) {
          output += "\\u00";
          output += hex[(c >> 4) & 0x0F];
          output += hex[c & 0x0F];
        } else {
          output += static_cast<char>(c);
        }
    }
  }

  return output;
}

inline String htmlEscape(String value) {
  value.replace("&", "&amp;");
  value.replace("<", "&lt;");
  value.replace(">", "&gt;");
  value.replace("\"", "&quot;");
  value.replace("'", "&#39;");
  return value;
}

inline String macToString(const uint8_t mac[6]) {
  char out[18];
  snprintf(
    out,
    sizeof(out),
    "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
  );
  return String(out);
}

}  // namespace DefenseText
