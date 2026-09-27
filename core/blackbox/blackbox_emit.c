/* core/blackbox/blackbox_emit.c — JSON emit helpers for the flight recorder. */
/* Split from blackbox.c (RULES §1.8 256-line cap). Included by the
 * umbrella TUs before blackbox.c; helpers stay static to the TU. */
#include <stddef.h>
#include <stdint.h>

static size_t bb_append(char *buf, size_t pos, size_t max, const char *s) {
  if (!s || pos >= max) return pos;
  while (*s && pos + 1 < max) buf[pos++] = *s++;
  buf[pos] = '\0';
  return pos;
}

static size_t bb_append_uint(char *buf, size_t pos, size_t max, uint64_t val) {
  char tmp[24]; int i = 0;
  if (val == 0) tmp[i++] = '0';
  while (val > 0) { tmp[i++] = (char)('0' + (val % 10)); val /= 10; }
  while (i > 0 && pos + 1 < max) buf[pos++] = tmp[--i];
  buf[pos] = '\0';
  return pos;
}

static size_t bb_append_hex(char *buf, size_t pos, size_t max, uintptr_t val) {
  static const char hex[] = "0123456789abcdef";
  char tmp[20]; int i = 0;
  pos = bb_append(buf, pos, max, "0x");
  if (val == 0) tmp[i++] = '0';
  while (val > 0) { tmp[i++] = hex[val & 0xf]; val >>= 4; }
  while (i > 0 && pos + 1 < max) buf[pos++] = tmp[--i];
  buf[pos] = '\0';
  return pos;
}

static size_t bb_append_json_str(char *buf, size_t pos, size_t max, const char *s) {
  if (pos + 1 >= max) return pos;
  buf[pos++] = '"';
  while (s && *s && pos + 2 < max) {
    if (*s == '"' || *s == '\\') { buf[pos++] = '\\'; buf[pos++] = *s++; }
    else if (*s == '\n') { buf[pos++] = '\\'; buf[pos++] = 'n'; s++; }
    else if (*s == '\t') { buf[pos++] = '\\'; buf[pos++] = 't'; s++; }
    else if ((unsigned char)*s < 32) { s++; }
    else { buf[pos++] = *s++; }
  }
  if (pos + 1 < max) buf[pos++] = '"';
  buf[pos] = '\0';
  return pos;
}

/* Inner escape without surrounding quotes, capped at n chars. Used for
 * coordinate segments that share one quoted string. Appends "..." when
 * input exceeds n. Crash-safe: no malloc, bounded writes. */
static size_t bb_append_esc_n(char *buf, size_t pos, size_t max,
    const char *s, size_t n) {
  size_t i = 0;
  while (s && *s && i < n && pos + 2 < max) {
    if (*s == '"' || *s == '\\') { buf[pos++] = '\\'; buf[pos++] = *s++; }
    else if (*s == '\n') { buf[pos++] = '\\'; buf[pos++] = 'n'; s++; }
    else if (*s == '\t') { buf[pos++] = '\\'; buf[pos++] = 't'; s++; }
    else if ((unsigned char)*s < 32) { s++; }
    else { buf[pos++] = *s++; }
    i++;
  }
  if (s && *s) pos = bb_append(buf, pos, max, "...");
  buf[pos] = '\0';
  return pos;
}

/* Quoted JSON string capped at n chars with "..." overflow marker. */
static size_t bb_append_json_str_n(char *buf, size_t pos, size_t max,
    const char *s, size_t n) {
  if (pos + 1 >= max) return pos;
  buf[pos++] = '"';
  pos = bb_append_esc_n(buf, pos, (pos + 2 < max) ? max - 1 : pos, s, n);
  if (pos + 1 < max) buf[pos++] = '"';
  buf[pos] = '\0';
  return pos;
}
