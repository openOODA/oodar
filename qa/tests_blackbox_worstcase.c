/* qa/tests_blackbox_worstcase.c — autopsy buffer worst-case integrity.
 *
 * Audit 14: s_autopsy_buf was 32768 bytes with silent truncation
 * (bb_append stops at max, no marker) — a full ring of max-length
 * events plus trap inputs could exceed 32K and yield invalid JSON.
 * The buffer is now 64K with a documented ~51K worst-case budget,
 * and unbounded trap inputs (file/fn/cap) are capped at 256 chars
 * with "..." markers (coordinate segments are also JSON-escaped;
 * previously a '"' in a file path broke the JSON shape).
 *
 * Rows: fill the ring with 64 maxed events (31/31/63 chars, every
 * other char a '"' to force 2x escape expansion), trap with 300-char
 * quotey strings, then assert the autopsy file:
 *   1. exists and is under 60K (budget 64K with margin),
 *   2. ends with "}\n" (no mid-value truncation),
 *   3. has balanced { } and [ ] outside strings,
 *   4. contains "..." overflow markers (caps engaged),
 *   5. contains failure_coordinate + flight_events + flight_log keys.
 *
 * Exit codes: 0 — all rows pass. 1 — any row fails.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../core/blackbox/blackbox.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
  else { printf("ok: %s\n", msg); } \
} while (0)

/* Fill dst (size n+1) with alternating 'A' and '"' to maximise output. */
static void fill_hostile(char *dst, size_t n) {
  for (size_t i = 0; i < n; i++) dst[i] = (i % 2 == 0) ? 'A' : '"';
  dst[n] = '\0';
}

int main(void) {
  char cat[32], act[32], det[64];
  fill_hostile(cat, 31); fill_hostile(act, 31); fill_hostile(det, 63);
  for (int i = 0; i < 64; i++)
    blackbox_record(cat, act, det);

  char big[301];
  fill_hostile(big, 300);
  blackbox_trap_cap(big, big, big, 123456);

  const char *path = ".blackbox/autopsy.json";
  struct stat st;
  CHECK(stat(path, &st) == 0, "autopsy file written");
  if (fails) return 1;
  CHECK(st.st_size > 1024, "autopsy nontrivial size");
  CHECK(st.st_size < 60 * 1024, "autopsy under 60K budget");

  FILE *f = fopen(path, "rb");
  if (!f) { printf("FAIL: cannot open autopsy\n"); return 1; }
  char *buf = malloc((size_t)st.st_size + 1);
  if (!buf) { fclose(f); printf("FAIL: oom\n"); return 1; }
  size_t got = fread(buf, 1, (size_t)st.st_size, f);
  fclose(f);
  buf[got] = '\0';
  CHECK(got == (size_t)st.st_size, "autopsy fully read");

  CHECK(got >= 2 && buf[got - 2] == '}' && buf[got - 1] == '\n',
      "autopsy ends with }\\n (no truncation)");

  /* Balance check outside strings (\" handled). */
  long brace = 0, bracket = 0;
  int in_str = 0, bad = 0;
  for (size_t i = 0; i < got; i++) {
    char c = buf[i];
    if (in_str) {
      if (c == '\\') { i++; continue; }
      if (c == '"') in_str = 0;
      continue;
    }
    if (c == '"') in_str = 1;
    else if (c == '{') brace++;
    else if (c == '}') { brace--; if (brace < 0) bad = 1; }
    else if (c == '[') bracket++;
    else if (c == ']') { bracket--; if (bracket < 0) bad = 1; }
  }
  CHECK(!bad && brace == 0 && bracket == 0 && !in_str,
      "braces/brackets balanced, no unterminated string");

  CHECK(strstr(buf, "...") != NULL, "overflow markers present (caps engaged)");
  CHECK(strstr(buf, "failure_coordinate") != NULL, "coordinate key present");
  CHECK(strstr(buf, "\"flight_events\"") != NULL, "flight_events present");
  CHECK(strstr(buf, "\"flight_log\"") != NULL, "flight_log present");
  CHECK(strstr(buf, "CAPABILITY_TRAP_VIOLATION") != NULL, "trap root cause present");

  free(buf);
  if (fails == 0) printf("PASS tests_blackbox_worstcase\n");
  return fails ? 1 : 0;
}
