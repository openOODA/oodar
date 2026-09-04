/* v2.3.0 split: SoA (Struct-of-Arrays) layout calculator. Parses a comma
 * separated spec like "x:8,y:4" and returns the per-row byte total.
 * A bare name (no colon) defaults to 8 bytes. Empty / null spec yields 0.
 * Used by arena callers that want to know the row footprint of an SoA
 * buffer before calling oo_arena_alloc. */
#include "../../oodar.h"

long long oo_soa_layout(OoStr spec) {
  long long total = 0;
  long long i = 0;
  int fields = 0;
  if (!spec.data || spec.len <= 0) return 0;
  while (i < spec.len) {
    long long start = i;
    long long colon = -1;
    long long sz = 8;
    while (i < spec.len && spec.data[i] != ',') {
      if (spec.data[i] == ':') colon = i;
      i++;
    }
    if (colon >= start && colon + 1 < i) {
      long long v = 0;
      long long p;
      for (p = colon + 1; p < i; p++) {
        if (spec.data[p] >= '0' && spec.data[p] <= '9') {
          v = v * 10 + (spec.data[p] - '0');
        }
      }
      if (v > 0) sz = v;
    }
    if (i > start) {
      total += sz;
      fields++;
    }
    if (i < spec.len && spec.data[i] == ',') i++;
  }
  if (fields == 0) return 0;
  return total;
}
