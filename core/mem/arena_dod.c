/* v2.3.0 split: DoD (Data-oriented Design) layout calculator. Returns the
 * byte footprint for n elements at 8 bytes each — the canonical SoA-style
 * fixed-stride row. v2.1.0 added the n > LLONG_MAX/8 overflow check that
 * the naive n*8 would silently wrap. */
#include "../../oodar.h"
#include <limits.h>

long long oo_dod_layout(long long n) {
  if (n < 0) return 0;
  /* v2.1.0: overflow check. n * 8 can wrap if n > LLONG_MAX/8. */
  if (n > LLONG_MAX / 8) return 0;
  return n * 8;
}
