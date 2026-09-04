/* examples/alloc_cap.c — grant AllocCap and allocate 64 bytes. */
#include "../oodar.h"
int main(void) {
  long long cap = oo_cap_grant_alloc();
  long long p = oo_alloc(cap, 64);
  if (!p) return 1;
  (oo_write_int)(cap, p, 0, 1);
  if ((oo_read_int)(cap, p, 0) != 1) return 1;
  oo_free(cap, p);
  return 0;
}
