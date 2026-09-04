/* v2.3.0 split: COW write-at-index (list_set) and structural equality (eq).
 * Folded back into a standalone .c after the v2.2.0 collapse into list.c.
 * list_set is the only mutator that needs a fresh payload if the buffer is
 * shared (rc > 1) — push can in-place-grow when the slot is owned. */
#include "../../oodar.h"
#include <stdio.h>
#include <stdlib.h>

/* list_set — COW write at index; OOB is fatal. Folded back from list.c (v2.2.0). */

OoIList oo_ilist_set(OoIList l, long long i, long long v) {
  OoIList n;
  long long ncap;
  if (i < 0 || i >= l.len) {
    fprintf(stderr, "ERR\tlist_set OOB\n");
    exit(1);
  }
  if (l.data && oo_list_owned(l.data)) {
    l.data[i] = v;
    oo_ilist_retain(l);
    return l;
  }
  ncap = l.cap ? l.cap : l.len;
  n.data = (long long *)oo_list_alloc_payload(sizeof(long long), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(long long));
  }
  n.data[i] = v;
  n.len = l.len;
  n.cap = ncap;
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

OoSList oo_slist_set(OoSList l, long long i, OoStr v) {
  OoSList n;
  long long ncap;
  long long j;
  if (i < 0 || i >= l.len) {
    fprintf(stderr, "ERR\tlist_set OOB\n");
    exit(1);
  }
  if (l.data && oo_list_owned(l.data)) {
    OoStr old = l.data[i];
    l.data[i] = v;
    oo_str_retain(v);
    oo_str_release(old);
    oo_slist_retain(l);
    return l;
  }
  ncap = l.cap ? l.cap : l.len;
  n.data = (OoStr *)oo_list_alloc_payload(sizeof(OoStr), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoStr));
    for (j = 0; j < l.len; j++) {
      if (j != i) oo_str_retain(n.data[j]);
    }
  }
  n.data[i] = v;
  oo_str_retain(v);
  n.len = l.len;
  n.cap = ncap;
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

int oo_ilist_eq(OoIList a, OoIList b) {
  if (a.len != b.len) return 0;
  if (a.data == b.data) return 1;
  for (long long i = 0; i < a.len; i++) {
    if (a.data[i] != b.data[i]) return 0;
  }
  return 1;
}

int oo_slist_eq(OoSList a, OoSList b) {
  if (a.len != b.len) return 0;
  if (a.data == b.data) return 1;
  for (long long i = 0; i < a.len; i++) {
    if (!oo_str_eq(a.data[i], b.data[i])) return 0;
  }
  return 1;
}

int oo_flist_eq(OoFList a, OoFList b) {
  if (a.len != b.len) return 0;
  if (a.data == b.data) return 1;
  for (long long i = 0; i < a.len; i++) {
    if (a.data[i] != b.data[i]) return 0;
  }
  return 1;
}
