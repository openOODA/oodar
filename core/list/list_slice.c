/* list_slice.c — oo_*_slice for OoSList / OoIList / OoFList.
 * Inclusive-lo, exclusive-hi. Empty when lo>=hi. No cap token. */
#include "../../oodar.h"

OoSList oo_slist_slice(OoSList l, long long lo, long long hi) {
  OoSList o = oo_slist_new();
  if (lo < 0) lo = 0;
  if (hi > l.len) hi = l.len;
  long long i = lo;
  while (i < hi && l.data) {
    OoSList n = oo_slist_push(o, l.data[i]);
    oo_slist_release(o);
    o = n;
    i++;
  }
  return o;
}

OoIList oo_ilist_slice(OoIList l, long long lo, long long hi) {
  OoIList o = oo_ilist_new();
  if (lo < 0) lo = 0;
  if (hi > l.len) hi = l.len;
  long long i = lo;
  while (i < hi && l.data) {
    OoIList n = oo_ilist_push(o, l.data[i]);
    oo_ilist_release(o);
    o = n;
    i++;
  }
  return o;
}

OoFList oo_flist_slice(OoFList l, long long lo, long long hi) {
  OoFList o = oo_flist_new();
  if (lo < 0) lo = 0;
  if (hi > l.len) hi = l.len;
  long long i = lo;
  while (i < hi && l.data) {
    OoFList n = oo_flist_push(o, l.data[i]);
    oo_flist_release(o);
    o = n;
    i++;
  }
  return o;
}

OoLL_I oo_ll_I_slice(OoLL_I l, long long lo, long long hi) {
  OoLL_I o = oo_ll_I_new();
  if (lo < 0) lo = 0;
  if (hi > l.len) hi = l.len;
  long long i = lo;
  while (i < hi && l.data) {
    OoLL_I n = oo_ll_I_push(o, l.data[i]);
    oo_ll_I_release(o);
    o = n;
    i++;
  }
  return o;
}

OoLL_S oo_ll_S_slice(OoLL_S l, long long lo, long long hi) {
  OoLL_S o = oo_ll_S_new();
  if (lo < 0) lo = 0;
  if (hi > l.len) hi = l.len;
  long long i = lo;
  while (i < hi && l.data) {
    OoLL_S n = oo_ll_S_push(o, l.data[i]);
    oo_ll_S_release(o);
    o = n;
    i++;
  }
  return o;
}

