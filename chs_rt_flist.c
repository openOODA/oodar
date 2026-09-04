/* List[Float] payload — same header/quota as OoIList, double elements. */

OoFList oo_flist_new(void) {
  OoFList l = {NULL, 0, 0};
  return l;
}

void oo_flist_retain(OoFList l) {
  if (!l.data) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);
  uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);
  if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  while (rc > 0 && rc < UINT32_MAX) {
    if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1,
                                    __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
      return;
    }
    rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);
    fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);
    if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  }
}

void oo_flist_release(OoFList l) {
  if (!l.data) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(double));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

void oo_flist_free(OoFList l) {
  oo_flist_release(l);
}

OoFList oo_flist_push(OoFList l, double v) {
  OoFList n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v;
    l.len = l.len + 1;
    oo_flist_retain(l);
    return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (double *)oo_list_alloc_payload(sizeof(double), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(double));
  }
  n.data[l.len] = v;
  n.len = l.len + 1;
  n.cap = ncap;
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

double oo_flist_get(OoFList l, long long i) {
  oo_flist_retain(l);
  double v;
  if (i < 0 || i >= l.len) {
    oo_flist_release(l);
    fprintf(stderr, "ERR\tflist_get OOB\n");
    exit(1);
  }
  v = l.data[i];
  oo_flist_release(l);
  return v;
}

long long oo_flist_len(OoFList l) { return l.len; }

OoFList oo_flist_set(OoFList l, long long i, double v) {
  OoFList n;
  long long ncap;
  if (i < 0 || i >= l.len) {
    fprintf(stderr, "ERR\tflist_set OOB\n");
    exit(1);
  }
  if (l.data && oo_list_owned(l.data)) {
    l.data[i] = v;
    oo_flist_retain(l);
    return l;
  }
  ncap = l.cap ? l.cap : l.len;
  n.data = (double *)oo_list_alloc_payload(sizeof(double), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(double));
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

