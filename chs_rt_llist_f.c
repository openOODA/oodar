/* Nested List[List[Float]] (2D) & List[List[List[Float]]] (3D) — OoFList / OoLL_F elements. */

void oo_ll_F_retain(OoLL_F l) {
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

void oo_ll_F_release(OoLL_F l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) {
      oo_flist_release(l.data[i]);
    }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoFList));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

OoLL_F oo_ll_F_new(void) {
  OoLL_F l = {NULL, 0, 0};
  return l;
}

OoLL_F oo_ll_F_push(OoLL_F l, OoFList v) {
  OoLL_F n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v;
    oo_flist_retain(v);
    l.len = l.len + 1;
    oo_ll_F_retain(l);
    return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoFList *)oo_list_alloc_payload(sizeof(OoFList), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoFList));
    for (long long i = 0; i < l.len; i++) {
      oo_flist_retain(n.data[i]);
    }
  }
  n.data[l.len] = v;
  oo_flist_retain(v);
  n.len = l.len + 1;
  n.cap = ncap;
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

OoFList oo_ll_F_get(OoLL_F l, long long i) {
  OoFList r;
  oo_ll_F_retain(l);
  if (i < 0 || i >= l.len) {
    oo_ll_F_release(l);
    fprintf(stderr, "ERR\tll_F_get OOB\n");
    exit(1);
  }
  oo_flist_retain(l.data[i]);
  r = l.data[i];
  oo_ll_F_release(l);
  return r;
}

long long oo_ll_F_len(OoLL_F l) { return l.len; }

OoLL_F oo_ll_F_set(OoLL_F l, long long i, OoFList v) {
  OoLL_F n;
  long long ncap;
  long long j;
  if (i < 0 || i >= l.len) {
    fprintf(stderr, "ERR\tll_F_set OOB\n");
    exit(1);
  }
  if (l.data && oo_list_owned(l.data)) {
    OoFList old = l.data[i];
    l.data[i] = v;
    oo_flist_retain(v);
    oo_flist_release(old);
    oo_ll_F_retain(l);
    return l;
  }
  ncap = l.cap ? l.cap : l.len;
  n.data = (OoFList *)oo_list_alloc_payload(sizeof(OoFList), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoFList));
    for (j = 0; j < l.len; j++) {
      if (j != i) oo_flist_retain(n.data[j]);
    }
  }
  n.data[i] = v;
  oo_flist_retain(v);
  n.len = l.len;
  n.cap = ncap;
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

/* OoLLL_F: List[List[List[Float]]] (3D) */
void oo_lll_F_retain(OoLLL_F l) {
  if (!l.data) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);
  uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);
  if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  while (rc > 0 && rc < UINT32_MAX) {
    if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return;
    rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);
    fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);
    if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  }
}

void oo_lll_F_release(OoLLL_F l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) { oo_ll_F_release(l.data[i]); }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoLL_F));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

OoLLL_F oo_lll_F_new(void) { OoLLL_F l = {NULL, 0, 0}; return l; }

OoLLL_F oo_lll_F_push(OoLLL_F l, OoLL_F v) {
  OoLLL_F n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v; oo_ll_F_retain(v); l.len = l.len + 1; oo_lll_F_retain(l); return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoLL_F *)oo_list_alloc_payload(sizeof(OoLL_F), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoLL_F));
    for (long long i = 0; i < l.len; i++) { oo_ll_F_retain(n.data[i]); }
  }
  n.data[l.len] = v; oo_ll_F_retain(v); n.len = l.len + 1; n.cap = ncap;
  { OoListHeader *hdr = ((OoListHeader *)n.data) - 1; __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }
  return n;
}

OoLL_F oo_lll_F_get(OoLLL_F l, long long i) {
  OoLL_F r;
  oo_lll_F_retain(l);
  if (i < 0 || i >= l.len) { oo_lll_F_release(l); fprintf(stderr, "ERR\tlll_F_get OOB\n"); exit(1); }
  oo_ll_F_retain(l.data[i]); r = l.data[i]; oo_lll_F_release(l); return r;
}

long long oo_lll_F_len(OoLLL_F l) { return l.len; }

/* OoLLLL_F: List[List[List[List[Float]]]] (4D) */
void oo_llll_F_retain(OoLLLL_F l) {
  if (!l.data) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);
  uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);
  if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  while (rc > 0 && rc < UINT32_MAX) {
    if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return;
    rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);
    fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);
    if (rc == 0 || rc == UINT32_MAX || (fl & 1)) return;
  }
}

void oo_llll_F_release(OoLLLL_F l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) { oo_lll_F_release(l.data[i]); }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoLLL_F));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

OoLLLL_F oo_llll_F_new(void) { OoLLLL_F l = {NULL, 0, 0}; return l; }

OoLLLL_F oo_llll_F_push(OoLLLL_F l, OoLLL_F v) {
  OoLLLL_F n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v; oo_lll_F_retain(v); l.len = l.len + 1; oo_llll_F_retain(l); return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoLLL_F *)oo_list_alloc_payload(sizeof(OoLLL_F), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoLLL_F));
    for (long long i = 0; i < l.len; i++) { oo_lll_F_retain(n.data[i]); }
  }
  n.data[l.len] = v; oo_lll_F_retain(v); n.len = l.len + 1; n.cap = ncap;
  { OoListHeader *hdr = ((OoListHeader *)n.data) - 1; __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }
  return n;
}

OoLLL_F oo_llll_F_get(OoLLLL_F l, long long i) {
  OoLLL_F r;
  oo_llll_F_retain(l);
  if (i < 0 || i >= l.len) { oo_llll_F_release(l); fprintf(stderr, "ERR\tllll_F_get OOB\n"); exit(1); }
  oo_lll_F_retain(l.data[i]); r = l.data[i]; oo_llll_F_release(l); return r;
}

long long oo_llll_F_len(OoLLLL_F l) { return l.len; }
