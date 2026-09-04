/* Nested List[List[Int]] — same header/quota as OoIList, OoIList elements. */

void oo_ll_I_retain(OoLL_I l) {
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

void oo_ll_I_release(OoLL_I l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) {
      oo_ilist_release(l.data[i]);
    }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoIList));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

OoLL_I oo_ll_I_new(void) {
  OoLL_I l = {NULL, 0, 0};
  return l;
}

OoLL_I oo_ll_I_push(OoLL_I l, OoIList v) {
  OoLL_I n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v;
    oo_ilist_retain(v);
    l.len = l.len + 1;
    oo_ll_I_retain(l);
    return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoIList *)oo_list_alloc_payload(sizeof(OoIList), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoIList));
    for (long long i = 0; i < l.len; i++) {
      oo_ilist_retain(n.data[i]);
    }
  }
  n.data[l.len] = v;
  oo_ilist_retain(v);
  n.len = l.len + 1;
  n.cap = ncap;
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

OoIList oo_ll_I_get(OoLL_I l, long long i) {
  OoIList r;
  oo_ll_I_retain(l);
  if (i < 0 || i >= l.len) {
    oo_ll_I_release(l);
    fprintf(stderr, "ERR\tll_I_get OOB\n");
    exit(1);
  }
  oo_ilist_retain(l.data[i]);
  r = l.data[i];
  oo_ll_I_release(l);
  return r;
}

long long oo_ll_I_len(OoLL_I l) { return l.len; }

OoLL_I oo_ll_I_set(OoLL_I l, long long i, OoIList v) {
  OoLL_I n;
  long long ncap;
  long long j;
  if (i < 0 || i >= l.len) {
    fprintf(stderr, "ERR\tll_I_set OOB\n");
    exit(1);
  }
  if (l.data && oo_list_owned(l.data)) {
    OoIList old = l.data[i];
    l.data[i] = v;
    oo_ilist_retain(v);
    oo_ilist_release(old);
    oo_ll_I_retain(l);
    return l;
  }
  ncap = l.cap ? l.cap : l.len;
  n.data = (OoIList *)oo_list_alloc_payload(sizeof(OoIList), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoIList));
    for (j = 0; j < l.len; j++) {
      if (j != i) oo_ilist_retain(n.data[j]);
    }
  }
  n.data[i] = v;
  oo_ilist_retain(v);
  n.len = l.len;
  n.cap = ncap;
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

/* OoLLL_I: List[List[List[Int]]] (3D) */
void oo_lll_I_retain(OoLLL_I l) {
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

void oo_lll_I_release(OoLLL_I l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) { oo_ll_I_release(l.data[i]); }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoLL_I));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

OoLLL_I oo_lll_I_new(void) { OoLLL_I l = {NULL, 0, 0}; return l; }

OoLLL_I oo_lll_I_push(OoLLL_I l, OoLL_I v) {
  OoLLL_I n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v; oo_ll_I_retain(v); l.len = l.len + 1; oo_lll_I_retain(l); return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoLL_I *)oo_list_alloc_payload(sizeof(OoLL_I), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoLL_I));
    for (long long i = 0; i < l.len; i++) { oo_ll_I_retain(n.data[i]); }
  }
  n.data[l.len] = v; oo_ll_I_retain(v); n.len = l.len + 1; n.cap = ncap;
  { OoListHeader *hdr = ((OoListHeader *)n.data) - 1; __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }
  return n;
}

OoLL_I oo_lll_I_get(OoLLL_I l, long long i) {
  OoLL_I r;
  oo_lll_I_retain(l);
  if (i < 0 || i >= l.len) { oo_lll_I_release(l); fprintf(stderr, "ERR\tlll_I_get OOB\n"); exit(1); }
  oo_ll_I_retain(l.data[i]); r = l.data[i]; oo_lll_I_release(l); return r;
}

long long oo_lll_I_len(OoLLL_I l) { return l.len; }

/* OoLLLL_I: List[List[List[List[Int]]]] (4D) */
void oo_llll_I_retain(OoLLLL_I l) {
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

void oo_llll_I_release(OoLLLL_I l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) { oo_lll_I_release(l.data[i]); }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoLLL_I));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

OoLLLL_I oo_llll_I_new(void) { OoLLLL_I l = {NULL, 0, 0}; return l; }

OoLLLL_I oo_llll_I_push(OoLLLL_I l, OoLLL_I v) {
  OoLLLL_I n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v; oo_lll_I_retain(v); l.len = l.len + 1; oo_llll_I_retain(l); return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoLLL_I *)oo_list_alloc_payload(sizeof(OoLLL_I), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoLLL_I));
    for (long long i = 0; i < l.len; i++) { oo_lll_I_retain(n.data[i]); }
  }
  n.data[l.len] = v; oo_lll_I_retain(v); n.len = l.len + 1; n.cap = ncap;
  { OoListHeader *hdr = ((OoListHeader *)n.data) - 1; __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }
  return n;
}

OoLLL_I oo_llll_I_get(OoLLLL_I l, long long i) {
  OoLLL_I r;
  oo_llll_I_retain(l);
  if (i < 0 || i >= l.len) { oo_llll_I_release(l); fprintf(stderr, "ERR\tllll_I_get OOB\n"); exit(1); }
  oo_lll_I_retain(l.data[i]); r = l.data[i]; oo_llll_I_release(l); return r;
}

long long oo_llll_I_len(OoLLLL_I l) { return l.len; }
