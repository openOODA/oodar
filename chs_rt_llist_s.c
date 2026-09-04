/* Nested List[List[String]] (2D) & List[List[List[String]]] (3D) — OoSList / OoLL_S elements. */

void oo_ll_S_retain(OoLL_S l) {
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

void oo_ll_S_release(OoLL_S l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) {
      oo_slist_release(l.data[i]);
    }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoSList));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

OoLL_S oo_ll_S_new(void) {
  OoLL_S l = {NULL, 0, 0};
  return l;
}

OoLL_S oo_ll_S_push(OoLL_S l, OoSList v) {
  OoLL_S n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v;
    oo_slist_retain(v);
    l.len = l.len + 1;
    oo_ll_S_retain(l);
    return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoSList *)oo_list_alloc_payload(sizeof(OoSList), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoSList));
    for (long long i = 0; i < l.len; i++) {
      oo_slist_retain(n.data[i]);
    }
  }
  n.data[l.len] = v;
  oo_slist_retain(v);
  n.len = l.len + 1;
  n.cap = ncap;
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

OoSList oo_ll_S_get(OoLL_S l, long long i) {
  OoSList r;
  oo_ll_S_retain(l);
  if (i < 0 || i >= l.len) {
    oo_ll_S_release(l);
    fprintf(stderr, "ERR\tll_S_get OOB\n");
    exit(1);
  }
  oo_slist_retain(l.data[i]);
  r = l.data[i];
  oo_ll_S_release(l);
  return r;
}

long long oo_ll_S_len(OoLL_S l) { return l.len; }

OoLL_S oo_ll_S_set(OoLL_S l, long long i, OoSList v) {
  OoLL_S n;
  long long ncap;
  long long j;
  if (i < 0 || i >= l.len) {
    fprintf(stderr, "ERR\tll_S_set OOB\n");
    exit(1);
  }
  if (l.data && oo_list_owned(l.data)) {
    OoSList old = l.data[i];
    l.data[i] = v;
    oo_slist_retain(v);
    oo_slist_release(old);
    oo_ll_S_retain(l);
    return l;
  }
  ncap = l.cap ? l.cap : l.len;
  n.data = (OoSList *)oo_list_alloc_payload(sizeof(OoSList), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoSList));
    for (j = 0; j < l.len; j++) {
      if (j != i) oo_slist_retain(n.data[j]);
    }
  }
  n.data[i] = v;
  oo_slist_retain(v);
  n.len = l.len;
  n.cap = ncap;
  {
    OoListHeader *hdr = ((OoListHeader *)n.data) - 1;
    __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE);
  }
  return n;
}

/* OoLLL_S: List[List[List[String]]] (3D) */
void oo_lll_S_retain(OoLLL_S l) {
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

void oo_lll_S_release(OoLLL_S l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) { oo_ll_S_release(l.data[i]); }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoLL_S));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

OoLLL_S oo_lll_S_new(void) { OoLLL_S l = {NULL, 0, 0}; return l; }

OoLLL_S oo_lll_S_push(OoLLL_S l, OoLL_S v) {
  OoLLL_S n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v; oo_ll_S_retain(v); l.len = l.len + 1; oo_lll_S_retain(l); return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoLL_S *)oo_list_alloc_payload(sizeof(OoLL_S), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoLL_S));
    for (long long i = 0; i < l.len; i++) { oo_ll_S_retain(n.data[i]); }
  }
  n.data[l.len] = v; oo_ll_S_retain(v); n.len = l.len + 1; n.cap = ncap;
  { OoListHeader *hdr = ((OoListHeader *)n.data) - 1; __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }
  return n;
}

OoLL_S oo_lll_S_get(OoLLL_S l, long long i) {
  OoLL_S r;
  oo_lll_S_retain(l);
  if (i < 0 || i >= l.len) { oo_lll_S_release(l); fprintf(stderr, "ERR\tlll_S_get OOB\n"); exit(1); }
  oo_ll_S_retain(l.data[i]); r = l.data[i]; oo_lll_S_release(l); return r;
}

long long oo_lll_S_len(OoLLL_S l) { return l.len; }

/* OoLLLL_S: List[List[List[List[String]]]] (4D) */
void oo_llll_S_retain(OoLLLL_S l) {
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

void oo_llll_S_release(OoLLLL_S l) {
  if (!oo_list_hdr_ok(l.data, l.len, l.cap)) return;
  OoListHeader *hdr = ((OoListHeader *)l.data) - 1;
  uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
  if (prev == 1) {
    for (long long i = 0; i < l.len; i++) { oo_lll_S_release(l.data[i]); }
    __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pthread_mutex_lock(&g_quota_mu);
    oo_list_ambient_bytes -= oo_list_block_bytes(l.cap, sizeof(OoLLL_S));
    pthread_mutex_unlock(&g_quota_mu);
    oo_payload_free(l.data);
  }
}

OoLLLL_S oo_llll_S_new(void) { OoLLLL_S l = {NULL, 0, 0}; return l; }

OoLLLL_S oo_llll_S_push(OoLLLL_S l, OoLLL_S v) {
  OoLLLL_S n;
  long long ncap = l.cap ? l.cap : 8;
  if (l.data && l.len < l.cap && oo_list_owned(l.data)) {
    l.data[l.len] = v; oo_lll_S_retain(v); l.len = l.len + 1; oo_llll_S_retain(l); return l;
  }
  while (ncap < l.len + 1) ncap *= 2;
  n.data = (OoLLL_S *)oo_list_alloc_payload(sizeof(OoLLL_S), (size_t)ncap);
  if (l.data && l.len > 0) {
    memcpy(n.data, l.data, (size_t)l.len * sizeof(OoLLL_S));
    for (long long i = 0; i < l.len; i++) { oo_lll_S_retain(n.data[i]); }
  }
  n.data[l.len] = v; oo_lll_S_retain(v); n.len = l.len + 1; n.cap = ncap;
  { OoListHeader *hdr = ((OoListHeader *)n.data) - 1; __atomic_store_n(&hdr->ref_count, 1, __ATOMIC_RELEASE); }
  return n;
}

OoLLL_S oo_llll_S_get(OoLLLL_S l, long long i) {
  OoLLL_S r;
  oo_llll_S_retain(l);
  if (i < 0 || i >= l.len) { oo_llll_S_release(l); fprintf(stderr, "ERR\tllll_S_get OOB\n"); exit(1); }
  oo_lll_S_retain(l.data[i]); r = l.data[i]; oo_llll_S_release(l); return r;
}

long long oo_llll_S_len(OoLLLL_S l) { return l.len; }
