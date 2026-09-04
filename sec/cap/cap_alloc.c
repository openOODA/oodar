/* sec/cap/cap_alloc.c — AllocCap subsystem (grant / require / is).
 *
 * v3.4.0 round-6: moved here from core/mem/alloc.c per the misplaced-
 * files audit. The cap store, init, and the three oo_cap_alloc_*
 * functions all belong with the rest of the cap module — the
 * allocator just calls oo_cap_require_alloc() and stays out of the
 * cap store.
 *
 * The fail-closed getentropy pattern (no LCG fallback) matches the
 * canonical store in sec/cap/caps.c. */

/* Classic forgeable magic OOAL — must never be the live token. */
#define OO_CLASSIC_ALLOC 0x4F4F414CLL

static pthread_once_t g_alloc_once = PTHREAD_ONCE_INIT;
/* v3.4.1: keep g_tok_alloc static (internal linkage). oo_cap_self_token
 * reads it via oo_cap_grant_alloc() instead of an extern pointer; this
 * sidesteps the single-TU-build linker confusion that arose when an
 * extern in caps.c competed with a static in cap_alloc.c. */
static long long g_tok_alloc;

static void alloc_init_once(void) {
  unsigned char b[8];
#if defined(__linux__) || defined(__APPLE__)
  if (getentropy(b, sizeof b) != 0) {
    /* Fail-closed: no LCG fallback. getentropy() must succeed. */
    fprintf(stderr, "ERR\tcap\tgetentropy() failed; refusing to derive alloc capability token\n");
    abort();
  }
#else
  /* Fail-closed: no LCG fallback. getentropy() is required. */
  fprintf(stderr, "ERR\tcap\tgetentropy() not available; refusing to derive alloc capability token\n");
  abort();
#endif
  {
    /* v2.2.0: the canonical cap system (caps.c, make_cap_tok) does
     * not use a band byte — the comment there calls the band byte
     * "redundant and ... consuming entropy" — so the alloc token now
     * uses the full 8 bytes of getentropy randomness, matching the
     * caps.c layout. The cap is identified by which g_tok_alloc global
     * it is stored in, not by a tag in the high byte. */
    unsigned long long ent = ((((unsigned long long)b[0]) << 56) |
                              (((unsigned long long)b[1]) << 48) |
                              (((unsigned long long)b[2]) << 40) |
                              (((unsigned long long)b[3]) << 32) |
                              (((unsigned long long)b[4]) << 24) |
                              (((unsigned long long)b[5]) << 16) |
                              (((unsigned long long)b[6]) << 8)  |
                              ((unsigned long long)b[7]));
    g_tok_alloc = (long long)ent;
  }
  if (g_tok_alloc == OO_CLASSIC_ALLOC) g_tok_alloc ^= 0x11111111LL;
}

static void oo_alloc_init(void) {
  pthread_once(&g_alloc_once, alloc_init_once);
}

long long oo_cap_grant_alloc(void) {
  oo_alloc_init();
  return g_tok_alloc;
}

void oo_cap_require_alloc(long long got, const char *op) {
  oo_alloc_init();
  if (got != g_tok_alloc) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n",
            op ? op : "alloc");
    exit(1);
  }
}

int oo_cap_is_alloc(long long got) {
  oo_alloc_init();
  return got == g_tok_alloc;
}
