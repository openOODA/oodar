/* sec/cap/cap_time.c — TimeCap / RandCap subsystem (grant / require).
 *
 * v3.4.0 round-6: moved here from fs/os/time_rand.c per the misplaced-
 * files audit. The cap store, init, and the oo_cap_grant_time /
 * oo_cap_grant_rand / oo_cap_require_time / oo_cap_require_rand functions
 * all belong with the rest of the cap module — fs/os/ just calls the
 * canonical cap API.
 *
 * The fail-closed getentropy pattern (no LCG fallback) matches the
 * canonical store in sec/cap/caps.c. */

static pthread_once_t g_tr_once = PTHREAD_ONCE_INIT;
static void tr_zeroize(void);
/* v3.4.1: keep g_tok_time/rand static. See cap_alloc.c for the
 * reason (single-TU build + extern/static collision). */
static long long g_tok_time, g_tok_rand;

static void tr_once_init(void) {
  unsigned char b[16];
#if defined(__linux__) || defined(__APPLE__)
  /* Fail-CLOSED: getentropy is the canonical source. If it fails we
   * abort() rather than fall back to a predictable LCG — the LCG
   * path (which previously lived here) was a direct cap-forge: an
   * attacker on a system with broken getentropy(3) could replay the
   * predictable LCG and forge g_tok_time / g_tok_rand. Per NORTHSTAR
   * Pillar 5, cap tokens are unforgeable or the process dies. */
  if (getentropy(b, sizeof b) != 0) {
    fprintf(stderr, "ERR\tcap\tgetentropy failed for time/rand token derivation: %s\n", strerror(errno));
    abort();
  }
#else
  fprintf(stderr, "ERR\tcap\tgetentropy unavailable for time/rand token derivation (no Linux/macOS)\n");
  abort();
#endif
  {
    unsigned long long ent0 = 0, ent1 = 0;
    int i;
    for (i = 0; i < 8; i++) ent0 = (ent0 << 8) | (unsigned long long)b[i];
    for (i = 0; i < 8; i++) ent1 = (ent1 << 8) | (unsigned long long)b[8 + i];
    g_tok_time = (long long)ent0;
    g_tok_rand = (long long)ent1;
    if (g_tok_time == 0) g_tok_time = 1;
    if (g_tok_rand == 0) g_tok_rand = 1;
  }
  if (g_tok_time == 0x4F4F544DLL) g_tok_time ^= 0x11111111LL;
  if (g_tok_rand == 0x4F4F524ELL) g_tok_rand ^= 0x11111111LL;
  if (atexit(tr_zeroize) != 0) abort();
}

static void oo_tr_init(void) {
  pthread_once(&g_tr_once, tr_once_init);
}

long long oo_cap_grant_time(void) { oo_tr_init(); return g_tok_time; }
long long oo_cap_grant_rand(void) { oo_tr_init(); return g_tok_rand; }

void oo_cap_require_time(long long got, const char *op) {
  oo_tr_init();
  if (got == 0 || got != g_tok_time) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "time");
    exit(1);
  }
}
void oo_cap_require_rand(long long got, const char *op) {
  oo_tr_init();
  if (got == 0 || got != g_tok_rand) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "rand");
    exit(1);
  }
}

static void tr_zeroize(void) {
  explicit_bzero(&g_tok_time, sizeof g_tok_time);
  explicit_bzero(&g_tok_rand, sizeof g_tok_rand);
}
