/* Symmetric subdir orchestrator — cap-gated HMAC and cap-signed CG.
 *
 * v2.3.0 file split: this file replaces the monolithic sec/crypto/crypto.c
 * for the cap/json/cg content that lived there but is out of scope for
 * the file-split's hash/HMAC/secure extraction (which live in
 * symmetric/hash.c, symmetric/hmac.c, and symmetric/secure.c).
 *
 * The umbrella order is:
 *   symmetric/secure.c   (crypto_secure_wipe, crypto_ct_cmp)
 *   symmetric/hash.c     (SHA-256, SHA-512, sha256_bytes used by HMAC)
 *   symmetric/hmac.c     (crypto_hmac_sha256_internal — used by cap_attenuate)
 *   symmetric/crypto.c   (this orchestrator: cap_attenuate, json, cg)
 *
 * json_*_internal and python_embed_internal are currently unused outside
 * this TU; they are preserved verbatim to avoid dropping any future caller. */
#include "../../../oodar.h"
#include "../crypto_internal.h"
/* v2.2.0: explicit include — oo_event_emit is called from this TU; relying
 * on the implicit-declaration fallback would hide a missing prototype under
 * -Wstrict-prototypes and is a latent bug if the signature ever changes. */
#include "../../../core/event/event.h"
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif

/* OPEN-72: child seal = HMAC-SHA256(parent_hmac, child_rights). Empty inputs fail closed.
 *
 * v3.1.0 NOTE (deferred to v3.2.0 Floor break): SECURITY_MODEL.oot
 * Rule 2 mandates a bitmask subset check — `parent_rights & child_rights
 * == child_rights` — before HMACing. The current API only takes
 * (parent_hmac, child_rights); it has no way to know the parent's
 * rights. The audit round 4 (2026-09) flagged this as CRITICAL but
 * the OCap auditor recommended tracking it as a separate Floor break
 * (it predates v2.3.0). The Floor break will change the signature to
 * `oo_cap_attenuate_v2(parent_hmac, parent_rights, child_rights)` and
 * add the bitmask check. Until then, the cap is unforgeable (you need
 * parent_hmac) but a holder of parent_hmac can mint a child for ANY
 * rights string. The verifier (oodac) is expected to enforce Rule 2
 * at the higher level. */
static OoStr cap_empty_str(void) {
  OoStr z; z.data = oo_str_alloc_payload(0); z.len = 0; return z;
}

OoStr cap_attenuate(OoStr parent_hmac, OoStr child_rights) {
  if (parent_hmac.len <= 0 || !parent_hmac.data || child_rights.len <= 0 || !child_rights.data)
    return cap_empty_str();
  oo_event_emit(oo_str_lit("cap.attenuate"));
  return crypto_hmac_sha256_internal(parent_hmac, child_rights);
}

int cap_attenuate_ok(OoStr parent_hmac, OoStr child_rights) {
  OoStr h;
  int ok;
  if (parent_hmac.len <= 0 || !parent_hmac.data || child_rights.len <= 0 || !child_rights.data)
    return 0;
  h = crypto_hmac_sha256_internal(parent_hmac, child_rights);
  ok = (h.len == 64);
  oo_str_release(h);
  return ok;
}

OoStr oo_cap_attenuate(OoStr parent_hmac, OoStr child_rights) {
  return cap_attenuate(parent_hmac, child_rights);
}

int oo_cap_attenuate_ok(OoStr parent_hmac, OoStr child_rights) {
  return cap_attenuate_ok(parent_hmac, child_rights);
}

/* v3.1.0 audit: removed the 6 dead json_*_internal and python_embed_internal
 * functions (~90 lines). The file's own prior comment admitted they were
 * "currently unused outside this TU; preserved verbatim to avoid dropping
 * any future caller." Per the round-4 audit (power-law lens), the
 * 80% long tail lives in dead code like this. The oo_cg_* HMAC
 * sign/verify below is the only live public surface in this TU. */

static pthread_once_t g_cg_sign_once = PTHREAD_ONCE_INIT;
static unsigned char g_cg_sign_key[32];

static void cg_sign_init(void) {
#if defined(__linux__) || defined(__APPLE__)
  /* Fail-CLOSED: getentropy is the canonical source. The LCG fallback
   * (which previously lived here) was a direct seal/verify forge: an
   * attacker on a system with broken getentropy(3) could replay the
   * predictable LCG and recover the HMAC key, then forge oo_cg_sign
   * / oo_cg_verify. Per NORTHSTAR Pillar 5, the seal key is
   * unforgeable or the process dies. */
  if (getentropy(g_cg_sign_key, sizeof(g_cg_sign_key)) != 0) {
    fprintf(stderr, "ERR\tcap\tgetentropy failed for cg_sign HMAC key: %s\n", strerror(errno));
    abort();
  }
#else
  /* Non-Linux/Apple platforms: no portable getentropy(3). Abort. */
  fprintf(stderr, "ERR\tcap\tgetentropy unavailable for cg_sign HMAC key (no Linux/macOS)\n");
  abort();
#endif
}

static long long oo_cg_calc_sig(long long cap) {
  pthread_once(&g_cg_sign_once, cg_sign_init);
  unsigned char k[64];
  memset(k, 0, sizeof(k));
  memcpy(k, g_cg_sign_key, sizeof(g_cg_sign_key));

  unsigned char ipad[64], opad[64];
  for (int i = 0; i < 64; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }

  unsigned char inner_buf[64 + 8];
  memcpy(inner_buf, ipad, 64);
  for (int i = 0; i < 8; i++) {
    inner_buf[64 + i] = (unsigned char)((uint64_t)cap >> ((7 - i) * 8));
  }

  unsigned char inner_digest[32];
  sha256_bytes(inner_buf, sizeof(inner_buf), inner_digest);
  crypto_secure_wipe(inner_buf, sizeof(inner_buf));

  unsigned char outer_buf[64 + 32];
  memcpy(outer_buf, opad, 64);
  memcpy(outer_buf + 64, inner_digest, 32);

  unsigned char outer_digest[32];
  sha256_bytes(outer_buf, sizeof(outer_buf), outer_digest);

  crypto_secure_wipe(k, sizeof(k));
  crypto_secure_wipe(ipad, sizeof(ipad));
  crypto_secure_wipe(opad, sizeof(opad));
  crypto_secure_wipe(outer_buf, sizeof(outer_buf));
  crypto_secure_wipe(inner_digest, sizeof(inner_digest));

  uint64_t sig = 0;
  for (int i = 0; i < 8; i++) {
    sig = (sig << 8) | (uint64_t)outer_digest[i];
  }
  crypto_secure_wipe(outer_digest, sizeof(outer_digest));
  return (long long)sig;
}

long long oo_cg_sign(long long cap) {
  oo_cap_require_sign(cap, "oo_cg_sign");
  return oo_cg_calc_sig(cap);
}

int oo_cg_verify(long long cap, long long sig) {
  oo_cap_require_sign(cap, "oo_cg_verify");
  if (sig == 0) return 0;
  long long expected = oo_cg_calc_sig(cap);
  int match = (crypto_ct_cmp(&sig, &expected, sizeof(long long)) == 0);
  crypto_secure_wipe(&expected, sizeof(expected));
  return match ? 1 : 0;
}
