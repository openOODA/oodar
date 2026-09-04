/* sec/cap/cap_attenuate_hmac.c — HMAC-sealed cap attenuator.
 *
 * v3.4.0 round-6: moved here from sec/crypto/symmetric/crypto.c per
 * the misplaced-files audit. The cap policy (Rule 2 bitmask subset
 * check) belongs with the rest of the cap module, not the crypto
 * module. The HMAC primitive (crypto_hmac_sha256_internal) is
 * transitively available via oodar.h; the cap store is initialized
 * by caps.c (included before this file in the umbrella).
 *
 * The two APIs:
 *   - oo_cap_attenuate / oo_cap_attenuate_ok   (v1, back-compat)
 *   - oo_cap_attenuate_v2 / oo_cap_attenuate_v2_ok (v2, Rule 2)
 *
 * v2 enforces SECURITY_MODEL.oot Rule 2: child rights bitmask must
 * be a subset of parent rights. v1 cannot enforce Rule 2 (the API
 * has no parent_rights arg) and is preserved for back-compat only.
 * The verifier (oodac) is updated to call v2. */
#include "../../core/event/event.h"

/* OPEN-72: child seal = HMAC-SHA256(parent_hmac, child_rights). Empty inputs fail closed.
 *
 * v3.3.0: SECURITY_MODEL.oot Rule 2 is now enforced. The new
 * oo_cap_attenuate_v2() takes (parent_hmac, parent_rights,
 * child_rights) and verifies `parent_rights & child_rights ==
 * child_rights` (the bitmask subset check) before HMACing. */
static OoStr cap_empty_str(void) {
  OoStr z; z.data = oo_str_alloc_payload(0); z.len = 0; return z;
}

/* v3.3.0: parse a rights string (a 4-char or 8-char hex string) into
 * a 32-bit bitmask. The string format matches what oodac emits
 * (a 32-bit or 64-bit hex representation of the cap bitmask). */
static long long cap_parse_rights(OoStr s) {
  if (s.len <= 0 || !s.data) return 0;
  long long r = 0;
  for (long long i = 0; i < s.len && i < 16; i++) {
    int c = (unsigned char)s.data[i];
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return 0;
    r = (r << 4) | d;
  }
  return r;
}

/* v3.3.0: the new bitmask-checked attenuate. The Rule 2 check
 * verifies that the child's rights bitmask is a subset of the
 * parent's rights. If not, the call returns "" (fail-closed). */
OoStr oo_cap_attenuate_v2(OoStr parent_hmac, OoStr parent_rights, OoStr child_rights) {
  if (parent_hmac.len <= 0 || !parent_hmac.data) return cap_empty_str();
  if (parent_rights.len <= 0 || !parent_rights.data) return cap_empty_str();
  if (child_rights.len <= 0 || !child_rights.data) return cap_empty_str();
  long long pr = cap_parse_rights(parent_rights);
  long long cr = cap_parse_rights(child_rights);
  /* Rule 2: parent & child == child. Equivalently, child & ~parent == 0. */
  if ((cr & ~pr) != 0) {
    /* Child requests rights the parent does not have — fail closed. */
    return cap_empty_str();
  }
  oo_event_emit(oo_str_lit("cap.attenuate"));
  return crypto_hmac_sha256_internal(parent_hmac, child_rights);
}

int oo_cap_attenuate_v2_ok(OoStr parent_hmac, OoStr parent_rights, OoStr child_rights) {
  OoStr h;
  int ok;
  if (parent_hmac.len <= 0 || !parent_hmac.data) return 0;
  if (parent_rights.len <= 0 || !parent_rights.data) return 0;
  if (child_rights.len <= 0 || !child_rights.data) return 0;
  long long pr = cap_parse_rights(parent_rights);
  long long cr = cap_parse_rights(child_rights);
  if ((cr & ~pr) != 0) return 0;
  h = crypto_hmac_sha256_internal(parent_hmac, child_rights);
  ok = (h.len == 64);
  oo_str_release(h);
  return ok;
}

/* v3.3.0: keep the old API for back-compat. The old API does NOT
 * do the Rule 2 check (it has no way to know the parent's
 * rights). New code MUST use oo_cap_attenuate_v2. The old
 * function is preserved with the same signature so existing
 * consumers don't need to rebuild. */
OoStr oo_cap_attenuate(OoStr parent_hmac, OoStr child_rights) {
  /* DEFERRED CHECK: the old API has no way to know parent_rights.
   * The verifier (oodac) is expected to enforce Rule 2 at the
   * higher level. The C-level helper is a thin HMAC. */
  if (parent_hmac.len <= 0 || !parent_hmac.data || child_rights.len <= 0 || !child_rights.data)
    return cap_empty_str();
  oo_event_emit(oo_str_lit("cap.attenuate"));
  return crypto_hmac_sha256_internal(parent_hmac, child_rights);
}

int oo_cap_attenuate_ok(OoStr parent_hmac, OoStr child_rights) {
  OoStr h;
  int ok;
  if (parent_hmac.len <= 0 || !parent_hmac.data || child_rights.len <= 0 || !child_rights.data)
    return 0;
  h = crypto_hmac_sha256_internal(parent_hmac, child_rights);
  ok = (h.len == 64);
  oo_str_release(h);
  return ok;
}
