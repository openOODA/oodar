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
static int cap_parse_rights(OoStr s, long long *out) {
  long long r = 0;
  long long i;
  if (s.len <= 0 || !s.data || !out) return 0;
  for (i = 0; i < s.len && i < 16; i++) {
    int c = (unsigned char)s.data[i];
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return 0;
    r = (r << 4) | d;
  }
  *out = r;
  return 1;
}

static OoStr cap_mac_v2(OoStr parent_hmac, OoStr parent_rights, OoStr child_rights) {
  size_t n;
  char *buf;
  OoStr key, msg, h;
  oo_caps_init();
  n = (size_t)parent_hmac.len + (size_t)parent_rights.len + (size_t)child_rights.len;
  buf = (char *)malloc(n ? n : 1);
  if (!buf) return cap_empty_str();
  memcpy(buf, parent_hmac.data, (size_t)parent_hmac.len);
  memcpy(buf + parent_hmac.len, parent_rights.data, (size_t)parent_rights.len);
  memcpy(buf + parent_hmac.len + parent_rights.len, child_rights.data,
         (size_t)child_rights.len);
  key.data = (char *)g_kernel_hmac_key;
  key.len = 32;
  msg.data = buf;
  msg.len = (long long)n;
  h = crypto_hmac_sha256_internal(key, msg);
  crypto_secure_wipe(buf, n);
  free(buf);
  return h;
}

OoStr oo_cap_attenuate_v2(OoStr parent_hmac, OoStr parent_rights, OoStr child_rights) {
  long long pr, cr;
  if (parent_hmac.len <= 0 || !parent_hmac.data) return cap_empty_str();
  if (!cap_parse_rights(parent_rights, &pr)) return cap_empty_str();
  if (!cap_parse_rights(child_rights, &cr)) return cap_empty_str();
  if ((cr & ~pr) != 0) return cap_empty_str();
  oo_event_emit(oo_str_lit("cap.attenuate"));
  return cap_mac_v2(parent_hmac, parent_rights, child_rights);
}

int oo_cap_attenuate_v2_ok(OoStr parent_hmac, OoStr parent_rights, OoStr child_rights) {
  OoStr h;
  int ok;
  long long pr, cr;
  if (parent_hmac.len <= 0 || !parent_hmac.data) return 0;
  if (!cap_parse_rights(parent_rights, &pr)) return 0;
  if (!cap_parse_rights(child_rights, &cr)) return 0;
  if ((cr & ~pr) != 0) return 0;
  h = cap_mac_v2(parent_hmac, parent_rights, child_rights);
  ok = (h.len == 64);
  oo_str_release(h);
  return ok;
}

OoStr oo_cap_attenuate(OoStr parent_hmac, OoStr child_rights) {
  (void)parent_hmac;
  (void)child_rights;
  return cap_empty_str();
}

int oo_cap_attenuate_ok(OoStr parent_hmac, OoStr child_rights) {
  (void)parent_hmac;
  (void)child_rights;
  return 0;
}
