/* sec/cap/cap_attenuate.c — cap-attenuation family.
 *
 * v3.4.0 round-6 audit: this file now hosts BOTH the path-cap attenuator
 * (OoPathCap, derived from FsReadCap + a path prefix) AND the HMAC-sealed
 * cap-attenuate family (oo_cap_attenuate / oo_cap_attenuate_v2).
 *
 * Prior to v3.4.0, the HMAC-sealed attenuate family lived in
 * sec/crypto/symmetric/crypto.c — but cap policy (the Rule 2 bitmask
 * subset check) belongs with the rest of the cap module, not in the
 * crypto module. Moving it here is a layering-inversion fix per
 * the round-6 misplaced-files audit.
 *
 * The two sub-families:
 *   1. Path-cap attenuator (this file, top): OoPathCap derived from
 *      FsReadCap with a path prefix. Uses g_kernel_hmac_key as the
 *      HMAC key. See oo_attenuate_fsread_to_path / oo_path_cap_check.
 *   2. HMAC-sealed cap attenuator (this file, bottom): the
 *      oo_cap_attenuate / oo_cap_attenuate_v2 family. v2 is Rule 2
 *      (parent & child == child) checked; v1 is preserved for back-
 *      compat but not Rule-2-safe.
 *
 * We compute mac = HMAC-SHA-256(g_kernel_hmac_key, parent_cap || prefix).
 * The HMAC domain-separates (parent, prefix) by concatenating an 8-byte
 * big-endian encoding of the parent_cap with the raw prefix bytes. The
 * resulting OoPathCap can be checked with oo_path_cap_check, which
 * re-derives the MAC and constant-time-compares it to the stored one.
 *
 * The hex-decode step is needed because crypto_hmac_sha256_internal
 * returns the digest as a 64-char lowercase hex string (not raw bytes);
 * the MAC field of OoPathCap is the 32 raw bytes.
 *
 * Ordering: caps.c (orchestrator) must be included before this file so
 * g_tok_fsread, g_tok_fs, g_kernel_hmac_key, and oo_caps_init are
 * visible. */

#define OO_PATH_CAP_MAX_PREFIX 4096

static void oo_path_cap_hex_decode(const char *hex, size_t hex_len, unsigned char out[32]) {
  /* hex_len must be 64; caller already checked. */
  size_t i;
  for (i = 0; i < 32; i++) {
    unsigned int b = 0;
    if (sscanf(hex + 2 * i, "%2x", &b) != 1) {
      /* Should not happen — crypto_hmac_sha256_internal always emits 64 lowercase hex chars. */
      memset(out, 0, 32);
      return;
    }
    out[i] = (unsigned char)(b & 0xFFu);
  }
  (void)hex_len;
}

OoPathCap oo_attenuate_fsread_to_path(long long cap, OoStr prefix) {
  OoPathCap r;
  unsigned char msg[8 + OO_PATH_CAP_MAX_PREFIX];
  size_t msg_len;
  OoStr key, m, mac_hex;
  oo_caps_init();
  memset(&r, 0, sizeof r);

  /* v3.3.1 round-5 audit fix: cap check is the FIRST line of defense,
   * before any path validation. The previous custom check
   * (cap == g_tok_fsread || cap == g_tok_fs) was brittle — it
   * required the cap to be the raw token value, not any cap that
   * grants FsRead via the canonical oo_cap_require_fsread path.
   * Moving to the canonical macro means a future cap that grants
   * FsRead (e.g., via FS subsumption or a new FsRead-granting cap)
   * will be accepted here automatically. The cap_require_fsread
   * macro internally checks the FsRead bit via the canonical store
   * (caps.c:57), which accepts FsReadCap and the FsCap (which
   * subsumes FsRead). */
  oo_cap_require_fsread(cap, "attenuate_fsread_to_path");
  /* Chain re-attenuation is allowed: the caller may pass the
   * parent_cap field of a previously-derived OoPathCap. The
   * canonical check above handles this because the OoPathCap's
   * parent_cap is one of g_tok_fsread / g_tok_fs (the same
   * values oo_cap_require_fsread accepts). */
  (void)cap;  /* cap is now validated by oo_cap_require_fsread */
  /* Validate prefix: non-empty, must point to a buffer, and must be an
   * absolute path (starts with '/'). */
  if (prefix.len <= 0 || !prefix.data || prefix.data[0] != '/') {
    fprintf(stderr, "ERR\tcap\too_attenuate_fsread_to_path: prefix must be non-empty absolute path\n");
    exit(1);
  }
  if ((size_t)prefix.len > OO_PATH_CAP_MAX_PREFIX) {
    fprintf(stderr, "ERR\tcap\too_attenuate_fsread_to_path: prefix too long (max %d)\n",
            OO_PATH_CAP_MAX_PREFIX);
    exit(1);
  }

  /* Build the HMAC message: 8 bytes parent_cap (big-endian) || prefix. */
  for (int i = 0; i < 8; i++) {
    msg[i] = (unsigned char)((unsigned long long)cap >> ((7 - i) * 8));
  }
  memcpy(msg + 8, prefix.data, (size_t)prefix.len);
  msg_len = 8 + (size_t)prefix.len;

  key.data = (char *)g_kernel_hmac_key;
  key.len = (long long)sizeof g_kernel_hmac_key;
  m.data = (char *)msg;
  m.len = (long long)msg_len;
  mac_hex = crypto_hmac_sha256_internal(key, m);

  if (mac_hex.len != 64 || !mac_hex.data) {
    crypto_secure_wipe(msg, sizeof msg);
    fprintf(stderr, "ERR\tcap\too_attenuate_fsread_to_path: HMAC output malformed\n");
    exit(1);
  }
  oo_path_cap_hex_decode(mac_hex.data, (size_t)mac_hex.len, r.mac);
  /* The mac_hex payload is a refcounted OoStr allocated by
   * crypto_hmac_sha256_internal; releasing it is the caller's job in
   * general, but here it's a temporary we can leak-then-wipe. The hex
   * decode ran synchronously and the digest bytes are now in r.mac. */
  oo_str_release(mac_hex);
  crypto_secure_wipe(msg, sizeof msg);

  r.parent_cap = cap;
  /* v3.3.3 round-5 audit fix: deep-copy the prefix into a new
   * buffer that the OoPathCap owns. The previous shallow borrow
   * (r.prefix = prefix) was a use-after-free trap: the caller
   * had to keep the underlying buffer alive for the lifetime
   * of the OoPathCap, but the function's return value doesn't
   * carry that contract visibly. A caller that derived a cap
   * and then freed the prefix buffer (e.g., from a stack-
   * allocated string or a heap string that fell out of scope)
   * would have oo_path_cap_check read freed memory.
   *
   * The deep-copy is small (prefixes are short, max 4096
   * bytes per the validation above) and removes the
   * lifetime-management footgun. The OoPathCap is now
   * self-contained: derive it, store it, pass it around —
   * the prefix is owned and survives any caller-side frees. */
  r.prefix.data = (char *)oo_str_alloc_payload((size_t)prefix.len);
  memcpy(r.prefix.data, prefix.data, (size_t)prefix.len);
  r.prefix.len = prefix.len;
  return r;
}

int oo_path_cap_check(OoPathCap path_cap, OoStr path) {
  unsigned char msg[8 + OO_PATH_CAP_MAX_PREFIX];
  size_t msg_len;
  OoStr key, m, mac_hex;
  unsigned char expected[32];
  int eq;

  oo_caps_init();

  /* A default-initialized (all-zero) OoPathCap has parent_cap == 0 and
   * prefix.data == NULL; the HMAC derivation below will still execute
   * (with msg_len == 8) and the constant-time MAC compare against an
   * all-zero mac will (overwhelmingly) fail. Same for any forged cap:
   * without the per-process g_kernel_hmac_key, an attacker can't
   * reproduce a valid MAC. */
  if (path_cap.prefix.len <= 0 || !path_cap.prefix.data) return 0;
  if (path_cap.prefix.data[0] != '/') return 0;
  if (path_cap.parent_cap == 0) return 0;
  if ((size_t)path_cap.prefix.len > OO_PATH_CAP_MAX_PREFIX) return 0;

  /* Re-derive the MAC. */
  for (int i = 0; i < 8; i++) {
    msg[i] = (unsigned char)((unsigned long long)path_cap.parent_cap >> ((7 - i) * 8));
  }
  memcpy(msg + 8, path_cap.prefix.data, (size_t)path_cap.prefix.len);
  msg_len = 8 + (size_t)path_cap.prefix.len;

  key.data = (char *)g_kernel_hmac_key;
  key.len = (long long)sizeof g_kernel_hmac_key;
  m.data = (char *)msg;
  m.len = (long long)msg_len;
  mac_hex = crypto_hmac_sha256_internal(key, m);

  if (mac_hex.len != 64 || !mac_hex.data) {
    crypto_secure_wipe(msg, sizeof msg);
    return 0;
  }
  oo_path_cap_hex_decode(mac_hex.data, (size_t)mac_hex.len, expected);
  oo_str_release(mac_hex);
  crypto_secure_wipe(msg, sizeof msg);

  /* Constant-time MAC compare. crypto_ct_cmp returns 0 iff equal. */
  eq = (crypto_ct_cmp(expected, path_cap.mac, 32) == 0);
  crypto_secure_wipe(expected, sizeof expected);
  if (!eq) return 0;

  /* MAC is genuine; now enforce the path-prefix rule. */
  if (!path.data || path.len <= 0) return 0;
  if ((size_t)path_cap.prefix.len > (size_t)path.len) return 0;
  return memcmp(path.data, path_cap.prefix.data, (size_t)path_cap.prefix.len) == 0;
}
