/* oo_cap_kernel_seal / oo_enclave_enter — cap-gated seal + enclave
 * measurement helpers. Both functions require the SysCap and use
 * g_kernel_hmac_key (declared in caps.c) for the kernel-keyed
 * attestation.
 *
 * Ordering: caps.c (orchestrator) and cap_require.c (which defines
 * oo_cap_require_sys) must both be included before this file. */

OoStr oo_cap_kernel_seal(long long sys, OoStr cap_id) {
  OoStr key;
  oo_caps_init();
  oo_cap_require_sys(sys, "oo_cap_kernel_seal");
  if (cap_id.len <= 0 || !cap_id.data) {
    OoStr z; z.data = oo_str_alloc_payload(0); z.len = 0; return z;
  }
  key.data = (char *)g_kernel_hmac_key;
  key.len = (long long)sizeof g_kernel_hmac_key;
  return crypto_hmac_sha256_internal(key, cap_id);
}

OoStr oo_enclave_enter(long long sys, OoStr sealed) {
  unsigned char page[64];
  OoStr acc, meas;
  size_t n;
  oo_caps_init();
  oo_cap_require_sys(sys, "oo_enclave_enter");
  memset(page, 0, sizeof page);
  memcpy(page, "ooda-enclave-v1", 15);
  if (sealed.data && sealed.len > 0) {
    n = (size_t)sealed.len;
    if (n > 32) n = 32;
    memcpy(page + 16, sealed.data, n);
  }
  for (int j = 0; j < 8; j++) {
    page[48 + j] = (unsigned char)(sys >> ((7 - j) * 8));
  }
  acc.data = (char *)page;
  acc.len = 64;
  meas = crypto_sha256_internal(acc);
  fputs("enclave_measurement ", stdout);
  if (meas.data && meas.len > 0) fwrite(meas.data, 1, (size_t)meas.len, stdout);
  fputc('\n', stdout);
  return meas;
}
