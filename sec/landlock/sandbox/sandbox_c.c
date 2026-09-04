#include "../../../oodar.h"
#include "../sandbox.h"
#include <stdint.h>
#include <stddef.h>

/* sandbox_c.c — the v2.2.0 C-ABI "sandbox" entry points.
 *
 * v2.2.0: Previously each of these called oo_cap_grant_sys() internally
 * to manufacture its own capability token, which bypassed the cap system
 * entirely (a covert backdoor — any C caller could apply a sandbox matrix
 * without holding SysCap). Now the caller MUST supply the sys_cap as the
 * first argument; the function validates it via oo_cap_require_sys(),
 * which fails closed (exits) on a missing or forged token. */

/* oo_sandbox_c_apply_matrix(sys_cap, writedir, cap_mask) — thin C-friendly
 * shim that builds an oo_sandbox_config_t with just the writedir and
 * cap_mask set, and delegates to oo_sandbox_apply_matrix(). Returns 0
 * on success, -1 on any failure. */
int oo_sandbox_c_apply_matrix(long long sys_cap, const char *writedir, uint64_t cap_mask) {
  oo_cap_require_sys(sys_cap, "sandbox_c_apply_matrix");
  oo_sandbox_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.allowed_caps_mask = (uint32_t)cap_mask;
  if (writedir) {
    cfg.write_dirs_colon = oo_str_lit(writedir);
  }
  OoResS r = oo_sandbox_apply_matrix(sys_cap, &cfg);
  return r.ok ? 0 : -1;
}

/* oo_sandbox_c_restrict_caps(sys_cap, cap_mask) — cap-only restriction
 * shim. Builds an empty config with just the cap mask, and delegates
 * to oo_sandbox_restrict_caps(). Returns 0 on success, -1 on failure. */
int oo_sandbox_c_restrict_caps(long long sys_cap, uint64_t cap_mask) {
  oo_cap_require_sys(sys_cap, "sandbox_c_restrict_caps");
  OoResS r = oo_sandbox_restrict_caps(sys_cap, (uint32_t)cap_mask);
  return r.ok ? 0 : -1;
}

/* oo_sandbox_c_set_quotas(sys_cap, mem_mb, cpu_sec, max_fds) — rlimit
 * shim. Delegates to oo_sandbox_set_quotas() with the three quota
 * parameters cast to long long. Returns 0 on success, -1 on failure. */
int oo_sandbox_c_set_quotas(long long sys_cap, uint64_t mem_mb, uint64_t cpu_sec, uint64_t max_fds) {
  oo_cap_require_sys(sys_cap, "sandbox_c_set_quotas");
  OoResS r = oo_sandbox_set_quotas(sys_cap, (long long)mem_mb, (long long)cpu_sec, (long long)max_fds);
  return r.ok ? 0 : -1;
}
