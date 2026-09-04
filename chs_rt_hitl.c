/* Leftover residual: runtime verify_human is not a product feature. */
/* M165/ZT path A: verify_human — EnvCap + FsCap required; policy env allowlisted.
 * OODA_HITL_ALLOW set → try TTY Enter or OODA_HITL_AUTO_APPROVE=1;
 * else fail-closed Err (E_HITL). Returns Ok("approved") on accept. */
#include "chs_rt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

OoResS oo_verify_human(long long env, long long fs, OoStr msg) {
  OoResS r;
  const char *allow;
  const char *auto_ap;
  FILE *tty;
  int c;

  oo_cap_require_env(env, "verify_human");
  oo_cap_require_fs(fs, "verify_human");

  allow = oo_process_policy_getenv("OODA_HITL_ALLOW");
  if (!allow || !allow[0]) {
    r.ok = 0;
    r.val = oo_str_lit(
        "E_HITL: set OODA_HITL_ALLOW (+ optional OODA_HITL_AUTO_APPROVE=1) for verify_human");
    return r;
  }

  fprintf(stderr, "[HITL] verify_human: ");
  if (msg.data && msg.len > 0) {
    fwrite(msg.data, 1, (size_t)msg.len, stderr);
  }
  fputc('\n', stderr);

  auto_ap = oo_process_policy_getenv("OODA_HITL_AUTO_APPROVE");
  if (auto_ap && strcmp(auto_ap, "1") == 0) {
    fprintf(stderr, "[HITL] Auto-approved (OODA_HITL_AUTO_APPROVE=1). Resuming...\n");
    r.ok = 1;
    r.val = oo_str_lit("approved");
    return r;
  }

  tty = fopen("/dev/tty", "r");
  if (tty) {
    fprintf(stderr, "[HITL] Press [Enter] to approve, or [Ctrl+C] to abort: ");
    fflush(stderr);
    while ((c = fgetc(tty)) != EOF && c != '\n') {
      /* drain line */
    }
    fclose(tty);
    fprintf(stderr, "[HITL] Approved (TTY). Resuming...\n");
    r.ok = 1;
    r.val = oo_str_lit("approved");
    return r;
  }

  r.ok = 0;
  r.val = oo_str_lit("E_HITL: no TTY and OODA_HITL_AUTO_APPROVE not set; deny");
  return r;
}
