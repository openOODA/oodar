/* qa/tests_challenger_env_pwd.c — PWD preservation through the env surface.
 *
 * sys_env.c keeps PWD in oo_child_filter_env (spawned tools anchor
 * relative writes to it) and admits PWD in oo_process_policy_getenv.
 * This test pins that contract: PWD readable via the policy getenv,
 * non-listed keys rejected, and the child filter keeping PWD while
 * scrubbing everything outside OODA_/OODAC_/OO_/OODACODEX/PWD.
 *
 * Exit codes:
 *   0 — all PWD beats hold
 *   1 — a beat failed (see FAIL lines on stderr)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../oodar.h"
#include "../oodar_internal.h"

static int failures = 0;

static void check(int cond, const char *name) {
  if (cond) {
    fprintf(stderr, "OK\tenv_pwd\t%s\n", name);
  } else {
    fprintf(stderr, "FAIL\tenv_pwd\t%s\n", name);
    failures++;
  }
}

static void beat_policy_getenv(void) {
  setenv("PWD", "/keep/pwd", 1);
  const char *pwd = oo_process_policy_getenv("PWD");
  check(pwd && strcmp(pwd, "/keep/pwd") == 0, "policy getenv admits PWD");

  setenv("OODA_E_PROBE", "kept", 1);
  const char *keep = oo_process_policy_getenv("OODA_E_PROBE");
  check(keep && strcmp(keep, "kept") == 0, "policy getenv admits OODA_");

  setenv("EVIL_E_DROP", "nope", 1);
  check(oo_process_policy_getenv("EVIL_E_DROP") == NULL, "policy getenv rejects unlisted");

  setenv("HOME", "/evil/home", 1);
  check(oo_process_policy_getenv("HOME") == NULL, "policy getenv rejects HOME");

  check(oo_process_policy_getenv(NULL) == NULL, "policy getenv rejects NULL");
  check(oo_process_policy_getenv("") == NULL, "policy getenv rejects empty");
}

static void child_filter_body(void) {
  oo_child_filter_env();
  int bad = 0;
  const char *pwd = getenv("PWD");
  if (!pwd || strcmp(pwd, "/keep/pwd") != 0) bad++;
  const char *keep = getenv("OODA_E_KEEP");
  if (!keep || strcmp(keep, "1") != 0) bad++;
  const char *oo = getenv("OO_E_KEEP");
  if (!oo || strcmp(oo, "1") != 0) bad++;
  const char *codex = getenv("OODACODEX");
  if (!codex || strcmp(codex, "x") != 0) bad++;
  if (getenv("EVIL_E_DROP") != NULL) bad++;
  if (getenv("HOME") != NULL) bad++;
  const char *path = getenv("PATH");
  if (!path || strcmp(path, "/usr/local/bin:/usr/bin:/bin") != 0) bad++;
  _exit(bad ? 1 : 0);
}

static void beat_child_filter(void) {
  setenv("PWD", "/keep/pwd", 1);
  setenv("OODA_E_KEEP", "1", 1);
  setenv("OO_E_KEEP", "1", 1);
  setenv("OODACODEX", "x", 1);
  setenv("EVIL_E_DROP", "1", 1);
  setenv("HOME", "/evil/home", 1);
  pid_t pid = fork();
  if (pid < 0) { check(0, "child filter fork"); return; }
  if (pid == 0) { alarm(5); child_filter_body(); _exit(2); }
  int st = 0;
  waitpid(pid, &st, 0);
  check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child filter keeps PWD, scrubs rest");
}

int main(void) {
  beat_policy_getenv();
  beat_child_filter();
  unsetenv("OODA_E_PROBE");
  unsetenv("OODA_E_KEEP");
  unsetenv("OO_E_KEEP");
  unsetenv("EVIL_E_DROP");
  if (failures == 0) {
    printf("OK\tenv_pwd\tPWD preserved through policy getenv and child filter\n");
    return 0;
  }
  fprintf(stderr, "FAIL\tenv_pwd\t%d beat(s) wrong\n", failures);
  return 1;
}
