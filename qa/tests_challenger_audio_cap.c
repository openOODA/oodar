/* tests_challenger_audio_cap.c — Hostile probe for the AudioCap wire-up.
 *
 * v4.6.0 (2026-09-12): verifies the AudioCap substrate wire-up. The
 * hw/audio/oo_audio_capture.c shim provides oo_audio_init/capture/
 * release, all cap-gated via oo_cap_require_audio (which is itself
 * dual-checked: bitmask + OCap bridge).
 *
 * Probe matrix:
 *   1. cap=0: oo_audio_init(0) must exit(1) (fail-closed on absence).
 *   2. wrong cap (g_tok_fs): oo_audio_init(fs_cap) must exit(1) (the
 *      bitmask check rejects because got != g_tok_audio).
 *   3. real cap (g_tok_audio): oo_audio_init(audio_cap) must return 0
 *      (stub-mode success), then oo_audio_capture must return .ok=0
 *      with val containing "no device" (stub mode, no ALSA).
 *   4. OCap disagreement (forced via oo_cap_bridge_set_test_force_fail):
 *      real cap + forced OCap fail → oo_audio_init exits(2) per the
 *      dual-check pattern (mirrors the cap-bridge probe).
 *
 * Exit codes: 0 = all probes pass; 1 = at least one probe failed.
 */

#include "../oodar.h"
#include "../sec/cap/cap_ocap_bridge.h"
#include "../hw/audio/audio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_failures = 0;
#define ASSERT(cond, msg) do { \
  if (!(cond)) { \
    fprintf(stderr, "FAIL\t%s: %s (line %d)\n", __FILE__, msg, __LINE__); \
    g_failures++; \
  } \
} while (0)

/* --- Probe 1: cap=0 fail-closed --- */
static void probe_cap_zero(void) {
  pid_t pid = fork();
  if (pid == 0) {
    /* Cap-gate should abort. On cap=0, oo_cap_require_audio exits(1). */
    (void)oo_audio_init(0);
    _exit(0);  /* must not reach here */
  }
  int status = 0;
  waitpid(pid, &status, 0);
  ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 1,
         "oo_audio_init(cap=0) should exit(1); child exited differently");
}

/* --- Probe 2: wrong cap (g_tok_fs) rejected --- */
static void probe_wrong_cap(void) {
  pid_t pid = fork();
  if (pid == 0) {
    long long fs = oo_cap_self_token(0);  /* g_tok_fs */
    (void)oo_audio_init(fs);
    _exit(0);  /* must not reach here — fs cap is not the audio cap */
  }
  int status = 0;
  waitpid(pid, &status, 0);
  ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 1,
         "oo_audio_init(fs_cap) should exit(1); wrong cap must be rejected");
}

/* --- Probe 3: real cap happy path --- */
static void probe_real_cap(void) {
  pid_t pid = fork();
  if (pid == 0) {
    long long audio = oo_cap_self_token(9);  /* g_tok_audio */
    int rc = oo_audio_init(audio);
    if (rc != 0) _exit(2);
    /* Stub mode: oo_audio_capture returns .ok=0 with "no device". */
    OoAudioBuf buf;
    OoResS r = oo_audio_capture(audio, &buf);
    if (r.ok != 0) _exit(3);
    /* Verify the buffer is zeroed + has the stub device name. */
    if (strstr(buf.device_name, "stub:no-device") == NULL) _exit(4);
    oo_audio_release(&buf);
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
         "oo_audio_init/capture with real audio cap should succeed in stub mode");
}

/* --- Probe 4: OCap disagreement fires (dual-check tripwire) --- */
static void probe_ocap_disagreement(void) {
  pid_t pid = fork();
  if (pid == 0) {
    /* Force the next OCap check to fail. The dual-check wrapper must
     * then abort with exit(2) because bitmask passes but OCap fails. */
    oo_cap_bridge_set_test_force_fail(1);
    long long audio = oo_cap_self_token(9);
    (void)oo_audio_init(audio);
    _exit(0);  /* must not reach here */
  }
  int status = 0;
  waitpid(pid, &status, 0);
  ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 2,
         "oo_audio_init(real audio cap, ocap forced fail) should exit(2)");
}

/* --- Driver --- */
int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  fprintf(stderr, "  audio-cap probe: starting\n");

  probe_cap_zero();
  probe_wrong_cap();
  probe_real_cap();
  probe_ocap_disagreement();

  if (g_failures != 0) {
    fprintf(stderr, "FAIL audio-cap: %d failures\n", g_failures);
    return 1;
  }
  fprintf(stderr,
          "OK audio-cap: 4 probes passed (cap=0, wrong-cap, real-cap, ocap-disagree)\n");
  return 0;
}
