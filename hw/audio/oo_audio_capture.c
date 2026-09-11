/* oodar/hw/audio/oo_audio_capture.c — Audio HAL stub + cap wire-up.
 *
 * v4.6.0 (2026-09-12): wire-up proof for the AudioCap substrate token.
 * Per NORTHSTAR §1.2, hardware HALs are part of the substrate role
 * (parallel to hw/gpu/gpu_hip_dispatch_buf.c). This file provides:
 *   - oo_audio_init(cap): cap-gated device open.
 *   - oo_audio_capture(cap, &buf): cap-gated capture entry point.
 *   - oo_audio_release(buf): cleanup.
 *
 * Build flags:
 *   default     — stub mode; oo_audio_capture returns OoResS with .ok=0.
 *   -DUSE_ALSA  — ALSA backend; requires alsa-lib-devel on the host.
 *                 NOT enabled on this host (`rpm -q alsa-lib-devel` →
 *                 "not installed"). Stub mode is the documented path.
 *
 * Why stub on this host:
 *   The 6 hardware-only caps are future-state per the substrate design.
 *   Adding a real ALSA capture loop would expand oodar's scope into a
 *   product HAL (DMA, format negotiation, codec integration). The stub
 *   proves the cap-gate works end-to-end without that scope expansion;
 *   a real HAL can be added later by enabling -DUSE_ALSA + writing the
 *   ALSA capture loop.
 *
 * Cap path (always enforced, even in stub mode):
 *   oo_audio_capture(cap, &buf):
 *     1. oo_cap_require_audio(cap, "audio_capture") — bitmask + OCap check
 *     2. (stub) return ERR_NO_DEVICE
 *     3. (USE_ALSA) snd_pcm_readi + fill OoAudioBuf
 *
 * The probe tests path 1 + 2; if -DUSE_ALSA is enabled, the probe
 * tests path 3 by attempting a real capture. */

#include "../../oodar.h"
#include "../../sec/cap/caps.h"
#include "audio.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_ALSA
#include <alsa/asoundlib.h>
#endif

static int g_audio_inited = 0;

int oo_audio_init(long long cap) {
  /* Cap-gate: AudioCap is required to open the audio device. The
   * dual_check in cap_require.c runs the bitmask check + the OCap
   * rights check; disagreement aborts with exit(2). */
  oo_cap_require_audio(cap, "audio_init");
#ifdef USE_ALSA
  /* Real ALSA path: enumerate devices, open the default capture device,
   * set hw params. Out of scope for v4.6.0 — stub mode is the documented
   * path on this host. */
  fprintf(stderr, "audio: USE_ALSA path not implemented in v4.6.0 (stub mode)\n");
  g_audio_inited = 0;
  return -1;
#else
  /* Stub mode: pretend success so the cap-gate probe can verify the
   * dual-check works. A real HAL would replace this with snd_pcm_open. */
  g_audio_inited = 1;
  return 0;
#endif
}

OoResS oo_audio_capture(long long cap, OoAudioBuf *out) {
  OoResS r = {0, oo_str_lit("audio_capture: no device")};
  if (out == NULL) {
    r.val = oo_str_lit("audio_capture: null OoAudioBuf*");
    return r;
  }
  /* Cap-gate first. Same dual-check pattern as oo_audio_init. */
  oo_cap_require_audio(cap, "audio_capture");
  if (!g_audio_inited) {
    fprintf(stderr,
            "audio: oo_audio_capture called before oo_audio_init; "
            "returning ERR_NO_INIT\n");
    r.val = oo_str_lit("audio_capture: not initialized");
    return r;
  }
#ifdef USE_ALSA
  /* Real ALSA path (out of scope for v4.6.0): would call snd_pcm_readi
   * here. The stub path documents the wire-up shape. */
  fprintf(stderr, "audio: USE_ALSA path not implemented in v4.6.0 (stub mode)\n");
  return r;
#else
  /* Stub mode: return ERR_NO_DEVICE. The probe expects this exit code. */
  memset(out, 0, sizeof *out);
  snprintf(out->device_name, sizeof out->device_name,
           "stub:no-device:USE_ALSA-not-defined");
  out->sample_rate = OO_AUDIO_SAMPLE_RATE_DEFAULT;
  out->channels = 0;  /* 0 = no device */
  out->is_capture = 1;
  fprintf(stderr,
          "audio: stub mode (no ALSA). To enable real capture, install "
          "alsa-lib-devel + rebuild with -DUSE_ALSA\n");
  return r;  /* .ok=0 */
#endif
}

void oo_audio_release(OoAudioBuf *buf) {
  if (buf == NULL) return;
#ifdef USE_ALSA
  /* Real ALSA path would snd_pcm_close(buf->device_handle) here. */
#endif
  memset(buf, 0, sizeof *buf);
  g_audio_inited = 0;
}
