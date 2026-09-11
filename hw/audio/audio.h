#ifndef OODAR_HW_AUDIO_H
#define OODAR_HW_AUDIO_H

/* oodar/hw/audio/audio.h — Audio HAL placeholder type.
 *
 * v4.6.0 (2026-09-12): wire-up proof for the AudioCap substrate token.
 * The 6 hardware-only caps (Audio/Camera/Usb/Hid/Window/Frame) are
 * structurally present in sec/cap/caps.h but have no consumers. This
 * file defines the placeholder type so a real consumer can be written
 * without depending on a missing struct.
 *
 * Per NORTHSTAR §1.2, hardware HALs are part of the substrate role
 * (parallel to hw/gpu/gpu.h which defines OoGpuDevice + OoGpuBuffer).
 * The audio HAL follows the same pattern: a struct with handle + metadata,
 * lifecycle functions, and a cap-gated entry point.
 *
 * On this host (no ALSA lib — `rpm -q alsa-lib-devel` reports "not
 * installed"), oo_audio_capture returns OoResS with .ok=0. The shim
 * compiles cleanly without alsa-lib-devel; an opt-in `-DUSE_ALSA` flag
 * would link against ALSA via <alsa/asoundlib.h> and call snd_pcm_open.
 * That flag is conditional + requires the host to have alsa-lib-devel
 * installed; we do NOT enable it by default. */

#include "../../oodar.h"
#include "../../sec/cap/caps.h"
#include "../../types.h"
#include <stddef.h>

#define OO_AUDIO_MAX_CHANNELS 8
#define OO_AUDIO_SAMPLE_RATE_DEFAULT 48000
#define OO_AUDIO_FRAMES_DEFAULT 1024

typedef struct {
  void *device_handle;        /* opaque; ALSA snd_pcm_t * under USE_ALSA */
  void *buffer_handle;        /* opaque; mmap'd DMA buffer under USE_ALSA */
  unsigned long long size_bytes;
  int sample_rate;            /* Hz */
  int channels;               /* 1=mono, 2=stereo, ... */
  int bit_depth;              /* 16, 24, 32 */
  int is_capture;             /* 1=capture (mic), 0=playback (speaker) */
  char device_name[128];
} OoAudioBuf;

/* Lifecycle. oo_audio_init: cap-gated via AudioCap; returns 0 on
 * success, -1 on failure (no audio device, ALSA not linked, cap fail). */
int oo_audio_init(long long cap);

/* Cap-gated capture. On a host with USE_ALSA + a capture device, fills
 * `out` with one buffer of frames from the device. On this host (no
 * ALSA lib), returns OoResS with .ok=0 + stderr diagnostic. */
OoResS oo_audio_capture(long long cap, OoAudioBuf *out);

/* Release: frees any DMA buffer + closes the device. No-op if init
 * failed. */
void oo_audio_release(OoAudioBuf *buf);

#endif
