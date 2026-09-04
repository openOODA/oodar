/* gpu/gpu_atomic.c — placeholder for atomic GPU operations.
 * The v2.3.0 source has no public atomic surface yet (the original
 * gpu.c only exposes alloc/free/copy/stream/event/sync/launch). This
 * file exists so the gpu/ sub-folder can be split as the spec requires
 * (one concept per file). New atomics will land here.
 * Cap token: GpuCap via oo_cap_require_gpu. */
#include "../gpu.h"

/* Intentionally empty for v2.3.0. Future oo_gpu_atomic_add / cas / etc.
 * will be defined here. The launch-kernel pipeline can already produce
 * atomic ops (the reduce_sum kernel uses atomicAdd); the user-facing
 * surface is what this file would expose. */
