# Changelog

## v1.0.1 — Thrust (internal reorg, no consumer change)

Per RULES.oot §1.21, v1.0.1 is a MINOR (Thrust) bump. The
internal subdir layout was reorganized to mirror std's
vocabulary (core, sec, fs, net, hw, app). No public symbol
changes, no API changes, no consumer changes — consumers
linking against v1.0.0 oodar.a or building from source with
`gcc oodar.c` see no difference.

### What changed (internal only)

- **17 subdirs → 6 subdirs** (using std's vocabulary). The v1.0.0
  layout had one subdir per concept (cap, landlock, mem,
  crypto, pqc, actor, gpu, xlang, hitl, io, math, meta, net,
  os, str, list, telemetry). v1.0.1 collapses these into 6
  tactical subdirs that match std's domain names:

  | v1.0.0 | v1.0.1 |
  |---|---|
  | cap, landlock, crypto, pqc | sec/ |
  | os, io | fs/ |
  | net | net/ |
  | gpu | hw/ |
  | actor, xlang, hitl, telemetry | app/ |
  | str, list, mem, math, meta | core/ |

- **Sub-subdirs added** for the multi-file domains (e.g.,
  core/str/, sec/cap/, app/actor/). Each sub-subdir has its
  own `ANCHOR.oo`, mirroring std's per-domain organization.

- **27 `ANCHOR.oo` files total** (1 root + 6 tactical + 20
  sub-subdir ANCHOR.oo). The root ANCHOR.oo documents the
  overall structure; each tactical and sub-subdir ANCHOR.oo
  documents its own files and reading order.

- **No file renames, no symbol changes.** The 53 .c files and
  13 .h files have the same names as v1.0.0. They just live
  in different subdirs.

- **No include path changes** for consumers. `gcc oodar.c`
  still works. The internal `#include` paths inside the runtime
  use `../../oodar.h` and `../../types.h` for the 2-level-deep
  files (per the user's "I don't mind option A" — live with
  the relative paths).

### What consumers must change

**Nothing.** This is a Thrust bump. The build command,
public header, public symbols, and ABI are all unchanged.

### What did NOT change

- The set of exported `oo_*` symbols.
- `oodar.h`, `oodar.c`, `types.h` at the root (same names, same
  locations, same contents).
- The build command `gcc oodar.c`.
- `api_surface=53` (53 .c files before, 53 after; just
  redistributed).
- The auto-release workflow and the version contract.

### Why the reorg

After v1.0.0 shipped with 17 subdirs, the user feedback was
that the layout felt "messy" and didn't match std's structure.
17 subdirs for 53 files is over-fragmented (avg 3 files per
subdir). std uses 8 tactical subdirs (core, sec, fs, net,
science, app, hw, meta) for 5794 files (avg 725 per subdir).
Mirroring std's vocabulary — even at oodar's smaller scale —
gives the two repos a consistent "library repo" feel and
makes it obvious where a new file should land.

science/ is omitted in oodar (no analog). All 6 of the
populated std domains map to oodar content; the 7th
(`hw/`) is for the GPU dispatch that std doesn't have.

## v1.0.0 — Floor break from v0.1.x

Per RULES.oot §1.21, v1.0.0 is a MAJOR (Floor) bump. The
subdir reorg + the C-coupled prefix drop in the file/header
names is incompatible at the build-include level with v0.1.x.

### What changed

1. **The 53 .c files are now in 17 per-domain subdirs** (was: a
   flat directory at the repo root). Each subdir has its own
   `ANCHOR.oo` describing its files and reading order.

2. **The C-coupled file/header prefix is gone.** The v0.1.x
   prefix encoded "C Host Substrate — Runtime" in every file
   name; the v1.0.0 drop is per the original concern that the
   prefix baked in C as the implementation language.

3. **The umbrella TU and the public header are renamed.** What
   was `chs_rt.c` (the umbrella) is now `oodar.c`. What was
   `chs_rt.h` (the public API) is now `oodar.h`.

### What consumers must change

If you include the public header:

```c
// v0.1.x
#include "chs_rt.h"

// v1.0.0
#include "oodar.h"
```

If you compile the umbrella TU directly:

```bash
# v0.1.x
gcc chs_rt.c -o my_program

# v1.0.0
gcc oodar.c -o my_program
```

If you include any per-subdir header from a subdir (e.g., the
weak-ref types in `mem/weak.h`):

```c
// v0.1.x (paths relative to repo root)
#include "mem/chs_rt_weak.h"

// v1.0.0 (no prefix; same-relative path)
#include "mem/weak.h"
```

If you include a per-subdir header from the SAME subdir
(e.g., `cap/cap.c` including the cap type defs):

```c
// v0.1.x
#include "chs_rt_caps.h"

// v1.0.0
#include "caps.h"
```

### What did NOT change

- **The set of exported `oo_*` symbols.** `oo_str_retain`,
  `oo_caps_seal`, `oo_arena_create`, `oo_gpu_hip_vec_add`, etc.
  are unchanged. A consumer linking against a prebuilt
  `oodar.o` or `liboodar.a` needs no change.

- **The semantics of every cap, alloc, crypto, PQC, GPU, FFI,
  net, os, actor, str, list, telemetry, math, meta, or hitl
  primitive.**

- **The `api_surface=53` invariant.** 53 .c files before; 53
  .c files after; just distributed across subdirs.

### Symbol renames in the public C ABI

A small set of `chs_cap_*` and `oo_chs_build` symbols were
renamed for consistency with the file/header prefix drop. The
direct renames are:

| v0.1.x | v1.0.0 |
|---|---|
| `chs_cap_init` | `oodar_cap_init` |
| `chs_cap_drop` | `oodar_cap_drop` |
| `chs_cap_is_sandboxed` | `oodar_cap_is_sandboxed` |
| `chs_cap_apply_seccomp_filter` | `oodar_cap_apply_seccomp_filter` |
| `oo_chs_build` | `oo_host_build` |
| `ooda_host_chs_build` | `ooda_host_build` |
| `CHS_CAP_NET`, `CHS_CAP_FS`, … | `OODAR_CAP_NET`, `OODAR_CAP_FS`, … |

These are the only public-symbol renames. The four
`oodar_cap_*` symbols are defined in `cap/cap.c`. `oo_host_build`
and `ooda_host_build` are in `os/host.c` (the latter is an
`extern` provided by the oodac build tool).

### Residuals (planned for follow-up)

- `pqc/dudect_c_native.c` and `gpu/oo_hip_so_smoke.c` are
  test utilities; they will move to `qa/` in a follow-up commit.
- The weak-ref mutators in `mem/weak.c` are not cap-gated.
  This is a deferred Floor break planned for v2.0.0.
