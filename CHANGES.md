# Changelog

## v2.1.0 — Patch (zero-trust audit pass 2: 6 CRITICAL fixes + 11 HIGH/MEDIUM cleanups)

Per RULES.oot §1.21, v2.1.0 is a PATCH bump. No ABI change — every
public function signature is unchanged. This release is a security
hardening + dead-code cleanup driven by a zero-trust re-audit of v2.0.0
(5 parallel subagents, one per lens: structural, REDTEAM, power-law
+ systems, OCap, Blue Ocean).

### CRITICAL — security

1. **oo_write_int / oo_read_int: bounds check inverted (was:
   arbitrary R/W into the process).** v2.0.0 had the bound check
   inside an `&&` with the magic-number check, so a foreign pointer
   (no oodar magic) silently bypassed the bound check. An attacker
   with any AllocCap could pass an arbitrary address and oodar
   would happily write to it. v2.1.0 inverts: the magic MUST match
   (else exit with "foreign pointer refused") AND the offset+sizeof
   must fit (else exit with "out of bounds"). Both checks are now
   mandatory, in series. See core/mem/alloc.c.

2. **oo_proc_mem_read: now requires Landlock APPLIED, not just
   available.** Previously the gate was `oo_landlock_is_available()`
   (which is true on any modern Linux kernel regardless of whether
   the process ever called `oo_sandbox_apply()`). An attacker could
   read /proc/self/mem — and the cap token lives in /proc/self/mem,
   so they could forge the cap. v2.1.0 adds `oo_landlock_is_applied()`
   (set to 1 only after a successful `oo_landlock_restrict()`) and
   requires both checks. The proc_mem reader now refuses unless the
   kernel-mediated sandbox is genuinely in force. See
   sec/landlock/landlock.c (new g_ll_applied state + accessor) and
   sec/landlock/proc_mem.c.

3. **mldsa.c: silent rejection-sampling bug fixed.** The
   `expand_a_inner` helper had `while (ctr < 256) { ...; break; }` —
   the `break` made the loop a single iteration, so any rejection
   failure left the polynomial coefficient uninitialised. FIPS 204
   §4.1.1 requires deterministic re-sampling. v2.1.0 keeps drawing
   from SHAKE until the budget is exhausted (with a fail-closed
   `exit(1)` on exhaustion — never a silent uninitialised output).
   See sec/pqc/mldsa.c.

4. **fs_file_size removed (declared but never implemented).** It was
   a v2.0.0 stale declaration. The canonical entry point is
   `oo_file_size`. See oodar.h.

5. **5 dead cap tokens removed (AUDIT, HITL, SYNC, MEM, HTTP).**
   These were declared in caps.h (v2.0.0) but either:
   - Had no grant/require function (AUDIT, HITL — declared but never
     defined), or
   - Were granted but never required by any function (SYNC, MEM, HTTP).
   The bit positions are reserved (no re-use) so a future re-
   introduction can use a different bit. See sec/cap/caps.h and
   sec/cap/caps.c (g_tok_* state + make_cap_tok site).

6. **6 dead cap-function declarations removed.** oo_cap_grant_audit,
   oo_cap_grant_hitl, oo_cap_grant_sync, oo_cap_grant_mem,
   oo_cap_grant_http, and the matching oo_cap_require_* for each.
   Plus oo_cap_require_http (was defined but never used). Plus
   `cap_attenuate` / `cap_attenuate_ok` (no oo_ prefix, declared but
   never defined; the canonical oo_cap_attenuate / oo_cap_attenuate_ok
   remain).

### HIGH — security & OCap

7. **oo_cap_rpc_send / oo_cap_rpc_recv: ThreadCap → SignCap.** Cap-rpc
   is a sign-style operation (HMAC over the payload), not a thread
   spawn. Previously the cap required was ThreadCap, which was too
   coarse: every actor recipient would have needed ThreadCap just to
   verify a signed message. v2.1.0 requires SignCap. See
   app/actor/actor.c.

8. **Integer overflow fix: oo_arena_alloc (core/mem/arena.c).** Was
   `if (a->off + (size_t)n > a->cap)` — can wrap if `a->off + n`
   overflows size_t. Now: `if ((size_t)n > a->cap - a->off)` — the
   subtraction is exact on a valid arena.

9. **Integer overflow fix: oo_dod_layout (core/mem/arena.c).** Was
   `return n * 8;` — wraps for n > LLONG_MAX/8. Now: saturate to 0
   on overflow.

### MEDIUM — cleanup

10. **3 dead event subscriptions removed** in app/telemetry/metrics.c:
    `cap.seal`, `fs.read`, `fs.write` were subscribed but no
    `oo_event_emit` call site emits them. The corresponding
    on_cap_seal / on_fs_read / on_fs_write handlers are also gone.
    The live subscriptions are cap.attenuate (emitted in caps.c:154),
    pq.sign, pq.verify, aead.seal, aead.open (emitted in
    sec/pqc/pq_sig.c).

11. **Test utilities moved from production tree to qa/.** Both
    `hw/gpu/oo_hip_so_smoke.c` (the HIP/.so smoke test) and
    `sec/pqc/dudect_c_native.c` (the dudect constant-time
    statistical test) are now `qa/oo_hip_so_smoke.c` and
    `qa/dudect_c_native.c`. They were never in the umbrella TU
    (the test util exclusion was already in place) but their
    location implied they were production code. They are test
    utilities and now sit with the test infrastructure.

12. **ANCHOR.oo fixes:**
    - `app/actor/ANCHOR.oo` was claiming `thread.h` (the
      OoThreadSlot type) — but no `thread.h` exists. The OoThreadSlot
      type is defined inline in `thread.c`. Fixed.
    - `app/actor/ANCHOR.oo` had 5 beats; the new layout has 4
      (thread + actor + channel + closure — no separate cycle beat
      since v2.0.0 killed it).
    - `sec/cap/ANCHOR.oo` was claiming "14 unforgeable capability
      tokens". The actual count after the dead-cap removal is 25
      (14 NORTHSTAR core + 11 future-state for not-yet-wired
      hardware caps). The ANCHOR.oo now states the full breakdown.

### What did NOT change

- Every public function signature. The v2.0.0 ABI is preserved.
- The 6 per-domain subdir layout (core, sec, fs, net, hw, app).
- The cap system architecture (still 30 cap bits, but 5 are
  reserved/dead-now; 25 have working grant/require).
- The set of files in the umbrella (still 48 .c files; api_surface=52
  unchanged because the test utilities are still in the repo, just
  in qa/).
- The CHANGELOG itself — every prior migration table still applies.

### Residuals (planned for v3.0.0 Floor break)

The next Floor break will add caps to the last 4 cap-free public
mutators (the rule "no cap-free public symbols"):

- `oo_read_stdin` / `oo_read_stdin_chunk` (fs/os/sys.c) — no cap
- `oo_file_stamp` (fs/os/sys.c) — no cap
- `oo_metrics_incr` / `oo_metrics_get` / `oo_metrics_reset` /
  `oo_metrics_export` / `oo_metrics_self_test` — no cap (potential
  side channel via counter)
- `oo_je_emit` / the `oo_je_*` arm-file mechanism — no cap
  (potential exfiltration via stderr-arming)

Adding a cap to any of these changes the public function signature
→ Floor break. See CHANGES.md "v3.0.0 plan" (next pass).

## v2.0.0 — Floor break (audit: cap-gating, dead-code kill, build fix)

Per RULES.oot §1.21, v2.0.0 is a MAJOR (Floor) bump. The super-check
audit (zero-trust pass over every file) found 1 broken build, 3
production .c files missing from the umbrella, 4 cap-gating gaps in
the public API, and 520 lines of dead code. v2.0.0 closes all of them.

### What changed (ABI break — consumers must rebuild)

1. **Cap-gating gaps closed (6 public symbols now require caps).**
   These were the last 4 cap-gating gaps flagged in v1.0.1's
   CHANGES.md "residuals" section:

   | v1.0.1 | v2.0.0 |
   |---|---|
   | `long long oo_alloc(long long size);` | `long long oo_alloc(long long cap, long long size);` |
   | `void oo_free(long long ptr);` | `void oo_free(long long cap, long long ptr);` |
   | `void (oo_write_int)(long long ptr, ...);` | `void (oo_write_int)(long long cap, long long ptr, ...);` |
   | `long long (oo_read_int)(long long ptr, ...);` | `long long (oo_read_int)(long long cap, long long ptr, ...);` |
   | `long long oo_checkpoint(long long v);` | `long long oo_checkpoint(long long cap, long long v);` |
   | `long long oo_rollback(void);` | `long long oo_rollback(long long cap);` |

   All 6 now call `oo_cap_require_alloc` (or `oo_cap_require_arena`
   for checkpoint/rollback). Consumers must thread a capability
   token through every alloc/free/checkpoint/rollback call. The
   `oo_write_int` / `oo_read_int` variadic macros in `oodar.h`
   are updated to match the new signatures.

2. **Weak-ref mutators now require AllocCap (12 public symbols).**
   All `oo_weak_*` and `oo_control_block_*` mutators gain a
   `long long cap` first arg and call `oo_cap_require_alloc`.
   Pure queries (`oo_weak_is_alive`, `oo_weak_expired`,
   `oo_weak_strong_count`, `oo_weak_weak_count`) remain cap-free.
   Oodac-emitted `Weak[T]` code that previously called
   `oo_retain_OoWeakRef` / `oo_release_OoWeakRef` (the in-`types.h`
   macros that operate on the `OoWeakRef` payload) is unaffected
   — those macros do not call the mutators.

   | v1.0.1 | v2.0.0 |
   |---|---|
   | `oo_control_block_create(payload, dtor)` | `oo_control_block_create(cap, payload, dtor)` |
   | `oo_control_block_init(ctrl, dtor)` | `oo_control_block_init(cap, ctrl, dtor)` |
   | `oo_control_block_retain(ctrl)` | `oo_control_block_retain(cap, ctrl)` |
   | `oo_control_block_release(ctrl, payload)` | `oo_control_block_release(cap, ctrl, payload)` |
   | `oo_control_block_free(ctrl)` | `oo_control_block_free(cap, ctrl)` |
   | `oo_weak_create(payload, ctrl)` | `oo_weak_create(cap, payload, ctrl)` |
   | `oo_weak_new()` | `oo_weak_new(cap)` |
   | `oo_weak_upgrade(ref)` | `oo_weak_upgrade(cap, ref)` |
   | `oo_weak_upgrade_val(ref)` | `oo_weak_upgrade_val(cap, ref)` |
   | `oo_weak_retain(ref)` | `oo_weak_retain(cap, ref)` |
   | `oo_weak_retain_val(ref)` | `oo_weak_retain_val(cap, ref)` |
   | `oo_weak_release(ref)` | `oo_weak_release(cap, ref)` |
   | `oo_weak_release_val(ref)` | `oo_weak_release_val(cap, ref)` |

3. **22 `crypto_*_internal` symbols moved out of the public header.**
   They were always named `_internal` but were still in `oodar.h`.
   v2.0.0 moves them to a private header `sec/crypto/crypto_internal.h`.
   External consumers who were calling them directly must now use
   the cap-gated public wrappers (`oo_seal`, `oo_open`, `oo_sign`,
   `oo_verify`) or define `OODAR_CRYPTO_INTERNAL` before
   `#include <oodar.h>` to opt back in (deliberate compat escape
   hatch, not a guarantee). The umbrella build always sees them
   via the `crypto_internal.h` include from `aead.c`, `crypto.c`,
   `caps.c`, `actor.c`, etc.

4. **app/actor/cycle.{c,h} removed (520 + 60 = 580 lines killed).**
   The Bacon-Rajan trial-deletion cycle detector had zero callers
   in oodar, oodac, or any other openOODA repo. Per the
   "old code is killed not deprecated" rule, it is removed entirely.
   `app/actor/ANCHOR.oo` and the parent `app/ANCHOR.oo` are
   updated to drop the cycle beat.

5. **Build paths fixed (was: `gcc oodar.c` would not compile).**
   v1.0.1's `oodar.h` had `#include "../types.h"` (path doesn't
   resolve from the root) and `#include "caps.h"` (file is at
   `sec/cap/caps.h`). v2.0.0 fixes to `#include "types.h"` and
   `#include "sec/cap/caps.h"`. Same fix for `sec/cap/caps.h`
   (`sandbox.h` → `../landlock/sandbox.h`) and `hw/gpu/gpu.h`
   (`caps.h` → `../../sec/cap/caps.h`). The `oodar.c` comment
   that showed `../../../oodar.h` (3-level path) is fixed to
   the actual 2-level path used by every leaf file.

6. **3 production .c files were not in the umbrella build.**
   `core/mem/weak.c` and `sec/landlock/proc_mem.c` are now
   included in `oodar.c` (their public APIs `OoWeakRef` /
   `oo_proc_mem_read` were declared in `oodar.h` but the
   definitions were not compiled — silent linker errors for
   any consumer). The umbrella also reorders `app/telemetry/event.c`
   to be included before `sec/crypto/crypto.c`, since crypto.c
   calls `oo_event_emit`.

7. **Misc cleanups:**
   - Removed duplicate `str_split` / `str_trim` declarations in
     `oodar.h` (declared twice each at lines 199/222 and 200/223).
   - `api_surface` 53 → 52 (cycle.c removed).
   - `sec/ANCHOR.oo` updated to reflect the actual 30 cap tokens
     (14 NORTHSTAR core + 16 future-state extensions), not just
     the 14 the v1.0.0 text claimed.
   - `core/ANCHOR.oo` corrected: types.h is at the **repo root**,
     not at `core/`.

### What consumers must change

You must rebuild. Concretely:

- Any caller of `oo_alloc` / `oo_free` / `oo_write_int` /
  `oo_read_int` / `oo_checkpoint` / `oo_rollback` must now
  pass a capability token (e.g., `oo_cap_grant_alloc()`).
- Any caller of `oo_weak_*` / `oo_control_block_*` mutators
  must now pass `oo_cap_grant_alloc()`. The pure queries
  are unchanged.
- Any caller of `crypto_*_internal` from outside the umbrella
  must either switch to the public cap-gated wrapper, define
  `OODAR_CRYPTO_INTERNAL` to opt back in, or move the call
  into a file inside the oodar umbrella.
- Any caller of `app/actor/cycle_*` will now fail to link —
  the API is gone. (No callers found in any openOODA repo.)
- The build command is unchanged: `gcc oodar.c` still works
  and now actually produces an `.o`.

### What did NOT change

- The `oo_*` public symbol *set* (no symbols renamed; only
  signatures changed for the 18 listed above).
- `oodar.h` and `types.h` are still at the repo root.
- The 6 per-domain subdir layout (core, sec, fs, net, hw, app)
  from v1.0.1 is unchanged.
- The cap system itself (14 core + 16 extensions, all defined
  in `sec/cap/caps.h`).
- The set of exported cap-gated mutators from v1.0.1.

### Residuals (planned for follow-up)

- `sec/pqc/dudect_c_native.c` and `hw/gpu/oo_hip_so_smoke.c`
  are test utilities; they will move to `qa/` in a follow-up
  commit.
- `oo_res_eq_s` and 13 other public OCap-pure utility symbols
  (no cap arg, side-effect-free): no cap added since they
  don't touch any privileged state.

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
