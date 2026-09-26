# Changelog

All notable changes to the `oodar` runtime substrate are documented in this file.
Version format follows Semantic Versioning (`MAJOR.MINOR.PATCH`) per `rules.oot` §1.21.
Historical releases from v1.0.0 through v3.4.2 are archived in `docs/archive/changes_v1_v3.oot`.

## Unreleased

### Added
- `oo_sys_path_is_dir` (`fs/os/fs.c`): SysCap-gated directory probe returning 1
  for directories (final-component symlinks followed) and 0 otherwise. Lets the
  oodac sandbox engine fail closed on regular-file allowlist entries while raw
  `landlock_restrict` keeps deliberately accepting listed files. Declared in
  `oodar.h`, covered by the challenger contract table (68/68 fail-closed).
- List/string bounds contract probe (`qa/tests_challenger_list_str_bounds.c`): every core
  list/string op classified as sentinel (clamp/empty/-1, non-fatal) or fail-closed
  (`stderr` + `exit(1)`, 17 fork-probed OOB aborts across ilist/slist/flist, char_at,
  ll/lll/llll depths). Wired into `CHALLENGERS` + `make test` (double-run) + `double_run.sh`.
- Recorded fuzz seeds (`qa/fuzz_seeds.txt`): `scripts/double_run.sh` now runs every
  `*fuzz*` binary under each recorded seed, twice per seed.
- musl/Alpine portability: `execinfo.h` fallback stub in `core/blackbox/blackbox.c`
  (stack frame list renders empty where the header is absent) and missing
  `<unistd.h>` (musl declares `getentropy` there, not in `<sys/random.h>`) in
  `sec/pqc/pq_sig/pq_aead_seal.c`. Verified: all 7 archives build and the full
  `make test` suite passes on Alpine 3.24/musl (gcc 15.2.0) under CI-equivalent
  `OODA_*` env.

### Changed
- Fuzz corpus doubled: `qa/tests_fuzz_smoke.c` `N_ITER` 200 → 400 (seeded, deterministic
  given `argv[1]`; cap values remain `getentropy`-backed by design).

- Remove residual `emit-c` from default make pipeline.
- Default `make all` relies on committed C shim `sec/cap/cap_bridge_emitted.c`.
- Product compilation path remains C99 `gcc oodar.c` plus `oodac` LLVM IR.

## v4.10.0 — 2026-09-12

### Added
- SMT-LIB 2 formal capability specification (`sec/cap/formal_spec.smt2`) encoding properties P1–P4 in QF_BV.
- Structural validation probe (`qa/tests_smt_spec_roundtrip.c`) asserting machine-readable QF_BV encodings.

### Changed
- Refactored formal verification property mappings to align with unforgeable 64-bit capability tokens.

## v4.9.0 — 2026-09-12

### Added
- Compiler stack-canary coverage audit suite (`scripts/canary_audit.sh`).
- Verified `-fstack-protector-strong` emission across all umbrella compilation units.

### Security
- Verified stack integrity protection across all exported `oo_*` entrypoints.

## v4.8.0 — 2026-09-12

### Added
- ASan and UBSan test harness expansion in `tests_challenger_address_safety.c` (12 to 18 probes).
- Dual-check capability validation cross-checking bitmasks against OCap descriptors.

### Fixed
- Bounds checks in string and buffer slice operations under address sanitizer.

## v4.7.0 — 2026-09-12

### Added
- Challenger test suites for substrate symbol coverage (`tests_challenger_fs_dir.c`, `tests_challenger_bytes_str.c`).
- Coverage gap closure for low-level memory and string transformation primitives.

### Changed
- Re-aligned internal test runner harnesses with ASD-STE100 logging standards.

## v4.6.0 — 2026-09-12

### Added
- Audio hardware capture substrate integration (`hw/audio/oo_audio_capture.c`).
- Exported public symbols: `oo_audio_init`, `oo_audio_capture`, `oo_audio_release`.
- Incremented public API surface count to 111 C source compilation units.

### Security
- Gated audio hardware access behind explicit `AudioCap` token verification.

## v4.5.0 — 2026-09-11

### Added
- Comprehensive capability bridge dual-checking across all 22 runtime gates.
- Public symbols `oo_cap_check_with_ocap` and `oo_cap_ocap_rights_at`.

### Security
- Hardened all capability checks to require simultaneous bitmask match and OCap table authorization.

## v4.4.0 — 2026-09-11

### Added
- Filesystem capability bridge integration (`sec/cap/cap_ocap_bridge.c`).
- Dual-checked capability verification for filesystem read and write operations.

### Changed
- Standardized open and stat syscall wrappers to enforce path attenuation invariants.

## v4.3.0 — 2026-09-11

### Added
- Initial capability bridge connecting standard capability tokens with runtime security tables.
- Added header `sec/cap/cap_ocap_bridge.h` to umbrella header dependencies.

### Security
- Established fail-closed trap handling for invalid capability descriptors.

## v4.2.0 — 2026-09-11

### Added
- HIP GPU buffer dispatch support (`hw/gpu/gpu/gpu_hip_dispatch_buf.c`).
- Public buffer constructor `oo_float_buf_new` and vector operation `oo_gpu_hip_vec_add_buf`.

### Security
- Hardened memory safety across GPU memory copies and kernel dispatch buffers.

## v4.1.0 — 2026-09-11

### Added
- Shared memory IPC support in `fs/os/sys_shm.c` under `SysCap`.
- Epoll multiplexing routines in `fs/os/sys_epoll.c` under `SysCap`.
- Direct sandbox syscall wrappers in `sec/landlock/sandbox_syscalls.c`.

### Changed
- Optimized low-level event loop latency without breaking existing public symbol ABIs.

## v4.0.1 — 2026-09-06

### Fixed
- Verified zero critical defects across clean wave test suite execution.
- Deterministic archive creation verified with `ar rcsD` producing byte-identical `liboodar.a`.
- Clean stationary topology verified with zero unintended path drift.

## v4.0.0 — 2026-09-06

### Added
- Sovereign C99 runtime substrate baseline supporting self-hosted openOODA toolchains.
- Strict capability gating across all public mutators and process lifecycle primitives.
- Pure Landlock ABI v1-v3 sandboxing with ambient path suppression.

---

Historical release notes for v1.0.0 through v3.4.2 are archived in `docs/archive/changes_v1_v3.oot`.
