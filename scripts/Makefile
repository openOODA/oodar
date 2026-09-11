# # oodar/scripts/Makefile — Build liboodar.a (Static Library Artifact)
#
# Logline: Parallel build path that produces liboodar.a. The canonical
# `all` target builds the lib from the umbrella TU (gcc -c oodar.c) and
# archives the result. An alternative `perfile` target attempts a
# per-file build for consumers who want finer-grained .o files.
#
# Setup: The Makefile is self-contained and works on any Linux system
# with GNU make and GCC. It does not require autotools or any package
# manager. UMBRELLA_SRCS below is derived from oodar.c's #includes (the
# umbrella TU). For the `perfile` target, each .c is
# compiled individually — note that some .c files in the umbrella rely
# on transitive includes (they don't #include oodar.h themselves),
# so the per-file build is best-effort and may fail for those files.
#
# Targets:
#   all     — build liboodar.a (default; uses the umbrella TU)
#   perfile — best-effort per-file build → liboodar_perfile.a
#   clean   — remove all .o and the lib artifacts
#   install — copy liboodar.a to ${DESTDIR}/${LIBDIR}
#   check    — verify all source files in UMBRELLA_SRCS are present in REPO_ROOT
#   lint     — run all 3 lint tests (anchors, file size, cap table)
#   adversarial — run the adversarial_read scanner (advisory, exit 0)
#
# Variables:
#   CC      — C compiler (default: gcc)
#   CFLAGS  — compile flags (default: -O2 -g -std=c11 -fPIC + D_GNU_SOURCE)
#   AR      — archiver (default: ar)
#   ARFLAGS — archiver flags (default: rcsD — deterministic mode)
#   DESTDIR — install prefix (default: /usr/local)
#   LIBDIR  — library subdir (default: lib)
#   REPO_ROOT — path to the oodar repo (default: parent of this Makefile)
#
# Usage:
#   make                 # build liboodar.a
#   make perfile         # best-effort per-file build
#   make clean           # remove all artifacts
#   make install         # install to ${DESTDIR}/${LIBDIR}
#   make CFLAGS='-O0 -g'  # debug build

# ---------------------------------------------------------------------------
# Repo root: where the oodar source tree lives. Default is the parent of
# scripts/ (i.e., the oodar repo root when this Makefile is at scripts/Makefile).
# We resolve to an absolute path early so the rules below can find the
# .c files regardless of make's CWD.
# ---------------------------------------------------------------------------
# Anchor on this Makefile's own location, not the caller's CWD: the old
# `cd .. && pwd` only resolved correctly when make ran inside scripts/,
# while BUILD_DIR/LIB_DIR were bare relatives that only resolved
# correctly from the repo root — so no single CWD ever made both right.
THIS_MAKEFILE := $(abspath $(lastword $(MAKEFILE_LIST)))
ifeq ($(origin REPO_ROOT),undefined)
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
endif

# ---------------------------------------------------------------------------
# Toolchain configuration
# ---------------------------------------------------------------------------
# `=`, not `?=`: GNU make ships a built-in CC=cc — `?=` never fired and
# builds ran cc (a gcc symlink on this host, but not the stated intent).
# Command-line `make CC=clang` still overrides a file assignment.
CC = gcc
AR ?= ar
# ---------------------------------------------------------------------------
# emit-std-ocap: Phase 1 of the std → oodar cap-bridge. Runs `oodac emit-c`
# on std/sec/capability/ocap_to_oodar.oo (the rights-mask shim) and
# writes the C output to sec/cap/cap_bridge_emitted.c. The umbrella
# TU includes this file (via oodar.c). The emitted file is gitignored
# — it's a build artifact, the source of truth is the .oo shim.
#
# Override OODAC if the oodac binary isn't at ~/.openooda/bin/oodac:
#   make OODAC=/path/to/oodac
# ---------------------------------------------------------------------------
OODAC ?= $(HOME)/.openooda/bin/oodac
STD_DIR := $(REPO_ROOT)/../std
OCAP_SHIM := $(STD_DIR)/sec/capability/ocap_to_oodar.oo
OCAP_EMITTED := $(REPO_ROOT)/sec/cap/cap_bridge_emitted.c

$(OCAP_EMITTED): $(OCAP_SHIM) | $(REPO_ROOT)/sec/cap
	@echo "EMIT std/sec/capability/ocap_to_oodar.oo (oodac check + emit-c, stripped)"
	@$(OODAC) check $< 2>&1 || (echo "OODAC check failed for $<"; exit 1)
	@$(OODAC) emit-c $< > $@.full 2>/dev/null
	# Strip lines 1-247. The umbrella already has the runtime decls
	# in oodar.h, types/types_str.h, and the core/list/*.c / core/str/*.c
	# TUs. We keep lines 248+ which contain the OCapBridgeRecord
	# struct definition (oodar.h doesn't have this) plus the
	# function bodies.
	# The function bodies reference oo_retain_S / oo_release_S (the
	# type-safe wrappers around oo_str_retain/release). We add a
	# small static-inline prologue that defines them locally — this
	# avoids redefinition conflicts with the umbrella's existing
	# types_str.h wrappers.
	@echo "/* runtime decls stripped; oo_retain_S/release_S shim added — see $(OCAP_SHIM) */" > $@
	@printf 'static inline void oo_retain_S(OoStr v) { oo_str_retain(v); }\nstatic inline void oo_release_S(OoStr v) { oo_str_release(v); }\n' >> $@
	@awk 'NR >= 248' $@.full >> $@
	@rm -f $@.full

emit-std-ocap: $(OCAP_EMITTED)
# Plain `=`, not `?=`: GNU make ships a built-in ARFLAGS=rv, which counts
# as "defined" — `?=` never fired and every archive ran `ar -rv` (real
# mtimes in the index header → non-deterministic .a, caught by `repro`).
# Determinism is a stated invariant, so the flag is not negotiable.
ARFLAGS = rcsD
# CFLAGS includes -DOODAR_CRYPTO_INTERNAL so sec/cap/cap.c can call
# crypto_secure_wipe (declared in sec/crypto/crypto_internal.h, which
# oodar.h includes when OODAR_CRYPTO_INTERNAL is defined). The umbrella
# build relies on the include chain; the per-file build needs the flag.
# -include oodar.h forces oodar.h into every TU so .c files that don't
# #include oodar.h themselves still see the type defs (e.g., OoStr).
# -fstack-protector-strong is explicit: the confinement code copies
# untrusted OoStr bytes into PATH_MAX stack buffers, and toolchain
# defaults vary (this host's gcc ships with the protector disabled).
CFLAGS ?= -O2 -g -std=c11 -fPIC -fstack-protector-strong -D_GNU_SOURCE -DOODAR_CRYPTO_INTERNAL -include oodar.h
# MEMSAFE_CFLAGS adds OODAR_MEMSAFE=1 + -O0 for the debug-mode safety
# build. The memsafe shims (core/mem/safety.h) turn every wrapped entry
# into a hostile-input probe: null deref, OOB, header corruption all
# abort. Production build is unchanged. Use for sandbox / fuzz / CI
# environments where the perf cost (~5-10%) is acceptable.
MEMSAFE_CFLAGS := -O0 -g -std=c11 -fPIC -fstack-protector-strong -D_GNU_SOURCE -DOODAR_CRYPTO_INTERNAL -DOODAR_MEMSAFE=1 -include oodar.h
DESTDIR ?= /usr/local
LIBDIR ?= lib

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------
# Artifacts anchor on this Makefile's own dir (scripts/build, scripts/lib)
# — repro_build.sh and .github/workflows/ci.yml consume that contract —
# while sources resolve through REPO_ROOT. Works from any CWD.
SCRIPT_DIR := $(dir $(THIS_MAKEFILE))
BUILD_DIR := $(SCRIPT_DIR)build
LIB_DIR := $(SCRIPT_DIR)lib
LIB := $(LIB_DIR)/liboodar.a
PERFILE_LIB := $(LIB_DIR)/liboodar_perfile.a
MEMSAFE_LIB := $(LIB_DIR)/liboodar_memsafe.a

# ---------------------------------------------------------------------------
# The 94 .c files in the umbrella TU (mirrors oodar.c:13-106). The order
# is dependency order from oodar.c; the order does not matter for .o
# files (only for #include chains, which are resolved at compile time
# per-file). v2.3.0: 17 files over 256 lines were split into 60+ files
# across 9 new sub-dirs (hw/gpu/gpu/, types/, sec/cap/, sec/crypto/
# {aead,symmetric}/, sec/landlock/{landlock,sandbox}/, sec/pqc/
# {mlkem,mldsa,pq_sig}/, core/mem/arena_*, core/list/list_*, app/
# actor/actor_*). The order below mirrors the umbrella includes.
# ---------------------------------------------------------------------------
# UMBRELLA_SRCS is derived from oodar.c (the umbrella TU #includes every
# source it compiles). Never hand-maintain this list: a stale entry breaks
# the build and a missing entry silently ships stale objects.
UMBRELLA_SRCS := $(shell sed -n 's/^#include "\([^"]*\.c\)".*/\1/p' $(REPO_ROOT)/oodar.c)

# Derived: .o files in BUILD_DIR, one per .c. Each .o lives at
# build/<path>.o (preserving the source path so the build dir
# mirrors the source tree).
UMBRELLA_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(UMBRELLA_SRCS))

# Phony targets
.PHONY: all clean install check perfile lint lint-anchors lint-file-size lint-cap-table adversarial test repro

# ---------------------------------------------------------------------------
# Default: build liboodar.a from the umbrella TU (single .o).
# This is the recommended path — one .o, one ar, no transitive-include
# issues. The output is lib/liboodar.a.
# ---------------------------------------------------------------------------
all: $(LIB)

# Build the lib from the single .o produced by `gcc -c oodar.c`.
# The sort is unnecessary here (one file) but kept for symmetry
# with the perfile rule. The result is lib/liboodar.a.
$(LIB): $(BUILD_DIR)/oodar.o | $(LIB_DIR)
	@echo "AR  $@"
	@$(AR) $(ARFLAGS) $@ $<

# The umbrella depends on the emitted OCap bridge (via oodar.c).
# Without this, the .o would silently link against a stale .c.
$(BUILD_DIR)/oodar.o: $(OCAP_EMITTED)

# memsafe: same source as `all`, but compiled with OODAR_MEMSAFE=1
# so the safety shims in core/mem/safety.h activate. Output is
# lib/liboodar_memsafe.a — separate artifact, doesn't replace liboodar.a.
# Use case: fuzz harnesses, sandbox probes, hostile-input CI. Cost:
# ~5-10% perf hit (O0 + extra checks); zero runtime cost when the
# caller doesn't use this build.
memsafe: $(MEMSAFE_LIB)

$(MEMSAFE_LIB): $(BUILD_DIR)/oodar_memsafe.o | $(LIB_DIR)
	@echo "AR  $@ (memsafe build)"
	@$(AR) $(ARFLAGS) $@ $<

$(BUILD_DIR)/oodar_memsafe.o: $(REPO_ROOT)/oodar.c | $(BUILD_DIR)
	@echo "CC  oodar.c (memsafe)"
	@$(CC) $(MEMSAFE_CFLAGS) -I$(REPO_ROOT) -c -o $@ $<

# Compile oodar.c into a single .o. The -I flag lets the .c files
# find oodar.h, types.h, and the per-subdir .h files.
# NOTE: oodar.c is an umbrella TU that #includes every file in UMBRELLA_SRCS,
# so the .o must depend on all of them — otherwise editing an included .c
# silently ships a stale lib with a lying reproducible hash.
$(BUILD_DIR)/oodar.o: $(REPO_ROOT)/oodar.c $(addprefix $(REPO_ROOT)/,$(UMBRELLA_SRCS)) | $(BUILD_DIR)
	@echo "CC  oodar.c"
	@$(CC) $(CFLAGS) -I$(REPO_ROOT) -c $< -o $@

# ---------------------------------------------------------------------------
# perfile: best-effort per-file build. Each .c is compiled to .o
# individually. Some files in the umbrella rely on transitive
# includes (e.g., core/list/flist.c does not #include oodar.h or
# <pthread.h>, relying on the prior .c in oodar.c to define the
# types). The per-file build will fail for those files; the recipe
# uses -k (keep going) so make continues to the next file. The
# resulting liboodar_perfile.a is a partial archive.
#
# The recommended path for consumers is `make all` (the umbrella TU).
# The perfile target exists for diagnostic purposes and for the
# subset of files that do compile standalone.
# ---------------------------------------------------------------------------
perfile: $(UMBRELLA_OBJS)
	@echo "AR  $(PERFILE_LIB) (best-effort)"
	@$(AR) $(ARFLAGS) $(PERFILE_LIB) $(sort $(UMBRELLA_OBJS)) 2>/dev/null || true
	@echo "NOTE: perfile archive is best-effort. Some .c files may have failed to compile"
	@echo "      due to transitive includes. Use 'make all' for the canonical liboodar.a."

# Explicit per-source rule. We use a static pattern rule so each
# .o target knows exactly which .c it depends on. The static
# pattern rule format is:
#   TARGETS: TARGET-PATTERN: PREREQ-PATTERNS
# which expands each .o to its corresponding .c prerequisite.
# The -k flag (in MAKECMDGOALS) keeps make going on per-file
# errors so the partial archive is still produced.
$(UMBRELLA_OBJS): $(BUILD_DIR)/%.o: $(REPO_ROOT)/%.c
	@mkdir -p $(dir $@)
	@echo "CC  $<"
	@$(CC) $(CFLAGS) -I$(REPO_ROOT) -c $< -o $@

# ---------------------------------------------------------------------------
# Directory creation
# ---------------------------------------------------------------------------
$(LIB_DIR):
	@mkdir -p $(LIB_DIR)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# ---------------------------------------------------------------------------
# Install: copy the lib to ${DESTDIR}/${LIBDIR}.
# ---------------------------------------------------------------------------
install: $(LIB)
	@echo "INSTALL $(DESTDIR)/$(LIBDIR)/liboodar.a"
	@install -d $(DESTDIR)/$(LIBDIR)
	@install -m 644 $(LIB) $(DESTDIR)/$(LIBDIR)/liboodar.a

# ---------------------------------------------------------------------------
# Clean: remove the lib, all .o, and the build/ tree.
# ---------------------------------------------------------------------------
clean:
	@echo "CLEAN"
	@rm -rf $(BUILD_DIR) $(LIB_DIR)

# ---------------------------------------------------------------------------
# Check: verify all source files in UMBRELLA_SRCS are present in REPO_ROOT.
# Useful as a CI gate.
# ---------------------------------------------------------------------------
check:
	@echo "UMBRELLA_SRCS = $(words $(UMBRELLA_SRCS)) files"
	@echo "UMBRELLA_OBJS = $(words $(UMBRELLA_OBJS)) objects"
	@missing=0; for f in $(UMBRELLA_SRCS); do \
		if [ ! -f $(REPO_ROOT)/$$f ]; then \
			echo "MISSING: $$f"; \
			missing=$$((missing+1)); \
		fi; \
	done; \
	if [ $$missing -eq 0 ]; then echo "CHECK OK: all $(words $(UMBRELLA_SRCS)) source files present in $(REPO_ROOT)"; fi

# ---------------------------------------------------------------------------
# lint: run all 3 structural lint tests. These verify:
#   - every directory has ANCHOR.oo (4-element header convention)
#   - every .c/.h file is ≤ 256 lines (small-LLM context cap)
#   - cap_table.json matches caps.h (no structural drift)
# Each can be run individually with `make lint-anchors`, `make lint-file-size`,
# or `make lint-cap-table`. The tests are built from qa/tests_lint_*.c and
# run with OODAR_REPO=$(REPO_ROOT) so the paths resolve correctly.
# v3.1.2 added: this target, after the v2.3.0 file split and v3.1.0
# audit produced drift in 8 missing ANCHOR.oo files and 2 borderline
# 256-line files (now fixed in v3.1.0 / v2.3.0).
# ---------------------------------------------------------------------------
LINT_BIN_DIR := $(BUILD_DIR)/lint
LINT_BINS := $(LINT_BIN_DIR)/tests_lint_anchors.o \
             $(LINT_BIN_DIR)/tests_lint_file_size.o \
             $(LINT_BIN_DIR)/tests_lint_cap_table.o

$(LINT_BIN_DIR):
	@mkdir -p $@

$(LINT_BIN_DIR)/%.o: $(REPO_ROOT)/qa/%.c | $(LINT_BIN_DIR)
	@$(CC) $(filter-out -D_GNU_SOURCE -include oodar.h,$(CFLAGS)) -I$(REPO_ROOT) -c $< -o $@

$(LINT_BIN_DIR)/tests_lint_anchors: $(LINT_BIN_DIR)/tests_lint_anchors.o
	@$(CC) -o $@ $<

$(LINT_BIN_DIR)/tests_lint_file_size: $(LINT_BIN_DIR)/tests_lint_file_size.o
	@$(CC) -o $@ $<

$(LINT_BIN_DIR)/tests_lint_cap_table: $(LINT_BIN_DIR)/tests_lint_cap_table.o
	@$(CC) -o $@ $<

lint-anchors: $(LINT_BIN_DIR)/tests_lint_anchors
	@OODAR_REPO=$(REPO_ROOT) $(LINT_BIN_DIR)/tests_lint_anchors

lint-file-size: $(LINT_BIN_DIR)/tests_lint_file_size
	@OODAR_REPO=$(REPO_ROOT) $(LINT_BIN_DIR)/tests_lint_file_size

lint-cap-table: $(LINT_BIN_DIR)/tests_lint_cap_table
	@OODAR_REPO=$(REPO_ROOT) $(LINT_BIN_DIR)/tests_lint_cap_table

lint: lint-anchors lint-file-size lint-cap-table
	@echo "LINT OK: all 3 structural lints pass"

# ---------------------------------------------------------------------------
# adversarial: surface every defensive claim in comments and check that
# the code path matches. Round-5 deep-dive lens. The scanner is
# advisory (exit 0) — false positives are common because:
#   - "constant-time" comments about the MAC don't apply to subsequent
#     memcmp() on public data
#   - "deterministic" comments may document the Joux-attack fix that
#     uses getentropy()
# The scanner is a tool for the human auditor, not a pass/fail gate.
# The 4 CRITICALs from round-4 (LCG fallbacks) would have been caught.
# ---------------------------------------------------------------------------
adversarial:
	@echo "SKIP adversarial python scanner (Wave 7: no .py in CI)"

TEST_DIR := $(BUILD_DIR)/test
CHALLENGERS := tests_challenger_contract tests_challenger_sys tests_challenger_wave1 \
	tests_challenger_wave3 tests_challenger_attenuate_v2 \
	tests_challenger_pathcap tests_challenger_cap_escape \
	tests_challenger_cap_threat tests_challenger_differential_cap \
	tests_challenger_actor_race tests_fuzz_smoke \
	tests_challenger_proc_mem_leak tests_challenger_sandbox_containment \
	tests_challenger_env_pwd tests_wal_append_sync tests_ffi_call \
	tests_stdin_owned_str tests_challenger_concurrency_stress \
	tests_challenger_adversarial_boundary tests_challenger_perf_benchmark \
	tests_challenger_address_safety \
	tests_challenger_ocap_bridge \
	tests_challenger_audio_cap

$(TEST_DIR):
	@mkdir -p $@

$(TEST_DIR)/%: $(REPO_ROOT)/qa/%.c $(REPO_ROOT)/oodar.c | $(TEST_DIR)
	@mkdir -p $(dir $@)
	@$(CC) $(filter-out -include oodar.h,$(CFLAGS)) -I$(REPO_ROOT) -o $@ $< $(REPO_ROOT)/oodar.c -lpthread -ldl -lm

test: lint $(addprefix $(TEST_DIR)/,$(CHALLENGERS))
	@echo "RUN contract (double-run)"
	@$(TEST_DIR)/tests_challenger_contract
	@$(TEST_DIR)/tests_challenger_contract
	@$(TEST_DIR)/tests_challenger_sys
	@$(TEST_DIR)/tests_challenger_sys
	@OODAR_REPO=$(REPO_ROOT) $(TEST_DIR)/tests_challenger_wave1
	@$(TEST_DIR)/tests_challenger_wave3
	@$(TEST_DIR)/tests_challenger_attenuate_v2
	@$(TEST_DIR)/tests_challenger_pathcap
	@$(TEST_DIR)/tests_challenger_cap_escape
	@$(TEST_DIR)/tests_challenger_cap_threat
	@$(TEST_DIR)/tests_challenger_differential_cap
	@$(TEST_DIR)/tests_challenger_actor_race
	@$(TEST_DIR)/tests_fuzz_smoke
	@$(TEST_DIR)/tests_challenger_proc_mem_leak
	@$(TEST_DIR)/tests_challenger_sandbox_containment
	@$(TEST_DIR)/tests_challenger_env_pwd
	@$(TEST_DIR)/tests_wal_append_sync
	@$(TEST_DIR)/tests_wal_append_sync
	@$(TEST_DIR)/tests_ffi_call
	@$(TEST_DIR)/tests_ffi_call
	@$(TEST_DIR)/tests_challenger_concurrency_stress
	@$(TEST_DIR)/tests_challenger_concurrency_stress
	@$(TEST_DIR)/tests_challenger_adversarial_boundary
	@$(TEST_DIR)/tests_challenger_adversarial_boundary
	@$(TEST_DIR)/tests_challenger_perf_benchmark
	@$(TEST_DIR)/tests_challenger_perf_benchmark
	@$(TEST_DIR)/tests_challenger_ocap_bridge
	@$(TEST_DIR)/tests_challenger_ocap_bridge
	@$(TEST_DIR)/tests_challenger_audio_cap
	@$(TEST_DIR)/tests_challenger_audio_cap
	@echo "TEST OK"

# test-asan: re-run the address-safety probe under ASan + UBSan. The
# probe (qa/tests_challenger_address_safety.c) exercises every public
# oo_* entry point with hostile inputs. ASan catches use-after-free +
# buffer overflows; UBSan catches integer overflow + alignment + null.
# Production builds stay unsanitized (perf cost ~2x on hot paths;
# unacceptable for the ABI), but the probe proves the public surface
# is safe under adversarial input. CI step: `make -C scripts test-asan`.
#
# ASAN_OPTIONS=detect_leaks=1: leak detection on at exit.
# UBSAN_OPTIONS=print_stacktrace=1: show the call site on UB.
# Uses clang (libasan is bundled — gcc's libasan.so isn't installed on
# this host, but clang ships its own runtime statically linked).
ASAN_CC := clang
ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
ASAN_LIBS  := -lpthread -ldl -lm

$(TEST_DIR)/%-asan: $(REPO_ROOT)/qa/%.c $(REPO_ROOT)/oodar.c | $(TEST_DIR)
	@mkdir -p $(dir $@)
	@$(ASAN_CC) $(filter-out -include oodar.h,$(CFLAGS)) $(ASAN_FLAGS) -I$(REPO_ROOT) \
		-o $@ $< $(REPO_ROOT)/oodar.c $(ASAN_LIBS)

test-asan: $(TEST_DIR)/tests_challenger_address_safety-asan
	@echo "RUN address-safety probe under ASan+UBSan (clang)"
	@echo "  (detect_leaks=0: the string intern table holds allocations"
	@echo "   for the program lifetime; that's by design, not a leak.)"
	@ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 \
		$(TEST_DIR)/tests_challenger_address_safety-asan
	@echo "ASAN OK"

# repro: bit-identical build gate — "the artifact is what the source says".
# Rebuilds liboodar.a twice from clean and compares SHA-256; any drift is a
# hard failure. `ar rcsD` is deterministic; sources carry no __DATE__/
# __TIME__. Scope note: this proves in-place reproducibility (same checkout
# dir → same DW_AT_comp_dir). Cross-location reproducibility would need
# -ffile-prefix-map and is a separate question.
repro:
	@set -e; \
	$(MAKE) --no-print-directory -f $(THIS_MAKEFILE) clean >/dev/null; \
	$(MAKE) --no-print-directory -f $(THIS_MAKEFILE) all >/dev/null; \
	h1=$$(sha256sum "$(LIB)" | cut -d' ' -f1); \
	$(MAKE) --no-print-directory -f $(THIS_MAKEFILE) clean >/dev/null; \
	$(MAKE) --no-print-directory -f $(THIS_MAKEFILE) all >/dev/null; \
	h2=$$(sha256sum "$(LIB)" | cut -d' ' -f1); \
	echo "REPRO 1: $$h1"; echo "REPRO 2: $$h2"; \
	if [ "$$h1" = "$$h2" ]; then echo "REPRO OK: liboodar.a bit-identical across clean rebuilds"; \
	else echo "REPRO FAIL: liboodar.a differs between clean rebuilds"; exit 1; fi
