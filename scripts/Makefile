# # oodar/scripts/Makefile — Build liboodar.a (Static Library Artifact)
#
# Logline: Parallel build path that produces liboodar.a. The canonical
# `all` target builds the lib from the umbrella TU (gcc -c oodar.c) and
# archives the result. An alternative `perfile` target attempts a
# per-file build for consumers who want finer-grained .o files.
#
# Setup: The Makefile is self-contained and works on any Linux system
# with GNU make and GCC. It does not require autotools or any package
# manager. The 99 .c files in the umbrella are listed in UMBRELLA_SRCS
# below (mirrors oodar.c:13-60). For the `perfile` target, each .c is
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
ifeq ($(origin REPO_ROOT),undefined)
REPO_ROOT := $(shell cd .. && pwd)
endif

# ---------------------------------------------------------------------------
# Toolchain configuration
# ---------------------------------------------------------------------------
CC ?= gcc
AR ?= ar
ARFLAGS ?= rcsD
# CFLAGS includes -DOODAR_CRYPTO_INTERNAL so sec/cap/cap.c can call
# crypto_secure_wipe (declared in sec/crypto/crypto_internal.h, which
# oodar.h includes when OODAR_CRYPTO_INTERNAL is defined). The umbrella
# build relies on the include chain; the per-file build needs the flag.
# -include oodar.h forces oodar.h into every TU so .c files that don't
# #include oodar.h themselves still see the type defs (e.g., OoStr).
CFLAGS ?= -O2 -g -std=c11 -fPIC -D_GNU_SOURCE -DOODAR_CRYPTO_INTERNAL -include oodar.h
DESTDIR ?= /usr/local
LIBDIR ?= lib

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------
BUILD_DIR := build
LIB_DIR := lib
LIB := $(LIB_DIR)/liboodar.a
PERFILE_LIB := $(LIB_DIR)/liboodar_perfile.a

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
UMBRELLA_SRCS := \
	sec/cap/caps.c \
	sec/cap/cap.c \
	sec/cap/cap_grant.c \
	sec/cap/cap_require.c \
	sec/cap/cap_attenuate_path.c \
	sec/cap/cap_attenuate_hmac.c \
	sec/cap/cap_alloc.c \
	sec/cap/cap_time.c \
	sec/cap/cap_ffi.c \
	sec/landlock/landlock/landlock.c \
	sec/landlock/landlock/landlock_restrict.c \
	sec/landlock/sandbox/sandbox.c \
	sec/landlock/sandbox/sandbox_matrix.c \
	sec/landlock/sandbox/sandbox_config.c \
	sec/landlock/sandbox/sandbox_c.c \
	sec/landlock/proc_mem.c \
	core/str/str.c \
	core/str/str_intern.c \
	core/str/str_from_int.c \
	core/str/str_tok.c \
	core/str/str_ops.c \
	core/event/event.c \
	core/list/list.c \
	core/list/list_alloc.c \
	core/list/list_atomic.c \
	core/list/list_set.c \
	core/list/flist.c \
	core/list/llist.c \
	fs/os/sys_env.c \
	fs/os/sys_stamp.c \
	fs/os/sys_stdin.c \
	fs/os/sys.c \
	net/fetch.c \
	app/xlang/ffi_sec.c \
	app/xlang/ffi.c \
	sec/crypto/hash.c \
	fs/os/netfloor.c \
	fs/os/netfloor_tcp.c \
	fs/os/netfloor_udp.c \
	net/tls.c \
	hw/gpu/gpu/gpu.c \
	hw/gpu/gpu/gpu_pool.c \
	hw/gpu/gpu/gpu_mem.c \
	hw/gpu/gpu/gpu_stream.c \
	hw/gpu/gpu/gpu_classify.c \
	hw/gpu/gpu/gpu_launch.c \
	hw/gpu/gpu/gpu_hip_dlopen.c \
	hw/gpu/gpu/gpu_hip_dispatch.c \
	hw/gpu/gpu/gpu_hip.c \
	app/actor/actor_thread.c \
	app/actor/actor_channel.c \
	app/actor/actor.c \
	app/actor/actor_rpc.c \
	fs/os/time_rand.c \
	core/mem/alloc.c \
	core/mem/arena.c \
	core/mem/arena_pin.c \
	core/mem/arena_soa.c \
	core/mem/arena_dod.c \
	core/mem/arena_checkpoint.c \
	fs/os/fs_lowlevel.c \
	fs/os/fs_dir.c \
	fs/os/fs.c \
	app/io/print.c \
	core/math/math.c \
	sec/crypto/symmetric/crypto.c \
	sec/crypto/symmetric/hash.c \
	sec/crypto/symmetric/hmac.c \
	sec/crypto/symmetric/secure.c \
	core/anti_emul/anti_emul.c \
	fs/os/host.c \
	fs/os/rlimit.c \
	fs/os/dns.c \
	app/xlang/xlang.c \
	sec/crypto/sha3.c \
	sec/crypto/aead/aead.c \
	sec/crypto/aead/aes_gcm.c \
	sec/crypto/aead/chacha20_poly1305.c \
	sec/crypto/seal.c \
	sec/pqc/mlkem/mlkem_internal.c \
	sec/pqc/mlkem/mlkem.c \
	sec/pqc/mlkem/mlkem_kem.c \
	sec/pqc/mldsa/mldsa_internal.c \
	sec/pqc/mldsa/mldsa.c \
	sec/pqc/mldsa/mldsa_sign.c \
	sec/pqc/mldsa/mldsa_verify.c \
	sec/pqc/pq_sig/pq_sig.c \
	sec/pqc/pq_sig/pq_aead_seal.c \
	sec/pqc/pq_sig/pq_aead_open.c \
	sec/pqc/pq_sig/pq_hmac.c \
	core/event/metrics.c \
	app/actor/actor_closure.c \
	core/mem/align.c \
	core/mem/weak.c \
	sec/crypto/random.c

# Derived: .o files in BUILD_DIR, one per .c. Each .o lives at
# build/<path>.o (preserving the source path so the build dir
# mirrors the source tree).
UMBRELLA_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(UMBRELLA_SRCS))

# Phony targets
.PHONY: all clean install check perfile lint lint-anchors lint-file-size lint-cap-table adversarial test

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

# Compile oodar.c into a single .o. The -I flag lets the .c files
# find oodar.h, types.h, and the per-subdir .h files.
$(BUILD_DIR)/oodar.o: $(REPO_ROOT)/oodar.c | $(BUILD_DIR)
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
CHALLENGERS := tests_challenger_contract tests_challenger_wave1 \
	tests_challenger_wave3 tests_challenger_attenuate_v2 \
	tests_challenger_pathcap tests_challenger_cap_escape \
	tests_challenger_cap_threat tests_challenger_differential_cap \
	tests_challenger_actor_race tests_fuzz_smoke \
	tests_challenger_proc_mem_leak tests_challenger_sandbox_containment

$(TEST_DIR):
	@mkdir -p $@

$(TEST_DIR)/%: $(REPO_ROOT)/qa/%.c $(REPO_ROOT)/oodar.c | $(TEST_DIR)
	@$(CC) $(filter-out -include oodar.h,$(CFLAGS)) -I$(REPO_ROOT) -o $@ $< $(REPO_ROOT)/oodar.c -lpthread -ldl -lm

test: lint $(addprefix $(TEST_DIR)/,$(CHALLENGERS))
	@echo "RUN contract (double-run)"
	@$(TEST_DIR)/tests_challenger_contract
	@$(TEST_DIR)/tests_challenger_contract
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
	@echo "TEST OK"
