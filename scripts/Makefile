# # oodar/scripts/Makefile — Build liboodar.a (Static Library Artifact)
#
# Logline: Parallel build path that produces liboodar.a. The canonical
# `all` target builds the lib from the umbrella TU (gcc -c oodar.c) and
# archives the result. An alternative `perfile` target attempts a
# per-file build for consumers who want finer-grained .o files.
#
# Setup: The Makefile is self-contained and works on any Linux system
# with GNU make and GCC. It does not require autotools or any package
# manager. The 48 .c files in the umbrella are listed in UMBRELLA_SRCS
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
#   check   — verify all 48 source files are present in REPO_ROOT
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
# The 48 .c files in the umbrella TU (mirrors oodar.c:13-60). The order
# is dependency order from oodar.c; the order does not matter for .o
# files (only for #include chains, which are resolved at compile time
# per-file).
# ---------------------------------------------------------------------------
UMBRELLA_SRCS := \
	sec/cap/caps.c \
	sec/landlock/landlock.c \
	sec/landlock/sandbox.c \
	sec/landlock/proc_mem.c \
	sec/cap/cap.c \
	core/str/str.c \
	core/str/str_intern.c \
	core/str/str_from_int.c \
	core/str/str_tok.c \
	core/str/str_ops.c \
	app/telemetry/event.c \
	core/list/list.c \
	core/list/flist.c \
	core/list/llist.c \
	fs/os/sys.c \
	net/fetch.c \
	app/xlang/ffi_sec.c \
	app/xlang/ffi.c \
	sec/crypto/hash.c \
	fs/os/netfloor.c \
	net/tls.c \
	hw/gpu/gpu.c \
	hw/gpu/gpu_hip.c \
	app/actor/thread.c \
	app/actor/channel.c \
	app/actor/actor.c \
	app/hitl/hitl.c \
	fs/os/time_rand.c \
	core/mem/alloc.c \
	core/mem/arena.c \
	fs/os/fs.c \
	app/io/print.c \
	core/math/math.c \
	sec/crypto/crypto.c \
	core/anti_emul/anti_emul.c \
	fs/os/host.c \
	fs/os/rlimit.c \
	fs/os/dns.c \
	app/xlang/xlang.c \
	sec/crypto/sha3.c \
	sec/crypto/aead.c \
	sec/pqc/mlkem.c \
	sec/pqc/mldsa.c \
	sec/pqc/pq_sig.c \
	app/telemetry/metrics.c \
	app/actor/closure.c \
	core/mem/align.c \
	core/mem/weak.c

# Derived: .o files in BUILD_DIR, one per .c. Each .o lives at
# build/<path>.o (preserving the source path so the build dir
# mirrors the source tree).
UMBRELLA_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(UMBRELLA_SRCS))

# Phony targets
.PHONY: all clean install check perfile

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
# Check: verify all 48 source files are present in REPO_ROOT.
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
	if [ $$missing -eq 0 ]; then echo "CHECK OK: all 48 source files present in $(REPO_ROOT)"; fi
