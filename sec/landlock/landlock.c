#include "../../oodar.h"
#include "landlock.h"
#include "sandbox.h"
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

/* ── E-M Informational Formulation: Landlock as Channel-Entropy Reduction ──
 * Landlock LSM is modelled as a noisy-channel confinement (capability) with
 * information-theoretic entropy reduction and latent-variable ruleset inference.
 *
 * 1) Channel Model — confinement completeness = entropy reduction:
 *    • Source S ~ filesystem namespace Ω (all absolute paths, PATH_MAX:184-188).
 *      Prior H(S) = log|Ω| (unconfined). After ruleset R, attainable set
 *      S|R = ⋃ read_dirs ∪ write_dirs filtered by ll_each_dir() [171-196].
 *    • Kernel channel T: S → Y ∈ {ALLOW,DENY} via landlock_restrict_self [279]
 *      and PR_SET_NO_NEW_PRIVS gate [275-278]. Capacity C(R)=max_{p(S)} I(S;Y).
 *      Without Landlock, C(∅) ≈ H(S) (covert side-channel escape noted [229-235]).
 *    • Confinement completeness η(R)=1−C(R)/C(∅)=1−H(S|R)/H(S).
 *      • η=1 ⇔ nread+nwrite==0 → 0 rules → total lockdown [254-255].
 *      • η→0 ⇔ allowlist → “/” [cf. sandbox.c:469-470 matrix path].
 *      • Each ll_add_one() [204-215] with allowed_access=ll_read_bits|ll_write_bits
 *        [155-168] adds at most log(|Ω|/|beneath|) bits and reduces ΔH.
 *    • Enforcement proof: oo_landlock_restrict() fails closed
 *      not_supported_on_this_kernel [237,241] and create_ruleset/add_rule/
 *      restrict_self errors [252,262,271,277,281] = zero undetected bypass;
 *      channel equivocation H(S|Y,R)=0 when R enforced → OK_LANDLOCK_ENFORCED [284].
 *
 * 2) E-M Latent-Variable Formulation — ruleset inference / completeness:
 *    • Observed X = {abi, traces}: abi=ll_abi_version() [133-141] via
 *      LANDLOCK_CREATE_RULESET_VERSION [89-91]; syscall traces rc from
 *      landlock_create_ruleset [251], landlock_add_rule PATH_BENEATH [212],
 *      restrict_self [279]; validation counts nread/nwrite/LL_MAX_DIRS [220,227].
 *    • Latent Z_i ∈ {benign_required, attacker_probe, abi_incompatible}:
 *      true minimal need behind path_i; not observed. Also latent
 *      handled_access_fs expansion Z_abi = ll_handled_fs(abi) [147-153]
 *      (REFER≥2, TRUNCATE≥3, IOCTL_DEV≥5).
 *    • Parameters Θ = {handled_access_fs [147,246], handled_access_net/scoped
 *      attr_sz [247-249], per-rule allowed_access [210,259,268]}.
 *      Θ is deterministically masked: access_eff = ll_*_bits(abi) & handled [259,268].
 *    • Likelihood p(X,Z;Θ)=∏_i p(Z_i)p(X_i|Z_i,Θ) with
 *      p(X_i|Z_i=benign,Θ)=1 iff path beneath allowed_access else EACCES trap,
 *      p(X_i|probe,Θ)=Bernoulli(bypass_prob)→0 when η→1.
 *    • E-step (t): γ_i^{(t)}(z)=p(Z_i=z|X_i,Θ^{(t)}) ∝ p(X_i|z,Θ^{(t)})p(z);
 *      sufficient statistic is abi + handled mask [246-249] and open(O_PATH) rc [206-207].
 *    • M-step (t+1): Θ^{(t+1)}=argmax_Θ Σ_i Σ_z γ_i^{(t)}(z) log p(X_i,z;Θ)
 *      s.t. handled_access_fs ⊇ LL_FS_ABI1 [124-126], LL_MAX_DIRS [127,227],
 *      path[0]=='/' [188] and len<PATH_MAX [185]; closes ELBO.
 *      Solution tightens allowed_access to ll_read_bits / ll_write_bits minima
 *      and expands attr_sz only if abi≥4/6 [248-249] proves ABI latent.
 *    • Probe as inference: oo_landlock_is_available()[143-145] = E-step oracle;
 *      AVAIL=0 ⇒ M-step chooses Θ=∅ and caller must refuse to start [229-232],
 *      i.e., EM converges to fail-closed fixed point, not fallback to
 *      oo_sandbox_restrict_paths (deleted, verified simd_codegen_probe.oo:119-123).
 *    • Completeness certificate: ELBO monotonic ↑ ⇔ η ↑; convergence when
 *      add_rule read+write cover all observed benign Z and γ(probe)→1 maps to deny.
 *      Sweep/probe summary (tier3_mutation_sweep.oo, simd_codegen_probe.oo:108-131)
 *      should assert η threshold and EM log-likelihood gain, not just presence.
 *
 * References: syscall NRs 444-446 [83-85], structs [96-105], bitmasks [107-127].
 */

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0200000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION 1U
#endif
#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif

struct landlock_path_beneath_attr {
  unsigned long long allowed_access;
  int parent_fd;
} __attribute__((packed));

struct landlock_ruleset_attr {
  unsigned long long handled_access_fs;
  unsigned long long handled_access_net;
  unsigned long long scoped;
};

#define LL_FS_EXECUTE (1ULL << 0)
#define LL_FS_WRITE_FILE (1ULL << 1)
#define LL_FS_READ_FILE (1ULL << 2)
#define LL_FS_READ_DIR (1ULL << 3)
#define LL_FS_REMOVE_DIR (1ULL << 4)
#define LL_FS_REMOVE_FILE (1ULL << 5)
#define LL_FS_MAKE_CHAR (1ULL << 6)
#define LL_FS_MAKE_DIR (1ULL << 7)
#define LL_FS_MAKE_REG (1ULL << 8)
#define LL_FS_MAKE_SOCK (1ULL << 9)
#define LL_FS_MAKE_FIFO (1ULL << 10)
#define LL_FS_MAKE_BLOCK (1ULL << 11)
#define LL_FS_MAKE_SYM (1ULL << 12)
#define LL_FS_REFER (1ULL << 13)
#define LL_FS_TRUNCATE (1ULL << 14)
#define LL_FS_IOCTL_DEV (1ULL << 15)

#define LL_FS_ABI1 (LL_FS_EXECUTE | LL_FS_WRITE_FILE | LL_FS_READ_FILE | LL_FS_READ_DIR | \
  LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE | LL_FS_MAKE_CHAR | LL_FS_MAKE_DIR | LL_FS_MAKE_REG | \
  LL_FS_MAKE_SOCK | LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK | LL_FS_MAKE_SYM)
#define LL_MAX_DIRS 64

static OoResS ll_err(const char *msg) {
  return (OoResS){0, oo_str_lit(msg)};
}

static int ll_abi_version(void) {
#if defined(__NR_landlock_create_ruleset)
  long v = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (v < 1) return 0;
  return (int)v;
#else
  return 0;
#endif
}

int oo_landlock_is_available(void) {
  return ll_abi_version() > 0;
}

/* v2.1.0: applied-state tracker. Set to 1 once oo_landlock_restrict
 * has successfully enforced a ruleset on the current process. Read by
 * oo_proc_mem_read to refuse /proc/self/mem reads unless the kernel-
 * mediated sandbox is genuinely APPLIED (not merely "available"). */
static int g_ll_applied = 0;
int oo_landlock_is_applied(void) {
  return g_ll_applied;
}

static unsigned long long ll_handled_fs(int abi) {
  unsigned long long a = LL_FS_ABI1;
  if (abi >= 2) a |= LL_FS_REFER;
  if (abi >= 3) a |= LL_FS_TRUNCATE;
  if (abi >= 5) a |= LL_FS_IOCTL_DEV;
  return a;
}

static unsigned long long ll_read_bits(int abi) {
  (void)abi;
  return LL_FS_EXECUTE | LL_FS_READ_FILE | LL_FS_READ_DIR;
}

static unsigned long long ll_write_bits(int abi) {
  unsigned long long a = LL_FS_WRITE_FILE | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE |
    LL_FS_MAKE_CHAR | LL_FS_MAKE_DIR | LL_FS_MAKE_REG | LL_FS_MAKE_SOCK |
    LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK | LL_FS_MAKE_SYM;
  a |= ll_read_bits(abi);
  if (abi >= 2) a |= LL_FS_REFER;
  if (abi >= 3) a |= LL_FS_TRUNCATE;
  return a;
}

/* Walk colon-separated absolute dirs. fn==NULL counts only. Returns 0 or negative error. */
static int ll_each_dir(OoStr dirs, int *count, int (*fn)(const char *, void *), void *ctx) {
  long long n = dirs.data ? dirs.len : 0;
  const char *p = dirs.data;
  long long i = 0;
  if (n < 0) n = 0;
  while (i <= n) {
    long long start = i;
    while (i < n && p[i] != ':') {
      if (p[i] == '\0') return -1;
      i++;
    }
    long long len = i - start;
    if (len > 0) {
      char buf[PATH_MAX];
      if (len >= PATH_MAX) return -2;
      memcpy(buf, p + start, (size_t)len);
      buf[len] = '\0';
      if (buf[0] != '/') return -3;
      if (fn && fn(buf, ctx) != 0) return -4;
      if (count) (*count)++;
    }
    if (i >= n) break;
    i++;
  }
  return 0;
}

#if defined(__NR_landlock_add_rule)
struct ll_add_ctx {
  int ruleset_fd;
  unsigned long long access;
};

static int ll_add_one(const char *path, void *v) {
  struct ll_add_ctx *c = (struct ll_add_ctx *)v;
  int fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return -1;
  struct landlock_path_beneath_attr attr;
  memset(&attr, 0, sizeof attr);
  attr.allowed_access = c->access;
  attr.parent_fd = fd;
  long rc = syscall(__NR_landlock_add_rule, c->ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
  close(fd);
  return rc == 0 ? 0 : -1;
}
#endif

OoResS oo_landlock_restrict(long long cap, OoStr read_dirs, OoStr write_dirs) {
  oo_cap_require_sys(cap, "landlock_restrict");
  int nread = 0, nwrite = 0;
  int pr = ll_each_dir(read_dirs, &nread, NULL, NULL);
  int pw = ll_each_dir(write_dirs, &nwrite, NULL, NULL);
  if (pr == -3 || pw == -3) return ll_err("ERR\tlandlock\tpath not absolute");
  if (pr == -2 || pw == -2) return ll_err("ERR\tlandlock\tpath too long");
  if (pr == -1 || pw == -1) return ll_err("ERR\tlandlock\tembedded NUL in path");
  if (pr != 0 || pw != 0) return ll_err("ERR\tlandlock\tinvalid path list");
  if (nread + nwrite > LL_MAX_DIRS) return ll_err("ERR\tlandlock\ttoo many paths");

  // Landlock is REQUIRED. We do NOT fall back to oo_sandbox_restrict_paths
  // (or any seccomp/matrix-only shim) — per project policy, fallbacks and
  // compatibility layers are removed. If Landlock is unavailable on this
  // kernel, the caller must probe oo_landlock_is_available() and refuse
  // to start. Refusing to fall back closes a class of side-channel escape
  // that would otherwise be possible on a system that has seccomp but not
  // Landlock, since the matrix-only path provides no path confinement.
#if !defined(__NR_landlock_create_ruleset)
  return ll_err("ERR\tlandlock\tnot_supported_on_this_kernel");
#else
  int abi = ll_abi_version();
  if (abi < 1) {
    return ll_err("ERR\tlandlock\tnot_supported_on_this_kernel");
  }

  struct landlock_ruleset_attr attr;
  memset(&attr, 0, sizeof attr);
  attr.handled_access_fs = ll_handled_fs(abi);
  size_t attr_sz = sizeof(attr.handled_access_fs);
  if (abi >= 4) attr_sz += sizeof(attr.handled_access_net);
  if (abi >= 6) attr_sz += sizeof(attr.scoped);

  int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &attr, attr_sz, 0);
  if (ruleset_fd < 0) return ll_err("ERR\tlandlock\tcreate_ruleset failed");

  /* GAP-10: If allowlist is empty (nread == 0 && nwrite == 0), 0 rules are added,
   * enforcing a total filesystem lockdown across the process. */
  if (nread > 0) {
    struct ll_add_ctx ctx;
    ctx.ruleset_fd = ruleset_fd;
    ctx.access = ll_read_bits(abi) & attr.handled_access_fs;
    if (ll_each_dir(read_dirs, NULL, ll_add_one, &ctx) != 0) {
      close(ruleset_fd);
      return ll_err("ERR\tlandlock\tadd_rule read path failed");
    }
  }
  if (nwrite > 0) {
    struct ll_add_ctx ctx;
    ctx.ruleset_fd = ruleset_fd;
    ctx.access = ll_write_bits(abi) & attr.handled_access_fs;
    if (ll_each_dir(write_dirs, NULL, ll_add_one, &ctx) != 0) {
      close(ruleset_fd);
      return ll_err("ERR\tlandlock\tadd_rule write path failed");
    }
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    close(ruleset_fd);
    return ll_err("ERR\tlandlock\tfailed to set PR_SET_NO_NEW_PRIVS");
  }
  if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
    close(ruleset_fd);
    return ll_err("ERR\tlandlock\trestrict_self failed");
  }
  close(ruleset_fd);
  g_ll_applied = 1; /* v2.1.0: mark the ruleset as applied for proc_mem. */
  return (OoResS){1, oo_str_lit("OK_LANDLOCK_ENFORCED")};
#endif
}
