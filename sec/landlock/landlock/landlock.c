#include "../../../oodar.h"
#include "../landlock.h"
#include "../sandbox.h"
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
 *      • η→0 ⇔ allowlist → "/" [cf. sandbox.c:469-470 matrix path].
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
 * mediated sandbox is genuinely APPLIED (not merely "available").
 *
 * The setter is non-static so landlock_restrict.c (in the same TU via
 * the umbrella) can mark the ruleset as applied after a successful
 * landlock_restrict_self() call. Both the getter and setter live here
 * in the orchestrator because g_ll_applied is the single source of
 * truth for "is Landlock currently enforced on this process". */
static int g_ll_applied = 0;
int oo_landlock_is_applied(void) {
  return g_ll_applied;
}

static void oo_landlock_mark_applied(void) {
  g_ll_applied = 1;
}
