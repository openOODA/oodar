/* sec/seccomp_audit_arch.h — build-arch → AUDIT_ARCH_* mapping shared by
 * the seccomp BPF filters (sec/cap/cap.c capf_install and
 * sec/landlock/sandbox/sandbox_config.c sand_install_seccomp).
 *
 * Compat-ABI escape: a filter that matches only native __NR_* values is
 * bypassed by 32-bit compat syscalls (int 0x80) or the x32 ABI, which
 * carry different syscall numbers. Filters must assert seccomp_data.arch
 * before the nr load. When the build arch has no AUDIT_ARCH_* constant,
 * OO_AUDIT_ARCH stays undefined and the filters must refuse to install —
 * a filter that cannot assert arch is a silent bypass surface, so we
 * fail closed rather than ship it.
 *
 * Consumers must #include <linux/audit.h> first (inside their
 * __linux__-gated region). */
#ifndef OO_SECCOMP_AUDIT_ARCH_H
#define OO_SECCOMP_AUDIT_ARCH_H
#if defined(__x86_64__)
# define OO_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define OO_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__riscv) && defined(__riscv_xlen) && __riscv_xlen == 64
# define OO_AUDIT_ARCH AUDIT_ARCH_RISCV64
#elif defined(__i386__)
# define OO_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__arm__) && defined(__ARM_EABI__)
# define OO_AUDIT_ARCH AUDIT_ARCH_ARM
#endif
#endif
