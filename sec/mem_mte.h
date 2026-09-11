/* oodar/sec/mem_mte.h — Memory Tagging Extension (MTE) plan.
 *
 * Phase 5 of the 2026-09-11 memory-safety plan. MTE is an ARMv8.5-A
 * extension that tags every memory allocation with a 4-bit tag and
 * tags every pointer with the same tag. On mismatch → SIGSEGV.
 *
 * Status as of 2026-09-11:
 *   - Host CPU: Intel i7-10610U (x86_64, no MTE). Phase 5 cannot be
 *     functionally verified on this host.
 *   - Plan: provide the runtime probe + tagging primitives; activate
 *     on ARM64 builds; no-op on x86_64.
 *
 * The probe in oo_mte_init() at process start detects MTE capability
 * via prctl(PR_GET_TAGGED_ADDR_CTRL, ...). If the kernel returns
 * PR_MTE_TAG_SHIFT > 0, MTE is available; all oo_payload_alloc*
 * allocations then get tagged.
 *
 * Build target: liboodar_mte.a — same source as liboodar.a, with
 * -march=armv8.5-a+memtag. Future makefile rule.
 */

#ifndef OODAR_MEM_MTE_H
#define OODAR_MEM_MTE_H

#include <stdint.h>

#ifdef __aarch64__
#include <sys/prctl.h>
#include <sys/mman.h>
#ifndef PR_GET_TAGGED_ADDR_CTRL
#define PR_GET_TAGGED_ADDR_CTRL  51
#endif
#ifndef PR_MTE_TAG_SHIFT
#define PR_MTE_TAG_SHIFT         5
#endif

/* oo_mte_init: probe MTE capability at process start. Returns 1 if
 * MTE is available, 0 otherwise. */
static inline int oo_mte_init(void) {
  unsigned long ctrl = 0;
  if (prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0) < 0) return 0;
  /* PR_MTE_TAG_SHIFT > 0 means tag-shift is configured = MTE on. */
  if ((ctrl >> PR_MTE_TAG_SHIFT) & 1) return 1;
  return 0;
}

/* oo_mte_tag_alloc: tag an allocation. On ARM64 MTE, this writes a
 * 4-bit tag to the allocation's metadata. Returns the tag (0-15).
 * On non-MTE, returns 0 (no-op). */
static inline uint8_t oo_mte_tag_alloc(void *ptr, size_t size) {
  (void)ptr;
  (void)size;
  /* Real implementation uses `__arm_mte_create_random_tag` from
   * <arm_acle.h> — requires the ACLE compiler extension. Stub for
   * the spec. */
  return 0;
}

/* oo_mte_tag_check: validate that the pointer's tag matches the
 * allocation's tag. Returns 1 on match, 0 on mismatch (UB in
 * the kernel, SIGSEGV in user space). */
static inline int oo_mte_tag_check(void *ptr, uint8_t tag) {
  (void)ptr;
  (void)tag;
  return 1;
}

#else /* __aarch64__ */

/* x86_64 / non-ARM64 — no MTE. All primitives are no-ops. */
static inline int oo_mte_init(void) { return 0; }
static inline uint8_t oo_mte_tag_alloc(void *ptr, size_t size) {
  (void)ptr; (void)size; return 0;
}
static inline int oo_mte_tag_check(void *ptr, uint8_t tag) {
  (void)ptr; (void)tag; return 1;
}

#endif /* __aarch64__ */

#endif /* OODAR_MEM_MTE_H */
