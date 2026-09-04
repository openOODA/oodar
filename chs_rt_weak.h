#ifndef CHS_RT_WEAK_H
#define CHS_RT_WEAK_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OO_FLAG_STATIC
#define OO_FLAG_STATIC    (1u << 0)
#endif
#ifndef OO_FLAG_PURPLE
#define OO_FLAG_PURPLE    (1u << 1)
#endif
#ifndef OO_FLAG_GRAY
#define OO_FLAG_GRAY      (1u << 2)
#endif
#ifndef OO_FLAG_WHITE
#define OO_FLAG_WHITE     (1u << 3)
#endif
#ifndef OO_FLAG_BLACK
#define OO_FLAG_BLACK     (1u << 4)
#endif
#ifndef OO_FLAG_CYCLE
#define OO_FLAG_CYCLE     (1u << 5)
#endif
#ifndef OO_FLAG_BUFFERED
#define OO_FLAG_BUFFERED  (1u << 6)
#endif

#ifndef OO_HAVE_CONTROL_BLOCK
#define OO_HAVE_CONTROL_BLOCK
typedef struct OoControlBlock {
  uint32_t strong_count;        /* Strong owners (payload live while > 0) */
  uint32_t weak_count;          /* Weak handles + 1 implicit strong hold */
  uint32_t flags;               /* OO_FLAG_STATIC, OO_FLAG_PURPLE, etc. */
  uint32_t epoch;               /* Allocation / GC collection epoch */
  void (*dtor)(void *payload);  /* Monomorphized destructor function pointer */
} OoControlBlock;

typedef struct OoWeakRef {
  void *payload;                /* Pointer to target data */
  OoControlBlock *ctrl;         /* Associated ARC control block */
} OoWeakRef;

typedef OoWeakRef OoWeak;
#endif

/* Control block lifecycle */
OoControlBlock *oo_control_block_create(void *payload, void (*dtor)(void *));
void oo_control_block_init(OoControlBlock *ctrl, void (*dtor)(void *));
void oo_control_block_retain(OoControlBlock *ctrl);
void oo_control_block_release(OoControlBlock *ctrl, void *payload);
void oo_control_block_free(OoControlBlock *ctrl);

/* Weak reference handle lifecycle */
OoWeakRef oo_weak_create(void *payload, OoControlBlock *ctrl);
OoWeakRef oo_weak_new(void);
void *oo_weak_upgrade(OoWeakRef *ref);
void *oo_weak_upgrade_val(OoWeakRef ref);
void oo_weak_retain(OoWeakRef *ref);
void oo_weak_release(OoWeakRef *ref);
void oo_weak_retain_val(OoWeakRef ref);
void oo_weak_release_val(OoWeakRef ref);
int oo_weak_is_alive(OoWeakRef ref);
int oo_weak_expired(OoWeakRef ref);
uint32_t oo_weak_strong_count(OoWeakRef ref);
uint32_t oo_weak_weak_count(OoWeakRef ref);

#ifdef __cplusplus
}
#endif

#endif /* CHS_RT_WEAK_H */
