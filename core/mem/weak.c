#define _GNU_SOURCE 1
#include "weak.h"
#include "../../oodar.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void oo_control_block_init(long long cap, OoControlBlock *ctrl, void (*dtor)(void *)) {
  oo_cap_require_alloc(cap, "control_block_init");
  if (!ctrl) return;
  ctrl->strong_count = 1;
  ctrl->weak_count = 1;
  ctrl->flags = 0;
  ctrl->epoch = 0;
  ctrl->dtor = dtor;
}

OoControlBlock *oo_control_block_create(long long cap, void *payload, void (*dtor)(void *)) {
  oo_cap_require_alloc(cap, "control_block_create");
  (void)payload;
  OoControlBlock *ctrl = (OoControlBlock *)calloc(1, sizeof(OoControlBlock));
  if (!ctrl) return NULL;
  oo_control_block_init(cap, ctrl, dtor);
  return ctrl;
}

void oo_control_block_retain(long long cap, OoControlBlock *ctrl) {
  oo_cap_require_alloc(cap, "control_block_retain");
  if (!ctrl) return;
  uint32_t sc = __atomic_load_n(&ctrl->strong_count, __ATOMIC_ACQUIRE);
  uint32_t fl = __atomic_load_n(&ctrl->flags, __ATOMIC_ACQUIRE);
  if (sc == 0 || sc == UINT32_MAX || (fl & OO_FLAG_STATIC) || fl == 0xFFFFFFFFu) {
    return;
  }
  while (sc > 0 && sc < UINT32_MAX) {
    if (__atomic_compare_exchange_n(&ctrl->strong_count, &sc, sc + 1, 1,
                                    __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
      return;
    }
    sc = __atomic_load_n(&ctrl->strong_count, __ATOMIC_RELAXED);
    fl = __atomic_load_n(&ctrl->flags, __ATOMIC_RELAXED);
    if (sc == 0 || sc == UINT32_MAX || (fl & OO_FLAG_STATIC) || fl == 0xFFFFFFFFu) {
      return;
    }
  }
}

void oo_control_block_release(long long cap, OoControlBlock *ctrl, void *payload) {
  oo_cap_require_alloc(cap, "control_block_release");
  if (!ctrl) return;
  uint32_t fl = __atomic_load_n(&ctrl->flags, __ATOMIC_ACQUIRE);
  if ((fl & OO_FLAG_STATIC) || fl == 0xFFFFFFFFu) return;

  uint32_t prev_sc = __atomic_fetch_sub(&ctrl->strong_count, 1, __ATOMIC_ACQ_REL);
  if (prev_sc == 1) {
    /* Strong refcount reached zero -> invoke destructor */
    if (ctrl->dtor != NULL) {
      ctrl->dtor(payload);
    }
    /* Release the implicit weak reference held on behalf of strong owners */
    uint32_t prev_wc = __atomic_fetch_sub(&ctrl->weak_count, 1, __ATOMIC_ACQ_REL);
    if (prev_wc == 1) {
      /* No weak references exist either -> free control block */
      __atomic_store_n(&ctrl->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
      free(ctrl);
    }
  }
}

void oo_control_block_free(long long cap, OoControlBlock *ctrl) {
  oo_cap_require_alloc(cap, "control_block_free");
  if (ctrl) {
    free(ctrl);
  }
}

OoWeakRef oo_weak_new(long long cap) {
  oo_cap_require_alloc(cap, "weak_new");
  OoWeakRef ref;
  ref.payload = NULL;
  ref.ctrl = NULL;
  return ref;
}

OoWeakRef oo_weak_create(long long cap, void *payload, OoControlBlock *ctrl) {
  oo_cap_require_alloc(cap, "weak_create");
  OoWeakRef ref = oo_weak_new(cap);
  if (!ctrl || !payload) return ref;

  uint32_t sc = __atomic_load_n(&ctrl->strong_count, __ATOMIC_ACQUIRE);
  if (sc == 0) return ref;

  __atomic_fetch_add(&ctrl->weak_count, 1, __ATOMIC_ACQ_REL);
  ref.payload = payload;
  ref.ctrl = ctrl;
  return ref;
}

void *oo_weak_upgrade(long long cap, OoWeakRef *ref) {
  oo_cap_require_alloc(cap, "weak_upgrade");
  if (!ref || !ref->ctrl || !ref->payload) return NULL;
  OoControlBlock *ctrl = ref->ctrl;

  uint32_t sc = __atomic_load_n(&ctrl->strong_count, __ATOMIC_ACQUIRE);
  uint32_t fl = __atomic_load_n(&ctrl->flags, __ATOMIC_ACQUIRE);
  if (sc == 0 || sc == UINT32_MAX || fl == 0xFFFFFFFFu) {
    return NULL;
  }
  while (sc > 0 && sc < UINT32_MAX) {
    if (__atomic_compare_exchange_n(&ctrl->strong_count, &sc, sc + 1, 1,
                                    __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
      return ref->payload;
    }
    sc = __atomic_load_n(&ctrl->strong_count, __ATOMIC_RELAXED);
    fl = __atomic_load_n(&ctrl->flags, __ATOMIC_RELAXED);
    if (sc == 0 || sc == UINT32_MAX || fl == 0xFFFFFFFFu) {
      return NULL;
    }
  }
  return NULL;
}

void *oo_weak_upgrade_val(long long cap, OoWeakRef ref) {
  return oo_weak_upgrade(cap, &ref);
}

void oo_weak_retain(long long cap, OoWeakRef *ref) {
  oo_cap_require_alloc(cap, "weak_retain");
  if (!ref || !ref->ctrl) return;
  __atomic_fetch_add(&ref->ctrl->weak_count, 1, __ATOMIC_ACQ_REL);
}

void oo_weak_retain_val(long long cap, OoWeakRef ref) {
  oo_weak_retain(cap, &ref);
}

void oo_weak_release(long long cap, OoWeakRef *ref) {
  oo_cap_require_alloc(cap, "weak_release");
  if (!ref || !ref->ctrl) return;
  OoControlBlock *ctrl = ref->ctrl;
  ref->payload = NULL;
  ref->ctrl = NULL;

  uint32_t prev_wc = __atomic_fetch_sub(&ctrl->weak_count, 1, __ATOMIC_ACQ_REL);
  if (prev_wc == 1) {
    uint32_t sc = __atomic_load_n(&ctrl->strong_count, __ATOMIC_ACQUIRE);
    if (sc == 0) {
      __atomic_store_n(&ctrl->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
      free(ctrl);
    }
  }
}

void oo_weak_release_val(long long cap, OoWeakRef ref) {
  oo_weak_release(cap, &ref);
}

int oo_weak_is_alive(OoWeakRef ref) {
  if (!ref.ctrl) return 0;
  return __atomic_load_n(&ref.ctrl->strong_count, __ATOMIC_ACQUIRE) > 0;
}

int oo_weak_expired(OoWeakRef ref) {
  return !oo_weak_is_alive(ref);
}

uint32_t oo_weak_strong_count(OoWeakRef ref) {
  if (!ref.ctrl) return 0;
  return __atomic_load_n(&ref.ctrl->strong_count, __ATOMIC_ACQUIRE);
}

uint32_t oo_weak_weak_count(OoWeakRef ref) {
  if (!ref.ctrl) return 0;
  uint32_t wc = __atomic_load_n(&ref.ctrl->weak_count, __ATOMIC_ACQUIRE);
  uint32_t sc = __atomic_load_n(&ref.ctrl->strong_count, __ATOMIC_ACQUIRE);
  return (sc > 0 && wc > 0) ? (wc - 1) : wc;
}
