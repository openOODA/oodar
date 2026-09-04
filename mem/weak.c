#define _GNU_SOURCE 1
#include "weak.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void oo_control_block_init(OoControlBlock *ctrl, void (*dtor)(void *)) {
  if (!ctrl) return;
  ctrl->strong_count = 1;
  ctrl->weak_count = 1;
  ctrl->flags = 0;
  ctrl->epoch = 0;
  ctrl->dtor = dtor;
}

OoControlBlock *oo_control_block_create(void *payload, void (*dtor)(void *)) {
  (void)payload;
  OoControlBlock *ctrl = (OoControlBlock *)calloc(1, sizeof(OoControlBlock));
  if (!ctrl) return NULL;
  oo_control_block_init(ctrl, dtor);
  return ctrl;
}

void oo_control_block_retain(OoControlBlock *ctrl) {
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

void oo_control_block_release(OoControlBlock *ctrl, void *payload) {
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

void oo_control_block_free(OoControlBlock *ctrl) {
  if (ctrl) {
    free(ctrl);
  }
}

OoWeakRef oo_weak_new(void) {
  OoWeakRef ref;
  ref.payload = NULL;
  ref.ctrl = NULL;
  return ref;
}

OoWeakRef oo_weak_create(void *payload, OoControlBlock *ctrl) {
  OoWeakRef ref = oo_weak_new();
  if (!ctrl || !payload) return ref;

  uint32_t sc = __atomic_load_n(&ctrl->strong_count, __ATOMIC_ACQUIRE);
  if (sc == 0) return ref;

  __atomic_fetch_add(&ctrl->weak_count, 1, __ATOMIC_ACQ_REL);
  ref.payload = payload;
  ref.ctrl = ctrl;
  return ref;
}

void *oo_weak_upgrade(OoWeakRef *ref) {
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

void *oo_weak_upgrade_val(OoWeakRef ref) {
  return oo_weak_upgrade(&ref);
}

void oo_weak_retain(OoWeakRef *ref) {
  if (!ref || !ref->ctrl) return;
  __atomic_fetch_add(&ref->ctrl->weak_count, 1, __ATOMIC_ACQ_REL);
}

void oo_weak_retain_val(OoWeakRef ref) {
  oo_weak_retain(&ref);
}

void oo_weak_release(OoWeakRef *ref) {
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

void oo_weak_release_val(OoWeakRef ref) {
  oo_weak_release(&ref);
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
