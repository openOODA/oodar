#include "chs_rt.h"
#include "chs_rt_closure.h"

OoClosure oo_closure_stack(void *fn, void *stack_env) {
    OoClosure clo;
    clo.fn = fn;
    clo.env = stack_env;
    clo.dtor = NULL;
    return clo;
}

void *oo_closure_flat_alloc(size_t env_payload_size, void (*dtor)(void*)) {
    size_t hdr_sz = sizeof(OoFlatEnvHeader);
    void *payload = oo_payload_alloc(hdr_sz, env_payload_size);
    if (!payload) abort();
    
    OoFlatEnvHeader *hdr = ((OoFlatEnvHeader *)payload) - 1;
    hdr->ref_count = 1;
    hdr->flags = 0;
    hdr->dtor = dtor;
    return payload;
}

OoClosure oo_closure_heap_create(void *fn, size_t env_size, const void *env_data, void (*dtor)(void*)) {
    OoClosure clo;
    clo.fn = fn;
    clo.dtor = dtor;
    if (env_size > 0 && env_data != NULL) {
        clo.env = oo_closure_flat_alloc(env_size, dtor);
        memcpy(clo.env, env_data, env_size);
    } else {
        clo.env = NULL;
    }
    return clo;
}

void oo_closure_flat_retain(void *env) {
    if (!env) return;
    OoFlatEnvHeader *hdr = ((OoFlatEnvHeader *)env) - 1;
    uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);
    if (fl & OO_FLAG_STATIC) return;
    uint32_t rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_ACQUIRE);
    while (rc > 0 && rc < UINT32_MAX) {
        if (__atomic_compare_exchange_n(&hdr->ref_count, &rc, rc + 1, 1, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return;
        rc = __atomic_load_n(&hdr->ref_count, __ATOMIC_RELAXED);
        fl = __atomic_load_n(&hdr->flags, __ATOMIC_RELAXED);
        if (rc == 0 || rc == UINT32_MAX || (fl & OO_FLAG_STATIC)) return;
    }
}

void oo_closure_flat_release(void *env) {
    if (!env) return;
    OoFlatEnvHeader *hdr = ((OoFlatEnvHeader *)env) - 1;
    uint32_t fl = __atomic_load_n(&hdr->flags, __ATOMIC_ACQUIRE);
    if (fl & OO_FLAG_STATIC) return;
    
    uint32_t prev = __atomic_fetch_sub(&hdr->ref_count, 1, __ATOMIC_ACQ_REL);
    if (prev == 1) {
        if (hdr->dtor) {
            hdr->dtor(env);
        }
        __atomic_store_n(&hdr->flags, 0xFFFFFFFFu, __ATOMIC_RELEASE);
        oo_payload_free(env);
    }
}

void oo_closure_retain(OoClosure clo) {
    if (!clo.env || !clo.dtor) return;
    oo_closure_flat_retain(clo.env);
}

void oo_closure_release(OoClosure clo) {
    if (!clo.env || !clo.dtor) return;
    oo_closure_flat_release(clo.env);
}
