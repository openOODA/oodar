#ifndef OODAR_TYPES_ACTOR_H
#define OODAR_TYPES_ACTOR_H
/* v2.3.0 split: closure primitive (OoClosure + OoFlatEnvHeader) and its
 * function decls. The implementation lives in app/actor/actor_closure.c.
 * OoClosure is a stack-or-heap callable: stack closures borrow env
 * (dtor=NULL), heap closures own env via OoFlatEnvHeader refcount. */
#include <stdint.h>
#include <stddef.h>

typedef struct OoClosure {
    void *fn;
    void *env;
    void (*dtor)(void*);
} OoClosure;

typedef struct OoFlatEnvHeader {
    uint32_t ref_count;
    uint32_t flags;
    void (*dtor)(void*);
} OoFlatEnvHeader;

OoClosure oo_closure_stack(void *fn, void *stack_env);
OoClosure oo_closure_heap_create(void *fn, size_t env_size, const void *env_data, void (*dtor)(void*));
void oo_closure_retain(OoClosure clo);
void oo_closure_release(OoClosure clo);
void *oo_closure_flat_alloc(size_t env_payload_size, void (*dtor)(void*));
void oo_closure_flat_retain(void *env);
void oo_closure_flat_release(void *env);

#endif
