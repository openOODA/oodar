#ifndef OODAR_TYPES_ACTOR_H
#define OODAR_TYPES_ACTOR_H
/* v2.3.0 split + v3.1.0 audit fix: actor-primitive types — OoClosure,
 * OoFlatEnvHeader, and OoChannel — live here. The implementations are
 * in app/actor/actor_closure.c and app/actor/actor_channel.c. v3.1.0
 * moved OoChannel from app/actor/actor_channel.c (file-local) into
 * this header for the "one type family per header" convention. */
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

/* OoChannel was previously file-local to app/actor/actor_channel.c.
 * v3.1.0 moves it here so downstream code (and tests) can refer to
 * the type without re-declaring it. The full struct definition stays
 * in actor_channel.c (where the 16-slot table, mutex, and condvar
 * live); this header provides a forward declaration only. */
typedef struct OoChannel OoChannel;

OoClosure oo_closure_stack(void *fn, void *stack_env);
OoClosure oo_closure_heap_create(void *fn, size_t env_size, const void *env_data, void (*dtor)(void*));
void oo_closure_retain(OoClosure clo);
void oo_closure_release(OoClosure clo);
void *oo_closure_flat_alloc(size_t env_payload_size, void (*dtor)(void*));
void oo_closure_flat_retain(void *env);
void oo_closure_flat_release(void *env);

#endif
