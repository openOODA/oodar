#ifndef OODAR_CLOSURE_H
#define OODAR_CLOSURE_H

#include "../../types.h"

#ifdef __cplusplus
extern "C" {
#endif

// OoClosure and OoFlatEnvHeader are defined in types.h (already included above).
// Re-declaring them here causes a redefinition error when closure.c is
// included into oodar.c (which already includes types.h).

OoClosure oo_closure_stack(void *fn, void *stack_env);
OoClosure oo_closure_heap_create(void *fn, size_t env_size, const void *env_data, void (*dtor)(void*));
void oo_closure_retain(OoClosure clo);
void oo_closure_release(OoClosure clo);
void *oo_closure_flat_alloc(size_t env_payload_size, void (*dtor)(void*));
void oo_closure_flat_retain(void *env);
void oo_closure_flat_release(void *env);

#ifdef __cplusplus
}
#endif

#endif /* OODAR_CLOSURE_H */
