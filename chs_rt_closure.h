#ifndef CHS_RT_CLOSURE_H
#define CHS_RT_CLOSURE_H

#include "chs_rt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// OoClosure and OoFlatEnvHeader are defined in chs_rt_types.h (already included above).
// Re-declaring them here causes a redefinition error when chs_rt_closure.c is
// included into chs_rt.c (which already includes chs_rt_types.h).

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

#endif /* CHS_RT_CLOSURE_H */
