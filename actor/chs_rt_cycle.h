#ifndef CHS_RT_CYCLE_H
#define CHS_RT_CYCLE_H

#include <stdint.h>
#include <stdlib.h>
#include "chs_rt_weak.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OO_COLOR_BLACK
#define OO_COLOR_BLACK   0
#define OO_COLOR_GRAY    1
#define OO_COLOR_WHITE   2
#define OO_COLOR_PURPLE  3
#endif

typedef void (*OoTraceVisitor)(void *child_payload, void *ctx);
typedef void (*OoTraceFn)(void *payload, OoTraceVisitor visitor, void *ctx);

#ifndef OO_HAVE_CYCLE_STATS
#define OO_HAVE_CYCLE_STATS
typedef struct OoCycleStats {
  uint64_t collections_run;
  uint64_t nodes_examined;
  uint64_t cycles_detected;
  uint64_t nodes_reclaimed;
  uint64_t bytes_reclaimed;
  uint32_t current_epoch;
} OoCycleStats;
#endif

/* Cycle collector subsystem initialization and teardown */
void oo_cycle_init(void);
void oo_cycle_shutdown(void);

/* Graph topology node & edge management */
int oo_cycle_register_node(void *payload, size_t size, void (*dtor)(void *));
void oo_cycle_unregister_node(void *payload);
int oo_cycle_add_edge(void *from_payload, void *to_payload);
int oo_cycle_remove_edge(void *from_payload, void *to_payload);
void oo_cycle_set_tracer(void *payload, OoTraceFn tracer);

/* Candidate buffering (possible roots) */
void oo_cycle_possible_root(void *payload);

/* Bacon-Rajan trial deletion collection pass */
OoCycleStats oo_cycle_collect(void);
OoCycleStats oo_cycle_get_stats(void);
uint32_t oo_cycle_current_epoch(void);
size_t oo_cycle_candidate_count(void);
size_t oo_cycle_tracked_nodes_count(void);
void oo_cycle_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* CHS_RT_CYCLE_H */
