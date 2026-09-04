#define _GNU_SOURCE 1
#include "chs_rt_cycle.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#define HASH_SIZE 4096

typedef struct OoCycleEdge {
  void *target;
  struct OoCycleEdge *next;
} OoCycleEdge;

typedef struct OoCycleNode {
  void *payload;
  size_t size;
  void (*dtor)(void *payload);
  OoTraceFn tracer;
  OoCycleEdge *edges;
  uint32_t color;
  int32_t trial_rc;
  int in_purple_buffer;
  int reclaimed;
  struct OoCycleNode *hash_next;
} OoCycleNode;

static OoCycleNode *g_node_buckets[HASH_SIZE];
static OoCycleNode **g_purple_candidates = NULL;
static size_t g_purple_count = 0;
static size_t g_purple_cap = 0;

static uint32_t g_gc_epoch = 0;
static OoCycleStats g_stats = {0, 0, 0, 0, 0, 0};
static pthread_mutex_t g_cycle_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_cycle_initialized = 0;

static size_t hash_ptr(const void *p) {
  uintptr_t v = (uintptr_t)p;
  v = (~v) + (v << 18);
  v = v ^ (v >> 31);
  v = v * 21;
  v = v ^ (v >> 11);
  v = v + (v << 6);
  v = v ^ (v >> 22);
  return (size_t)(v % HASH_SIZE);
}

static OoCycleNode *find_node_unlocked(const void *payload) {
  if (!payload) return NULL;
  size_t idx = hash_ptr(payload);
  OoCycleNode *cur = g_node_buckets[idx];
  while (cur) {
    if (cur->payload == payload) return cur;
    cur = cur->hash_next;
  }
  return NULL;
}

static int32_t compute_node_rc_unlocked(const OoCycleNode *node) {
  if (!node) return 0;
  int32_t rc = 0;
  for (size_t i = 0; i < HASH_SIZE; i++) {
    OoCycleNode *cur = g_node_buckets[i];
    while (cur) {
      if (!cur->reclaimed) {
        OoCycleEdge *e = cur->edges;
        while (e) {
          if (e->target == node->payload) rc++;
          e = e->next;
        }
      }
      cur = cur->hash_next;
    }
  }
  return rc;
}

void oo_cycle_init(void) {
  pthread_mutex_lock(&g_cycle_mutex);
  if (!g_cycle_initialized) {
    memset(g_node_buckets, 0, sizeof(g_node_buckets));
    g_purple_candidates = NULL;
    g_purple_count = 0;
    g_purple_cap = 0;
    g_gc_epoch = 0;
    memset(&g_stats, 0, sizeof(g_stats));
    g_cycle_initialized = 1;
  }
  pthread_mutex_unlock(&g_cycle_mutex);
}

void oo_cycle_shutdown(void) {
  pthread_mutex_lock(&g_cycle_mutex);
  for (size_t i = 0; i < HASH_SIZE; i++) {
    OoCycleNode *cur = g_node_buckets[i];
    while (cur) {
      OoCycleNode *next = cur->hash_next;
      OoCycleEdge *e = cur->edges;
      while (e) {
        OoCycleEdge *enext = e->next;
        free(e);
        e = enext;
      }
      free(cur);
      cur = next;
    }
    g_node_buckets[i] = NULL;
  }
  if (g_purple_candidates) {
    free(g_purple_candidates);
    g_purple_candidates = NULL;
  }
  g_purple_count = 0;
  g_purple_cap = 0;
  g_cycle_initialized = 0;
  pthread_mutex_unlock(&g_cycle_mutex);
}

int oo_cycle_register_node(void *payload, size_t size, void (*dtor)(void *)) {
  if (!payload) return 0;
  pthread_mutex_lock(&g_cycle_mutex);
  if (!g_cycle_initialized) {
    g_cycle_initialized = 1;
    memset(g_node_buckets, 0, sizeof(g_node_buckets));
  }
  if (find_node_unlocked(payload) != NULL) {
    pthread_mutex_unlock(&g_cycle_mutex);
    return 0;
  }
  OoCycleNode *n = (OoCycleNode *)calloc(1, sizeof(OoCycleNode));
  if (!n) {
    pthread_mutex_unlock(&g_cycle_mutex);
    return 0;
  }
  n->payload = payload;
  n->size = size;
  n->dtor = dtor;
  n->color = OO_COLOR_BLACK;
  n->trial_rc = 0;
  n->edges = NULL;
  n->tracer = NULL;
  n->in_purple_buffer = 0;
  n->reclaimed = 0;

  size_t idx = hash_ptr(payload);
  n->hash_next = g_node_buckets[idx];
  g_node_buckets[idx] = n;
  pthread_mutex_unlock(&g_cycle_mutex);
  return 1;
}

void oo_cycle_unregister_node(void *payload) {
  if (!payload) return;
  pthread_mutex_lock(&g_cycle_mutex);
  size_t idx = hash_ptr(payload);
  OoCycleNode **cur = &g_node_buckets[idx];
  while (*cur) {
    if ((*cur)->payload == payload) {
      OoCycleNode *victim = *cur;
      *cur = victim->hash_next;

      OoCycleEdge *e = victim->edges;
      while (e) {
        OoCycleEdge *next = e->next;
        free(e);
        e = next;
      }
      free(victim);
      break;
    }
    cur = &((*cur)->hash_next);
  }
  pthread_mutex_unlock(&g_cycle_mutex);
}

int oo_cycle_add_edge(void *from_payload, void *to_payload) {
  if (!from_payload || !to_payload) return 0;
  pthread_mutex_lock(&g_cycle_mutex);
  OoCycleNode *from = find_node_unlocked(from_payload);
  if (!from) {
    pthread_mutex_unlock(&g_cycle_mutex);
    return 0;
  }
  OoCycleEdge *e = from->edges;
  while (e) {
    if (e->target == to_payload) {
      pthread_mutex_unlock(&g_cycle_mutex);
      return 1;
    }
    e = e->next;
  }
  OoCycleEdge *ne = (OoCycleEdge *)malloc(sizeof(OoCycleEdge));
  if (!ne) {
    pthread_mutex_unlock(&g_cycle_mutex);
    return 0;
  }
  ne->target = to_payload;
  ne->next = from->edges;
  from->edges = ne;
  pthread_mutex_unlock(&g_cycle_mutex);
  return 1;
}

int oo_cycle_remove_edge(void *from_payload, void *to_payload) {
  if (!from_payload || !to_payload) return 0;
  pthread_mutex_lock(&g_cycle_mutex);
  OoCycleNode *from = find_node_unlocked(from_payload);
  if (!from) {
    pthread_mutex_unlock(&g_cycle_mutex);
    return 0;
  }
  OoCycleEdge **cur = &from->edges;
  int removed = 0;
  while (*cur) {
    if ((*cur)->target == to_payload) {
      OoCycleEdge *victim = *cur;
      *cur = victim->next;
      free(victim);
      removed = 1;
      break;
    }
    cur = &((*cur)->next);
  }
  pthread_mutex_unlock(&g_cycle_mutex);
  if (removed) {
    oo_cycle_possible_root(to_payload);
  }
  return removed;
}

void oo_cycle_set_tracer(void *payload, OoTraceFn tracer) {
  if (!payload) return;
  pthread_mutex_lock(&g_cycle_mutex);
  OoCycleNode *n = find_node_unlocked(payload);
  if (n) {
    n->tracer = tracer;
  }
  pthread_mutex_unlock(&g_cycle_mutex);
}

void oo_cycle_possible_root(void *payload) {
  if (!payload) return;
  pthread_mutex_lock(&g_cycle_mutex);
  OoCycleNode *n = find_node_unlocked(payload);
  if (n && n->color != OO_COLOR_PURPLE && !n->reclaimed) {
    n->color = OO_COLOR_PURPLE;
    if (!n->in_purple_buffer) {
      if (g_purple_count >= g_purple_cap) {
        size_t ncap = (g_purple_cap == 0) ? 64 : g_purple_cap * 2;
        OoCycleNode **nbuf = (OoCycleNode **)realloc(g_purple_candidates, ncap * sizeof(OoCycleNode *));
        if (nbuf) {
          g_purple_candidates = nbuf;
          g_purple_cap = ncap;
        }
      }
      if (g_purple_count < g_purple_cap) {
        g_purple_candidates[g_purple_count++] = n;
        n->in_purple_buffer = 1;
      }
    }
  }
  pthread_mutex_unlock(&g_cycle_mutex);
}

/* Phase 1: Mark Gray (Trial Deletion) */
static void mark_gray_node(OoCycleNode *n);

static void mark_gray_visitor(void *child_payload, void *ctx) {
  (void)ctx;
  OoCycleNode *child = find_node_unlocked(child_payload);
  if (child && !child->reclaimed) {
    child->trial_rc--;
    mark_gray_node(child);
  }
}

static void mark_gray_node(OoCycleNode *n) {
  if (!n || n->reclaimed) return;
  if (n->color != OO_COLOR_GRAY) {
    n->color = OO_COLOR_GRAY;
    OoCycleEdge *e = n->edges;
    while (e) {
      OoCycleNode *child = find_node_unlocked(e->target);
      if (child && !child->reclaimed) {
        child->trial_rc--;
        mark_gray_node(child);
      }
      e = e->next;
    }
    if (n->tracer) {
      n->tracer(n->payload, mark_gray_visitor, NULL);
    }
  }
}

/* Phase 2: Scan Roots (Scan & Restore) */
static void scan_black_node(OoCycleNode *n);

static void scan_black_visitor(void *child_payload, void *ctx) {
  (void)ctx;
  OoCycleNode *child = find_node_unlocked(child_payload);
  if (child && !child->reclaimed) {
    child->trial_rc++;
    if (child->color != OO_COLOR_BLACK) {
      scan_black_node(child);
    }
  }
}

static void scan_black_node(OoCycleNode *n) {
  if (!n || n->reclaimed) return;
  n->color = OO_COLOR_BLACK;
  OoCycleEdge *e = n->edges;
  while (e) {
    OoCycleNode *child = find_node_unlocked(e->target);
    if (child && !child->reclaimed) {
      child->trial_rc++;
      if (child->color != OO_COLOR_BLACK) {
        scan_black_node(child);
      }
    }
    e = e->next;
  }
  if (n->tracer) {
    n->tracer(n->payload, scan_black_visitor, NULL);
  }
}

static void scan_node(OoCycleNode *n);

static void scan_white_visitor(void *child_payload, void *ctx) {
  (void)ctx;
  OoCycleNode *child = find_node_unlocked(child_payload);
  if (child && !child->reclaimed) {
    scan_node(child);
  }
}

static void scan_node(OoCycleNode *n) {
  if (!n || n->reclaimed) return;
  if (n->color == OO_COLOR_GRAY) {
    if (n->trial_rc > 0) {
      scan_black_node(n);
    } else {
      n->color = OO_COLOR_WHITE;
      OoCycleEdge *e = n->edges;
      while (e) {
        OoCycleNode *child = find_node_unlocked(e->target);
        if (child && !child->reclaimed) {
          scan_node(child);
        }
        e = e->next;
      }
      if (n->tracer) {
        n->tracer(n->payload, scan_white_visitor, NULL);
      }
    }
  }
}

/* Phase 3: Collect White */
static void collect_white_node(OoCycleNode *n);

static void collect_white_visitor(void *child_payload, void *ctx) {
  (void)ctx;
  OoCycleNode *child = find_node_unlocked(child_payload);
  if (child && !child->reclaimed) {
    collect_white_node(child);
  }
}

static void collect_white_node(OoCycleNode *n) {
  if (!n || n->reclaimed) return;
  if (n->color == OO_COLOR_WHITE) {
    n->color = OO_COLOR_BLACK;
    n->reclaimed = 1;
    g_stats.cycles_detected++;

    OoCycleEdge *e = n->edges;
    while (e) {
      OoCycleNode *child = find_node_unlocked(e->target);
      if (child && !child->reclaimed && child->color == OO_COLOR_WHITE) {
        collect_white_node(child);
      }
      e = e->next;
    }
    if (n->tracer) {
      n->tracer(n->payload, collect_white_visitor, NULL);
    }

    if (n->dtor) {
      n->dtor(n->payload);
    }
    g_stats.nodes_reclaimed++;
    g_stats.bytes_reclaimed += n->size;
  }
}

OoCycleStats oo_cycle_collect(void) {
  pthread_mutex_lock(&g_cycle_mutex);
  g_gc_epoch++;
  g_stats.collections_run++;
  g_stats.current_epoch = g_gc_epoch;

  /* Initialize trial_rc for all nodes */
  for (size_t i = 0; i < HASH_SIZE; i++) {
    OoCycleNode *cur = g_node_buckets[i];
    while (cur) {
      if (!cur->reclaimed) {
        cur->trial_rc = compute_node_rc_unlocked(cur);
        g_stats.nodes_examined++;
      }
      cur = cur->hash_next;
    }
  }

  /* Phase 1: Mark Gray */
  for (size_t i = 0; i < g_purple_count; i++) {
    OoCycleNode *n = g_purple_candidates[i];
    if (n && n->color == OO_COLOR_PURPLE && !n->reclaimed) {
      mark_gray_node(n);
    }
  }

  /* Phase 2: Scan Roots */
  for (size_t i = 0; i < g_purple_count; i++) {
    OoCycleNode *n = g_purple_candidates[i];
    if (n && !n->reclaimed) {
      scan_node(n);
    }
  }

  /* Phase 3: Collect White */
  for (size_t i = 0; i < g_purple_count; i++) {
    OoCycleNode *n = g_purple_candidates[i];
    if (n && n->color == OO_COLOR_WHITE && !n->reclaimed) {
      collect_white_node(n);
    }
  }

  /* Phase 4: Prune candidate buffer FIRST, then free reclaimed nodes */
  size_t new_purple = 0;
  for (size_t i = 0; i < g_purple_count; i++) {
    OoCycleNode *n = g_purple_candidates[i];
    if (n) {
      if (!n->reclaimed && n->color == OO_COLOR_PURPLE) {
        g_purple_candidates[new_purple++] = n;
      } else if (!n->reclaimed) {
        n->in_purple_buffer = 0;
      }
    }
  }
  g_purple_count = new_purple;

  for (size_t i = 0; i < HASH_SIZE; i++) {
    OoCycleNode **cur = &g_node_buckets[i];
    while (*cur) {
      if ((*cur)->reclaimed) {
        OoCycleNode *victim = *cur;
        *cur = victim->hash_next;
        OoCycleEdge *e = victim->edges;
        while (e) {
          OoCycleEdge *enext = e->next;
          free(e);
          e = enext;
        }
        free(victim);
      } else {
        cur = &((*cur)->hash_next);
      }
    }
  }

  OoCycleStats res = g_stats;
  pthread_mutex_unlock(&g_cycle_mutex);
  return res;
}

OoCycleStats oo_cycle_get_stats(void) {
  pthread_mutex_lock(&g_cycle_mutex);
  OoCycleStats s = g_stats;
  pthread_mutex_unlock(&g_cycle_mutex);
  return s;
}

uint32_t oo_cycle_current_epoch(void) {
  pthread_mutex_lock(&g_cycle_mutex);
  uint32_t e = g_gc_epoch;
  pthread_mutex_unlock(&g_cycle_mutex);
  return e;
}

size_t oo_cycle_candidate_count(void) {
  pthread_mutex_lock(&g_cycle_mutex);
  size_t c = g_purple_count;
  pthread_mutex_unlock(&g_cycle_mutex);
  return c;
}

size_t oo_cycle_tracked_nodes_count(void) {
  pthread_mutex_lock(&g_cycle_mutex);
  size_t count = 0;
  for (size_t i = 0; i < HASH_SIZE; i++) {
    OoCycleNode *cur = g_node_buckets[i];
    while (cur) {
      if (!cur->reclaimed) count++;
      cur = cur->hash_next;
    }
  }
  pthread_mutex_unlock(&g_cycle_mutex);
  return count;
}

void oo_cycle_reset_stats(void) {
  pthread_mutex_lock(&g_cycle_mutex);
  memset(&g_stats, 0, sizeof(g_stats));
  pthread_mutex_unlock(&g_cycle_mutex);
}
