/* core/blackbox/blackbox.h — Substrate Flight Recorder & Crash Autopsy
 *
 * Provides zero-heap crash signal interception and telemetry recording
 * for openOODA flight diagnostics and capability trap containment.
 */

#ifndef OODAR_BLACKBOX_H
#define OODAR_BLACKBOX_H

#include <stdint.h>
#include <stddef.h>
#include <signal.h>

#define BLACKBOX_RING_CAPACITY 64
#define BLACKBOX_RING_SIZE     64

#define BLACKBOX_EVENT_PHASE_CHANGE 1
#define BLACKBOX_EVENT_CAP_REQUIRE  2
#define BLACKBOX_EVENT_AST_NODE     3
#define BLACKBOX_EVENT_ARENA_MARK   4
#define BLACKBOX_EVENT_IO_DISPATCH  5
#define BLACKBOX_EVENT_TRAP_SIGNAL  6

typedef struct {
  uint64_t seq;
  uint64_t timestamp_us;
  int event_type;
  char category[32];
  char action[32];
  char detail[64];
} BlackboxFlightEvent;

typedef struct {
  BlackboxFlightEvent events[BLACKBOX_RING_CAPACITY];
  uint64_t head;
  uint64_t count;
} BlackboxRingBuffer;

#ifdef __cplusplus
extern "C" {
#endif

/* Core Flight Sensor API */
void blackbox_init(void);
void blackbox_record(const char *category, const char *action, const char *detail);
void blackbox_trap_cap(const char *cap_name, const char *caller_fn, const char *file, int line);
void blackbox_dump_autopsy(int sig, const siginfo_t *info, void *ucontext);

/* Substrate oo_ aliases */
void oo_blackbox_init(void);
void oo_blackbox_record(const char *category, const char *action, const char *detail);
void oo_blackbox_trap_cap(const char *cap_name, const char *caller_fn, const char *file, int line);

#ifdef __cplusplus
}
#endif

#endif /* OODAR_BLACKBOX_H */
