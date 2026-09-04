/* Event bus — generic publisher/subscriber. Producers emit named events; consumers
 * subscribe a void(*)(void) callback. Used to decouple cross-cutting telemetry
 * (metrics) from the cryptographic and FS subsystems that emit them.
 *
 * Thread-safe: the subscription list is guarded by a mutex. Subscribers MUST
 * not call oo_event_subscribe from a callback (deadlock). */

#ifndef OODAR_EVENT_H
#define OODAR_EVENT_H

#include "../oodar.h"

#define OO_EVENT_MAX_SUBSCRIBERS 32
#define OO_EVENT_MAX_NAME        32
#define OO_EVENT_MAX_EVENTS      32

void oo_event_emit(OoStr name);
void oo_event_subscribe(OoStr name, void (*fn)(void));
void oo_event_init(void);
int  oo_event_self_test(void);

#endif
