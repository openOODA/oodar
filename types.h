#ifndef OODAR_TYPES_H
#define OODAR_TYPES_H
/* v2.3.0 split: types.h is now a thin umbrella. The type defs and decls
 * live in types/types_*.h, one concept per file. Existing #include
 * "types.h" sites do not need to change. The base stdio/stdlib/time/
 * stdint includes and the oo_monotonic_us forward decl stay here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>

long long oo_monotonic_us(void);

#include "types/types_str.h"
#include "types/types_num.h"
#include "types/types_res.h"
#include "types/types_actor.h"
#include "types/types_control.h"
#include "types/types_q.h"

#endif
