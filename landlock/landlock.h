#ifndef OODAR_LANDLOCK_H
#define OODAR_LANDLOCK_H
#include "../oodar.h"

OoResS oo_landlock_restrict(long long cap, OoStr read_dirs_colon, OoStr write_dirs_colon);
int oo_landlock_is_available(void);

#endif
