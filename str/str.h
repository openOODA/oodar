#pragma once
#include "../oodar.h"
#include <stdarg.h>
char *oo_str_alloc_payload(size_t len);
OoStr oo_str_concat(OoStr a, OoStr b);
OoStr oo_str_concat_list(OoSList lst);
OoStr oo_str_concat_multi(int n, ...);
long long oo_str_byte_len(OoStr s);
