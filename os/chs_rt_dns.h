#ifndef CHS_RT_DNS_H
#define CHS_RT_DNS_H
#include "chs_rt.h"

OoResS oo_dns_resolve(long long cap, OoStr host);
OoResS oo_dns_resolve_ipv4(long long cap, OoStr host);

#endif
