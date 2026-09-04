#ifndef OODAR_DNS_H
#define OODAR_DNS_H
#include "../oodar.h"

OoResS oo_dns_resolve(long long cap, OoStr host);
OoResS oo_dns_resolve_ipv4(long long cap, OoStr host);

#endif
