/* sec/cap/cap_bridge_emitted.c — committed NORTHSTAR rights-mask shim.
 *
 * The 20 language-token rights masks used by cap_ocap_bridge.c. This is
 * hand-written C, compiled by the umbrella TU. Default make does not
 * invoke oodac emit-c (that command is residual, exit 2).
 *
 * Masks match std/sec/capability/ocap_to_oodar.oo (NORTHSTAR §1.4):
 *   bit0 read, bit1 write, bit2 execute, bit3 delegate, bit4 revoke.
 */
#include "../../oodar.h"
#include <stddef.h>
#include <string.h>

#ifndef OO_TY_OCapBridgeRecord
#define OO_TY_OCapBridgeRecord
typedef struct OCapBridgeRecord {
  OoStr cap_name;
  OoStr language_token;
  long long rights_mask;
} OCapBridgeRecord;
#endif

typedef struct {
  const char *name;
  const char *token;
  long long mask;
} OCapRow;

static const OCapRow ROWS[] = {
  {"FsReadCap", "fsread", 1LL},
  {"FsWriteCap", "fswrite", 3LL},
  {"NetCap", "net", 3LL},
  {"TcpCap", "tcp", 3LL},
  {"UdpCap", "udp", 3LL},
  {"SysCap", "sys", 7LL},
  {"ProcessCap", "process", 7LL},
  {"EnvCap", "env", 1LL},
  {"TimeCap", "time", 1LL},
  {"RandCap", "rand", 1LL},
  {"AllocCap", "alloc", 3LL},
  {"ThreadCap", "thread", 7LL},
  {"GpuCap", "gpu", 7LL},
  {"FfiCap", "ffi", 7LL},
  {"FsCap", "fs", 31LL},
  {"ArenaCap", "arena", 11LL},
  {"MetricsCap", "metrics", 1LL},
  {"SignCap", "sign", 3LL},
  {"BindCap", "bind", 3LL},
  {"CompilerReadCap", "compiler_read", 1LL},
};

static const OCapRow *find_row(OoStr name) {
  size_t i, n;
  if (!name.data || name.len < 0) return NULL;
  for (i = 0; i < sizeof ROWS / sizeof ROWS[0]; i++) {
    n = strlen(ROWS[i].name);
    if ((long long)n == name.len && memcmp(name.data, ROWS[i].name, n) == 0)
      return &ROWS[i];
  }
  return NULL;
}

static OCapBridgeRecord record_from_row(const OCapRow *row) {
  OCapBridgeRecord r;
  if (!row) {
    r.cap_name = oo_str_lit("");
    r.language_token = oo_str_lit("");
    r.rights_mask = 0;
    return r;
  }
  r.cap_name = oo_str_lit(row->name);
  r.language_token = oo_str_lit(row->token);
  r.rights_mask = row->mask;
  return r;
}

OCapBridgeRecord ocap_to_oodar_record_for(OoStr name) {
  return record_from_row(find_row(name));
}

long long ocap_to_oodar_rights_for_name(OoStr name) {
  const OCapRow *row = find_row(name);
  return row ? row->mask : 0LL;
}

OoSList ocap_to_oodar_all_names(void) {
  OoSList names = oo_slist_new();
  size_t i;
  for (i = 0; i < sizeof ROWS / sizeof ROWS[0]; i++) {
    OoStr n = oo_str_lit(ROWS[i].name);
    OoSList tmp = names;
    names = oo_slist_push(names, n);
    oo_str_release(n);
    oo_slist_release(tmp);
  }
  return names;
}

int ocap_to_oodar_has_permission(OoStr name, long long required) {
  long long granted = ocap_to_oodar_rights_for_name(name);
  return (granted & required) == required;
}
