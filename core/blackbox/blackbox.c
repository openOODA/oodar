/* core/blackbox/blackbox.c — Substrate Flight Recorder & Crash Autopsy */
#include "blackbox.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <execinfo.h>
#include <string.h>

static uint8_t s_altstack[16384];
static char s_autopsy_buf[32768];
static BlackboxRingBuffer s_ring;
static volatile sig_atomic_t s_in_handler = 0;
static volatile sig_atomic_t s_initialized = 0;

static size_t bb_append(char *buf, size_t pos, size_t max, const char *s) {
  if (!s || pos >= max) return pos;
  while (*s && pos + 1 < max) buf[pos++] = *s++;
  buf[pos] = '\0';
  return pos;
}

static size_t bb_append_uint(char *buf, size_t pos, size_t max, uint64_t val) {
  char tmp[24]; int i = 0;
  if (val == 0) tmp[i++] = '0';
  while (val > 0) { tmp[i++] = (char)('0' + (val % 10)); val /= 10; }
  while (i > 0 && pos + 1 < max) buf[pos++] = tmp[--i];
  buf[pos] = '\0';
  return pos;
}

static size_t bb_append_hex(char *buf, size_t pos, size_t max, uintptr_t val) {
  static const char hex[] = "0123456789abcdef";
  char tmp[20]; int i = 0;
  pos = bb_append(buf, pos, max, "0x");
  if (val == 0) tmp[i++] = '0';
  while (val > 0) { tmp[i++] = hex[val & 0xf]; val >>= 4; }
  while (i > 0 && pos + 1 < max) buf[pos++] = tmp[--i];
  buf[pos] = '\0';
  return pos;
}

static size_t bb_append_json_str(char *buf, size_t pos, size_t max, const char *s) {
  if (pos + 1 >= max) return pos;
  buf[pos++] = '"';
  while (s && *s && pos + 2 < max) {
    if (*s == '"' || *s == '\\') { buf[pos++] = '\\'; buf[pos++] = *s++; }
    else if (*s == '\n') { buf[pos++] = '\\'; buf[pos++] = 'n'; s++; }
    else if (*s == '\t') { buf[pos++] = '\\'; buf[pos++] = 't'; s++; }
    else if ((unsigned char)*s < 32) { s++; }
    else { buf[pos++] = *s++; }
  }
  if (pos + 1 < max) buf[pos++] = '"';
  buf[pos] = '\0';
  return pos;
}

static uint64_t bb_now_us(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
  return 0;
}

void blackbox_record(const char *category, const char *action, const char *detail) {
  uint64_t seq = __atomic_add_fetch(&s_ring.count, 1, __ATOMIC_SEQ_CST);
  uint64_t idx = (seq - 1) % BLACKBOX_RING_CAPACITY;
  BlackboxFlightEvent *ev = &s_ring.events[idx];
  ev->seq = seq; ev->timestamp_us = bb_now_us(); ev->event_type = 1;
  size_t i;
  for (i = 0; i < 31 && category && category[i]; i++) ev->category[i] = category[i];
  ev->category[i] = '\0';
  for (i = 0; i < 31 && action && action[i]; i++) ev->action[i] = action[i];
  ev->action[i] = '\0';
  for (i = 0; i < 63 && detail && detail[i]; i++) ev->detail[i] = detail[i];
  ev->detail[i] = '\0';
  __atomic_store_n(&s_ring.head, idx, __ATOMIC_RELEASE);
}

static size_t bb_format_events(char *buf, size_t pos, size_t max) {
  pos = bb_append(buf, pos, max, "[\n");
  uint64_t count = __atomic_load_n(&s_ring.count, __ATOMIC_ACQUIRE);
  uint64_t total = count < BLACKBOX_RING_CAPACITY ? count : BLACKBOX_RING_CAPACITY;
  uint64_t start = count <= BLACKBOX_RING_CAPACITY ? 0 : count - BLACKBOX_RING_CAPACITY;
  for (uint64_t i = 0; i < total; i++) {
    uint64_t idx = (start + i) % BLACKBOX_RING_CAPACITY;
    BlackboxFlightEvent *ev = &s_ring.events[idx];
    pos = bb_append(buf, pos, max, "    {\"seq\": ");
    pos = bb_append_uint(buf, pos, max, ev->seq);
    pos = bb_append(buf, pos, max, ", \"timestamp_us\": ");
    pos = bb_append_uint(buf, pos, max, ev->timestamp_us);
    pos = bb_append(buf, pos, max, ", \"category\": ");
    pos = bb_append_json_str(buf, pos, max, ev->category);
    pos = bb_append(buf, pos, max, ", \"action\": ");
    pos = bb_append_json_str(buf, pos, max, ev->action);
    pos = bb_append(buf, pos, max, ", \"detail\": ");
    pos = bb_append_json_str(buf, pos, max, ev->detail);
    pos = bb_append(buf, pos, max, (i + 1 < total) ? "},\n" : "}\n");
  }
  return bb_append(buf, pos, max, "  ]");
}

static size_t bb_format_stack(char *buf, size_t pos, size_t max) {
  void *frames[32];
  int n = backtrace(frames, 32);
  pos = bb_append(buf, pos, max, "[\n");
  for (int i = 0; i < n; i++) {
    pos = bb_append(buf, pos, max, "    {\"frame\": ");
    pos = bb_append_uint(buf, pos, max, (uint64_t)i);
    pos = bb_append(buf, pos, max, ", \"address\": \"");
    pos = bb_append_hex(buf, pos, max, (uintptr_t)frames[i]);
    pos = bb_append(buf, pos, max, (i + 1 < n) ? "\"},\n" : "\"}\n");
  }
  return bb_append(buf, pos, max, "  ]");
}

static void bb_write_file(const char *buf, size_t len) {
  (void)mkdir(".blackbox", 0777);
  int fd = open(".blackbox/autopsy.json", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) { (void)write(fd, buf, len); (void)close(fd); }
  else { (void)write(STDERR_FILENO, buf, len); }
}

void blackbox_dump_autopsy(int sig, const siginfo_t *info, void *ucontext) {
  (void)ucontext;
  uintptr_t faddr = info ? (uintptr_t)info->si_addr : 0;
  const char *sname = "NONE", *rc = "PROCESS_SNAPSHOT";
  const char *rem = "Examine process flight events.";
  if (sig == SIGSEGV) {
    sname = "SIGSEGV";
    if (faddr < 0x1000) { rc = "NULL_POINTER_DEREFERENCE"; rem = "Check pointer initialization before dereference."; }
    else { rc = "MEMORY_ACCESS_VIOLATION"; rem = "Verify buffer boundaries and memory permissions."; }
  } else if (sig == SIGABRT) {
    sname = "SIGABRT"; rc = "PROCESS_ABORT"; rem = "Review assertion condition or process abort call.";
  } else if (sig == SIGBUS) {
    sname = "SIGBUS"; rc = "BUS_ERROR"; rem = "Inspect memory alignment and mmap boundaries.";
  } else if (sig == SIGILL) {
    sname = "SIGILL"; rc = "ILLEGAL_INSTRUCTION"; rem = "Inspect instruction alignment and code integrity.";
  }

  size_t p = 0, m = sizeof(s_autopsy_buf);
  p = bb_append(s_autopsy_buf, p, m, "{\n  \"schema_version\": \"1.0.0\",\n  \"crash_type\": \"SIGNAL\",\n");
  p = bb_append(s_autopsy_buf, p, m, "  \"crash_signal\": ");
  p = bb_append_uint(s_autopsy_buf, p, m, (uint64_t)sig);
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"signal_name\": ");
  p = bb_append_json_str(s_autopsy_buf, p, m, sname);
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"signal\": ");
  p = bb_append_json_str(s_autopsy_buf, p, m, sname);
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"fault_address\": \"");
  p = bb_append_hex(s_autopsy_buf, p, m, faddr);
  p = bb_append(s_autopsy_buf, p, m, "\",\n  \"failure_coordinate\": ");
  if (sig != 0) {
    char coord[48]; size_t cp = bb_append(coord, 0, sizeof(coord), "fault@");
    cp = bb_append_hex(coord, cp, sizeof(coord), faddr);
    p = bb_append_json_str(s_autopsy_buf, p, m, coord);
  } else { p = bb_append_json_str(s_autopsy_buf, p, m, "unknown:0:0:unknown"); }
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"root_cause\": ");
  p = bb_append_json_str(s_autopsy_buf, p, m, rc);
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"remediation\": ");
  p = bb_append_json_str(s_autopsy_buf, p, m, rem);
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"call_stack\": ");
  p = bb_format_stack(s_autopsy_buf, p, m);
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"flight_events\": ");
  p = bb_format_events(s_autopsy_buf, p, m);
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"flight_log\": ");
  p = bb_format_events(s_autopsy_buf, p, m);
  p = bb_append(s_autopsy_buf, p, m, "\n}\n");
  bb_write_file(s_autopsy_buf, p);
}

void blackbox_trap_cap(const char *cap_name, const char *caller_fn, const char *file, int line) {
  blackbox_record("capability", "violation", cap_name ? cap_name : "unknown");
  size_t p = 0, m = sizeof(s_autopsy_buf);
  p = bb_append(s_autopsy_buf, p, m, "{\n  \"schema_version\": \"1.0.0\",\n  \"crash_type\": \"CAPABILITY_VIOLATION\",\n");
  p = bb_append(s_autopsy_buf, p, m, "  \"crash_signal\": 0,\n  \"signal_name\": \"NONE\",\n  \"signal\": \"NONE\",\n");
  p = bb_append(s_autopsy_buf, p, m, "  \"fault_address\": \"0x0\",\n  \"failure_coordinate\": \"");
  p = bb_append(s_autopsy_buf, p, m, file ? file : "unknown");
  p = bb_append(s_autopsy_buf, p, m, ":");
  p = bb_append_uint(s_autopsy_buf, p, m, (uint64_t)(line > 0 ? line : 0));
  p = bb_append(s_autopsy_buf, p, m, ":0:");
  p = bb_append(s_autopsy_buf, p, m, caller_fn ? caller_fn : "unknown");
  p = bb_append(s_autopsy_buf, p, m, "\",\n  \"root_cause\": \"CAPABILITY_TRAP_VIOLATION\",\n");
  p = bb_append(s_autopsy_buf, p, m, "  \"remediation\": \"Grant required capability token before invoking restricted operation.\",\n");
  p = bb_append(s_autopsy_buf, p, m, "  \"capability\": {\n    \"token_name\": ");
  p = bb_append_json_str(s_autopsy_buf, p, m, cap_name ? cap_name : "unknown");
  p = bb_append(s_autopsy_buf, p, m, ",\n    \"operation\": ");
  p = bb_append_json_str(s_autopsy_buf, p, m, caller_fn ? caller_fn : "unknown");
  p = bb_append(s_autopsy_buf, p, m, "\n  },\n  \"call_stack\": ");
  p = bb_format_stack(s_autopsy_buf, p, m);
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"flight_events\": ");
  p = bb_format_events(s_autopsy_buf, p, m);
  p = bb_append(s_autopsy_buf, p, m, ",\n  \"flight_log\": ");
  p = bb_format_events(s_autopsy_buf, p, m);
  p = bb_append(s_autopsy_buf, p, m, "\n}\n");
  bb_write_file(s_autopsy_buf, p);
}

static void blackbox_signal_handler(int sig, siginfo_t *info, void *ucontext) {
  if (__atomic_test_and_set(&s_in_handler, __ATOMIC_SEQ_CST)) {
    signal(sig, SIG_DFL); raise(sig); return;
  }
  blackbox_record("signal", "trap", (sig == SIGSEGV) ? "SIGSEGV" :
                  (sig == SIGABRT) ? "SIGABRT" : (sig == SIGBUS) ? "SIGBUS" : "SIGILL");
  blackbox_dump_autopsy(sig, info, ucontext);
  signal(sig, SIG_DFL);
  sigset_t ss; sigemptyset(&ss); sigaddset(&ss, sig);
  sigprocmask(SIG_UNBLOCK, &ss, NULL);
  raise(sig);
}

__attribute__((constructor)) void blackbox_init(void) {
  if (__atomic_test_and_set(&s_initialized, __ATOMIC_SEQ_CST)) return;
  stack_t ss; memset(&ss, 0, sizeof(ss));
  ss.ss_sp = s_altstack; ss.ss_size = sizeof(s_altstack); ss.ss_flags = 0;
  (void)sigaltstack(&ss, NULL);
  struct sigaction sa; memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = blackbox_signal_handler;
  sa.sa_flags = SA_ONSTACK | SA_SIGINFO | SA_RESETHAND;
  sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGSEGV, &sa, NULL);
  (void)sigaction(SIGABRT, &sa, NULL);
  (void)sigaction(SIGBUS, &sa, NULL);
  (void)sigaction(SIGILL, &sa, NULL);
  blackbox_record("core", "init", "flight_sensor_active");
}

void oo_blackbox_init(void) { blackbox_init(); }
void oo_blackbox_record(const char *c, const char *a, const char *d) { blackbox_record(c, a, d); }
void oo_blackbox_trap_cap(const char *c, const char *fn, const char *f, int l) { blackbox_trap_cap(c, fn, f, l); }
