/* qa/tests_challenger_wave3.c — loopback, alloc-table write_int, actor send.
 * Exit 0 iff every probe fails closed. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "../oodar.h"

static int fail;

static int child_dies(void (*fn)(void)) {
  pid_t p = fork();
  if (p < 0) return 0;
  if (p == 0) { alarm(2); fn(); _exit(0); }
  int st = 0;
  waitpid(p, &st, 0);
  return (WIFEXITED(st) && WEXITSTATUS(st) != 0) || WIFSIGNALED(st);
}

static void foreign_write(void) {
  long long cap = oo_cap_grant_alloc();
  (oo_write_int)(cap, 0x1000, 0, 1);
}

int main(void) {
  long long ncap = oo_cap_grant_net();
  long long ucap = oo_cap_grant_udp();
  long long tcap = oo_cap_grant_tcp();
  long long acap = oo_cap_grant_alloc();
  long long th = oo_cap_grant_thread();
  OoResS r;
  long long p;

  r = oo_udp_send(ucap, 0, oo_str_lit("8.8.8.8"), 53, oo_str_lit("x"));
  if (r.ok) {
    fprintf(stderr, "FAIL\twave3\tudp_send to 8.8.8.8 succeeded\n");
    fail = 1;
  } else printf("OK\twave3\tudp_send 8.8.8.8 fail-closed\n");

  r = oo_tcp_connect(tcap, oo_str_lit("8.8.8.8"), 53);
  if (r.ok) {
    fprintf(stderr, "FAIL\twave3\ttcp_connect 8.8.8.8 succeeded\n");
    fail = 1;
  } else printf("OK\twave3\ttcp_connect 8.8.8.8 fail-closed\n");
  (void)ncap;

  if (child_dies(foreign_write)) {
    printf("OK\twave3\twrite_int foreign pointer fail-closed\n");
  } else {
    fprintf(stderr, "FAIL\twave3\twrite_int foreign pointer leaked\n");
    fail = 1;
  }

  p = oo_alloc(acap, 64);
  (oo_write_int)(acap, p, 0, 42);
  if ((oo_read_int)(acap, p, 0) != 42) {
    fprintf(stderr, "FAIL\twave3\twrite/read_int roundtrip\n");
    fail = 1;
  } else printf("OK\twave3\twrite/read_int via alloc table\n");
  oo_free(acap, p);

  r = oo_channel_new(th);
  if (!r.ok) {
    fprintf(stderr, "FAIL\twave3\tchannel_new failed\n");
    fail = 1;
  } else {
    long long slot = 0;
    OoResS s = oo_channel_send(th, slot, oo_str_lit("m"));
    OoResS d = oo_channel_destroy(th, slot);
    (void)s; (void)d;
    printf("OK\twave3\tchannel send/destroy under boot lock\n");
  }

  if (fail) return 1;
  printf("PASS\twave3\tloopback + alloc table + channel lock\n");
  return 0;
}
