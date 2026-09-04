/* oo_cap_require_* — per-token cap checkers. Each function compares the
 * caller-supplied token against the process-local g_tok_* value and
 * exits on mismatch (fail-closed). Ordering: caps.c (orchestrator)
 * must be included before this file so g_tok_* and oo_caps_init are
 * visible. */

int oo_cap_is_arena(long long got) { oo_caps_init(); return got == g_tok_arena; }

void oo_cap_require(long long got, long long want, const char *op) {
  oo_caps_init();
  if (got == 0 || got != want) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "?");
    exit(1);
  }
}

void oo_cap_require_fs(long long got, const char *op) { oo_cap_require(got, g_tok_fs, op ? op : "fs"); }
void oo_cap_require_sys(long long got, const char *op) { oo_cap_require(got, g_tok_sys, op ? op : "sys"); }
void oo_cap_require_env(long long got, const char *op) { oo_cap_require(got, g_tok_env, op ? op : "env"); }
void oo_cap_require_net(long long got, const char *op) { oo_cap_require(got, g_tok_net, op ? op : "net"); }
void oo_cap_require_sign(long long got, const char *op) { oo_cap_require(got, g_tok_sign, op ? op : "sign"); }
/* v2.1.0: removed oo_cap_require_sync, oo_cap_require_mem (dead caps). */
void oo_cap_require_audio(long long got, const char *op) { oo_cap_require(got, g_tok_audio, op ? op : "audio"); }
void oo_cap_require_camera(long long got, const char *op) { oo_cap_require(got, g_tok_camera, op ? op : "camera"); }
void oo_cap_require_usb(long long got, const char *op) { oo_cap_require(got, g_tok_usb, op ? op : "usb"); }
void oo_cap_require_hid(long long got, const char *op) { oo_cap_require(got, g_tok_hid, op ? op : "hid"); }
void oo_cap_require_window(long long got, const char *op) { oo_cap_require(got, g_tok_window, op ? op : "window"); }
void oo_cap_require_frame(long long got, const char *op) { oo_cap_require(got, g_tok_frame, op ? op : "frame"); }
void oo_cap_require_arena(long long got, const char *op) { oo_cap_require(got, g_tok_arena, op ? op : "arena"); }
void oo_cap_require_thread(long long got, const char *op) { oo_cap_require(got, g_tok_thread, op ? op : "thread"); }
void oo_cap_require_gpu(long long got, const char *op) { oo_cap_require(got, g_tok_gpu, op ? op : "gpu"); }
void oo_cap_require_compiler_read(long long got, const char *op) { oo_cap_require(got, g_tok_compiler_read, op ? op : "compiler_read"); }
void oo_cap_require_metrics(long long got, const char *op) { oo_cap_require(got, g_tok_metrics, op ? op : "metrics"); }

/* v2.1.0: removed oo_cap_require_http (dead cap). */
void oo_cap_require_tcp(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_tcp && got != g_tok_net)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "tcp");
    exit(1);
  }
}
void oo_cap_require_udp(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_udp && got != g_tok_net)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "udp");
    exit(1);
  }
}
void oo_cap_require_bind(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_bind && got != g_tok_net)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "bind");
    exit(1);
  }
}
void oo_cap_require_fsread(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_fsread && got != g_tok_fs)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "fsread");
    exit(1);
  }
}
void oo_cap_require_fswrite(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_fswrite && got != g_tok_fs)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "fswrite");
    exit(1);
  }
}
void oo_cap_require_process(long long got, const char *op) {
  oo_caps_init();
  if (got == 0 || (got != g_tok_process && got != g_tok_sys)) {
    fprintf(stderr, "ERR\tcap\t%s: missing or forged capability\n", op ? op : "process");
    exit(1);
  }
}
