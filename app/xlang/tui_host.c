/* tui_host.c — termios and ioctl TUI host primitives for raw mode line editing.
 * FfiCap-gated primitives implementing oo_tui_* declared intrinsics. */
#include "../../oodar.h"
#include "../../oodar_internal.h"
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct termios s_orig_termios;
static int s_raw_active = 0;
static volatile sig_atomic_t s_winch_flag = 0;

static void tui_atexit_restore(void) {
  if (s_raw_active) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &s_orig_termios);
    s_raw_active = 0;
  }
}

static void sigwinch_handler(int sig) {
  (void)sig;
  s_winch_flag = 1;
}

OoResS oo_tui_enable_raw(long long cap, OoStr tty_path) {
  (void)tty_path;
  oo_cap_require_ffi(cap, "tui_enable_raw");
  OoResS r;
  if (!isatty(STDIN_FILENO)) {
    r.ok = 0;
    r.val = oo_str_lit("not a tty");
    return r;
  }
  if (!s_raw_active) {
    if (tcgetattr(STDIN_FILENO, &s_orig_termios) == -1) {
      r.ok = 0;
      r.val = oo_str_lit("tcgetattr failed");
      return r;
    }
    struct termios raw = s_orig_termios;
    cfmakeraw(&raw);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1) {
      r.ok = 0;
      r.val = oo_str_lit("tcsetattr failed");
      return r;
    }
    s_raw_active = 1;
    atexit(tui_atexit_restore);
  }
  r.ok = 1;
  r.val = oo_str_lit("ok");
  return r;
}

OoResS oo_tui_disable_raw(long long cap, OoStr tty_path) {
  (void)tty_path;
  oo_cap_require_ffi(cap, "tui_disable_raw");
  OoResS r;
  if (s_raw_active) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &s_orig_termios);
    s_raw_active = 0;
  }
  r.ok = 1;
  r.val = oo_str_lit("ok");
  return r;
}

OoResS oo_tui_read_byte(long long cap, OoStr tty_path) {
  (void)tty_path;
  oo_cap_require_ffi(cap, "tui_read_byte");
  OoResS r;
  char c = 0;
  ssize_t n = read(STDIN_FILENO, &c, 1);
  if (n == 1) {
    r.ok = 1;
    r.val = oo_chr((unsigned char)c);
    return r;
  }
  r.ok = 0;
  r.val = (n == 0) ? oo_str_lit("eof") : oo_str_lit("err");
  return r;
}

OoResS oo_tui_read_byte_timeout(long long cap, OoStr tty_path, long long timeout_ms) {
  (void)tty_path;
  oo_cap_require_ffi(cap, "tui_read_byte_timeout");
  OoResS r;
  struct pollfd pfd;
  pfd.fd = STDIN_FILENO;
  pfd.events = POLLIN;
  pfd.revents = 0;
  int prc = poll(&pfd, 1, (int)timeout_ms);
  if (prc == 0) {
    r.ok = 1;
    r.val = oo_str_lit("");
    return r;
  }
  if (prc > 0 && (pfd.revents & POLLIN)) {
    char c = 0;
    ssize_t n = read(STDIN_FILENO, &c, 1);
    if (n == 1) {
      r.ok = 1;
      r.val = oo_chr((unsigned char)c);
      return r;
    }
    r.ok = 0;
    r.val = (n == 0) ? oo_str_lit("eof") : oo_str_lit("err");
    return r;
  }
  r.ok = 0;
  r.val = oo_str_lit("err");
  return r;
}

OoResS oo_tui_get_size(long long cap) {
  oo_cap_require_ffi(cap, "tui_get_size");
  OoResS r;
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d:%d", (int)ws.ws_row, (int)ws.ws_col);
    r.ok = 1;
    r.val = oo_str_lit(buf);
    return r;
  }
  if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d:%d", (int)ws.ws_row, (int)ws.ws_col);
    r.ok = 1;
    r.val = oo_str_lit(buf);
    return r;
  }
  r.ok = 1;
  r.val = oo_str_lit("24:80");
  return r;
}

OoResS oo_tui_write(long long cap, OoStr data) {
  oo_cap_require_ffi(cap, "tui_write");
  OoResS r;
  if (data.data && data.len > 0) {
    ssize_t nw = write(STDOUT_FILENO, data.data, (size_t)data.len);
    (void)nw;
  }
  r.ok = 1;
  r.val = oo_str_lit("ok");
  return r;
}

OoResS oo_tui_alt_screen_enter(long long cap) {
  oo_cap_require_ffi(cap, "tui_alt_screen_enter");
  OoResS r;
  const char *seq = "\x1b[?1049h\x1b[H";
  ssize_t nw = write(STDOUT_FILENO, seq, strlen(seq));
  (void)nw;
  r.ok = 1;
  r.val = oo_str_lit("ok");
  return r;
}

OoResS oo_tui_alt_screen_leave(long long cap) {
  oo_cap_require_ffi(cap, "tui_alt_screen_leave");
  OoResS r;
  const char *seq = "\x1b[?1049l";
  ssize_t nw = write(STDOUT_FILENO, seq, strlen(seq));
  (void)nw;
  r.ok = 1;
  r.val = oo_str_lit("ok");
  return r;
}

OoResS oo_tui_show_cursor(long long cap, long long vis) {
  oo_cap_require_ffi(cap, "tui_show_cursor");
  OoResS r;
  const char *seq = vis ? "\x1b[?25h" : "\x1b[?25l";
  ssize_t nw = write(STDOUT_FILENO, seq, strlen(seq));
  (void)nw;
  r.ok = 1;
  r.val = oo_str_lit("ok");
  return r;
}

OoResS oo_tui_clear(long long cap) {
  oo_cap_require_ffi(cap, "tui_clear");
  OoResS r;
  const char *seq = "\x1b[2J\x1b[H";
  ssize_t nw = write(STDOUT_FILENO, seq, strlen(seq));
  (void)nw;
  r.ok = 1;
  r.val = oo_str_lit("ok");
  return r;
}

OoResS oo_tui_signal_winch_install(long long cap) {
  oo_cap_require_ffi(cap, "tui_signal_winch_install");
  OoResS r;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigwinch_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGWINCH, &sa, NULL);
  r.ok = 1;
  r.val = oo_str_lit("ok");
  return r;
}

OoResS oo_tui_signal_winch_poll(long long cap) {
  oo_cap_require_ffi(cap, "tui_signal_winch_poll");
  OoResS r;
  r.ok = 1;
  if (s_winch_flag) {
    s_winch_flag = 0;
    r.val = oo_str_lit("1");
  } else {
    r.val = oo_str_lit("0");
  }
  return r;
}
