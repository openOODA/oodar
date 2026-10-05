#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
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
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>

struct VarlinkWorkerArgs {
  int efd;
  char *bin;
  char *cwd;
  char req[16384];
};

static void *varlink_worker_thread(void *arg) {
  struct VarlinkWorkerArgs *a = (struct VarlinkWorkerArgs *)arg;
  int pfd[2];
  if (pipe2(pfd, O_CLOEXEC) == 0) {
    pid_t pid = fork();
    if (pid == 0) {
      if (a->cwd && a->cwd[0]) {
        if (chdir(a->cwd) != 0) {}
      }
      dup2(pfd[1], STDOUT_FILENO);
      close(pfd[0]);
      close(pfd[1]);
      char *av[] = {a->bin, "--varlink-call", a->req, NULL};
      execv(a->bin, av);
      _exit(127);
    }
    close(pfd[1]);
    char rep[16384];
    size_t rtot = 0;
    while (rtot < sizeof(rep) - 2) {
      ssize_t red = read(pfd[0], rep + rtot, sizeof(rep) - rtot - 2);
      if (red <= 0) break;
      rtot += (size_t)red;
    }
    close(pfd[0]);
    waitpid(pid, NULL, 0);
    if (rtot == 0 || rep[rtot - 1] != '\0') {
      rep[rtot++] = '\0';
    }
    ssize_t nw = write(a->efd, rep, rtot);
    (void)nw;
  }
  close(a->efd);
  free(a->bin);
  free(a->cwd);
  free(a);
  return NULL;
}

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
    signal(SIGINT, SIG_IGN);
    atexit(tui_atexit_restore);
  } else {
    signal(SIGINT, SIG_IGN);
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
  oo_cap_require_ffi(cap, "tui_read_byte");
  OoResS r;
  if (tty_path.len >= 4 && memcmp(tty_path.data, "poll", 4) == 0) {
    struct pollfd pfd;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int prc = poll(&pfd, 1, 25);
    if (prc <= 0 || !(pfd.revents & POLLIN)) {
      r.ok = 1;
      r.val = oo_str_lit("");
      return r;
    }
  }
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

static volatile sig_atomic_t s_daemon_running = 1;
static void daemon_sig_handler(int sig) {
  (void)sig;
  s_daemon_running = 0;
}

static void oo_run_child_cmd(const char *cmd) {
  if (!cmd || !*cmd) _exit(0);

  char self_path[4096];
  ssize_t slen = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
  if (slen > 0) self_path[slen] = '\0';
  else strcpy(self_path, "./dist/oosh");

  int has_meta = 0;
  for (const char *p = cmd; *p; p++) {
    if (*p == ';' || *p == '&' || *p == '|' || *p == '<' || *p == '>' ||
        *p == '$' || *p == '`' || *p == '*' || *p == '?' || *p == '(' || *p == ')') {
      has_meta = 1;
      break;
    }
  }

  if (!has_meta) {
    char *dup = strdup(cmd);
    if (dup) {
      char *argv[128];
      int argc = 0;
      char *p = dup;
      while (*p && argc < 127) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (!*p) break;
        char *token_start = p;
        if (*p == '"' || *p == '\'') {
          char q = *p++;
          token_start = p;
          while (*p && *p != q) p++;
          if (*p == q) { *p = '\0'; p++; }
        } else {
          while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
          if (*p) { *p = '\0'; p++; }
        }
        argv[argc++] = token_start;
      }
      argv[argc] = NULL;

      if (argc > 0) {
        const char *b = argv[0];
        if (strcmp(b, "whereami") == 0 || strcmp(b, "caps") == 0 ||
            strcmp(b, "autopsy") == 0 || strcmp(b, "remedy") == 0 ||
            strcmp(b, "scry") == 0 || strcmp(b, "rune") == 0 ||
            strcmp(b, "status") == 0 || strcmp(b, "help") == 0 ||
            strcmp(b, "version") == 0 || strcmp(b, "alias") == 0 ||
            strcmp(b, "unalias") == 0 || strcmp(b, "export") == 0 ||
            strcmp(b, "pwd") == 0 || strcmp(b, "take") == 0) {
          free(dup);
          execl(self_path, "oosh", "-c", cmd, (char *)NULL);
          _exit(127);
        }
        execvp(argv[0], argv);
        if (errno == ENOENT) {
          execl(self_path, "oosh", "-c", cmd, (char *)NULL);
        }
      }
      free(dup);
    }
  }

  execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
  _exit(127);
}

OoResS oo_tui_write(long long cap, OoStr data) {
  oo_cap_require_ffi(cap, "tui_write");
  OoResS r;
  r.ok = 1;
  r.val = oo_str_lit("ok");
  if (!data.data || data.len <= 0) return r;

  /* Native filesystem control channel */
  if ((data.len >= 4 && memcmp(data.data, "\x00cd:", 4) == 0) ||
      (data.len >= 5 && memcmp(data.data, "\x1b_cd:", 5) == 0)) {
    char path_buf[4096];
    size_t offset = (data.data[0] == '\x1b') ? 5 : 4;
    size_t plen = (size_t)data.len - offset;
    if (plen >= sizeof(path_buf)) {
      r.ok = 0;
      r.val = oo_str_lit("path too long");
      return r;
    }
    memcpy(path_buf, data.data + offset, plen);
    path_buf[plen] = '\0';
    const char *target = path_buf;
    char exp_buf[4096];
    if (plen == 0 || (plen == 1 && path_buf[0] == '~')) {
      const char *h = getenv("HOME");
      target = (h && h[0]) ? h : "/";
    } else if (path_buf[0] == '~' && path_buf[1] == '/') {
      const char *h = getenv("HOME");
      snprintf(exp_buf, sizeof(exp_buf), "%s%s", (h && h[0]) ? h : "", path_buf + 1);
      target = exp_buf;
    }
    if (chdir(target) != 0) {
      r.ok = 0;
      r.val = oo_str_lit("chdir failed");
      return r;
    }
    char cwd_buf[4096];
    if (getcwd(cwd_buf, sizeof(cwd_buf))) {
      setenv("PWD", cwd_buf, 1);
      r.ok = 1;
      r.val = oo_str_lit(cwd_buf);
    }
    return r;
  }
  if ((data.len >= 4 && memcmp(data.data, "\0pwd", 4) == 0) ||
      (data.len >= 5 && memcmp(data.data, "\x1b_pwd", 5) == 0)) {
    char cwd_buf[4096];
    if (getcwd(cwd_buf, sizeof(cwd_buf))) {
      r.ok = 1;
      r.val = oo_str_lit(cwd_buf);
      return r;
    }
    r.ok = 1;
    r.val = oo_str_lit(".");
    return r;
  }
  if ((data.len >= 4 && memcmp(data.data, "\0env", 4) == 0) ||
      (data.len >= 5 && memcmp(data.data, "\x1b_env", 5) == 0)) {
    extern char **environ;
    size_t total = 0;
    if (environ) {
      for (char **e = environ; *e; e++) {
        total += strlen(*e) + 1;
      }
    }
    char *buf = (char *)malloc(total > 0 ? total + 1 : 1);
    if (buf) {
      size_t pos = 0;
      if (environ) {
        for (char **e = environ; *e; e++) {
          size_t elen = strlen(*e);
          memcpy(buf + pos, *e, elen);
          pos += elen;
          buf[pos++] = '\n';
        }
      }
      r.ok = 1;
      r.val = oo_str_intern_bytes(buf, pos);
      free(buf);
      return r;
    }
    r.ok = 1;
    r.val = oo_str_lit("");
    return r;
  }
  if ((data.len >= 7 && memcmp(data.data, "\0mkdir:", 7) == 0) ||
      (data.len >= 8 && memcmp(data.data, "\x1b_mkdir:", 8) == 0)) {
    char path_buf[4096];
    size_t offset = (data.data[0] == '\x1b') ? 8 : 7;
    size_t plen = (size_t)data.len - offset;
    if (plen >= sizeof(path_buf)) {
      r.ok = 0;
      r.val = oo_str_lit("path too long");
      return r;
    }
    memcpy(path_buf, data.data + offset, plen);
    path_buf[plen] = '\0';
    for (char *p = path_buf + 1; *p; p++) {
      if (*p == '/') {
        *p = '\0';
        mkdir(path_buf, 0755);
        *p = '/';
      }
    }
    if (mkdir(path_buf, 0755) != 0 && errno != EEXIST) {
      r.ok = 0;
      r.val = oo_str_lit("mkdir failed");
      return r;
    }
    r.ok = 1;
    r.val = oo_str_lit("ok");
    return r;
  }
  if ((data.len >= 5 && memcmp(data.data, "\x00set:", 5) == 0) ||
      (data.len >= 6 && memcmp(data.data, "\x1b_set:", 6) == 0)) {
    char kv_buf[4096];
    size_t offset = (data.data[0] == '\x1b') ? 6 : 5;
    size_t kvlen = (size_t)data.len - offset;
    if (kvlen < sizeof(kv_buf)) {
      memcpy(kv_buf, data.data + offset, kvlen);
      kv_buf[kvlen] = '\0';
      char *eq = strchr(kv_buf, '=');
      if (eq) {
        *eq = '\0';
        setenv(kv_buf, eq + 1, 1);
      }
    }
    return r;
  }
  if ((data.len >= 7 && memcmp(data.data, "\x00unset:", 7) == 0) ||
      (data.len >= 8 && memcmp(data.data, "\x1b_unset:", 8) == 0) ||
      (data.len >= 5 && memcmp(data.data, "\x00uns:", 5) == 0) ||
      (data.len >= 6 && memcmp(data.data, "\x1b_uns:", 6) == 0)) {
    char k_buf[256];
    size_t offset = (data.data[0] == '\x1b') ? ((data.len >= 8 && memcmp(data.data, "\x1b_unset:", 8) == 0) ? 8 : 6)
                                             : ((data.len >= 7 && memcmp(data.data, "\x00unset:", 7) == 0) ? 7 : 5);
    size_t klen = (size_t)data.len - offset;
    if (klen < sizeof(k_buf)) {
      memcpy(k_buf, data.data + offset, klen);
      k_buf[klen] = '\0';
      unsetenv(k_buf);
    }
    return r;
  }
  if ((data.len >= 6 && memcmp(data.data, "\0" "exec:", 6) == 0) ||
      (data.len >= 7 && memcmp(data.data, "\x1b_exec:", 7) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 7 : 6;
    size_t elen = (size_t)data.len - offset;
    char *ecmd = (char *)malloc(elen + 1);
    if (ecmd) {
      memcpy(ecmd, data.data + offset, elen);
      ecmd[elen] = '\0';
      oo_run_child_cmd(ecmd);
      _exit(127);
    }
    return r;
  }
  if ((data.len >= 8 && memcmp(data.data, "\0" "daemon:", 8) == 0) ||
      (data.len >= 9 && memcmp(data.data, "\x1b_daemon:", 9) == 0)) {
    char d_buf[8192];
    size_t offset = (data.data[0] == '\x1b') ? 9 : 8;
    size_t dlen = (size_t)data.len - offset;
    if (dlen < sizeof(d_buf)) {
      memcpy(d_buf, data.data + offset, dlen);
      d_buf[dlen] = '\0';
      char *sock = NULL;
      char *bin = NULL;
      char *cwd = NULL;
      char *cur = d_buf;
      while (cur && *cur) {
        char *next = strchr(cur, ';');
        if (next) *next = '\0';
        if (strncmp(cur, "sock=", 5) == 0) sock = cur + 5;
        else if (strncmp(cur, "bin=", 4) == 0) bin = cur + 4;
        else if (strncmp(cur, "cwd=", 4) == 0) cwd = cur + 4;
        cur = next ? next + 1 : NULL;
      }
      if (sock && bin) {
        // Run native epoll AF_UNIX daemon
        unlink(sock);
        char pdir[4096];
        strncpy(pdir, sock, sizeof(pdir) - 1);
        pdir[sizeof(pdir) - 1] = '\0';
        char *last_sl = strrchr(pdir, '/');
        if (last_sl && last_sl != pdir) {
          *last_sl = '\0';
          char mk_cmd[4096];
          snprintf(mk_cmd, sizeof(mk_cmd), "mkdir -p \"%s\" 2>/dev/null", pdir);
          system(mk_cmd);
        }
        int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (lfd >= 0) {
          struct sockaddr_un sa;
          memset(&sa, 0, sizeof(sa));
          sa.sun_family = AF_UNIX;
          strncpy(sa.sun_path, sock, sizeof(sa.sun_path) - 1);
          if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            chmod(sock, 0600);
            if (listen(lfd, 16) == 0) {
              int epfd = epoll_create1(EPOLL_CLOEXEC);
              if (epfd >= 0) {
                struct epoll_event ev;
                ev.events = EPOLLIN;
                ev.data.fd = lfd;
                epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &ev);
                s_daemon_running = 1;
                void (*old_int)(int) = signal(SIGINT, daemon_sig_handler);
                void (*old_term)(int) = signal(SIGTERM, daemon_sig_handler);
                void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);
                struct epoll_event evs[16];
                while (s_daemon_running) {
                  int nfds = epoll_wait(epfd, evs, 16, 500);
                  if (nfds < 0) {
                    if (errno == EINTR) continue;
                    break;
                  }
                  for (int ei = 0; ei < nfds; ei++) {
                    int efd = evs[ei].data.fd;
                    if (efd == lfd) {
                      int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
                      if (cfd >= 0) {
                        struct ucred cred;
                        socklen_t crlen = sizeof(cred);
                        if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &crlen) != 0 || cred.uid != getuid()) {
                          close(cfd);
                          continue;
                        }
                        struct epoll_event cev;
                        cev.events = EPOLLIN;
                        cev.data.fd = cfd;
                        epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev);
                      }
                    } else {
                      char req[16384];
                      ssize_t nr = read(efd, req, sizeof(req) - 1);
                      if (nr <= 0) {
                        epoll_ctl(epfd, EPOLL_CTL_DEL, efd, NULL);
                        close(efd);
                      } else {
                        epoll_ctl(epfd, EPOLL_CTL_DEL, efd, NULL);
                        req[nr] = '\0';
                        struct VarlinkWorkerArgs *a = (struct VarlinkWorkerArgs *)malloc(sizeof(struct VarlinkWorkerArgs));
                        if (a) {
                          a->efd = efd;
                          a->bin = strdup(bin);
                          a->cwd = strdup(cwd ? cwd : "");
                          memcpy(a->req, req, (size_t)nr);
                          a->req[nr] = '\0';
                          pthread_t th;
                          pthread_attr_t attr;
                          pthread_attr_init(&attr);
                          pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                          if (pthread_create(&th, &attr, varlink_worker_thread, a) != 0) {
                            varlink_worker_thread(a);
                          }
                          pthread_attr_destroy(&attr);
                        } else {
                          close(efd);
                        }
                      }
                    }
                  }
                }
                close(epfd);
                signal(SIGINT, old_int);
                signal(SIGTERM, old_term);
                signal(SIGPIPE, old_pipe);
              }
            }
            close(lfd);
            unlink(sock);
          } else {
            close(lfd);
          }
        }
      }
    }
    return r;
  }

  if ((data.len >= 6 && memcmp(data.data, "\x00pipe:", 6) == 0) ||
      (data.len >= 7 && memcmp(data.data, "\x1b_pipe:", 7) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 7 : 6;
    size_t plen = (size_t)data.len - offset;
    const char *payload = data.data + offset;
    const char *nl = (const char *)memchr(payload, '\n', plen);
    if (nl) {
      size_t cmd_len = (size_t)(nl - payload);
      char *cmd_buf = (char *)malloc(cmd_len + 1);
      if (cmd_buf) {
        memcpy(cmd_buf, payload, cmd_len);
        cmd_buf[cmd_len] = '\0';
        const char *inp = nl + 1;
        size_t inp_len = plen - (cmd_len + 1);
        int pfd[2];
        if (pipe2(pfd, O_CLOEXEC) == 0) {
          pid_t pid = fork();
          if (pid == 0) {
            dup2(pfd[0], STDIN_FILENO);
            close(pfd[0]);
            close(pfd[1]);
            oo_run_child_cmd(cmd_buf);
            _exit(127);
          }
          close(pfd[0]);
          if (inp_len > 0) {
            size_t w_tot = 0;
            while (w_tot < inp_len) {
              ssize_t w = write(pfd[1], inp + w_tot, inp_len - w_tot);
              if (w <= 0) break;
              w_tot += (size_t)w;
            }
          }
          close(pfd[1]);
          int st = 0;
          waitpid(pid, &st, 0);
          free(cmd_buf);
          int rc = WIFEXITED(st) ? WEXITSTATUS(st) : (WIFSIGNALED(st) ? 128 + WTERMSIG(st) : 1);
          char rc_buf[32];
          snprintf(rc_buf, sizeof(rc_buf), "%d", rc);
          r.ok = (rc == 0) ? 1 : 0;
          r.val = oo_str_intern_bytes(rc_buf, strlen(rc_buf));
          return r;
        }
        free(cmd_buf);
      }
    }
    r.ok = 0;
    r.val = oo_str_lit("pipe failed");
    return r;
  }
  if ((data.len >= 7 && memcmp(data.data, "\x00pipe2:", 7) == 0) ||
      (data.len >= 8 && memcmp(data.data, "\x1b_pipe2:", 8) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 8 : 7;
    size_t plen = (size_t)data.len - offset;
    const char *payload = data.data + offset;
    const char *nl = (const char *)memchr(payload, '\n', plen);
    if (nl) {
      size_t cmd1_len = (size_t)(nl - payload);
      char *cmd1 = (char *)malloc(cmd1_len + 1);
      size_t cmd2_len = plen - (cmd1_len + 1);
      char *cmd2 = (char *)malloc(cmd2_len + 1);
      if (cmd1 && cmd2) {
        memcpy(cmd1, payload, cmd1_len);
        cmd1[cmd1_len] = '\0';
        memcpy(cmd2, nl + 1, cmd2_len);
        cmd2[cmd2_len] = '\0';
        int pfd[2];
        if (pipe2(pfd, O_CLOEXEC) == 0) {
          pid_t pid1 = fork();
          if (pid1 == 0) {
            dup2(pfd[1], STDOUT_FILENO);
            close(pfd[0]);
            close(pfd[1]);
            oo_run_child_cmd(cmd1);
            _exit(127);
          }
          pid_t pid2 = fork();
          if (pid2 == 0) {
            dup2(pfd[0], STDIN_FILENO);
            close(pfd[0]);
            close(pfd[1]);
            oo_run_child_cmd(cmd2);
            _exit(127);
          }
          close(pfd[0]);
          close(pfd[1]);
          int st1 = 0, st2 = 0;
          waitpid(pid1, &st1, 0);
          waitpid(pid2, &st2, 0);
          free(cmd1);
          free(cmd2);
          int rc = WIFEXITED(st2) ? WEXITSTATUS(st2) : 1;
          char rc_buf[32];
          snprintf(rc_buf, sizeof(rc_buf), "%d", rc);
          r.ok = (rc == 0) ? 1 : 0;
          r.val = oo_str_intern_bytes(rc_buf, strlen(rc_buf));
          return r;
        }
      }
      if (cmd1) free(cmd1);
      if (cmd2) free(cmd2);
    }
    r.ok = 0;
    r.val = oo_str_lit("pipe2 failed");
    return r;
  }
  if ((data.len >= 7 && memcmp(data.data, "\x00redir:", 7) == 0) ||
      (data.len >= 8 && memcmp(data.data, "\x1b_redir:", 8) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 8 : 7;
    size_t plen = (size_t)data.len - offset;
    const char *payload = data.data + offset;
    const char *nl = (const char *)memchr(payload, '\n', plen);
    if (nl) {
      size_t hdr_len = (size_t)(nl - payload);
      char *hdr = (char *)malloc(hdr_len + 1);
      size_t cmd_len = plen - (hdr_len + 1);
      char *cmd = (char *)malloc(cmd_len + 1);
      if (hdr && cmd) {
        memcpy(hdr, payload, hdr_len);
        hdr[hdr_len] = '\0';
        memcpy(cmd, nl + 1, cmd_len);
        cmd[cmd_len] = '\0';
        char *colon = strchr(hdr, ':');
        if (colon) {
          *colon = '\0';
          const char *op = hdr;
          const char *filename = colon + 1;
          pid_t pid = fork();
          if (pid == 0) {
            int fd = -1;
            if (strcmp(op, "2>&1") == 0) {
              dup2(STDOUT_FILENO, STDERR_FILENO);
            } else if (strcmp(op, "2>") == 0) {
              fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0664);
              if (fd >= 0) { dup2(fd, STDERR_FILENO); close(fd); }
              else { perror("oosh"); _exit(1); }
            } else if (strcmp(op, "2>>") == 0) {
              fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0664);
              if (fd >= 0) { dup2(fd, STDERR_FILENO); close(fd); }
              else { perror("oosh"); _exit(1); }
            } else if (strcmp(op, "&>") == 0) {
              fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0664);
              if (fd >= 0) { dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd); }
              else { perror("oosh"); _exit(1); }
            } else if (strcmp(op, "<") == 0) {
              fd = open(filename, O_RDONLY);
              if (fd >= 0) { dup2(fd, STDIN_FILENO); close(fd); }
              else { perror("oosh"); _exit(1); }
            } else if (strcmp(op, ">>") == 0) {
              fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0664);
              if (fd >= 0) { dup2(fd, STDOUT_FILENO); close(fd); }
              else { perror("oosh"); _exit(1); }
            } else {
              fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0664);
              if (fd >= 0) { dup2(fd, STDOUT_FILENO); close(fd); }
              else { perror("oosh"); _exit(1); }
            }
            oo_run_child_cmd(cmd);
            _exit(127);
          }
          int st = 0;
          waitpid(pid, &st, 0);
          free(hdr);
          free(cmd);
          int rc = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
          char rc_buf[32];
          snprintf(rc_buf, sizeof(rc_buf), "%d", rc);
          r.ok = (rc == 0) ? 1 : 0;
          r.val = oo_str_intern_bytes(rc_buf, strlen(rc_buf));
          return r;
        }
      }
      if (hdr) free(hdr);
      if (cmd) free(cmd);
    }
    r.ok = 0;
    r.val = oo_str_lit("redir failed");
    return r;
  }
  static int s_saved_stdout = -1;
  static int s_saved_stderr = -1;
  static int s_saved_stdin = -1;
  if ((data.len >= 12 && memcmp(data.data, "\x00redir_push:", 12) == 0) ||
      (data.len >= 13 && memcmp(data.data, "\x1b_redir_push:", 13) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 13 : 12;
    size_t plen = (size_t)data.len - offset;
    char buf[4096];
    if (plen >= sizeof(buf)) plen = sizeof(buf) - 1;
    memcpy(buf, data.data + offset, plen);
    buf[plen] = '\0';
    char *colon = strchr(buf, ':');
    if (colon) {
      *colon = '\0';
      const char *op = buf;
      const char *filename = colon + 1;
      fflush(stdout);
      fflush(stderr);
      int fd = -1;
      if (strcmp(op, "2>&1") == 0) {
        if (s_saved_stderr < 0) s_saved_stderr = dup(STDERR_FILENO);
        dup2(STDOUT_FILENO, STDERR_FILENO);
      } else if (strcmp(op, "2>") == 0) {
        if (s_saved_stderr < 0) s_saved_stderr = dup(STDERR_FILENO);
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0664);
        if (fd >= 0) { dup2(fd, STDERR_FILENO); close(fd); }
      } else if (strcmp(op, "2>>") == 0) {
        if (s_saved_stderr < 0) s_saved_stderr = dup(STDERR_FILENO);
        fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0664);
        if (fd >= 0) { dup2(fd, STDERR_FILENO); close(fd); }
      } else if (strcmp(op, "&>") == 0) {
        if (s_saved_stdout < 0) s_saved_stdout = dup(STDOUT_FILENO);
        if (s_saved_stderr < 0) s_saved_stderr = dup(STDERR_FILENO);
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0664);
        if (fd >= 0) { dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd); }
      } else if (strcmp(op, "<") == 0) {
        if (s_saved_stdin < 0) s_saved_stdin = dup(STDIN_FILENO);
        fd = open(filename, O_RDONLY);
        if (fd >= 0) { dup2(fd, STDIN_FILENO); close(fd); }
      } else if (strcmp(op, ">>") == 0) {
        if (s_saved_stdout < 0) s_saved_stdout = dup(STDOUT_FILENO);
        fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0664);
        if (fd >= 0) { dup2(fd, STDOUT_FILENO); close(fd); }
      } else {
        if (s_saved_stdout < 0) s_saved_stdout = dup(STDOUT_FILENO);
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0664);
        if (fd >= 0) { dup2(fd, STDOUT_FILENO); close(fd); }
      }
    }
    r.ok = 1;
    r.val = oo_str_lit("0");
    return r;
  }
  if ((data.len >= 10 && memcmp(data.data, "\x00redir_pop", 10) == 0) ||
      (data.len >= 11 && memcmp(data.data, "\x1b_redir_pop", 11) == 0)) {
    fflush(stdout);
    fflush(stderr);
    if (s_saved_stdout >= 0) {
      dup2(s_saved_stdout, STDOUT_FILENO);
      close(s_saved_stdout);
      s_saved_stdout = -1;
    }
    if (s_saved_stderr >= 0) {
      dup2(s_saved_stderr, STDERR_FILENO);
      close(s_saved_stderr);
      s_saved_stderr = -1;
    }
    if (s_saved_stdin >= 0) {
      dup2(s_saved_stdin, STDIN_FILENO);
      close(s_saved_stdin);
      s_saved_stdin = -1;
    }
    r.ok = 1;
    r.val = oo_str_lit("0");
    return r;
  }
  if ((data.len >= 4 && memcmp(data.data, "\x00bg:", 4) == 0) ||
      (data.len >= 5 && memcmp(data.data, "\x1b_bg:", 5) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 5 : 4;
    size_t cmd_len = (size_t)data.len - offset;
    char *cmd_buf = (char *)malloc(cmd_len + 1);
    if (cmd_buf) {
      memcpy(cmd_buf, data.data + offset, cmd_len);
      cmd_buf[cmd_len] = '\0';
      pid_t pid = fork();
      if (pid == 0) {
        setpgid(0, 0);
        oo_run_child_cmd(cmd_buf);
        _exit(127);
      }
      free(cmd_buf);
      if (pid > 0) {
        setpgid(pid, pid);
        char pid_buf[32];
        snprintf(pid_buf, sizeof(pid_buf), "%d", (int)pid);
        r.ok = 1;
        r.val = oo_str_intern_bytes(pid_buf, strlen(pid_buf));
        return r;
      }
    }
    r.ok = 0;
    r.val = oo_str_lit("bg failed");
    return r;
  }
  if ((data.len >= 10 && memcmp(data.data, "\x00job_poll:", 10) == 0) ||
      (data.len >= 11 && memcmp(data.data, "\x1b_job_poll:", 11) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 11 : 10;
    char buf[32];
    size_t l = (size_t)data.len - offset;
    if (l >= sizeof(buf)) l = sizeof(buf) - 1;
    memcpy(buf, data.data + offset, l);
    buf[l] = '\0';
    pid_t pid = (pid_t)atoi(buf);
    int st = 0;
    pid_t ret = waitpid(pid, &st, WNOHANG);
    if (ret == 0) {
      r.ok = 1;
      r.val = oo_str_lit("Running");
    } else {
      r.ok = 1;
      r.val = oo_str_lit("Done");
    }
    return r;
  }
  if ((data.len >= 10 && memcmp(data.data, "\x00job_wait:", 10) == 0) ||
      (data.len >= 11 && memcmp(data.data, "\x1b_job_wait:", 11) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 11 : 10;
    char buf[32];
    size_t l = (size_t)data.len - offset;
    if (l >= sizeof(buf)) l = sizeof(buf) - 1;
    memcpy(buf, data.data + offset, l);
    buf[l] = '\0';
    pid_t pid = (l > 0) ? (pid_t)atoi(buf) : -1;
    int st = 0;
    if (pid <= 0) {
      while (waitpid(-1, &st, 0) > 0 || errno == EINTR) {}
    } else {
      while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    }
    r.ok = 1;
    r.val = oo_str_lit("0");
    return r;
  }
  if ((data.len >= 8 && memcmp(data.data, "\x00job_fg:", 8) == 0) ||
      (data.len >= 9 && memcmp(data.data, "\x1b_job_fg:", 9) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 9 : 8;
    char buf[32];
    size_t l = (size_t)data.len - offset;
    if (l >= sizeof(buf)) l = sizeof(buf) - 1;
    memcpy(buf, data.data + offset, l);
    buf[l] = '\0';
    pid_t pid = (pid_t)atoi(buf);
    pid_t pgrp = getpgid(pid);
    if (pgrp > 0 && isatty(STDIN_FILENO)) {
      tcsetpgrp(STDIN_FILENO, pgrp);
    }
    kill(-pgrp, SIGCONT);
    int st = 0;
    waitpid(pid, &st, WUNTRACED);
    if (isatty(STDIN_FILENO)) {
      tcsetpgrp(STDIN_FILENO, getpgrp());
    }
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : 0;
    char rc_buf[32];
    snprintf(rc_buf, sizeof(rc_buf), "%d", rc);
    r.ok = 1;
    r.val = oo_str_intern_bytes(rc_buf, strlen(rc_buf));
    return r;
  }
  if ((data.len >= 8 && memcmp(data.data, "\x00job_bg:", 8) == 0) ||
      (data.len >= 9 && memcmp(data.data, "\x1b_job_bg:", 9) == 0)) {
    size_t offset = (data.data[0] == '\x1b') ? 9 : 8;
    char buf[32];
    size_t l = (size_t)data.len - offset;
    if (l >= sizeof(buf)) l = sizeof(buf) - 1;
    memcpy(buf, data.data + offset, l);
    buf[l] = '\0';
    pid_t pid = (pid_t)atoi(buf);
    pid_t pgrp = getpgid(pid);
    if (pgrp > 0) {
      kill(-pgrp, SIGCONT);
    } else {
      kill(pid, SIGCONT);
    }
    r.ok = 1;
    r.val = oo_str_lit("Running");
    return r;
  }

  ssize_t nw = write(STDOUT_FILENO, data.data, (size_t)data.len);
  (void)nw;
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
