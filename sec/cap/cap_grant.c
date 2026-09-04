/* oo_cap_grant_* — per-token cap issuers. Each function returns the
 * process-local g_tok_* value for its kind. Ordering: caps.c
 * (orchestrator) must be included before this file so g_tok_*,
 * oo_caps_init, and oo_sandbox_note_* are visible. */

long long oo_cap_grant_fs(void) { oo_caps_init(); return g_tok_fs; }
long long oo_cap_grant_sys(void) { oo_caps_init(); oo_sandbox_note_proc(); return g_tok_sys; }
long long oo_cap_grant_env(void) { oo_caps_init(); return g_tok_env; }
long long oo_cap_grant_net(void) { oo_caps_init(); oo_sandbox_note_net(); return g_tok_net; }
long long oo_cap_grant_sign(void) { oo_caps_init(); return g_tok_sign; }
long long oo_cap_grant_process(void) { oo_caps_init(); oo_sandbox_note_proc(); return g_tok_process; }
/* v2.1.0: removed oo_cap_grant_sync, oo_cap_grant_mem, oo_cap_grant_http
 * (dead caps — granted but never required). */
long long oo_cap_grant_tcp(void) { oo_caps_init(); oo_sandbox_note_net(); return g_tok_tcp; }
long long oo_cap_grant_udp(void) { oo_caps_init(); oo_sandbox_note_net(); return g_tok_udp; }
long long oo_cap_grant_bind(void) { oo_caps_init(); oo_sandbox_note_net(); return g_tok_bind; }
long long oo_cap_grant_audio(void) { oo_caps_init(); return g_tok_audio; }
long long oo_cap_grant_camera(void) { oo_caps_init(); return g_tok_camera; }
long long oo_cap_grant_usb(void) { oo_caps_init(); return g_tok_usb; }
long long oo_cap_grant_hid(void) { oo_caps_init(); return g_tok_hid; }
long long oo_cap_grant_window(void) { oo_caps_init(); return g_tok_window; }
long long oo_cap_grant_frame(void) { oo_caps_init(); return g_tok_frame; }
long long oo_cap_grant_fsread(void) { oo_caps_init(); return g_tok_fsread; }
long long oo_cap_grant_fswrite(void) { oo_caps_init(); return g_tok_fswrite; }
long long oo_cap_grant_arena(void) { oo_caps_init(); return g_tok_arena; }
long long oo_cap_grant_thread(void) { oo_caps_init(); return g_tok_thread; }
long long oo_cap_grant_gpu(void) { oo_caps_init(); return g_tok_gpu; }
long long oo_cap_grant_compiler_read(void) { oo_caps_init(); return g_tok_compiler_read; }
long long oo_cap_grant_metrics(void) { oo_caps_init(); return g_tok_metrics; }
