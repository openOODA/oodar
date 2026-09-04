#ifndef OODAR_CAPS_H
#define OODAR_CAPS_H
#include "../../types.h"
#include "../landlock/sandbox.h"

#define OODAR_CAP_NET 1u
#define OODAR_CAP_PROCESS 2u
#define OODAR_CAP_FSWRITE 4u
#define OODAR_CAP_FSREAD 8u
#define OODAR_CAP_SYS 16u
#define OODAR_CAP_FS 32u
#define OODAR_CAP_TIME 64u
#define OODAR_CAP_RAND 128u
#define OODAR_CAP_ALLOC 256u
#define OODAR_CAP_ARENA 512u
#define OODAR_CAP_FFI 1024u
#define OODAR_CAP_AUDIT 2048u
#define OODAR_CAP_SIGN 4096u
#define OODAR_CAP_HITL 8192u
#define OODAR_CAP_SYNC 16384u
#define OODAR_CAP_MEM 32768u
#define OODAR_CAP_HTTP (1u << 16)
#define OODAR_CAP_TCP (1u << 17)
#define OODAR_CAP_UDP (1u << 18)
#define OODAR_CAP_BIND (1u << 19)
#define OODAR_CAP_AUDIO (1u << 20)
#define OODAR_CAP_CAMERA (1u << 21)
#define OODAR_CAP_USB (1u << 22)
#define OODAR_CAP_HID (1u << 23)
#define OODAR_CAP_WINDOW (1u << 24)
#define OODAR_CAP_FRAME (1u << 25)
#define OODAR_CAP_THREAD (1u << 26)
#define OODAR_CAP_GPU (1u << 27)
#define OODAR_CAP_ENV (1u << 28)
#define OODAR_CAP_COMPILER_READ (1u << 29)

void oodar_cap_init(void);
void oodar_cap_drop(void);
int oodar_cap_is_sandboxed(void);
int oodar_cap_apply_seccomp_filter(uint32_t allowed_caps_mask);

long long oo_cap_grant_fs(void);
long long oo_cap_grant_sys(void);
long long oo_cap_grant_env(void);
long long oo_cap_grant_net(void);
long long oo_cap_grant_time(void);
long long oo_cap_grant_rand(void);
long long oo_cap_grant_alloc(void);
long long oo_cap_grant_arena(void);
long long oo_cap_grant_ffi(void);
long long oo_cap_grant_audit(void);
long long oo_cap_grant_sign(void);
long long oo_cap_grant_hitl(void);
long long oo_cap_grant_process(void);
long long oo_cap_grant_sync(void);
long long oo_cap_grant_mem(void);
long long oo_cap_grant_http(void);
long long oo_cap_grant_tcp(void);
long long oo_cap_grant_udp(void);
long long oo_cap_grant_bind(void);
long long oo_cap_grant_audio(void);
long long oo_cap_grant_camera(void);
long long oo_cap_grant_usb(void);
long long oo_cap_grant_hid(void);
long long oo_cap_grant_window(void);
long long oo_cap_grant_frame(void);
long long oo_cap_grant_fsread(void);
long long oo_cap_grant_fswrite(void);
long long oo_cap_grant_thread(void);
long long oo_cap_grant_gpu(void);
long long oo_cap_grant_compiler_read(void);

void oo_cap_require(long long got, long long want, const char *op);
void oo_cap_require_fs(long long got, const char *op);
void oo_cap_require_sys(long long got, const char *op);
void oo_cap_require_env(long long got, const char *op);
void oo_cap_require_net(long long got, const char *op);
void oo_cap_require_time(long long got, const char *op);
void oo_cap_require_rand(long long got, const char *op);
void oo_cap_require_alloc(long long got, const char *op);
void oo_cap_require_arena(long long got, const char *op);
int oo_cap_is_arena(long long got);
int oo_cap_is_alloc(long long got);
void oo_cap_require_ffi(long long got, const char *op);
void oo_cap_require_audit(long long got, const char *op);
void oo_cap_require_sign(long long got, const char *op);
void oo_cap_require_hitl(long long got, const char *op);
void oo_cap_require_process(long long got, const char *op);
void oo_cap_require_sync(long long got, const char *op);
void oo_cap_require_mem(long long got, const char *op);
void oo_cap_require_http(long long got, const char *op);
void oo_cap_require_tcp(long long got, const char *op);
void oo_cap_require_udp(long long got, const char *op);
void oo_cap_require_bind(long long got, const char *op);
void oo_cap_require_audio(long long got, const char *op);
void oo_cap_require_camera(long long got, const char *op);
void oo_cap_require_usb(long long got, const char *op);
void oo_cap_require_hid(long long got, const char *op);
void oo_cap_require_window(long long got, const char *op);
void oo_cap_require_frame(long long got, const char *op);
void oo_cap_require_fsread(long long got, const char *op);
void oo_cap_require_fswrite(long long got, const char *op);
void oo_cap_require_thread(long long got, const char *op);
void oo_cap_require_gpu(long long got, const char *op);
void oo_cap_require_compiler_read(long long got, const char *op);

OoStr cap_attenuate(OoStr parent_hmac, OoStr child_rights);
int cap_attenuate_ok(OoStr parent_hmac, OoStr child_rights);
OoStr oo_cap_attenuate(OoStr parent_hmac, OoStr child_rights);
int oo_cap_attenuate_ok(OoStr parent_hmac, OoStr child_rights);
OoStr oo_cap_kernel_seal(long long sys, OoStr cap_id);
OoStr oo_enclave_enter(long long sys, OoStr sealed);

#endif
