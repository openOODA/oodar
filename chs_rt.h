#ifndef CHS_RT_H
#define CHS_RT_H
#include "chs_rt_types.h"
#include "chs_rt_caps.h"

#ifndef __has_builtin
  #define __has_builtin(x) 0
#endif

#if !__has_builtin(__builtin_expect_with_probability) && (!defined(__GNUC__) || __GNUC__ < 9)
  #ifndef __builtin_expect_with_probability
    #if defined(__GNUC__) || defined(__clang__)
      #define __builtin_expect_with_probability(exp, c, prob) __builtin_expect((exp), (c))
    #else
      #define __builtin_expect_with_probability(exp, c, prob) (exp)
    #endif
  #endif
#endif

#ifndef __builtin_expect
  #if !defined(__GNUC__) && !defined(__clang__)
    #define __builtin_expect(exp, c) (exp)
  #endif
#endif

#ifndef OO_HOT
  #if defined(__GNUC__) || defined(__clang__)
    #define OO_HOT __attribute__((hot))
    #define OO_COLD __attribute__((cold, noinline))
    #define OO_ALWAYS_INLINE __attribute__((always_inline))
  #else
    #define OO_HOT
    #define OO_COLD
    #define OO_ALWAYS_INLINE
  #endif
#endif

void oo_emit_tmp_reset(void);
void oo_emit_tmp_enter(void);
void oo_emit_tmp_leave(void);
void oo_emit_tmp_release_print(void);
void oo_emit_tmp_own(OoStr expr);
void oo_emit_tmp_release_all_print(void);
OoStr oo_emit_tmp_bind(OoStr call);

void oo_print_str(OoStr s);
void oo_eprint_str(OoStr s);
void oo_print_int(long long n);
void oo_print_bool(int b);
void oo_print_double(double x);
void oo_println(void);
void oo_eprintln(void);

double oo_sin(double x);
double oo_cos(double x);
double oo_ln(double x);
double oo_exp(double x);
double oo_sqrt(double x);
double oo_pow(double base, double expn);

OoResS oo_read_file(long long cap, OoStr path);
OoResV oo_write_file(long long cap, OoStr path, OoStr content);
int oo_path_exists(long long cap, OoStr path);
long long oo_file_size(long long cap, OoStr path);
OoResS oo_env_get(long long cap, OoStr key);
long long fs_file_size(long long cap, OoStr path);
OoSList oo_fs_read_dir(long long cap, OoStr path);
int oo_fs_is_dir(long long cap, OoStr path);
OoResV oo_fs_remove_file(long long cap, OoStr path);
OoResV oo_fs_rmdir(long long cap, OoStr path);
OoResV oo_fs_mkdir(long long cap, OoStr path);
OoResV oo_fs_hardlink(long long cap, OoStr oldpath, OoStr newpath);
OoResV oo_fs_symlink(long long cap, OoStr target, OoStr linkpath);
int path_under_allowdir(const char *rp, const char *dir);
int path_under_sys_lib(const char *rp);
int ffi_verify_signature(const char *path);

OoSList oo_sys_args(long long cap);
OoResS oo_sys_exec(long long cap, int argc, OoStr *argv);
OoResS oo_sys_spawn(long long cap, OoStr cmd);
OoResS oo_sys_wait(long long cap, long long pid);
OoResS oo_sys_kill(long long cap, long long pid, long long sig);
OoResS oo_sys_epoll_create(long long cap, long long flags);
OoResS oo_sys_inotify_init(long long cap);
OoResS oo_sys_prctl(long long cap, long long option);
const char *oo_process_policy_getenv(const char *key);
void oo_child_filter_env(void);
void oo_process_exit(long long c);
OoResS oo_proc_mem_read(long long cap, long long offset, long long n);

OoResS oo_dlopen(long long cap, OoStr path);
OoResS oo_dlsym(long long cap, OoStr handle, OoStr name);
OoResS oo_dlclose(long long cap, OoStr handle);
OoStr oo_host_ast_dump(long long cap, OoStr path);
OoStr oo_host_check(long long cap, OoStr path);
OoStr oo_host_token_dump(long long cap, OoStr path);
OoResS oo_chs_build(long long cap, OoStr src, OoStr out_bin);

OoStr crypto_md5_internal(OoStr data);
OoStr crypto_sha1_internal(OoStr data);
OoStr crypto_aes_encrypt_internal(OoStr key, OoStr plain);
OoStr crypto_sha256_internal(OoStr data);
OoStr crypto_sha512_internal(OoStr data);
OoStr crypto_hmac_sha256_internal(OoStr key, OoStr msg);
void crypto_secure_wipe(void *p, size_t n);
int crypto_ct_cmp(const void *a, const void *b, size_t n);
OoStr crypto_sha3_256_internal(OoStr data);
OoStr crypto_aes_gcm_seal_internal(OoStr key, OoStr nonce, OoStr pt, OoStr aad);
OoStr crypto_aes_gcm_open_internal(OoStr key, OoStr nonce, OoStr ct, OoStr tag, OoStr aad);
OoStr crypto_chacha20poly1305_seal_internal(OoStr key, OoStr nonce, OoStr pt, OoStr aad);
OoStr crypto_chacha20poly1305_open_internal(OoStr key, OoStr nonce, OoStr ct, OoStr tag, OoStr aad);
OoStr crypto_mlkem768_keygen_internal(OoStr dz);
OoStr crypto_mlkem768_encaps_internal(OoStr ek, OoStr m);
OoStr crypto_mlkem768_decaps_internal(OoStr dk, OoStr ct);
OoStr crypto_mldsa65_keygen_internal(OoStr seed);
OoStr crypto_mldsa65_sign_internal(OoStr sk, OoStr msg, OoStr rnd);
OoStr crypto_mldsa65_verify_internal(OoStr pk, OoStr msg, OoStr sig);
OoStr crypto_pq_hmac_sha256_internal(OoStr key, OoStr msg);
int crypto_pq_hmac_sha256_verify_internal(OoStr seal, OoStr msg);
int crypto_pq_hmac_self_test(void);
OoStr crypto_pq_aead_seal_internal(OoStr cap_key32, OoStr aead_key16, OoStr plaintext);
OoStr crypto_pq_aead_open_internal(OoStr cap_key32, OoStr aead_key16, OoStr seal);

int oo_metrics_incr(OoStr name);
long long oo_metrics_get(OoStr name);
int oo_metrics_reset(OoStr name);
OoStr oo_metrics_export(void);
int oo_metrics_self_test(void);
void oo_metrics_cap_seal(void);
void oo_metrics_cap_attenuate(void);
void oo_metrics_pq_sign(void);
void oo_metrics_pq_verify(void);
void oo_metrics_aead_seal(void);
void oo_metrics_aead_open(void);
void oo_metrics_fs_read(void);
void oo_metrics_fs_write(void);

long long oo_byte_at(OoStr s, long long idx);
long long oo_str_byte_at(OoStr s, long long idx);
long long oo_limb_add(long long a, long long b, long long cin, long long *cout);
long long oo_limb_sub(long long a, long long b, long long bin, long long *bout);
long long oo_limb_mul(long long a, long long b, long long cin, long long *hi);
long long oo_limb_div(long long hi, long long lo, long long divisor, long long *rem);
long long oo_limb_cmp(long long a, long long b);
long long oo_bytes_len(OoStr s);
OoStr oo_byte_slice(OoStr s, long long start, long long end);
int oo_bytes_eq(OoStr a, OoStr b);
OoStr oo_bytes_from_str(OoStr s);
OoStr oo_bytes_concat(OoStr a, OoStr b);
OoIList oo_bytes_new(void);
OoIList oo_bytes_push(OoIList l, long long b);
long long oo_bytes_get(OoIList l, long long i);
OoStr oo_bytes_to_str(OoIList l);

OoResS oo_tcp_bind(long long cap, long long port);
OoResS oo_tcp_accept(long long cap, long long listen_slot);
OoResS oo_tcp_connect(long long cap, OoStr host, long long port);
OoResS oo_bind_udp(long long cap, long long port);
OoResS oo_tcp_write(long long cap, long long slot, OoStr data);
OoResS oo_tcp_read(long long cap, long long slot, long long max_n);
OoResS oo_udp_recv(long long cap, long long slot, long long max_n);
OoResS oo_udp_send(long long cap, long long slot, OoStr host, long long port, OoStr data);
OoResS oo_tcp_close(long long cap, long long slot);
OoResS oo_sock_raw(long long cap, long long proto);
OoResS oo_tls_connect(long long cap, OoStr host, long long port);

OoResS oo_mutex_lock(long long cap, long long mid);
OoResS oo_mutex_unlock(long long cap, long long mid);
OoResS oo_thread_spawn(long long cap, OoStr name);
OoResS oo_thread_join(long long cap, long long slot);
OoResS oo_thread_join_s(long long cap, OoStr tid);
OoResS oo_channel_new(long long cap);
OoResS oo_channel_send(long long cap, long long slot, OoStr msg);
OoResS oo_channel_recv(long long cap, long long slot);
OoResS oo_channel_destroy(long long cap, long long slot);
OoResS oo_actor_spawn(long long cap, OoStr name);
OoResS oo_actor_send(long long cap, long long id, OoStr msg);
OoResS oo_actor_recv(long long cap, long long id);
OoResS oo_actor_destroy(long long cap, long long id);
OoResS oo_actor_restart(long long cap, long long id);
OoResS oo_otp_supervise(long long cap, long long id);

long long oo_meta_epoch(void);
long long oo_meta_mix(long long salt);
int oo_meta_is_path_a(void);
void oo_meta_decoy_touch(void);
OoResS oo_verify_human(long long env, long long fs, OoStr msg);
OoResS oo_gpu_launch(long long cap, OoStr shader);
int oo_gpu_hip_available(void);
OoResS oo_gpu_hip_vec_add(long long cap, float *a, float *b, float *c, int n);
OoResS oo_gpu_hip_try_launch(long long cap, OoStr shader);
OoResS oo_fetch(long long cap, OoStr url);

long long oo_now_ms(long long cap);
void oo_sleep_ms(long long cap, long long ms);
long long oo_random(long long cap);
#ifndef OO_ALLOC_BYTES_MAX
#define OO_ALLOC_BYTES_MAX (1LL << 30) /* 1 GiB per allocation ceiling */
#endif
long long oo_alloc_bytes(long long cap, long long n);
void oo_free_bytes(long long cap, long long p);
long long oo_alloc(long long size);
void oo_free(long long ptr);
void (oo_write_int)(long long ptr, long long offset, long long val);
long long (oo_read_int)(long long ptr, long long offset);
long long heap_alloc_test(void);

#ifndef oo_write_int
#define OO_WRITE_INT_GET_MACRO(_1, _2, _3, NAME, ...) NAME
#define oo_write_int_2(p, v) (oo_write_int)((p), 0LL, (v))
#define oo_write_int_3(p, o, v) (oo_write_int)((p), (o), (v))
#define oo_write_int(...) OO_WRITE_INT_GET_MACRO(__VA_ARGS__, oo_write_int_3, oo_write_int_2)(__VA_ARGS__)
#endif

#ifndef oo_read_int
#define OO_READ_INT_GET_MACRO(_1, _2, NAME, ...) NAME
#define oo_read_int_1(p) (oo_read_int)((p), 0LL)
#define oo_read_int_2(p, o) (oo_read_int)((p), (o))
#define oo_read_int(...) OO_READ_INT_GET_MACRO(__VA_ARGS__, oo_read_int_2, oo_read_int_1)(__VA_ARGS__)
#endif
long long oo_cg_sign(long long cap);
int oo_cg_verify(long long cap, long long sig);

OoSList str_split(OoStr s, OoStr delim);
OoStr str_trim(OoStr s);

OoResS oo_rlimit_set_mem_mb(long long cap, long long megabytes);
OoResS oo_rlimit_set_nofile(long long cap, long long max_fds);
OoResS oo_rlimit_set_cpu_sec(long long cap, long long seconds);

int oo_landlock_is_available(void);
OoResS oo_landlock_restrict(long long cap, OoStr read_dirs_colon, OoStr write_dirs_colon);

OoResS oo_arena_create(long long cap, long long bytes);
OoResS oo_arena_alloc(long long cap, long long id, long long n);
OoResS oo_arena_reset(long long cap, long long id);
OoResS oo_arena_destroy(long long cap, long long id);
void oo_arena_free(long long cap, long long id);
long long oo_soa_layout(OoStr name);
long long oo_dod_layout(long long n);
long long oo_checkpoint(long long v);
long long oo_rollback(void);

OoResS oo_cap_rpc_send(long long cap, OoStr payload);
OoResS oo_cap_rpc_recv(long long cap, OoStr sealed);
OoStr oo_read_stdin(void);
OoResS oo_read_stdin_chunk(long long timeout_ms);
OoStr oo_file_stamp(OoStr path);
long long oo_import_c(long long cap, OoStr hdr);
long long oo_ffi_gen(long long cap, OoStr hdr);
long long oo_lto_xlang_link(long long cap, OoStr a, OoStr b);
OoStr oo_str_macro_expand(OoStr src);
OoStr oo_str_ast_macro(OoStr src);

#endif
