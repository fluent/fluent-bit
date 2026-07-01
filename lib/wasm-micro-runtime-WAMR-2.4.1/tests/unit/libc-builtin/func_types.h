/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#pragma once

#include "bh_platform.h"
#include "wasm_export.h"

extern "C" {
typedef char *_va_list;

typedef int (*printf_func_type)(wasm_exec_env_t exec_env, const char *format,
                                _va_list va_args);

typedef int (*sprintf_func_type)(wasm_exec_env_t exec_env, char *str,
                                 const char *format, _va_list va_args);

typedef int (*snprintf_func_type)(wasm_exec_env_t exec_env, char *str,
                                  uint32 size, const char *format,
                                  _va_list va_args);

typedef int (*puts_func_type)(wasm_exec_env_t exec_env, const char *str);

typedef int (*putchar_func_type)(wasm_exec_env_t exec_env, int c);

typedef uint32 (*strdup_func_type)(wasm_exec_env_t exec_env, const char *str);

typedef uint32 (*_strdup_func_type)(wasm_exec_env_t exec_env, const char *str);

typedef int32 (*memcmp_func_type)(wasm_exec_env_t exec_env, const void *s1,
                                  const void *s2, uint32 size);

typedef uint32 (*memcpy_func_type)(wasm_exec_env_t exec_env, void *dst,
                                   const void *src, uint32 size);

typedef uint32 (*memmove_func_type)(wasm_exec_env_t exec_env, void *dst,
                                    void *src, uint32 size);

typedef uint32 (*memset_func_type)(wasm_exec_env_t exec_env, void *s, int32 c,
                                   uint32 size);

typedef uint32 (*strchr_func_type)(wasm_exec_env_t exec_env, const char *s,
                                   int32 c);

typedef int32 (*strcmp_func_type)(wasm_exec_env_t exec_env, const char *s1,
                                  const char *s2);

typedef int32 (*strncmp_func_type)(wasm_exec_env_t exec_env, const char *s1,
                                   const char *s2, uint32 size);

typedef uint32 (*strcpy_func_type)(wasm_exec_env_t exec_env, char *dst,
                                   const char *src);

typedef uint32 (*strncpy_func_type)(wasm_exec_env_t exec_env, char *dst,
                                    const char *src, uint32 size);

typedef uint32 (*strlen_func_type)(wasm_exec_env_t exec_env, const char *s);

typedef uint32 (*malloc_func_type)(wasm_exec_env_t exec_env, uint32 size);

typedef uint32 (*calloc_func_type)(wasm_exec_env_t exec_env, uint32 nmemb,
                                   uint32 size);

typedef uint32 (*realloc_func_type)(wasm_exec_env_t exec_env, uint32 ptr,
                                    uint32 new_size);

typedef void (*free_func_type)(wasm_exec_env_t exec_env, void *ptr);

typedef int32 (*atoi_func_type)(wasm_exec_env_t exec_env, const char *s);

typedef void (*exit_func_type)(wasm_exec_env_t exec_env, int32 status);

typedef int32 (*strtol_func_type)(wasm_exec_env_t exec_env, const char *nptr,
                                  char **endptr, int32 base);

typedef uint32 (*strtoul_func_type)(wasm_exec_env_t exec_env, const char *nptr,
                                    char **endptr, int32 base);

typedef uint32 (*memchr_func_type)(wasm_exec_env_t exec_env, const void *s,
                                   int32 c, uint32 n);

typedef int32 (*strncasecmp_func_type)(wasm_exec_env_t exec_env, const char *s1,
                                       const char *s2, uint32 n);
typedef uint32 (*strspn_func_type)(wasm_exec_env_t exec_env, const char *s,
                                   const char *accept);

typedef uint32 (*strcspn_func_type)(wasm_exec_env_t exec_env, const char *s,
                                    const char *reject);

typedef uint32 (*strstr_func_type)(wasm_exec_env_t exec_env, const char *s,
                                   const char *find);

typedef int32 (*isupper_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef int32 (*isalpha_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef int32 (*isspace_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef int32 (*isgraph_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef int32 (*isprint_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef int32 (*isdigit_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef int32 (*isxdigit_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef int32 (*tolower_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef int32 (*toupper_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef int32 (*isalnum_func_type)(wasm_exec_env_t exec_env, int32 c);

typedef void (*setTempRet0_func_type)(wasm_exec_env_t exec_env,
                                      uint32 temp_ret);

typedef uint32 (*getTempRet0_func_type)(wasm_exec_env_t exec_env);

typedef uint32 (*llvm_bswap_i16_func_type)(wasm_exec_env_t exec_env,
                                           uint32 data);

typedef uint32 (*llvm_bswap_i32_func_type)(wasm_exec_env_t exec_env,
                                           uint32 data);

typedef uint32 (*bitshift64Lshr_func_type)(wasm_exec_env_t exec_env,
                                           uint32 uint64_part0,
                                           uint32 uint64_part1, uint32 bits);

typedef uint32 (*bitshift64Shl_func_type)(wasm_exec_env_t exec_env,
                                          uint32 int64_part0,
                                          uint32 int64_part1, uint32 bits);

typedef void (*llvm_stackrestore_func_type)(wasm_exec_env_t exec_env,
                                            uint32 llvm_stack);

typedef uint32 (*llvm_stacksave_func_type)(wasm_exec_env_t exec_env);

typedef uint32 (*emscripten_memcpy_big_func_type)(wasm_exec_env_t exec_env,
                                                  void *dst, const void *src,
                                                  uint32 size);

typedef void (*abort_func_type)(wasm_exec_env_t exec_env, int32 code);

typedef void (*abortStackOverflow_func_type)(wasm_exec_env_t exec_env,
                                             int32 code);

typedef void (*nullFunc_X_func_type)(wasm_exec_env_t exec_env, int32 code);

typedef uint32 (*__cxa_allocate_exception_func_type)(wasm_exec_env_t exec_env,
                                                     uint32 thrown_size);

typedef void (*__cxa_begin_catch_func_type)(wasm_exec_env_t exec_env,
                                            void *exception_object);

typedef void (*__cxa_throw_func_type)(wasm_exec_env_t exec_env,
                                      void *thrown_exception, void *tinfo,
                                      uint32 table_elem_idx);

struct timespec_app {
    int64 tv_sec;
    int32 tv_nsec;
};

typedef uint32 (*clock_gettime_func_type)(wasm_exec_env_t exec_env,
                                          uint32 clk_id,
                                          struct timespec_app *ts_app);

typedef uint64 (*clock_func_type)(wasm_exec_env_t exec_env);
}
