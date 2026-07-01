/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#ifndef FLB_IN_EXEC_WIN32_COMPAT_H
#define FLB_IN_EXEC_WIN32_COMPAT_H

#include <stdio.h>
#include <fluent-bit/flb_info.h>

/*
 * Work around lack of sys/wait.h and POSIX exit status macros from waitpid()
 * in win32's _popen() and _pclose() implementation, since fluent-bit uses
 * these in the in_exec plugin.
 *
 * On POSIX-like OSes this'll just use the standard macros with a name alias.
 *
 * On windows, where the concept of a signal exit does not exist, it defines
 * dummy macros to indicate that the process exited normally and extract the
 * exit code.
 *
 * These macros are for use with flb_pclose() only. Do not use them with
 * other APIs that may differ in return value semantics.
 */
#ifdef FLB_HAVE_SYS_WAIT_H
#include <sys/wait.h>
#define FLB_WIFEXITED(status) WIFEXITED((status))
#define FLB_WEXITSTATUS(status) WEXITSTATUS((status))
#define FLB_WIFSIGNALED(status) WIFSIGNALED((status))
#define FLB_WTERMSIG(status) WTERMSIG((status))
#else
#define FLB_WIFEXITED(status) (1)
#define FLB_WEXITSTATUS(status) ((status) & 0x00ff)
#define FLB_WIFSIGNALED(status) (0)
#define FLB_WTERMSIG(status) (-1)
#endif

/*
 * Because Windows has to do everything differently, call _popen() and
 * _pclose() instead of the POSIX popen() and pclose() functions.
 *
 * flb_pclose() has different return value semantics on Windows vs non-windows
 * targets because it propagates the pclose() or _pclose() return value
 * directly. You MUST use the FLB_WIFEXITED(), FLB_WEXITSTATUS(),
 * FLB_WIFSIGNALED() and FLB_WTERMSIG() macros to consume the return value,
 * rather than the underlying POSIX macros or manual bit-shifts.
 */
#if !defined(FLB_SYSTEM_WINDOWS)
static inline FILE* flb_popen(const char *command, const char *type) {
    return popen(command, type);
}
static inline int flb_pclose(FILE *stream) {
    return pclose(stream);
}
#define FLB_PCLOSE pclose
#else
static inline FILE* flb_popen(const char *command, const char *type) {
    return _popen(command, type);
}
/*
 * flb_pclose() has the same return value on Windows as win32 _pclose(), rather
 * than posix pclose(). The process exit code is not bit-shifted to the high
 * byte.
 *
 * The MSVC docs for _pclose() at
 * https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/pclose?view=msvc-170
 * are misleading; they say that "The format of the return value is the same as
 * for _cwait, except the low-order and high-order bytes are swapped." But
 * _cwait isn't documented as having any meaningful return on success, the
 * process exit code is meant to be in  its "termstat" out parameter per
 * https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/cwait?view=msvc-170
 * The return code of _pclose() actually appears to be the process exit code
 * without the bit-shift that waitpid() applies.
 */
static inline int flb_pclose(FILE *stream) {
    return _pclose(stream);
}
#endif

#endif /* FLB_IN_EXEC_WIN32_COMPAT_H */
