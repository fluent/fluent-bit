/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <stdint.h>
#include <stdlib.h>

#define ANALYZER_VERSION_STRING "1.0.0"

#define WASM_MAGIC_NUMBER 0x6d736100
#define WASM_CURRENT_VERSION 1

#define AOT_MAGIC_NUMBER 0x746f6100
#define AOT_CURRENT_VERSION 5

/* Legal values for bin_type */
#define BIN_TYPE_ELF32L 0 /* 32-bit little endian */
#define BIN_TYPE_ELF32B 1 /* 32-bit big endian */
#define BIN_TYPE_ELF64L 2 /* 64-bit little endian */
#define BIN_TYPE_ELF64B 3 /* 64-bit big endian */
#define BIN_TYPE_COFF32 4 /* 32-bit little endian */
#define BIN_TYPE_COFF64 6 /* 64-bit little endian */

/* Legal values for e_type (object file type). */
#define E_TYPE_NONE 0 /* No file type */
#define E_TYPE_REL 1  /* Relocatable file */
#define E_TYPE_EXEC 2 /* Executable file */
#define E_TYPE_DYN 3  /* Shared object file */
#define E_TYPE_XIP 4  /* eXecute In Place file */

/* Legal values for e_machine (architecture).  */
#define E_MACHINE_386 3             /* Intel 80386 */
#define E_MACHINE_MIPS 8            /* MIPS R3000 big-endian */
#define E_MACHINE_MIPS_RS3_LE 10    /* MIPS R3000 little-endian */
#define E_MACHINE_ARM 40            /* ARM/Thumb */
#define E_MACHINE_AARCH64 183       /* AArch64 */
#define E_MACHINE_ARC 45            /* Argonaut RISC Core */
#define E_MACHINE_IA_64 50          /* Intel Merced */
#define E_MACHINE_MIPS_X 51         /* Stanford MIPS-X */
#define E_MACHINE_X86_64 62         /* AMD x86-64 architecture */
#define E_MACHINE_ARC_COMPACT 93    /* ARC International ARCompact */
#define E_MACHINE_ARC_COMPACT2 195  /* Synopsys ARCompact V2 */
#define E_MACHINE_XTENSA 94         /* Tensilica Xtensa Architecture */
#define E_MACHINE_RISCV 243         /* RISC-V 32/64 */
#define E_MACHINE_WIN_I386 0x14c    /* Windows i386 architecture */
#define E_MACHINE_WIN_X86_64 0x8664 /* Windows x86-64 architecture */

/* Whether <alloca.h> is available */
#define HAVE_ALLOCA_H 1

/* Whether snprintf is defined by stdio.h */
#define HAVE_SNPRINTF 1

/* Whether ssize_t is defined by stddef.h */
#define HAVE_SSIZE_T 1

/* Whether strcasecmp is defined by strings.h */
#define HAVE_STRCASECMP 1

#define COMPILER_IS_CLANG 0
#define COMPILER_IS_GNU 1
#define COMPILER_IS_MSVC 0

#define WITH_EXCEPTIONS 0

#define SIZEOF_SIZE_T 8

#if HAVE_ALLOCA_H
#include <alloca.h>
#elif COMPILER_IS_MSVC
#include <malloc.h>
#define alloca _alloca
#elif defined(__MINGW32__)
#include <malloc.h>
#endif

#if COMPILER_IS_CLANG || COMPILER_IS_GNU

#if __MINGW32__
#define ANALYZER_PRINTF_FORMAT(format_arg, first_arg) \
    __attribute__((format(gnu_printf, (format_arg), (first_arg))))
#else
#define ANALYZER_PRINTF_FORMAT(format_arg, first_arg) \
    __attribute__((format(printf, (format_arg), (first_arg))))
#endif

#ifdef __cplusplus
#define ANALYZER_STATIC_ASSERT(x) static_assert((x), #x)
#else
#define ANALYZER_STATIC_ASSERT(x) _Static_assert((x), #x)
#endif

#elif COMPILER_IS_MSVC

#include <intrin.h>
#include <string.h>

#define ANALYZER_STATIC_ASSERT(x) _STATIC_ASSERT(x)
#define ANALYZER_PRINTF_FORMAT(format_arg, first_arg)

#else

#error unknown compiler

#endif

#define ANALYZER_UNREACHABLE abort()

#ifdef __cplusplus

#if COMPILER_IS_MSVC

#elif COMPILER_IS_CLANG || COMPILER_IS_GNU

/* print format specifier for size_t */
#define PRIzd "zd"
#define PRIzx "zx"

#else

#error unknown compiler

#endif

#if HAVE_SNPRINTF
#define analyzer_snprintf snprintf
#elif COMPILER_IS_MSVC
#include <cstdarg>
int
analyzer_snprintf(char *str, size_t size, const char *format, ...);
#else
#error no snprintf
#endif

#if COMPILER_IS_MSVC
int
analyzer_vsnprintf(char *str, size_t size, const char *format, va_list ap);
#else
#define analyzer_vsnprintf vsnprintf
#endif

#if !HAVE_SSIZE_T
#if COMPILER_IS_MSVC
#if defined(_WIN64)
typedef signed __int64 ssize_t;
#else
typedef signed int ssize_t;
#endif
#else
typedef long ssize_t;
#endif
#endif

#if !HAVE_STRCASECMP
#if COMPILER_IS_MSVC
#define strcasecmp _stricmp
#else
#error no strcasecmp
#endif
#endif

#endif

#endif
