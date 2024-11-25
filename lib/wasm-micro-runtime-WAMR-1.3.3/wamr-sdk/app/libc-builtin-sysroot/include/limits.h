/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WAMR_LIBC_LIMITS_H
#define _WAMR_LIBC_LIMITS_H

#ifdef __cplusplus
extern "C" {
#endif

#define CHAR_BIT    8
#define SCHAR_MIN   -128
#define SCHAR_MAX   127
#define UCHAR_MAX   255
#define CHAR_MIN    0
#define CHAR_MAX    127
#define MB_LEN_MAX  1
#define SHRT_MIN    -32768
#define SHRT_MAX    +32767
#define USHRT_MAX   65535
#define INT_MIN     -32768
#define INT_MAX     +32767
#define UINT_MAX    65535
#define LONG_MIN    -2147483648
#define LONG_MAX    +2147483647
#define ULONG_MAX   4294967295

#ifdef __cplusplus
}
#endif

#endif