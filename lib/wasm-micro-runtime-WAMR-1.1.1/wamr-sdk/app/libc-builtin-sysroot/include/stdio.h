/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WAMR_LIBC_STDIO_H
#define _WAMR_LIBC_STDIO_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#  define NULL ((void*) 0)
#endif

typedef unsigned long size_t;

int printf(const char *format, ...);
int putchar(int c);
int snprintf(char *str, size_t size, const char *format, ...);
int sprintf(char *str, const char *format, ...);
int puts(char *string);


#ifdef __cplusplus
}
#endif

#endif