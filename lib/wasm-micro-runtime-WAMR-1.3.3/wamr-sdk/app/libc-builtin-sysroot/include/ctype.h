/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WAMR_LIBC_CTYPE_H
#define _WAMR_LIBC_CTYPE_H

#ifdef __cplusplus
extern "C" {
#endif

int isupper(int c);
int isalpha(int c);
int isspace(int c);
int isgraph(int c);
int isprint(int c);
int isdigit(int c);
int isxdigit(int c);
int tolower(int c);
int toupper(int c);
int isalnum(int c);

#ifdef __cplusplus
}
#endif

#endif