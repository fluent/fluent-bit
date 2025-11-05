/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WAMR_LIBC_STRING_H
#define _WAMR_LIBC_STRING_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long size_t;

int
memcmp(const void *s1, const void *s2, size_t n);
void *
memcpy(void *dest, const void *src, size_t n);
void *
memmove(void *dest, const void *src, size_t n);
void *
memset(void *s, int c, size_t n);
void *
memchr(const void *s, int c, size_t n);
int
strncasecmp(const char *s1, const char *s2, size_t n);
size_t
strspn(const char *s, const char *accept);
size_t
strcspn(const char *s, const char *reject);
char *
strstr(const char *s, const char *find);
char *
strchr(const char *s, int c);
int
strcmp(const char *s1, const char *s2);
char *
strcpy(char *dest, const char *src);
size_t
strlen(const char *s);
int
strncmp(const char *str1, const char *str2, size_t n);
char *
strncpy(char *dest, const char *src, unsigned long n);
char *
strdup(const char *s);

#ifdef __cplusplus
}
#endif

#endif