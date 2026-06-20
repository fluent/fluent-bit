/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

void
on_init()
{}

int
my_sqrt(int x, int y)
{
    return x * x + y * y;
}

void *
null_pointer()
{
    void *ptr = NULL;
    return ptr;
}

void *
my_malloc(int size)
{
    return malloc(size);
}

void *
my_calloc(int nmemb, int size)
{
    return calloc(nmemb, size);
}

void
my_free(void *ptr)
{
    free(ptr);
}

void *
my_memcpy(void *dst, void *src, int size)
{
    return memcpy(dst, src, size);
}

char *
my_strdup(const char *s)
{
    return strdup(s);
}

int
my_memcmp(const void *buf1, const void *buf2, int size)
{
    return memcmp(buf1, buf2, size);
}

int
my_printf(const char *format, char *s)
{
    return printf(format, s);
}

int
my_sprintf(char *buf1, const char *format, char *buf2)
{
    return sprintf(buf1, format, buf2);
}

int
my_snprintf(char *buf1, int size, const char *format, char *buf2)
{
    return snprintf(buf1, size, format, buf2);
}

int
my_puts(const char *s)
{
    return puts(s);
}

int
my_putchar(int s)
{
    return putchar(s);
}

void *
my_memmove(void *buf1, const void *buf2, int size)
{
    return memmove(buf1, buf2, size);
}

void *
my_memset(void *buf, int c, int size)
{
    return memset(buf, c, size);
}

char *
my_strchr(const char *s, int c)
{
    return strchr(s, c);
}

int
my_strcmp(const char *buf1, const char *buf2)
{
    return strcmp(buf1, buf2);
}

char *
my_strcpy(char *buf1, const char *buf2)
{
    return strcpy(buf1, buf2);
}

int
my_strlen(const char *s)
{
    return (int)strlen(s);
}

int
my_strncmp(const char *buf1, const char *buf2, int n)
{
    return strncmp(buf1, buf2, n);
}

char *
my_strncpy(char *buf1, const char *buf2, int n)
{
    return strncpy(buf1, buf2, n);
}
