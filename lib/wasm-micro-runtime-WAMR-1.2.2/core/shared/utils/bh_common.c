/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_common.h"

static char *
align_ptr(char *src, unsigned int b)
{
    uintptr_t v = (uintptr_t)src;
    uintptr_t m = b - 1;
    return (char *)((v + m) & ~m);
}

/*
Memory copy, with word alignment
*/
int
b_memcpy_wa(void *s1, unsigned int s1max, const void *s2, unsigned int n)
{
    char *dest = (char *)s1;
    char *src = (char *)s2;

    char *pa = align_ptr(src, 4);
    char *pb = align_ptr((src + n), 4);

    unsigned int buff;
    const char *p_byte_read;

    unsigned int *p;
    char *ps;

    if (pa > src) {
        pa -= 4;
    }

    for (p = (unsigned int *)pa; p < (unsigned int *)pb; p++) {
        buff = *(p);
        p_byte_read = ((char *)&buff);

        /* read leading word */
        if ((char *)p <= src) {
            for (ps = src; ps < ((char *)p + 4); ps++) {
                if (ps >= src + n) {
                    break;
                }
                p_byte_read = ((char *)&buff) + (ps - (char *)p);
                *dest++ = *p_byte_read;
            }
        }
        /* read trailing word */
        else if ((char *)p >= pb - 4) {
            for (ps = (char *)p; ps < src + n; ps++) {
                *dest++ = *p_byte_read++;
            }
        }
        /* read meaning word(s) */
        else {
            if ((char *)p + 4 >= src + n) {
                for (ps = (char *)p; ps < src + n; ps++) {
                    *dest++ = *p_byte_read++;
                }
            }
            else {
                *(unsigned int *)dest = buff;
                dest += 4;
            }
        }
    }

    return 0;
}

int
b_memcpy_s(void *s1, unsigned int s1max, const void *s2, unsigned int n)
{
    char *dest = (char *)s1;
    char *src = (char *)s2;
    if (n == 0) {
        return 0;
    }

    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL || n > s1max) {
        memset(dest, 0, s1max);
        return -1;
    }
    memcpy(dest, src, n);
    return 0;
}

int
b_memmove_s(void *s1, unsigned int s1max, const void *s2, unsigned int n)
{
    char *dest = (char *)s1;
    char *src = (char *)s2;
    if (n == 0) {
        return 0;
    }

    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL || n > s1max) {
        memset(dest, 0, s1max);
        return -1;
    }
    memmove(dest, src, n);
    return 0;
}

int
b_strcat_s(char *s1, unsigned int s1max, const char *s2)
{
    if (NULL == s1 || NULL == s2 || s1max < (strlen(s1) + strlen(s2) + 1)) {
        return -1;
    }

    memcpy(s1 + strlen(s1), s2, strlen(s2) + 1);
    return 0;
}

int
b_strcpy_s(char *s1, unsigned int s1max, const char *s2)
{
    if (NULL == s1 || NULL == s2 || s1max < (strlen(s2) + 1)) {
        return -1;
    }

    memcpy(s1, s2, strlen(s2) + 1);
    return 0;
}

char *
bh_strdup(const char *s)
{
    uint32 size;
    char *s1 = NULL;

    if (s) {
        size = (uint32)(strlen(s) + 1);
        if ((s1 = BH_MALLOC(size)))
            bh_memcpy_s(s1, size, s, size);
    }
    return s1;
}

char *
wa_strdup(const char *s)
{
    uint32 size;
    char *s1 = NULL;

    if (s) {
        size = (uint32)(strlen(s) + 1);
        if ((s1 = WA_MALLOC(size)))
            bh_memcpy_s(s1, size, s, size);
    }
    return s1;
}
