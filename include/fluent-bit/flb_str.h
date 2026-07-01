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

#ifndef FLB_STR_H
#define FLB_STR_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_mem.h>

#include <stdlib.h>
#include <string.h>

static inline char *flb_strndup(const char *s, size_t n)
{
    char *str;

    str = (char *) flb_malloc(n + 1);
    if (!str) {
        return NULL;
    }
    memcpy(str, s, n);
    str[n] = '\0';

    return str;
}

static inline char *flb_strdup(const char *s)
{
    return flb_strndup(s, strlen(s));
}

/* emptyval checks whether a string has a non-null value "". */
static inline int flb_str_emptyval(const char *s)
{
    if (s != NULL && strcmp(s, "") == 0) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/*
 Trim the `c` character sequence to the right of the `*str` string and return a copy.
 * @param *str Source string;
 * @param c Character to be trimmed.
 * @returns a new string, which is a trimmed copy of `*str`.
*/
static inline char *flb_rtrim(const char *str, char c) {
    ssize_t pos = strlen(str);

    while(c == str[--pos]);

    if (pos < 0){
        return NULL;
    }

    return flb_strndup(str, pos+1);
}

#endif
