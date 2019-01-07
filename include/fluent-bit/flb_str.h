/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

static inline char *flb_strdup(const char *s)
{
    int len;
    char *str;

    len = strlen(s);
    str = (char *) flb_malloc(len + 1);
    if (!str) {
        return NULL;
    }
    strncpy(str, s, len);
    str[len] = '\0';

    return str;
}

static inline char *flb_strndup(const char *s, size_t n)
{
    char *str;

    str = (char *) flb_malloc(n + 1);
    if (!str) {
        return NULL;
    }
    strncpy(str, s, n);
    str[n] = '\0';

    return str;
}

#endif
