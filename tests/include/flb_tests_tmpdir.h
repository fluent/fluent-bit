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

#ifndef FLB_TESTS_TMPDIR_H
#define FLB_TESTS_TMPDIR_H

#include <string.h>
#include <stdlib.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>

static inline char* flb_test_env_tmpdir()
{
    char *env;

    /* Unix */
    env = getenv("TMPDIR");
    if (env) {
        return flb_strdup(env);
    }

    /* Windows */
    env = getenv("TEMP");
    if (env) {
        return flb_strdup(env);
    }
    env = getenv("TMP");
    if (env) {
        return flb_strdup(env);
    }

    /* Fallback */
    return flb_strdup("/tmp");
}

static inline char* flb_test_tmpdir_cat(const char *postfix)
{
    char *tmpdir;
    char *ret;
    size_t tmpdir_len;
    size_t postfix_len;

    tmpdir = flb_test_env_tmpdir();
    if (!tmpdir) {
        return NULL;
    }

    tmpdir_len = strlen(tmpdir);
    postfix_len = strlen(postfix);
    ret = (char *) flb_malloc(tmpdir_len + postfix_len + 1);
    if (!ret) {
        flb_free(tmpdir);
        return NULL;
    }

    memcpy(ret, tmpdir, tmpdir_len);
    flb_free(tmpdir);
    memcpy(ret + tmpdir_len, postfix, postfix_len);
    ret[tmpdir_len + postfix_len] = '\0';
    return ret;
}

#endif
