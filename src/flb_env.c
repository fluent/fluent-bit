/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>

#include <stdlib.h>

struct flb_buf {
    char *str;
    size_t size;
    size_t len;
};

static inline int buf_append(struct flb_buf *buf, char *str, int len)
{
    size_t av;
    size_t new_size;
    char *tmp;

    av = buf->size - buf->len;
    if (av < len + 1) {
        new_size = buf->size + len + 1;
        tmp = flb_realloc(buf->str, new_size);
        if (tmp) {
            buf->str = tmp;
            buf->size = new_size;
        }
        else {
            flb_errno();
            return -1;
        }
    }

    memcpy(buf->str + buf->len, str, len);
    buf->len += len;
    buf->str[buf->len] = '\0';

    return 0;
}

struct flb_env *flb_env_create()
{
    struct flb_env *env;
    struct flb_hash *ht;

    env = flb_malloc(sizeof(struct flb_env));
    if (!env) {
        flb_errno();
        return NULL;
    }

    /* Create the hash-table */
    ht = flb_hash_create(FLB_ENV_SIZE);
    if (!ht) {
        flb_free(env);
        return NULL;
    }

    env->ht = ht;
    return env;
}

void flb_env_destroy(struct flb_env *env)
{
    flb_hash_destroy(env->ht);
    flb_free(env);
}

char *flb_env_get(struct flb_env *env, char *key)
{
    int len;
    int ret;
    char *out_buf;
    size_t out_size;

    if (!key) {
        return NULL;
    }

    len = strlen(key);

    /* Try to get the value from the hash table */
    ret = flb_hash_get(env->ht, key, len, &out_buf, &out_size);
    if (ret >= 0) {
        return out_buf;
    }

    /* If it was not found, try to get it from the real environment */
    return getenv(key);
}

/*
 * Given a 'value', lookup for variables, if found, return a new composed
 * string.
 */
char *flb_env_var_translate(struct flb_env *env, char *value)
{
    int i;
    int len;
    int v_len;
    int pre_var;
    char *env_var;
    char *v_start;
    char *v_end;
    char tmp[64];
    struct flb_buf buf;

    buf.str = NULL;
    buf.len = 0;
    buf.size = 0;

    if (!value) {
        return NULL;
    }

    len = strlen(value);

    for (i = 0; i < len; i++) {
        v_start = strstr(value + i, "${");
        if (!v_start) {
            break;
        }

        v_end = strstr(value + i, "}");
        if (!v_end) {
            break;
        }

        v_start += 2;
        v_len = v_end - v_start;
        if (v_len <= 0) {
            break;
        }

        /* variable */
        strncpy(tmp, v_start, v_len);
        tmp[v_len] = '\0';

        /* Append pre-variable content */
        pre_var = (v_start - 2) - (value + i);
        if (pre_var > 0) {
            buf_append(&buf, value + i, (v_start - 2) - (value + i));
        }

        /* Lookup the variable in our env-hash */
        env_var = flb_env_get(env, tmp);
        if (env_var) {
            len = strlen(env_var);
            buf_append(&buf, env_var, len);
        }
        i += (v_start - (value + i)) + v_len;
    }

    if (buf.len == 0) {
        return flb_strdup(value);
    }

    return buf.str;
}
