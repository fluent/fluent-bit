/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_file.h>

#include <stdlib.h>
#include <time.h>

static inline flb_sds_t buf_append(flb_sds_t buf, const char *str, int len)
{
    flb_sds_t tmp;

    tmp = flb_sds_cat(buf, str, len);
    if (!tmp) {
        return NULL;
    }

    return tmp;
}

/* Preset some useful variables */
static int env_preset(struct flb_env *env)
{
    int ret;
    char *buf;
    char tmp[512];

    /*
     * ${HOSTNAME} this variable is very useful to identify records,
     * despite this variable is recognized by the Shell, that does not
     * means that is exposed as a real environment variable, e.g:
     *
     *  1. $ echo $HOSTNAME
     *     monotop
     *  2. $ env | grep HOSTNAME
     *     (nothing)
     */
    buf = getenv("HOSTNAME");
    if (!buf) {
        ret = gethostname(tmp, sizeof(tmp) - 1);
        if (ret == 0) {
            flb_env_set(env, "HOSTNAME", tmp);
        }
    }

    return 0;
}

struct flb_env *flb_env_create()
{
    struct flb_env *env;
    struct flb_hash_table *ht;

    env = flb_malloc(sizeof(struct flb_env));
    if (!env) {
        flb_errno();
        return NULL;
    }

    /* Create the hash-table */
    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, FLB_ENV_SIZE, -1);
    if (!ht) {
        flb_free(env);
        return NULL;
    }

    env->warn_unused = FLB_TRUE;
    env->ht = ht;
    mk_list_init(&env->vars);
    env_preset(env);

    return env;
}

void flb_env_destroy(struct flb_env *env)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_env_var *var;

    mk_list_foreach_safe(head, tmp, &env->vars) {
        var = mk_list_entry(head, struct flb_env_var, _head);
        if (var->name) {
            flb_sds_destroy(var->name);
        }
        if (var->value) {
            flb_sds_destroy(var->value);
        }
        if (var->uri) {
            flb_sds_destroy(var->uri);
        }
        flb_free(var);
    }

    flb_hash_table_destroy(env->ht);
    flb_free(env);
}

int flb_env_set_extended(struct flb_env *env, const char *key, const char *val,
                         const char *uri, int refresh_interval)
{
    int id;
    int klen;
    int vlen;
    void *out_buf;
    size_t out_size;
    flb_sds_t fs_buf = NULL;
    const char *orig_uri = NULL;
    const char *value = val;
    struct flb_env_var *var;

    if (uri) {
        orig_uri = uri;
        value = uri;
    }

    if (value == NULL) {
        value = "";
    }

    klen = strlen(key);
    vlen = strlen(value);

    /* Check if the variable is a reference to a file */
    if (vlen > 7 && strncmp(value, "file://", 7) == 0) {
        orig_uri = value;
        vlen -= 7;
        value += 7;

        if (access(value, R_OK) == -1) {
            flb_error("[env] file %s not found", value);
            return -1;
        }

        fs_buf = flb_file_read(value);
        if (!fs_buf) {
            flb_error("[env] file %s could not be read", value);
            return -1;
        }

        value = fs_buf;
        vlen = flb_sds_len(fs_buf);

        if (vlen > 0 && (value[vlen - 1] == '\n' || value[vlen - 1] == '\r')) {
            vlen--;
            flb_sds_len_set(fs_buf, vlen);
        }

        if (vlen == 0) {
            flb_error("[env] file %s content is empty", value);
            flb_sds_destroy(fs_buf);
            return -1;
        }

        flb_debug("[env] file %s content read propery, length= %d", value, vlen);
    }

    /* Check if the key is already set */
    id = flb_hash_table_get(env->ht, key, klen, &out_buf, &out_size);
    if (id >= 0) {
        flb_hash_table_del(env->ht, key);
    }

    id = flb_hash_table_add(env->ht, key, klen, (void *) value, vlen);

    var = flb_calloc(1, sizeof(struct flb_env_var));
    if (!var) {
        flb_errno();
        if (fs_buf) {
            flb_sds_destroy(fs_buf);
        }
        return -1;
    }
    mk_list_add(&var->_head, &env->vars);
    var->name = flb_sds_create(key);
    if (vlen > 0) {
        var->value = flb_sds_create_len(value, vlen);
    }
    if (orig_uri) {
        var->uri = flb_sds_create(orig_uri);
    }
    var->refresh_interval = refresh_interval;
    if (orig_uri) {
        var->last_refresh = time(NULL);
    }
    else {
        var->last_refresh = 0;
    }

    if (fs_buf) {
        flb_sds_destroy(fs_buf);
    }

    return id;
}

int flb_env_set(struct flb_env *env, const char *key, const char *val)
{
    return flb_env_set_extended(env, key, val, NULL, 0);
}

const char *flb_env_get(struct flb_env *env, const char *key)
{
    int len;
    int ret;
    void *out_buf;
    size_t out_size;
    struct mk_list *head;
    struct flb_env_var *var;
    time_t now;
    flb_sds_t fs_buf;
    int vlen;
    const char *file;

    if (!key) {
        return NULL;
    }

    len = strlen(key);

    mk_list_foreach(head, &env->vars) {
        var = mk_list_entry(head, struct flb_env_var, _head);
        if (var->name && strcmp(var->name, key) == 0) {
            if (var->uri && var->refresh_interval > 0) {
                now = time(NULL);
                if (var->last_refresh == 0 ||
                    now - var->last_refresh >= var->refresh_interval) {
                    file = var->uri;
                    if (strncmp(file, "file://", 7) == 0) {
                        file += 7;
                    }

                    if (access(file, R_OK) == -1) {
                        flb_error("[env] file %s not found", file);
                        break;
                    }

                    fs_buf = flb_file_read(file);
                    if (!fs_buf) {
                        flb_error("[env] file %s could not be read", file);
                        break;
                    }

                    vlen = flb_sds_len(fs_buf);
                    if (vlen > 0 && (fs_buf[vlen - 1] == '\n' || fs_buf[vlen - 1] == '\r')) {
                        vlen--;
                        flb_sds_len_set(fs_buf, vlen);
                    }

                    if (vlen == 0) {
                        flb_error("[env] file %s content is empty", file);
                        flb_sds_destroy(fs_buf);
                        break;
                    }

                    flb_hash_table_del(env->ht, key);
                    if (var->value) {
                        flb_sds_destroy(var->value);
                    }
                    var->value = fs_buf;
                    ret = flb_hash_table_add(env->ht, key, len, fs_buf, vlen);
                    if (ret < 0) {
                        break;
                    }
                    var->last_refresh = now;
                }
            }
            break;
        }
    }

    ret = flb_hash_table_get(env->ht, key, len, &out_buf, &out_size);
    if (ret >= 0) {
        return (char *) out_buf;
    }

    out_buf = getenv(key);
    if (!out_buf) {
        return NULL;
    }

    if (strlen(out_buf) == 0) {
        return NULL;
    }

    return (char *) out_buf;
}

/*
 * Given a 'value', lookup for variables, if found, return a new composed
 * sds string.
 */
flb_sds_t flb_env_var_translate(struct flb_env *env, const char *value)
{
    int i;
    int len;
    int v_len;
    int e_len;
    int pre_var;
    int have_var = FLB_FALSE;
    const char *env_var = NULL;
    char *v_start = NULL;
    char *v_end = NULL;
    char tmp[4096];
    flb_sds_t buf;
    flb_sds_t s;

    if (!value) {
        return NULL;
    }

    len = strlen(value);
    buf = flb_sds_create_size(len);
    if (!buf) {
        return NULL;
    }

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
        if (v_len <= 0 || v_len >= sizeof(tmp)) {
            break;
        }

        /* variable */
        strncpy(tmp, v_start, v_len);
        tmp[v_len] = '\0';
        have_var = FLB_TRUE;

        /* Append pre-variable content */
        pre_var = (v_start - 2) - (value + i);
        if (pre_var > 0) {
            s = buf_append(buf, value + i, (v_start - 2) - (value + i));
            if (!s) {
                flb_sds_destroy(buf);
                return NULL;
            }
            if (s != buf) {
                buf = s;
            }
        }

        /* Lookup the variable in our env-hash */
        env_var = flb_env_get(env, tmp);
        if (env_var) {
            e_len = strlen(env_var);
            s = buf_append(buf, env_var, e_len);
            if (!s) {
                flb_sds_destroy(buf);
                return NULL;
            }
            if (s != buf) {
                buf = s;
            }
        }
        else if (env->warn_unused == FLB_TRUE) {
            flb_warn("[env] variable ${%s} is used but not set", tmp);
        }
        i += (v_start - (value + i)) + v_len;
    }

    /* Copy the remaining value into our buffer */
    if (v_end) {
        if (have_var == FLB_TRUE && (value + len) - (v_end + 1) > 0) {
            s = buf_append(buf, v_end + 1, (value + len) - (v_end + 1));
            if (!s) {
                flb_sds_destroy(buf);
                return NULL;
            }
            if (s != buf) {
                buf = s;
            }
        }
    }

    if (flb_sds_len(buf) == 0) {
        /*
         * If the output length buffer is zero, it could mean:
         *
         * - just one variable was given and it don't have any value
         * - no variables given (keep original value)
         *
         * In order to avoid problems in the caller, if a variable is null
         * and is the only one content available, return a new empty memory
         * string.
         */
        if (have_var == FLB_TRUE) {
            return flb_sds_copy(buf, "", 0);
        }
        else {
            return flb_sds_copy(buf, value, len);
        }
    }

    return buf;
}
