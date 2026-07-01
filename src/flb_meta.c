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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_meta.h>

/*
 * A meta is a way to extend the configuration through specific commands, e.g:
 *
 *   @SET a=b
 *
 * the meta command is prefixed with @, the command it self is 'SET' and have
 * the parameters 'a=b'.
 *
 * Each command have their own handler function: meta_cmd_ABC().
 */

/* @SET command: register a key/value as a configuration variable */
static int meta_cmd_set(struct flb_config *ctx, const char *params)
{
    int ret;
    int len;
    char *p;
    char *key;
    char *val;

    p = strchr(params, '=');
    if (!p) {
        fprintf(stderr, "[meta SET] invalid parameter '%s'\n", params);
        return -1;
    }

    len = strlen(params);
    key = mk_string_copy_substr(params, 0, p - params);
    if (!key) {
        return -1;
    }

    val = mk_string_copy_substr(params, (p - params) + 1, len);
    if (!val) {
        flb_free(key);
        return -1;
    }

    /* Set the variable in our local environment */
    ret = flb_env_set(ctx->env, key, val);
    flb_free(key);
    flb_free(val);

    return ret;
}

/* Run a specific command */
int flb_meta_run(struct flb_config *ctx, const char *cmd, const char *params)
{
    if (strcasecmp(cmd, "SET") == 0) {
        return meta_cmd_set(ctx, params);
    }

    return -1;
}
