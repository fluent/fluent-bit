/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>

#include "lua_config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct lua_filter *lua_config_create(struct flb_filter_instance *ins,
                                     struct flb_config *config)
{
    int ret;
    const char *tmp;
    char *tmp_key;
    char buf[PATH_MAX];
    const char *script = NULL;
    (void) config;
    struct stat st;
    struct lua_filter *lf;
    struct mk_list *split   = NULL;
    struct mk_list *head    = NULL;
    struct mk_list *tmp_list= NULL;
    struct l2c_type  *l2c   = NULL;
    struct flb_split_entry *sentry = NULL;

    /* Allocate context */
    lf = flb_calloc(1, sizeof(struct lua_filter));
    if (!lf) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&lf->l2c_types);
    lf->ins = ins;

    /* Config: script */
    tmp = flb_filter_get_property("script", ins);
    if (!tmp) {
        flb_plg_error(lf->ins, "no script path defined");
        flb_free(lf);
        return NULL;
    }
    script = tmp;

    /* Compose path */
    ret = stat(tmp, &st);
    if (ret == -1 && errno == ENOENT) {
        if (tmp[0] == '/') {
            flb_plg_error(lf->ins, "cannot access script '%s'", tmp);
            flb_free(lf);
            return NULL;
        }

        if (config->conf_path) {
            snprintf(buf, sizeof(buf) - 1, "%s%s",
                     config->conf_path, tmp);
            script = buf;
        }
    }

    /* Validate script path */
    ret = access(script, R_OK);
    if (ret == -1) {
        flb_plg_error(lf->ins, "cannot access script '%s'", script);
        flb_free(lf);
        return NULL;
    }

    lf->script = flb_sds_create(script);
    if (!lf->script) {
        flb_plg_error(lf->ins, "could not allocate string");
        flb_free(lf);
        return NULL;
    }

    /* Config: call */
    tmp = flb_filter_get_property("call", ins);
    if (!tmp) {
        flb_plg_error(lf->ins, "no call property defined");
        lua_config_destroy(lf);
        return NULL;
    }

    lf->call = flb_sds_create(tmp);
    if (!lf->call) {
        flb_plg_error(lf->ins, "could not allocate call");
        lua_config_destroy(lf);
        return NULL;
    }

    lf->buffer = flb_sds_create_size(LUA_BUFFER_CHUNK);
    if (!lf->buffer) {
        flb_plg_error(lf->ins, "could not allocate decode buffer");
        lua_config_destroy(lf);
        return NULL;
    }

    lf->l2c_types_num = 0;
    tmp = flb_filter_get_property("type_int_key", ins);
    if (tmp) {
        split = flb_utils_split(tmp, ' ', L2C_TYPES_NUM_MAX);
        mk_list_foreach_safe(head, tmp_list, split) {
            l2c = flb_malloc(sizeof(struct l2c_type));

            sentry = mk_list_entry(head, struct flb_split_entry, _head);

            tmp_key = flb_strndup(sentry->value, sentry->len);
            l2c->key = flb_sds_create(tmp_key);
            flb_free(tmp_key);

            mk_list_add(&l2c->_head, &lf->l2c_types);
            lf->l2c_types_num++;
        }
        flb_utils_split_free(split);
    }

    lf->protected_mode = FLB_TRUE;
    tmp = flb_filter_get_property("protected_mode", ins);
    if (tmp) {
        lf->protected_mode = flb_utils_bool(tmp);
    }

    return lf;
}

void lua_config_destroy(struct lua_filter *lf)
{
    struct mk_list  *tmp_list = NULL;
    struct mk_list  *head     = NULL;
    struct l2c_type *l2c      = NULL;

    if (!lf) {
        return;
    }

    if (lf->script) {
        flb_sds_destroy(lf->script);
    }
    if (lf->call) {
        flb_sds_destroy(lf->call);
    }
    if (lf->buffer) {
        flb_sds_destroy(lf->buffer);
    }

    mk_list_foreach_safe(head, tmp_list, &lf->l2c_types) {
        l2c = mk_list_entry(head, struct l2c_type, _head);
        if (l2c) {
            if (l2c->key) {
                flb_sds_destroy(l2c->key);
            }
            mk_list_del(&l2c->_head);
            flb_free(l2c);
        }
    }

    flb_free(lf);
}
