/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_kv.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <fluent-bit/flb_dlfcn_win32.h>
#else
#include <dlfcn.h>
#endif

#include <msgpack.h>
#include "cgo.h"

#include "go.h"

// copy from filter_parser.c
static int msgpackobj2char(msgpack_object *obj,
                           char **ret_char, int *ret_char_size)
{
    int ret = -1;

    if (obj->type == MSGPACK_OBJECT_STR) {
        *ret_char      = (char*)obj->via.str.ptr;
        *ret_char_size = obj->via.str.size;
        ret = 0;
    }
    else if (obj->type == MSGPACK_OBJECT_BIN) {
        *ret_char      = (char*)obj->via.bin.ptr;
        *ret_char_size = obj->via.bin.size;
        ret = 0;
    }

    return ret;
}

/*
 * unpack msg, call filter , write result to parameter result
 */
static int callGoFilter(struct go_conf *ctx, msgpack_sbuffer *result, const char *tag, int tag_len, const void *data, size_t bytes)
{
    int index= 0, i;
    char *key_str, *val_str;
    int key_len, val_len;

    msgpack_object_kv *kv;
    size_t off = 0;
    msgpack_object *obj;
    int map_num;
    struct flb_time tm;

    GoSlice name_slice, value_slice;
    _GoString_ name[MAX_FIELD]={0}, value[MAX_FIELD]={0};
    GoInt ret;

    msgpack_unpacked unpackMsg;
    msgpack_packer tmp_pck;

    name_slice.data = name;
    value_slice.data = value;
    name_slice.len = 0;
    name_slice.cap = MAX_FIELD;
    value_slice.len = 0;
    value_slice.cap = MAX_FIELD;

    msgpack_sbuffer_init(result);
    msgpack_packer_init(&tmp_pck, result, msgpack_sbuffer_write);

    msgpack_unpacked_init(&unpackMsg);
    while (msgpack_unpack_next(&unpackMsg, data, bytes, &off)) {
        if (unpackMsg.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }
        flb_time_pop_from_msgpack(&tm, &unpackMsg, &obj);
        if (obj->type != MSGPACK_OBJECT_MAP) {
            continue;
        }
        msgpack_pack_array(&tmp_pck, 2);
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        map_num = obj->via.map.size;

        // add tag to slice
        name[0].p = "tag";
        name[0].n = 3;
        value[0].p = tag;
        value[0].n = tag_len;
        index = 1;
        for (i=0;i<map_num; i++) {
            kv = &obj->via.map.ptr[i];
            if ( msgpackobj2char(&kv->key, &key_str, &key_len) < 0 ) {
                /* key is not string */
                continue;
            }
            if ( msgpackobj2char(&kv->val, &val_str, &val_len) < 0 ) {
                /* val is not string */
                continue;
            }
            name[index].p = key_str;
            name[index].n = key_len;
            value[index].p= val_str;
            value[index].n = val_len;
            index++;
        }

        name_slice.len = index;
        value_slice.len = index;
        // call cgo filter
        ret = ctx->filter_lib_func(name_slice, value_slice);
        if (ret == -1) {
            flb_error("[filter_go] go filter_lib_func fail. ");
            msgpack_unpacked_destroy(&unpackMsg);
            return -1;
        }

        // load result
        msgpack_pack_map(&tmp_pck, ret);
        for (i=0;i<ret;i++) {
            msgpack_pack_str(&tmp_pck, name[i].n);
            msgpack_pack_str_body(&tmp_pck, name[i].p, name[i].n);

            msgpack_pack_str(&tmp_pck, value[i].n);
            msgpack_pack_str_body(&tmp_pck, value[i].p, value[i].n);
        }

    }
    msgpack_unpacked_destroy(&unpackMsg);

    return 0;
}


static int cb_go_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    struct go_conf *ctx;

    char *error;

    struct mk_list *head;
    struct flb_kv *p;

    char lib_so_name[200];

    GoInt ret;
    GoSlice name_slice, value_slice; // for []string  slice
    _GoString_ name[MAX_PARAMETERS], value[MAX_PARAMETERS];
    int para_num; // actual parametres num

    ctx = malloc(sizeof(struct go_conf));
    f_ins->context = ctx;

    name_slice.data = name;
    value_slice.data = value;

    para_num = 0;
    mk_list_foreach(head, &f_ins->properties) {
        p = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp(GOLIB_SO_KEY_NAME, p->key) == 0) {
            strcpy(lib_so_name, p->val);
            continue;
        }
        name[para_num].p = p->key;
        name[para_num].n = strlen(p->key);

        value[para_num].p = p->val;
        value[para_num].n = strlen(p->val);

        para_num++;
    }
    name_slice.len = para_num;
    name_slice.cap = para_num;
    value_slice.len = para_num;
    value_slice.cap = para_num;

    ctx->handler = dlopen (lib_so_name, RTLD_LAZY);
    if (!ctx->handler) {
        flb_error("[filter_go] open lib so %s [%s] fail. ", lib_so_name, dlerror());
        return -1;
    }

    ctx->init_lib_func = dlsym(ctx->handler, INIT_FUNC_NAME);
    if ((error = dlerror()) != NULL)  {
        flb_error("[filter_go] get init func from lib_so fail %s. ", error);
        return -1;
    }
    ctx->filter_lib_func = dlsym(ctx->handler, FILTER_FUNC_NAME);
    if ((error = dlerror()) != NULL)  {
        flb_error("[filter_go] get filter func from lib_so fail %s. ", error);
        return -1;
    }
    ctx->exit_lib_func = dlsym(ctx->handler, EXIT_FUNC_NAME);
    if ((error = dlerror()) != NULL)  {
        flb_error("[filter_go] get exit func from lib_so fail %s. ", error);
        return -1;
    }

    ret = ctx->init_lib_func(name_slice, value_slice);
    if (ret != 0) {
        flb_error("[filter_go] init go lib fail %s. ", error);
        return -1;
    }

    return 0;
}


static int cb_go_filter(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          void **out_buf, size_t *out_bytes,
                          struct flb_filter_instance *f_ins,
                          void *filter_context,
                          struct flb_config *config)
{
    int ret;
    struct go_conf *ctx = f_ins->context;

    msgpack_sbuffer result;

    ret = callGoFilter(ctx, &result, tag, tag_len, data, bytes);
    if (ret == -1) {
        flb_error("[filter_go] get_slice_from_msgpacker fail. ");
        msgpack_sbuffer_destroy(&result);
        return -1;
    }

    *out_buf = result.data;
    *out_bytes = result.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_go_exit(void *data, struct flb_config *config)
{
    struct go_conf *ctx;

    ctx = data;

    flb_trace("[filter_go] get exit  cb_go_exit . ");
    ctx->exit_lib_func();

    dlclose(ctx->handler);

    return 0;
}

struct flb_filter_plugin filter_go_plugin = {
    .name         = "go",
    .description  = "Filter to call go",
    .cb_init      = cb_go_init,
    .cb_filter    = cb_go_filter,
    .cb_exit      = cb_go_exit,
    .flags        = 0
};
