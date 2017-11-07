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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include <string.h>

#include "filter_parser.h"

static int unescape_string(char *buf, int buf_len, char **unesc_buf)
{
    int i = 0;
    int j = 0;
    char *p;
    char n;

    p = *unesc_buf;
    while (i < buf_len) {
        if (buf[i] == '\\') {
            if (i + 1 < buf_len) {
                n = buf[i + 1];
                if (n != 'a' && n != 'b' &&
                    n != 't' && n != 'n' &&
                    n != 'v' && n != 'f' &&
                    n != 'r') {
                    i++;
                }
                else {
                    if (n == 'a') {
                        p[j++] = '\a';
                    }
                    else if (n == 'b') {
                        p[j++] = '\b';
                    }
                    else if (n == 't') {
                        p[j++] = '\t';
                    }
                    else if (n == 'n') {
                        p[j++] = '\n';
                    }
                    else if (n == 'v') {
                        p[j++] = '\v';
                    }
                    else if (n == 'f') {
                        p[j++] = '\f';
                    }
                    else if (n == 'r') {
                        p[j++] = '\r';
                    }
                    i += 2;
                    continue;
                }
            }
            else {
                i++;
            }
        }
        p[j++] = buf[i++];
    }
    p[j] = '\0';
    return j;
}

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

static int configure(struct filter_parser_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{
    struct flb_config_prop *prop = NULL;
    struct mk_list *head = NULL;

    ctx->key_name = NULL;
    ctx->parser   = NULL;
    ctx->reserve_data = FLB_FALSE;
    ctx->unescape_key = FLB_FALSE;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        if (!strcasecmp(prop->key, "key_name")) {
            ctx->key_name = prop->val;
            ctx->key_name_len = strlen(prop->val);
        }
        if (!strcasecmp(prop->key, "parser")) {
            ctx->parser  = flb_parser_get(prop->val, config);
            if (ctx->parser == NULL) {
                flb_error("[filter_parser] requested parser '%s' not found", prop->val);
            }
        }

        if (!strcasecmp(prop->key, "unescape_key") &&
            ctx->unescape_key == FLB_FALSE) {
            ctx->unescape_key = flb_utils_bool(prop->val);

            /* Buffer to handle unescape_key case */
            ctx->buf_data = flb_malloc(FLB_PARSER_UNS_BUF_SIZE);
            if (!ctx->buf_data) {
                return -1;
            }
            ctx->buf_len = 0;
            ctx->buf_size = FLB_PARSER_UNS_BUF_SIZE;
        }

        if (!strcasecmp(prop->key, "reserve_data")) {
            ctx->reserve_data = flb_utils_bool(prop->val);
        }

    }

    if (ctx->key_name == NULL) {
        flb_error("[filter_parser] \"key_name\" is missing\n");
        return -1;
    }
    if (ctx->parser == NULL) {
        flb_error("[filter_parser] Invalid \"parser\"\n");
        return -1;
    }

    return 0;
}

static int cb_parser_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data)
{
    (void) f_ins;
    (void) config;
    (void) data;

    struct filter_parser_ctx *ctx = NULL;

    /* Create context */
    ctx = flb_malloc(sizeof(struct filter_parser_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    if ( configure(ctx, f_ins, config) < 0 ){
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int cb_parser_filter(void *data, size_t bytes,
                            char *tag, int tag_len,
                            void **ret_buf, size_t *ret_bytes,
                            struct flb_filter_instance *f_ins,
                            void *context,
                            struct flb_config *config)
{
    struct filter_parser_ctx *ctx = context;
    msgpack_unpacked result;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    struct flb_time tm;
    msgpack_object *obj;

    msgpack_object_kv *kv;
    int i;
    int unescape;
    int unesc_size;
    int ret = FLB_FILTER_NOTOUCH;
    int map_num;
    char *tmp;
    char *key_str;
    int key_len;
    char *val_str;
    int val_len;
    char *out_buf;
    size_t out_size;
    struct flb_time parsed_time;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    msgpack_object_kv **append_arr = NULL;
    size_t            append_arr_len;
    int                append_arr_i;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        out_buf = NULL;
        append_arr_i = 0;

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }
        flb_time_pop_from_msgpack(&tm, &result, &obj);
        if (obj->type == MSGPACK_OBJECT_MAP) {
            map_num = obj->via.map.size;
            if (ctx->reserve_data) {
                append_arr_len = obj->via.map.size;
                append_arr = flb_malloc(sizeof(msgpack_object_kv*) * append_arr_len);

                for (i = 0; i < append_arr_len; i++){
                    append_arr[i] = NULL;
                }
            }

            for (i = 0; i < map_num; i++) {
                kv = &obj->via.map.ptr[i];
                if (ctx->reserve_data) {
                    append_arr[append_arr_i] = kv;
                    append_arr_i++;
                }
                if ( msgpackobj2char(&kv->key, &key_str, &key_len) < 0 ) {
                    /* key is not string */
                    continue;
                }
                if (key_len == ctx->key_name_len &&
                    !strncmp(key_str, ctx->key_name, key_len)) {
                    if ( msgpackobj2char(&kv->val, &val_str, &val_len) < 0 ) {
                        /* val is not string */
                        continue;
                    }

                    unescape = FLB_FALSE;
                    if (ctx->unescape_key == FLB_TRUE) {
                        if (val_len >= ctx->buf_size) {
                            tmp = flb_realloc(ctx->buf_data, val_len);
                            if (tmp) {
                                ctx->buf_data = tmp;
                                ctx->buf_size = val_len;
                                ctx->buf_len = 0;
                                unescape = FLB_TRUE;
                            }
                            else {
                                flb_errno();
                                ctx->unescape_key = FLB_FALSE;
                                unescape = FLB_FALSE;
                            }
                        }
                        else {
                            unescape = FLB_TRUE;
                        }
                    }


                    if (unescape == FLB_TRUE) {
                        unesc_size = unescape_string(val_str, val_len,
                                                     &ctx->buf_data);
                        ctx->buf_data[unesc_size] = '\0';
                        val_str = ctx->buf_data;
                        val_len = unesc_size;
                    }


                    /* Reset time */
                    flb_time_zero(&parsed_time);

                    /* Parse record */
                    if (flb_parser_do(ctx->parser,
                                      val_str, val_len,
                                      (void **)&out_buf, &out_size, &parsed_time) >= 0) {
                        if (flb_time_to_double(&parsed_time) != 0) {
                            flb_time_copy(&tm, &parsed_time);
                        }
                        if (ctx->reserve_data) {
                            append_arr_i--;
                            append_arr_len--;
                            append_arr[append_arr_i] = NULL;
                        }
                        else {
                            break;
                        }
                    }
                    else {
                        flb_warn("[filter_parser] parse error");
                    }
                }
            }

            if (out_buf != NULL) {
                msgpack_pack_array(&tmp_pck, 2);
                flb_time_append_to_msgpack(&tm, &tmp_pck, 0);
                if (ctx->reserve_data) {
                    char *new_buf = NULL;
                    int  new_size;
                    int ret;
                    ret = flb_msgpack_expand_map(out_buf, out_size,
                                                 append_arr, append_arr_len,
                                                 &new_buf, &new_size);
                    if (ret == -1) {
                        flb_error("[filter_parser] cannot expand map");
                        flb_free(append_arr);
                        msgpack_unpacked_destroy(&result);
                        return FLB_FILTER_NOTOUCH;
                    }

                    flb_free(out_buf);
                    out_buf = new_buf;
                    out_size = new_size;
                }
                msgpack_sbuffer_write(&tmp_sbuf, out_buf, out_size);
                flb_free(out_buf);
                ret = FLB_FILTER_MODIFIED;
            }
            else {
                /* re-use original data*/
                msgpack_pack_object(&tmp_pck, result.data);
            }
            flb_free(append_arr);
            append_arr = NULL;
        }
        else {
            continue;
        }
    }
    msgpack_unpacked_destroy(&result);

    if (ret == FLB_FILTER_NOTOUCH) {
        /* Destroy the buffer to avoid more overhead */
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }

    *ret_buf = tmp_sbuf.data;
    *ret_bytes = tmp_sbuf.size;

    return ret;
}


static int cb_parser_exit(void *data, struct flb_config *config)
{
    struct filter_parser_ctx *ctx = data;

    if (ctx->unescape_key == FLB_TRUE) {
        flb_free(ctx->buf_data);
    }

    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_parser_plugin = {
    .name         = "parser",
    .description  = "Parse events",
    .cb_init      = cb_parser_init,
    .cb_filter    = cb_parser_filter,
    .cb_exit      = cb_parser_exit,
    .flags        = 0
};
