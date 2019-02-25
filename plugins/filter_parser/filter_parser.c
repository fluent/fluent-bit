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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include <string.h>
#include <fluent-bit.h>

#include "filter_parser.h"

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

static int add_parser(char *parser, struct filter_parser_ctx *ctx,
                       struct flb_config *config)
{
    struct flb_parser *p;
    struct filter_parser *fp;

    p = flb_parser_get(parser, config);
    if (!p) {
        return -1;
    }

    fp = flb_malloc(sizeof(struct filter_parser));
    if (!fp) {
        flb_errno();
        return -1;
    }

    fp->parser = p;
    mk_list_add(&fp->_head, &ctx->parsers);
    return 0;
}

static int delete_parsers(struct filter_parser_ctx *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct filter_parser *fp;

    mk_list_foreach_safe(head, tmp, &ctx->parsers) {
        fp = mk_list_entry(head, struct filter_parser, _head);
        mk_list_del(&fp->_head);
        flb_free(fp);
        c++;
    }

    return c;
}

static int configure(struct filter_parser_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{
    int ret;
    char *tmp;
    struct mk_list *head;
    struct flb_config_prop *p;

    ctx->key_name = NULL;
    ctx->reserve_data = FLB_FALSE;
    ctx->preserve_key = FLB_FALSE;
    mk_list_init(&ctx->parsers);

    /* Key name */
    tmp = flb_filter_get_property("key_name", f_ins);
    if (tmp) {
        ctx->key_name = flb_strdup(tmp);
        ctx->key_name_len = strlen(tmp);
    }
    else {
        flb_error("[filter_parser] \"key_name\" is missing\n");
        return -1;
    }

    /* Read all Parsers */
    mk_list_foreach(head, &f_ins->properties) {
        p = mk_list_entry(head, struct flb_config_prop, _head);
        if (strcasecmp("parser", p->key) != 0) {
            continue;
        }

        ret = add_parser(p->val, ctx, config);
        if (ret == -1) {
            flb_error("[filter_parser] requested parser '%s' not found", tmp);
        }
    }

    if (mk_list_size(&ctx->parsers) == 0) {
        flb_error("[filter_parser] Invalid \"parser\"\n");
        return -1;
    }

    /* Reserve data */
    tmp = flb_filter_get_property("reserve_data", f_ins);
    if (tmp) {
        ctx->reserve_data = flb_utils_bool(tmp);
    }

    /* Preserve key */
    tmp = flb_filter_get_property("preserve_key", f_ins);
    if (tmp) {
        ctx->preserve_key = flb_utils_bool(tmp);
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
    int continue_parsing;
    struct filter_parser_ctx *ctx = context;
    msgpack_unpacked result;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    struct flb_time tm;
    msgpack_object *obj;

    msgpack_object_kv *kv;
    int i;
    int ret = FLB_FILTER_NOTOUCH;
    int parse_ret = -1;
    int map_num;
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
    struct mk_list *head;
    struct filter_parser *fp;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
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
                if (!append_arr) {
                    flb_errno();
                    msgpack_unpacked_destroy(&result);
                    msgpack_sbuffer_destroy(&tmp_sbuf);
                    return FLB_FILTER_NOTOUCH;
                }

                for (i = 0; i < append_arr_len; i++){
                    append_arr[i] = NULL;
                }
            }

            continue_parsing = FLB_TRUE;
            for (i = 0; i < map_num && continue_parsing; i++) {
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

                    /* Lookup parser */
                    mk_list_foreach(head, &ctx->parsers) {
                        fp = mk_list_entry(head, struct filter_parser, _head);

                        /* Reset time */
                        flb_time_zero(&parsed_time);

                        parse_ret = flb_parser_do(fp->parser, val_str, val_len,
                                            (void **) &out_buf, &out_size,
                                            &parsed_time);
                        if (parse_ret >= 0) {
                            /*
                             * If the parser succeeded we need to check the
                             * status of the parsed time. If the time was
                             * parsed successfully 'parsed_time' will be
                             * different than zero, if so, override the time
                             * holder with the new value, otherwise keep the
                             * original.
                             */
                            if (flb_time_to_double(&parsed_time) != 0.0) {
                                flb_time_copy(&tm, &parsed_time);
                            }

                            if (ctx->reserve_data) {
                                if (!ctx->preserve_key) {
                                    append_arr_i--;
                                    append_arr_len--;
                                    append_arr[append_arr_i] = NULL;
                                }
                            }
                            else {
                                continue_parsing = FLB_FALSE;
                                break;
                            }
                        }
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

    if (!ctx) {
        return 0;
    }

    delete_parsers(ctx);
    flb_free(ctx->key_name);
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
