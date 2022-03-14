/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

#include "ml.h"

static int multiline_load_parsers(struct ml_ctx *ctx)
{
    int ret;
    struct mk_list *head;
    struct mk_list *head_p;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *val = NULL;
    struct flb_ml_parser_ins *parser_i;

    if (!ctx->multiline_parsers) {
        return -1;
    }

    /*
     * Iterate all 'multiline.parser' entries. Every entry is considered
     * a group which can have multiple multiline parser instances.
     */
    flb_config_map_foreach(head, mv, ctx->multiline_parsers) {
        mk_list_foreach(head_p, mv->val.list) {
            val = mk_list_entry(head_p, struct flb_slist_entry, _head);

            /* Create an instance of the defined parser */
            parser_i = flb_ml_parser_instance_create(ctx->m, val->str);
            if (!parser_i) {
                return -1;
            }

            /* Always override parent parser values */
            if (ctx->key_content) {
                ret = flb_ml_parser_instance_set(parser_i,
                                                 "key_content",
                                                 ctx->key_content);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "could not override 'key_content'");
                    return -1;
                }
            }
        }
    }

    return 0;
}

static int flush_callback(struct flb_ml_parser *parser,
                          struct flb_ml_stream *mst,
                          void *data, char *buf_data, size_t buf_size)
{
    struct ml_ctx *ctx = data;

    if (ctx->debug_flush) {
        flb_ml_flush_stdout(parser, mst, data, buf_data, buf_size);
    }

    /* Append incoming record to our msgpack context buffer */
    msgpack_sbuffer_write(&ctx->mp_sbuf, buf_data, buf_size);

    return 0;
}

static int cb_ml_init(struct flb_filter_instance *ins,
                      struct flb_config *config,
                      void *data)
{
    int ret;
    int len;
    uint64_t stream_id;
    struct ml_ctx *ctx;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct ml_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->debug_flush = FLB_FALSE;

    /* Init buffers */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    /* Load the config map */
    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set plugin context */
    flb_filter_set_context(ins, ctx);

    /* Create multiline context */
    ctx->m = flb_ml_create(config, ctx->ins->name);
    if (!ctx->m) {
        /*
        * we don't free the context since upon init failure, the exit
         * callback will be triggered with our context set above.
         */
        return -1;
    }

    /* Load the parsers/config */
    ret = multiline_load_parsers(ctx);
    if (ret == -1) {
        return -1;
    }

    /* Create a stream for this file */
    len = strlen(ins->name);
    ret = flb_ml_stream_create(ctx->m,
                               ins->name, len,
                               flush_callback, ctx,
                               &stream_id);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not create multiline stream");
        return -1;
    }
    ctx->stream_id = stream_id;

    return 0;
}

static int cb_ml_filter(const void *data, size_t bytes,
                        const char *tag, int tag_len,
                        void **out_buf, size_t *out_bytes,
                        struct flb_filter_instance *f_ins,
                        void *filter_context,
                        struct flb_config *config)
{
    int ret;
    int ok = MSGPACK_UNPACK_SUCCESS;
    size_t off = 0;
    (void) out_buf;
    (void) out_bytes;
    (void) f_ins;
    (void) filter_context;
    (void) config;
    msgpack_unpacked result;
    msgpack_object *obj;
    char *tmp_buf;
    size_t tmp_size;
    struct ml_ctx *ctx = filter_context;
    struct flb_time tm;

    /* reset mspgack size content */
    ctx->mp_sbuf.size = 0;

    /* process records */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == ok) {
        flb_time_pop_from_msgpack(&tm, &result, &obj);
        ret = flb_ml_append_object(ctx->m, ctx->stream_id, &tm, obj);
        if (ret != 0) {
            flb_plg_debug(ctx->ins,
                          "could not append object from tag: %s", tag);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* flush all pending buffered data (there is no auto-flush in filters) */
    flb_ml_flush_pending_now(ctx->m);

    if (ctx->mp_sbuf.size > 0) {
        /*
         * If the filter will report a new set of records because the
         * original data was modified, we make a copy to a new memory
         * area, since the buffer might be invalidated in the filter
         * chain.
         */

        tmp_buf = flb_malloc(ctx->mp_sbuf.size);
        if (!tmp_buf) {
            flb_errno();
            return FLB_FILTER_NOTOUCH;
        }
        tmp_size = ctx->mp_sbuf.size;
        memcpy(tmp_buf, ctx->mp_sbuf.data, tmp_size);
        *out_buf = tmp_buf;
        *out_bytes = tmp_size;
        ctx->mp_sbuf.size = 0;

        return FLB_FILTER_MODIFIED;
    }

    /* unlikely to happen.. but just in case */
    return FLB_FILTER_NOTOUCH;
}

static int cb_ml_exit(void *data, struct flb_config *config)
{
    struct ml_ctx *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->m) {
        flb_ml_destroy(ctx->m);
    }

    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    flb_free(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "debug_flush", "false",
     0, FLB_TRUE, offsetof(struct ml_ctx, debug_flush),
     "enable debugging for concatenation flush to stdout"
    },

    /* Multiline Core Engine based API */
    {
     FLB_CONFIG_MAP_CLIST, "multiline.parser", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct ml_ctx, multiline_parsers),
     "specify one or multiple multiline parsers: docker, cri, go, java, etc."
    },

    {
     FLB_CONFIG_MAP_STR, "multiline.key_content", NULL,
     0, FLB_TRUE, offsetof(struct ml_ctx, key_content),
     "specify the key name that holds the content to process."
    },

    /* EOF */
    {0}
};

struct flb_filter_plugin filter_multiline_plugin = {
    .name         = "multiline",
    .description  = "Concatenate multiline messages",
    .cb_init      = cb_ml_init,
    .cb_filter    = cb_ml_filter,
    .cb_exit      = cb_ml_exit,
    .config_map   = config_map,
    .flags        = 0
};
