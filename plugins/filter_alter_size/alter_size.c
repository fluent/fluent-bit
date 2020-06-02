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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

struct flb_alter_size {
    int add;
    int remove;
};

static int cb_alter_size_init(struct flb_filter_instance *ins,
                              struct flb_config *config,
                              void *data)
{
    int ret;
    (void) data;
    struct flb_alter_size *ctx;

    ctx = flb_malloc(sizeof(struct flb_alter_size));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    if (ctx->add > 0 && ctx->remove > 0) {
        flb_plg_error(ins, "cannot use 'add' and 'remove' at the same time");
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(ins, ctx);
    return 0;
}

static int cb_alter_size_filter(const void *data, size_t bytes,
                                const char *tag, int tag_len,
                                void **out_buf, size_t *out_size,
                                struct flb_filter_instance *ins,
                                void *filter_context,
                                struct flb_config *config)
{
    int i;
    int ok = MSGPACK_UNPACK_SUCCESS;
    int len;
    int total;
    int count = 0;
    size_t off = 0;
    (void) config;
    char tmp[32];
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    struct flb_alter_size *ctx = filter_context;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    if (ctx->add > 0) {
        flb_plg_debug(ins, "add %i records", ctx->add);

        /* append old data */
        msgpack_sbuffer_write(&mp_sbuf, data, bytes);

        for (i = 0; i < ctx->add; i++) {
            msgpack_pack_array(&mp_pck, 2);
            flb_time_append_to_msgpack(NULL, &mp_pck, FLB_TIME_ETFMT_V1_FIXEXT);

            len = snprintf(tmp, sizeof(tmp) - 1, "alter_size %i", i);
            msgpack_pack_map(&mp_pck, 1);
            msgpack_pack_str(&mp_pck, 3);
            msgpack_pack_str_body(&mp_pck, "key", 3);
            msgpack_pack_str(&mp_pck, len);
            msgpack_pack_str_body(&mp_pck, tmp, len);
        }
    }
    else if (ctx->remove > 0) {
        flb_plg_debug(ins, "remove %i records", ctx->remove);
        count = 0;

        /* Count number of current items */
        total = flb_mp_count(data, bytes);
        total -= ctx->remove;
        if (total <= 0) {
            /* zero records */
            goto exit;
        }

        msgpack_unpacked_init(&result);
        while (count < total &&
               msgpack_unpack_next(&result, data, bytes, &off) == ok) {
            root = result.data;
            msgpack_pack_object(&mp_pck, root);
            count++;
        }
        msgpack_unpacked_destroy(&result);
    }

    exit:
    /* link new buffers */
    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_alter_size_exit(void *data, struct flb_config *config)
{
    (void) config;
    struct flb_alter_size *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_INT, "add", "0",
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_alter_size, add),
     "add N records to the chunk"
    },
    {
     FLB_CONFIG_MAP_INT, "remove", "0",
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_alter_size, remove),
     "remove N records from the chunk"
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_alter_size_plugin = {
    .name         = "alter_size",
    .description  = "Alter incoming chunk size",
    .cb_init      = cb_alter_size_init,
    .cb_filter    = cb_alter_size_filter,
    .cb_exit      = cb_alter_size_exit,
    .config_map   = config_map,
    .flags        = 0
};
