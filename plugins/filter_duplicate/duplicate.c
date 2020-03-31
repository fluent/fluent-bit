/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *  Copyright (C) 2020 Nick Fischer
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
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_storage.h>

#include "duplicate.h"

/* Create an emitter input instance */
static int emitter_create(struct flb_duplicate *ctx)
{
    int ret;
    int coll_fd;
    struct flb_input_instance *ins;

    ret = flb_input_name_exists(ctx->emitter_name, ctx->config);
    if (ret == FLB_TRUE) {
        flb_plg_error(ctx->ins, "emitter_name '%s' already exists");
        return -1;
    }

    ins = flb_input_new(ctx->config, "emitter", NULL, FLB_FALSE);
    if (!ins) {
        flb_plg_error(ctx->ins, "cannot create emitter instance");
        return -1;
    }

    /* Set the alias name */
    ret = flb_input_set_property(ins, "alias", ctx->emitter_name);
    if (ret == -1) {
        flb_plg_warn(ctx->ins,
                     "cannot set emitter_name, using fallback name '%s'",
                     ins->name);
    }

    /* Initialize emitter plugin */
    ret = flb_input_instance_init(ins, ctx->config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot initialize emitter instance '%s'",
                      ins->name);
        flb_input_instance_exit(ins, ctx->config);
        flb_input_instance_destroy(ins);
        return -1;
    }

    /* Retrieve the collector id registered on the in_emitter initialization */
    coll_fd = in_emitter_get_collector_id(ins);

    /* Initialize plugin collector (event callback) */
    flb_input_collector_start(coll_fd, ins);

#ifdef FLB_HAVE_METRICS
    /* Override Metrics title */
    ret = flb_metrics_title(ctx->emitter_name, ins->metrics);
    if (ret == -1) {
        flb_plg_warn(ctx->ins, "cannot set metrics title, using fallback name %s",
                     ins->name);
    }
#endif

    /* Storage context */
    ret = flb_storage_input_create(ctx->config->cio, ins);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot initialize storage for stream '%s'",
                      ctx->emitter_name);
        return -1;
    }
    ctx->ins_emitter = ins;
    return 0;
}

static int cb_duplicate_init(struct flb_filter_instance *ins,
                               struct flb_config *config,
                               void *data)
{
    int ret;
    flb_sds_t tmp;
    flb_sds_t emitter_name = NULL;
    struct flb_duplicate *ctx;
    (void) data;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_duplicate));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->config = config;

    /*
     * Emitter name: every duplicate instance needs an emitter input plugin. We
     * use a unique instance so we can use the metrics interface.
     */
    tmp = (char *) flb_filter_get_property("emitter_name", ins);
    if (!tmp) {
        emitter_name = flb_sds_create_size(64);
        if (!emitter_name) {
            flb_free(ctx);
            return -1;
        }

        tmp = flb_sds_printf(&emitter_name, "emitter_for_%s", ins->name);
        if (!tmp) {
            flb_error("[filter duplicate] cannot compose emitter_name");
            flb_sds_destroy(emitter_name);
            flb_free(ctx);
            return -1;
        }

        flb_filter_set_property(ins, "emitter_name", emitter_name);
        flb_sds_destroy(emitter_name);
    }

    /* Set config_map properties in our local context */
    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set plugin context */
    flb_filter_set_context(ins, ctx);

    if (!ctx->new_tag) {
        flb_plg_error(ctx->ins, "new_tag property unspecified");
        flb_errno();
        flb_free(ctx);
        return -1;
    }

    /* Create the emitter context */
    ret = emitter_create(ctx);
    if (ret == -1) {
        return -1;
    }

    /* Register a metric to count the number of emitted records */
#ifdef FLB_HAVE_METRICS
    flb_metrics_add(FLB_DUP_METRIC_EMITTED,
                    "emit_records", ctx->ins->metrics);
#endif

    return 0;
}

/* Emit record with the new tag */
static int process_record(const void *buf, size_t buf_size,
                          struct flb_duplicate *ctx)
{
    int ret;

    /* Emit record with new tag */
    ret = in_emitter_add_record(ctx->new_tag, strlen(ctx->new_tag), buf, buf_size, ctx->ins_emitter);

    if (ret == -1) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int cb_duplicate_filter(const void *data, size_t bytes,
                                 const char *tag, int tag_len,
                                 void **out_buf, size_t *out_bytes,
                                 struct flb_filter_instance *f_ins,
                                 void *filter_context,
                                 struct flb_config *config)
{
    int ret;
    int emitted = 0;
    size_t pre = 0;
    size_t off = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_unpacked result;
    struct flb_duplicate *ctx = (struct flb_duplicate *) filter_context;
    (void) f_ins;
    (void) config;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /*
         * If it returns FLB_TRUE means
         * the record was emitter with a different tag.
         */
        ret = process_record((char *) data + pre, off - pre, ctx);
        if (ret == FLB_TRUE) {
            /* A record with the new tag was emitted */
            emitted++;
        }

        /* Write out the record with its original tag. */
        msgpack_sbuffer_write(&mp_sbuf, (char *) data + pre, off - pre);

        /* Adjust previous offset */
        pre = off;
    }
    msgpack_unpacked_destroy(&result);

    if (emitted == 0) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }
#ifdef FLB_HAVE_METRICS
    else if (emitted > 0) {
        flb_metrics_sum(FLB_DUP_METRIC_EMITTED, emitted, ctx->ins->metrics);
    }
#endif

    *out_buf = mp_sbuf.data;
    *out_bytes = mp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_duplicate_exit(void *data, struct flb_config *config)
{
    struct flb_duplicate *ctx = (struct flb_duplicate *) data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "new_tag", NULL,
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_duplicate, new_tag),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "emitter_name", NULL,
     FLB_FALSE, FLB_TRUE, offsetof(struct flb_duplicate, emitter_name),
     NULL
    },

    /* EOF */
    {0}
};

struct flb_filter_plugin filter_duplicate_plugin = {
    .name         = "duplicate",
    .description  = "Duplicate records with new tag.",
    .cb_init      = cb_duplicate_init,
    .cb_filter    = cb_duplicate_filter,
    .cb_exit      = cb_duplicate_exit,
    .config_map   = config_map,
    .flags        = 0
};
