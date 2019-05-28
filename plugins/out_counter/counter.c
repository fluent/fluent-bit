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

#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_mp.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

struct flb_counter_ctx {
    uint64_t total;
    msgpack_zone *zone;
};

int cb_counter_init(struct flb_output_instance *ins,
                 struct flb_config *config,
                 void *data)
{
    (void) ins;
    (void) config;
    (void) data;
    struct flb_counter_ctx *ctx;

    ctx = flb_malloc(sizeof(struct flb_counter_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->total = 0;
    ctx->zone = msgpack_zone_new(MSGPACK_ZONE_CHUNK_SIZE);
    if (!ctx->zone) {
        flb_free(ctx);
        return -1;
    }

    flb_output_set_context(ins, ctx);
    return 0;
}

void cb_counter_flush(const void *data, size_t bytes,
                      const char *tag, int tag_len,
                      struct flb_input_instance *i_ins,
                      void *out_context,
                      struct flb_config *config)
{
    (void) data;
    (void) bytes;
    (void) tag;
    (void) tag_len;
    (void) i_ins;
    (void) out_context;
    (void) config;
    size_t cnt;
    struct flb_counter_ctx *ctx = out_context;
    struct flb_time tm;

    /* Count number of parent items */
    cnt = flb_mp_count_zone(data, bytes, ctx->zone);
    ctx->total += cnt;

    flb_time_get(&tm);
    printf("%f,%lu (total = %"PRIu64")\n", flb_time_to_double(&tm), cnt,
           ctx->total);

    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_counter_exit(void *data, struct flb_config *config)
{
    struct flb_counter_ctx *ctx = data;

    msgpack_zone_free(ctx->zone);
    flb_free(ctx);
    return 0;
}

struct flb_output_plugin out_counter_plugin = {
    .name         = "counter",
    .description  = "Records counter",
    .cb_init      = cb_counter_init,
    .cb_flush     = cb_counter_flush,
    .cb_exit      = cb_counter_exit,
    .flags        = 0,
};
