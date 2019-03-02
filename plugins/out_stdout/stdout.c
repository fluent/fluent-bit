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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include "stdout.h"

static int cb_stdout_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    char *tmp;
    struct flb_out_stdout_config *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_stdout_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->out_format = FLB_STDOUT_OUT_MSGPACK;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "msgpack") == 0) {
            ctx->out_format = FLB_STDOUT_OUT_MSGPACK;
        }
        else if (strcasecmp(tmp, "json_lines") == 0) {
            ctx->out_format = FLB_STDOUT_OUT_JSON_LINES;
        }
        else {
            flb_warn("[out_stdout] unrecognized 'format' option. Using 'msgpack'");
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = flb_output_get_date_format("json_date_format", ins);

    /* Date key for JSON output */
    tmp = flb_output_get_property("json_date_key", ins);
    ctx->json_date_key = flb_strdup(tmp ? tmp : "date");

    flb_output_set_context(ins, ctx);
    return 0;
}

static void cb_stdout_flush(void *data, size_t bytes,
                            char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    struct flb_out_stdout_config *ctx = out_context;
    char *json = NULL;
    char *buf = NULL;
    uint64_t json_len;

    (void) i_ins;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;

    if (ctx->out_format == FLB_STDOUT_OUT_JSON_LINES) {
        json = flb_msgpack_to_json_with_date(data, bytes, &json_len,
                                             ctx->json_date_key,
                                             ctx->json_date_format,
                                             FLB_JSON_FORMAT_LINES);
        printf("%s\n", json);
        flb_free(json);
        fflush(stdout);
    }
    else {
        /* A tag might not contain a NULL byte */
        buf = flb_malloc(tag_len + 1);
        if (!buf) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        memcpy(buf, tag, tag_len);
        buf[tag_len] = '\0';
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
            printf("[%zd] %s: [", cnt++, buf);
            flb_time_pop_from_msgpack(&tmp, &result, &p);
            printf("%"PRIu32".%09lu, ", (uint32_t)tmp.tm.tv_sec, tmp.tm.tv_nsec);
            msgpack_object_print(stdout, *p);
            printf("]\n");
        }
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_stdout_exit(void *data, struct flb_config *config)
{
    struct flb_out_stdout_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->json_date_key) {
        flb_free(ctx->json_date_key);
    }
    flb_free(ctx);
    return 0;
}

struct flb_output_plugin out_stdout_plugin = {
    .name         = "stdout",
    .description  = "Prints events to STDOUT",
    .cb_init      = cb_stdout_init,
    .cb_flush     = cb_stdout_flush,
    .cb_exit      = cb_stdout_exit,
    .flags        = 0,
};
