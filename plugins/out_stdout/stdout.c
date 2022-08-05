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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_metrics.h>

#include <msgpack.h>
#include "stdout.h"


static int cb_stdout_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct flb_stdout *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_stdout));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ctx->out_format = FLB_PACK_JSON_FORMAT_NONE;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unrecognized 'format' option. "
                          "Using 'msgpack'");
        }
        else {
            ctx->out_format = ret;
        }
    }

    /* Date key */
    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        /* Just check if we have to disable it */
        if (flb_utils_bool(tmp) == FLB_FALSE) {
            ctx->date_key = NULL;
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "invalid json_date_format '%s'. "
                          "Using 'double' type", tmp);
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

#ifdef FLB_HAVE_METRICS
static void print_metrics_text(struct flb_output_instance *ins,
                               const void *data, size_t bytes)
{
    int ret;
    size_t off = 0;
    cmt_sds_t text;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) data, bytes, &off);
    if (ret != 0) {
        flb_plg_error(ins, "could not process metrics payload");
        return;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);

    /* destroy cmt context */
    cmt_destroy(cmt);

    printf("%s", text);
    fflush(stdout);

    cmt_encode_text_destroy(text);
}
#endif

static void cb_stdout_flush(struct flb_event_chunk *event_chunk,
                            struct flb_output_flush *out_flush,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    struct flb_stdout *ctx = out_context;
    flb_sds_t json;
    char *buf = NULL;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;

#ifdef FLB_HAVE_METRICS
    /* Check if the event type is metrics, handle the payload differently */
    if (event_chunk->type == FLB_EVENT_TYPE_METRIC) {
        print_metrics_text(ctx->ins, (char *)
                           event_chunk->data,
                           event_chunk->size);
        FLB_OUTPUT_RETURN(FLB_OK);
    }
#endif

    /* Assuming data is a log entry...*/
    if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
        json = flb_pack_msgpack_to_json_format(event_chunk->data,
                                               event_chunk->size,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->date_key);
        write(STDOUT_FILENO, json, flb_sds_len(json));
        flb_sds_destroy(json);

        /*
         * If we are 'not' in json_lines mode, we need to add an extra
         * breakline.
         */
        if (ctx->out_format != FLB_PACK_JSON_FORMAT_LINES) {
            printf("\n");
        }
        fflush(stdout);
    }
    else {
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result,
                                   event_chunk->data,
                                   event_chunk->size, &off) == MSGPACK_UNPACK_SUCCESS) {
            if (flb_time_pop_from_msgpack(&tmp, &result, &p) != -1 ) {
                printf("[%zd] %s: [", cnt++, event_chunk->tag);
                printf("%"PRIu32".%09lu, ", (uint32_t)tmp.tm.tv_sec, tmp.tm.tv_nsec);
                msgpack_object_print(stdout, *p);
                printf("]\n");
            }
        }
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
    }
    fflush(stdout);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_stdout_exit(void *data, struct flb_config *config)
{
    struct flb_stdout *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     "Specifies the data format to be printed. Supported formats are msgpack json, json_lines and json_stream."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
    FBL_PACK_JSON_DATE_FORMAT_DESCRIPTION
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_stdout, json_date_key),
    "Specifies the name of the date field in output."
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_stdout_plugin = {
    .name         = "stdout",
    .description  = "Prints events to STDOUT",
    .cb_init      = cb_stdout_init,
    .cb_flush     = cb_stdout_flush,
    .cb_exit      = cb_stdout_exit,
    .flags        = 0,
    .workers      = 1,
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS,
    .config_map   = config_map
};
