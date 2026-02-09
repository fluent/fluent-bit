/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_log_event_decoder.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>

#include <cprofiles/cprofiles.h>
#include <cprofiles/cprof_encode_text.h>
#include <cprofiles/cprof_decode_msgpack.h>

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
    cfl_sds_t text;
    struct cmt *cmt = NULL;
    int ok = CMT_DECODE_MSGPACK_SUCCESS;

    /* get cmetrics context */
    while((ret = cmt_decode_msgpack_create(&cmt,
                                           (char *) data,
                                           bytes, &off)) == ok) {
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

    if (ret != ok) {
        flb_plg_debug(ins, "cmt decode msgpack returned : %d", ret);
    }
}
#endif

static void print_traces_text(struct flb_output_instance *ins,
                              const void *data, size_t bytes)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text;
    struct ctrace *ctr = NULL;
    int ok = CTR_DECODE_MSGPACK_SUCCESS;

    /* Decode each ctrace context */
    while ((ret = ctr_decode_msgpack_create(&ctr,
                                            (char *) data,
                                            bytes, &off)) == ok) {
        /* convert to text representation */
        text = ctr_encode_text_create(ctr);

        /* destroy ctr context */
        ctr_destroy(ctr);

        printf("%s", text);
        fflush(stdout);

        ctr_encode_text_destroy(text);
    }
    if (ret != ok) {
        flb_plg_debug(ins, "ctr decode msgpack returned : %d", ret);
    }
}

static void print_profiles_text(struct flb_output_instance *ins,
                                const void *data, size_t bytes)
{
    int ret;
    size_t off;
    cfl_sds_t text;
    struct cprof *profiles_context;

    profiles_context = NULL;
    off = 0;

    /* Decode each profiles context */
    while ((ret = cprof_decode_msgpack_create(&profiles_context,
                                              (unsigned char *) data,
                                              bytes, &off)) ==
                                                CPROF_DECODE_MSGPACK_SUCCESS) {
        /* convert to text representation */
        ret = cprof_encode_text_create(&text,
                                       profiles_context,
                                       CPROF_ENCODE_TEXT_RENDER_RESOLVED);

        if (ret != CPROF_ENCODE_TEXT_SUCCESS) {
            flb_plg_debug(ins, "cprofiles text encoder returned : %d", ret);

            continue;
        }

        /* destroy ctr context */
        cprof_decode_msgpack_destroy(profiles_context);

        printf("%s", text);
        fflush(stdout);

        cprof_encode_text_destroy(text);
    }

    if (ret != CPROF_DECODE_MSGPACK_SUCCESS) {
        flb_plg_debug(ins, "cprofiles msgpack decoder returned : %d", ret);
    }
}

static void cb_stdout_flush(struct flb_event_chunk *event_chunk,
                            struct flb_output_flush *out_flush,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event         log_event;
    int                          result;
    flb_sds_t                    json;
    struct flb_stdout           *ctx;
    size_t                       cnt;

    (void) config;

    result = FLB_EVENT_DECODER_SUCCESS;
    ctx = (struct flb_stdout *) out_context;
    cnt = 0;

#ifdef FLB_HAVE_METRICS
    /* Check if the event type is metrics, handle the payload differently */
    if (event_chunk->type == FLB_EVENT_TYPE_METRICS) {
        print_metrics_text(ctx->ins, (char *)
                           event_chunk->data,
                           event_chunk->size);
        FLB_OUTPUT_RETURN(FLB_OK);
    }
#endif

    if (event_chunk->type == FLB_EVENT_TYPE_TRACES) {
        print_traces_text(ctx->ins, (char *)
                          event_chunk->data,
                          event_chunk->size);
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    if (event_chunk->type == FLB_EVENT_TYPE_PROFILES) {
        print_profiles_text(ctx->ins, (char *)
                            event_chunk->data,
                            event_chunk->size);
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    /* Assuming data is a log entry...*/
    if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
        json = flb_pack_msgpack_to_json_format(event_chunk->data,
                                               event_chunk->size,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->date_key,
                                               config->json_escape_unicode);
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
        result = flb_log_event_decoder_init(&log_decoder,
                                            (char *) event_chunk->data,
                                            event_chunk->size);

        if (result != FLB_EVENT_DECODER_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "Log event decoder initialization error : %d", result);

            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        while (flb_log_event_decoder_next(&log_decoder,
                                           &log_event) == FLB_EVENT_DECODER_SUCCESS) {

            if (log_event.group_attributes != NULL) {
                printf("GROUP METADATA : \n\n");
                msgpack_object_print(stdout, *log_event.group_metadata);
                printf("\n\n");

                printf("GROUP ATTRIBUTES : \n\n");
                msgpack_object_print(stdout, *log_event.group_attributes);
                printf("\n\n");
            }

            printf("[%zd] %s: [[", cnt++, event_chunk->tag);

            printf("%"PRId32".%09lu, ", (int32_t) log_event.timestamp.tm.tv_sec,
                    log_event.timestamp.tm.tv_nsec);

            msgpack_object_print(stdout, *log_event.metadata);

            printf("], ");

            msgpack_object_print(stdout, *log_event.body);

            printf("]\n");
        }
        result = flb_log_event_decoder_get_last_result(&log_decoder);

        flb_log_event_decoder_destroy(&log_decoder);
    }

    fflush(stdout);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event decoder error : %d", result);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

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
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS | FLB_OUTPUT_TRACES |
                    FLB_OUTPUT_PROFILES | FLB_OUTPUT_BLOBS,
    .config_map   = config_map
};
