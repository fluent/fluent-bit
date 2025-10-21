/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>

struct flb_null {
    struct flb_output_instance *ins;

    /* config map properties */
    int out_format;
    int json_date_format;
    flb_sds_t json_date_key;
    flb_sds_t date_key;
};

int cb_null_init(struct flb_output_instance *ins, struct flb_config *config,
                 void *data)
{
    int ret;
    (void) config;
    (void) data;
    const char *tmp;
    struct flb_null *ctx;

    ctx = flb_malloc(sizeof(struct flb_null));
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

    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_null_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    (void) out_context;
    (void) config;
    flb_sds_t json;
    struct flb_null *ctx = out_context;

#ifdef FLB_HAVE_METRICS
    /* Check if the event type is metrics, just return */
    if (event_chunk->type == FLB_EVENT_TYPE_METRICS) {
        FLB_OUTPUT_RETURN(FLB_OK);
    }
#endif

    /*
     * There are cases where the user might want to test the performance
     * of msgpack payload conversion to JSON. Nothing will be printed,
     * just encodeed and destroyed.
     */
    if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
        json = flb_pack_msgpack_to_json_format(event_chunk->data,
                                               event_chunk->size,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->date_key,
                                               config->json_escape_unicode);
        flb_sds_destroy(json);
    }

    flb_plg_debug(ctx->ins, "discarding %lu bytes", event_chunk->size);
    FLB_OUTPUT_RETURN(FLB_OK);
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
    "Specifies the name of the date field in output."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_null, json_date_key),
    FBL_PACK_JSON_DATE_FORMAT_DESCRIPTION
    },

    /* EOF */
    {0}
};

static int cb_null_exit(void *data, struct flb_config *config)
{
    struct flb_null *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

struct flb_output_plugin out_null_plugin = {
    .name         = "null",
    .description  = "Throws away events",
    .cb_init      = cb_null_init,
    .cb_flush     = cb_null_flush,
    .cb_exit      = cb_null_exit,
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS,
    .config_map   = config_map,
    .flags        = 0,
    .workers      = 1,
};
