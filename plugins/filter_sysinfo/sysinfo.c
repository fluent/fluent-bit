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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>
#include "sysinfo.h"

static int cb_sysinfo_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data)
{
    struct filter_sysinfo_ctx *ctx = NULL;
    int ret;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct filter_sysinfo_ctx));
    if (ctx == NULL) {
        flb_errno();
        return -1;
    }
    ctx->ins = f_ins;

    if (flb_filter_config_map_set(f_ins, ctx) == -1) {
        flb_plg_error(f_ins, "unable to load configuration");
        flb_free(ctx);
        return -1;
    }

    ret = flb_sysinfo_platform_init(ctx);
    if (ret != 0) {
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int init_encoder_decoder(struct filter_sysinfo_ctx *ctx,
                                struct flb_log_event_encoder *enc,
                                struct flb_log_event_decoder *dec,
                                char *data, size_t bytes)
{
    int dec_ret;
    int enc_ret;

    dec_ret = flb_log_event_decoder_init(dec, (char *) data, bytes);
    if (dec_ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %s",
                      flb_log_event_decoder_get_error_description(dec_ret));

        return -1;
    }
    enc_ret = flb_log_event_encoder_init(enc, FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %s",
                      flb_log_event_encoder_get_error_description(enc_ret));
        flb_log_event_decoder_destroy(dec);
        return -1;
    }
    return 0;
}

static int exit_encoder_decoder(struct filter_sysinfo_ctx *ctx,
                                struct flb_log_event_encoder *enc,
                                struct flb_log_event_decoder *dec,
                                void **out_buf, size_t *out_bytes)
{
    int dec_ret;
    int ret = FLB_FILTER_NOTOUCH;

    dec_ret = flb_log_event_decoder_get_last_result(dec);
    if (dec_ret == FLB_EVENT_DECODER_SUCCESS) {
        if (enc->output_length > 0) {
            *out_buf = enc->output_buffer;
            *out_bytes = enc->output_length;
            ret = FLB_FILTER_MODIFIED;
            flb_log_event_encoder_claim_internal_buffer_ownership(enc);
        }
    }
    else {
        flb_plg_error(ctx->ins,
                      "flb_log_event_decoder_get_last_result error : %s",
                      flb_log_event_decoder_get_error_description(dec_ret));
    }

    flb_log_event_decoder_destroy(dec);
    flb_log_event_encoder_destroy(enc);

    return ret;
}



static int copy_original_event(struct filter_sysinfo_ctx *ctx,
                               struct flb_log_event_encoder *enc,
                               struct flb_log_event *log_event)
{
    msgpack_object *obj;
    int enc_ret;
    int map_num;
    int i;


    enc_ret = flb_log_event_encoder_begin_record(enc);
    if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "flb_log_event_encoder_begin_record failed: %s",
                      flb_log_event_encoder_get_error_description(enc_ret));
        return -1;
    }

    enc_ret = flb_log_event_encoder_set_timestamp(enc, &log_event->timestamp);
    if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "flb_log_event_encoder_set_timestamp failed: %s",
                      flb_log_event_encoder_get_error_description(enc_ret));
        return -1;
    }

    obj = log_event->body;
    if (obj->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "body object is not a map");
        return -1;
    }

    map_num = obj->via.map.size;

    for (i=0; i<map_num; i++) {
        enc_ret = flb_log_event_encoder_append_body_values(
                    enc,
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&obj->via.map.ptr[i].key),
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&obj->via.map.ptr[i].val));
        if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins, "flb_log_event_encoder_append_body_values failed: %s",
                          flb_log_event_encoder_get_error_description(enc_ret));
            return -1;
        }
    }

    enc_ret = flb_log_event_encoder_set_metadata_from_msgpack_object(enc,
                                                                     log_event->metadata);
    if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "flb_log_event_encoder_set_metadata_from_msgpack_object failed: %s",
                      flb_log_event_encoder_get_error_description(enc_ret));
        return -1;
    }


    return 0;
}

static int cb_sysinfo_filter(const void *data, size_t bytes,
                             const char *tag, int tag_len,
                             void **out_buf, size_t *out_bytes,
                             struct flb_filter_instance *f_ins,
                             struct flb_input_instance *i_ins,
                             void *filter_context,
                             struct flb_config *config)
{
    struct filter_sysinfo_ctx *ctx = filter_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event log_event;
    int dec_ret;
    int ret;

    (void) f_ins;
    (void) i_ins;
    (void) filter_context;
    (void) config;

    ret = init_encoder_decoder(ctx, &log_encoder, &log_decoder, (char*)data, bytes);
    if (ret != 0) {
        return FLB_FILTER_NOTOUCH;
    }

    while ((dec_ret = flb_log_event_decoder_next(
                      &log_decoder,
                      &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = copy_original_event(ctx, &log_encoder, &log_event);
        if (ret != 0) {
            flb_log_event_encoder_rollback_record(&log_encoder);
            continue;
        }

        ret = flb_sysinfo_append_common_info(ctx, &log_encoder);
        if (ret != 0) {
            flb_log_event_encoder_rollback_record(&log_encoder);
            continue;
        }
        ret = flb_sysinfo_platform_filter(ctx, &log_encoder, &log_decoder);
        if (ret != 0) {
            flb_log_event_encoder_rollback_record(&log_encoder);
            continue;
        }

        flb_log_event_encoder_commit_record(&log_encoder);
    }

    return exit_encoder_decoder(ctx, &log_encoder, &log_decoder, out_buf, out_bytes);
}

static int cb_sysinfo_exit(void *data, struct flb_config *config)
{
    struct filter_sysinfo_ctx *ctx = data;
    if (ctx == NULL) {
        return 0;
    }
    flb_sysinfo_platform_exit(ctx);

    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "fluentbit_version_key", NULL,
     0, FLB_TRUE, offsetof(struct filter_sysinfo_ctx, flb_ver_key),
     "Specify the key name for fluent-bit version."
    },
    {
     FLB_CONFIG_MAP_STR, "os_name_key", NULL,
     0, FLB_TRUE, offsetof(struct filter_sysinfo_ctx, os_name_key),
     "Specify the key name for os name. e.g. linux, win64 or macos."
    },
    {
     FLB_CONFIG_MAP_STR, "hostname_key", NULL,
     0, FLB_TRUE, offsetof(struct filter_sysinfo_ctx, hostname_key),
     "Specify the key name for hostname."
    },



    /* Platform specific config */
    {
     FLB_CONFIG_MAP_STR, "os_version_key", NULL,
     0, FLB_TRUE, offsetof(struct filter_sysinfo_ctx, os_version_key),
     "Specify the key name for os version. It is not supported on some platforms."
    },
    {
     FLB_CONFIG_MAP_STR, "kernel_version_key", NULL,
     0, FLB_TRUE, offsetof(struct filter_sysinfo_ctx, kernel_version_key),
     "Specify the key name for kernel version. It is not supported on some platforms."
    },

    /* EOF */
    {0}
};

struct flb_filter_plugin filter_sysinfo_plugin = {
    .name         = "sysinfo",
    .description  = "Filter for system info",
    .cb_init      = cb_sysinfo_init,
    .cb_filter    = cb_sysinfo_filter,
    .cb_exit      = cb_sysinfo_exit,
    .config_map   = config_map,
    .flags        = 0
};
