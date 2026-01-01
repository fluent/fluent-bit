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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "in_head.h"
#define BUF_SIZE_MAX 512

static int read_lines(struct flb_in_head_config *ctx)
{
    FILE *fp = NULL;
    int i;
    int index = 0;
    int str_len;
    char buf[BUF_SIZE_MAX] = {0};
    int  new_len = 0;
    char *tmp;
    char *ret_buf;

    fp = fopen(ctx->filepath, "r");
    if (fp == NULL) {
        flb_errno();
        return -1;
    }

    for (i = 0; i<ctx->lines; i++){
        ret_buf = fgets(buf, BUF_SIZE_MAX-1, fp);
        if (ret_buf == NULL) {
            break;
        }
        str_len = strlen(buf);
        if (ctx->buf_size < str_len + index + 1) {
            /* buffer full. re-allocate new buffer */
            new_len = ctx->buf_size + str_len + 1;
            tmp = flb_malloc(new_len);
            if (tmp == NULL) {
                flb_plg_error(ctx->ins, "failed to allocate buffer");
                /* try to output partial data */
                break;
            }
            /* copy and release old buffer */
            strcpy(tmp, ctx->buf);
            flb_free(ctx->buf);

            ctx->buf_size = new_len;
            ctx->buf      = tmp;
        }
        strncat(&ctx->buf[index], buf, str_len);
        ctx->buf_len += str_len;
        index += str_len;
    }

    fclose(fp);
    return 0;
}

static int read_bytes(struct flb_in_head_config *ctx)
{
    int fd = -1;
    /* open at every collect callback */
    fd = open(ctx->filepath, O_RDONLY);
    if (fd < 0) {
        flb_errno();
        return -1;
    }
    ctx->buf_len = read(fd, ctx->buf, ctx->buf_size);
    close(fd);

    if (ctx->buf_len < 0) {
        flb_errno();
        return -1;
    }
    else {
        return 0;
    }
}

static int single_value_per_record(struct flb_input_instance *i_ins,
                                   struct flb_in_head_config *ctx)
{
    int ret = -1;

    ctx->buf[0] = '\0'; /* clear buf */
    ctx->buf_len =   0;

    if (ctx->lines > 0) {
        read_lines(ctx);
    }
    else {
        read_bytes(ctx);
    }

    flb_plg_trace(ctx->ins, "%s read_len=%zd buf_size=%zu", __FUNCTION__,
                  ctx->buf_len, ctx->buf_size);

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(
                &ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
                &ctx->log_encoder,
                FLB_LOG_EVENT_CSTRING_VALUE(ctx->key),
                FLB_LOG_EVENT_STRING_VALUE(ctx->buf, ctx->buf_len));

    }

    if (ctx->add_path) {
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("path"),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->filepath, ctx->path_len));
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(i_ins, NULL, 0,
                             ctx->log_encoder.output_buffer,
                             ctx->log_encoder.output_length);

        ret = 0;
    }
    else {
        flb_plg_error(i_ins, "Error encoding record : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_reset(&ctx->log_encoder);

    return ret;
}

#define KEY_LEN_MAX 32
static int split_lines_per_record(struct flb_input_instance *i_ins,
                      struct flb_in_head_config *ctx)
{
    FILE *fp = NULL;
    int i;
    int ret;
    size_t str_len;
    size_t key_len;
    char *ret_buf;
    char key_str[KEY_LEN_MAX] = {0};

    fp = fopen(ctx->filepath, "r");
    if (fp == NULL) {
        flb_errno();
        return -1;
    }

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(
                &ctx->log_encoder);
    }

    if (ctx->add_path) {
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("path"),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->filepath, ctx->path_len));
        }
    }

    for (i = 0; i < ctx->lines; i++) {
        ret_buf = fgets(ctx->buf, ctx->buf_size, fp);
        if (ret_buf == NULL) {
            ctx->buf[0] = '\0';
            str_len = 0;
        }
        else {
            str_len = strnlen(ctx->buf, ctx->buf_size-1);
            ctx->buf[str_len-1] = '\0';/* chomp str */
        }

        key_len = snprintf(key_str, KEY_LEN_MAX, "line%d", i);
        if (key_len > KEY_LEN_MAX) {
            key_len = KEY_LEN_MAX;
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(key_str),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->buf, str_len));
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(i_ins, NULL, 0,
                             ctx->log_encoder.output_buffer,
                             ctx->log_encoder.output_length);

        ret = 0;
    }
    else {
        flb_plg_error(i_ins, "Error encoding record : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_reset(&ctx->log_encoder);

    fclose(fp);

    return ret;
}


/* cb_collect callback */
static int in_head_collect(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    int ret = -1;
    struct flb_in_head_config *ctx = in_context;

    if (ctx->lines > 0 && ctx->split_line) {
        ret = split_lines_per_record(i_ins, ctx);
    }
    else {
        ret = single_value_per_record(i_ins, ctx);
    }

    return ret;
}

/* read config file and*/
static int in_head_config_read(struct flb_in_head_config *ctx,
                               struct flb_input_instance *in)
{
    int ret;
    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(in, "unable to load configuration");
        return -1;
    }


    ctx->key_len = strlen(ctx->key);

    /* only set lines if not explicitly set */
    if (ctx->split_line && ctx->lines <= 0) {
        ctx->lines      = 10;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }

    if (ctx->add_path) {
        ctx->path_len = strlen(ctx->filepath);
    }

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);

        return -1;
    }

    flb_plg_debug(ctx->ins, "buf_size=%zu path=%s",
                  ctx->buf_size, ctx->filepath);
    flb_plg_debug(ctx->ins, "interval_sec=%d interval_nsec=%d",
                  ctx->interval_sec, ctx->interval_nsec);

    return 0;
}

static void delete_head_config(struct flb_in_head_config *ctx)
{
    if (!ctx) {
        return;
    }

    flb_log_event_encoder_destroy(&ctx->log_encoder);

    /* release buffer */
    if (ctx->buf) {
        flb_free(ctx->buf);
    }

    flb_free(ctx);
}

/* Initialize plugin */
static int in_head_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_in_head_config *ctx;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_head_config));
    if (!ctx) {
        return -1;
    }

    ctx->buf = NULL;
    ctx->buf_len = 0;
    ctx->add_path = FLB_FALSE;
    ctx->lines = 0;
    ctx->ins = in;

    /* Initialize head config */
    ret = in_head_config_read(ctx, in);
    if (ret < 0) {
        goto init_error;
    }

    ctx->buf = flb_malloc(ctx->buf_size);
    if (!ctx->buf) {
        flb_errno();
        goto init_error;
    }

    flb_plg_trace(ctx->ins, "%s read_len=%zd buf_size=%zu", __FUNCTION__,
                  ctx->buf_len, ctx->buf_size);

    flb_input_set_context(in, ctx);

    ret = flb_input_set_collector_time(in,
                                       in_head_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec, config);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not set collector for head input plugin");
        goto init_error;
    }

    ctx->coll_fd = ret;
    return 0;

  init_error:
    delete_head_config(ctx);

    return -1;
}

static void in_head_pause(void *data, struct flb_config *config)
{
    struct flb_in_head_config *ctx = data;
    (void) config;

    /* Pause collector */
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_head_resume(void *data, struct flb_config *config)
{
    struct flb_in_head_config *ctx = data;
    (void) config;

    /* Resume collector */
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_head_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_head_config *head_config = data;

    delete_head_config(head_config);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "file", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_head_config, filepath),
     "Set the file"
    },
    {
     FLB_CONFIG_MAP_STR, "key", "head",
     0, FLB_TRUE, offsetof(struct flb_in_head_config, key),
     "Set the record key"
    },
    {
      FLB_CONFIG_MAP_SIZE, "buf_size", DEFAULT_BUF_SIZE,
      0, FLB_TRUE, offsetof(struct flb_in_head_config, buf_size),
      "Set the read buffer size"
    },
    {
      FLB_CONFIG_MAP_BOOL, "split_line", "false",
      0, FLB_TRUE, offsetof(struct flb_in_head_config, split_line),
      "generate key/value pair per line"
    },
    {
      FLB_CONFIG_MAP_INT, "lines", "0",
      0, FLB_TRUE, offsetof(struct flb_in_head_config, lines),
      "Line number to read"
    },
    {
      FLB_CONFIG_MAP_BOOL, "add_path", "false",
      0, FLB_TRUE, offsetof(struct flb_in_head_config, add_path),
      "append filepath to records"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_in_head_config, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_in_head_config, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_head_plugin = {
    .name         = "head",
    .description  = "Head Input",
    .cb_init      = in_head_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_head_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_head_pause,
    .cb_resume    = in_head_resume,
    .config_map   = config_map,
    .cb_exit      = in_head_exit
};
