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
#include <fluent-bit/flb_input.h>
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
                flb_error("failed to allocate buffer");
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
    int num_map = 1;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    ctx->buf[0] = '\0'; /* clear buf */
    ctx->buf_len =   0;

    if (ctx->lines > 0) {
        read_lines(ctx);
    }
    else {
        read_bytes(ctx);
    }

    flb_trace("%s read_len=%d buf_size=%d", __FUNCTION__,
              ctx->buf_len, ctx->buf_size);

    if (ctx->add_path == FLB_TRUE) {
        num_map++;
    }

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack data */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, num_map);

    msgpack_pack_str(&mp_pck, ctx->key_len);
    msgpack_pack_str_body(&mp_pck, ctx->key,
                          ctx->key_len);
    msgpack_pack_str(&mp_pck, ctx->buf_len);
    msgpack_pack_str_body(&mp_pck,
                          ctx->buf, ctx->buf_len);

    if (ctx->add_path == FLB_TRUE) {
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "path", 4);
        msgpack_pack_str(&mp_pck, ctx->path_len);
        msgpack_pack_str_body(&mp_pck,
                              ctx->filepath, ctx->path_len);
    }

    ret = 0;

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return ret;

}

#define KEY_LEN_MAX 32
static int split_lines_per_record(struct flb_input_instance *i_ins,
                      struct flb_in_head_config *ctx)
{
    FILE *fp = NULL;
    int i;
    size_t str_len;
    size_t key_len;
    int num_map = ctx->lines;
    char *ret_buf;
    char key_str[KEY_LEN_MAX] = {0};
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    fp = fopen(ctx->filepath, "r");
    if (fp == NULL) {
        flb_errno();
        return -1;
    }

    if (ctx->add_path == FLB_TRUE) {
        num_map++;
    }

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack data */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, num_map);

    if (ctx->add_path == FLB_TRUE) {
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "path", 4);
        msgpack_pack_str(&mp_pck, ctx->path_len);
        msgpack_pack_str_body(&mp_pck,
                              ctx->filepath, ctx->path_len);
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

        msgpack_pack_str(&mp_pck, key_len);
        msgpack_pack_str_body(&mp_pck, key_str, key_len);
        msgpack_pack_str(&mp_pck, str_len);
        msgpack_pack_str_body(&mp_pck,
                              ctx->buf, str_len);
    }

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);
    fclose(fp);
    return 0;
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
    const char *filepath = NULL;
    const char *pval = NULL;

    /* filepath setting */
    filepath = flb_input_get_property("file", in);
    if (!filepath) {
        return -1;
    }
    ctx->filepath = filepath;

    pval = flb_input_get_property("key", in);
    if (pval) {
        ctx->key      = pval;
        ctx->key_len  = strlen(pval);
    }
    else {
        ctx->key      = "head";
        ctx->key_len  = 4;
    }

    /* buffer size setting */
    pval = flb_input_get_property("buf_size", in);
    if (pval != NULL && atoi(pval) > 0) {
        ctx->buf_size = atoi(pval);
    }
    else {
        ctx->buf_size = DEFAULT_BUF_SIZE;
    }

    /* interval settings */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        ctx->interval_sec = atoi(pval);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }

    pval = flb_input_get_property("interval_nsec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        ctx->interval_nsec = atoi(pval);
    }
    else {
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    pval = flb_input_get_property("split_line", in);
    if (pval != NULL && flb_utils_bool(pval)) {
        ctx->split_line = FLB_TRUE;
        ctx->lines      = 10;
    }
    else {
        ctx->split_line = FLB_FALSE;
    }

    pval = flb_input_get_property("lines", in);
    if (pval != NULL && atoi(pval) >= 0) {
        ctx->lines = atoi(pval);
    }
    else {
        ctx->lines = 0; /* read bytes mode */
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    pval = flb_input_get_property("add_path", in);
    if (pval) {
        if (strcasecmp(pval, "true") == 0 || strcasecmp(pval, "on") == 0) {
            ctx->add_path = FLB_TRUE;
            ctx->path_len = strlen(ctx->filepath);
        }
    }

    flb_debug("[in_head] buf_size=%d path=%s",
              ctx->buf_size, ctx->filepath);
    flb_debug("[in_head] interval_sec=%d interval_nsec=%d",
              ctx->interval_sec, ctx->interval_nsec);

    return 0;
}

static void delete_head_config(struct flb_in_head_config *ctx)
{
    if (!ctx) {
        return;
    }

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
    ctx->ins= in;

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

    flb_trace("%s read_len=%d buf_size=%d", __FUNCTION__, ctx->buf_len,
              ctx->buf_size);

    flb_input_set_context(in, ctx);

    ret = flb_input_set_collector_time(in,
                                       in_head_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec, config);
    if (ret < 0) {
        flb_error("could not set collector for head input plugin");
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


struct flb_input_plugin in_head_plugin = {
    .name         = "head",
    .description  = "Head Input",
    .cb_init      = in_head_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_head_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_head_pause,
    .cb_resume    = in_head_resume,
    .cb_exit      = in_head_exit
};
