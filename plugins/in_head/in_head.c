/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_stats.h>

#include "in_head.h"

/* cb_collect callback */
static int in_head_collect(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_in_head_config *head_config = in_context;
    int fd = -1;
    int ret = -1;
    int num_map = 1;

    /* open at every collect callback */
    fd = open(head_config->filepath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    head_config->buf_len = read(fd, head_config->buf, head_config->buf_size);
    flb_trace("%s read_len=%d buf_size=%d", __FUNCTION__,
              head_config->buf_len, head_config->buf_size);

    if (head_config->buf_len < 0) {
        perror("read");
        goto collect_fin;
    }

    if (head_config->add_path == FLB_TRUE) {
        num_map++;
    }

    msgpack_pack_array(&i_ins->mp_pck, 2);
    msgpack_pack_uint64(&i_ins->mp_pck, time(NULL));

    msgpack_pack_map(&i_ins->mp_pck, num_map);

    msgpack_pack_bin(&i_ins->mp_pck, 4);
    msgpack_pack_bin_body(&i_ins->mp_pck, "head", 4);
    msgpack_pack_bin(&i_ins->mp_pck, head_config->buf_len);
    msgpack_pack_bin_body(&i_ins->mp_pck,
                          head_config->buf, head_config->buf_len);

    if (head_config->add_path == FLB_TRUE) {
        msgpack_pack_bin(&i_ins->mp_pck, 4);
        msgpack_pack_bin_body(&i_ins->mp_pck, "path", 4);
        msgpack_pack_bin(&i_ins->mp_pck, head_config->path_len);
        msgpack_pack_bin_body(&i_ins->mp_pck,
                              head_config->filepath, head_config->path_len);
    }

    ret = 0;
    head_config->idx++;
    flb_stats_update(in_head_plugin.stats_fd, 0, 1);

 collect_fin:
    close(fd);
    return ret;
}

/* read config file and*/
static int in_head_config_read(struct flb_in_head_config *head_config,
                               struct flb_input_instance *in)
{
    char *filepath = NULL;
    char *pval = NULL;

    /* filepath setting */
    filepath = flb_input_get_property("file", in);
    if (!filepath) {
        return -1;
    }
    head_config->filepath = filepath;

    /* buffer size setting */
    pval = flb_input_get_property("buf_size", in);
    if (pval != NULL && atoi(pval) > 0) {
        head_config->buf_size = atoi(pval);
    }
    else {
        head_config->buf_size = DEFAULT_BUF_SIZE;
    }

    /* interval settings */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        head_config->interval_sec = atoi(pval);
    }
    else {
        head_config->interval_sec = DEFAULT_INTERVAL_SEC;
    }

    pval = flb_input_get_property("interval_nsec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        head_config->interval_nsec = atoi(pval);
    }
    else {
        head_config->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    if (head_config->interval_sec <= 0 && head_config->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        head_config->interval_sec = DEFAULT_INTERVAL_SEC;
        head_config->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    pval = flb_input_get_property("add_path", in);
    if (pval) {
        if (strcasecmp(pval, "true") == 0 || strcasecmp(pval, "on") == 0) {
            head_config->add_path = FLB_TRUE;
            head_config->path_len = strlen(head_config->filepath);
        }
    }

    flb_debug("[in_head] buf_size=%d path=%s",
              head_config->buf_size, head_config->filepath);
    flb_debug("[in_head] interval_sec=%d interval_nsec=%d",
              head_config->interval_sec, head_config->interval_nsec);

    return 0;
}

static void delete_head_config(struct flb_in_head_config *head_config)
{
    if (head_config) {
        /* release buffer */
        if (head_config->buf != NULL) {
            flb_free(head_config->buf);
        }
        flb_free(head_config);
    }
}

/* Initialize plugin */
static int in_head_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    struct flb_in_head_config *head_config = NULL;
    int ret = -1;

    /* Allocate space for the configuration */
    head_config = flb_malloc(sizeof(struct flb_in_head_config));
    if (head_config == NULL) {
        return -1;
    }
    head_config->buf = NULL;
    head_config->buf_len = 0;
    head_config->idx = 0;
    head_config->add_path = FLB_FALSE;

    /* Initialize head config */
    ret = in_head_config_read(head_config, in);
    if (ret < 0) {
        goto init_error;
    }

    head_config->buf = flb_malloc(head_config->buf_size);
    if (head_config->buf == NULL) {
        flb_utils_error_c("could not allocate head buffer");
        goto init_error;
    }

    flb_trace("%s read_len=%d buf_size=%d", __FUNCTION__,
              head_config->buf_len, sizeof(head_config->buf));

    flb_input_set_context(in, head_config);

    ret = flb_input_set_collector_time(in,
                                       in_head_collect,
                                       head_config->interval_sec,
                                       head_config->interval_nsec, config);
    if (ret < 0) {
        flb_utils_error_c("could not set collector for head input plugin");
        goto init_error;
    }

    return 0;

  init_error:
    delete_head_config(head_config);

    return -1;
}

int in_head_exit(void *data, struct flb_config *config)
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
    .cb_exit      = in_head_exit
};
