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
static int read_lines(struct flb_in_head_config *head_config)
{
    FILE *fp = NULL;
    int i;
    int index = 0;
    int str_len;
    char buf[BUF_SIZE_MAX] = {0};

    int  new_len = 0;
    char *tmp;
    char *ret_buf;

    fp = fopen(head_config->filepath, "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    for(i=0; i<head_config->lines; i++){
        ret_buf = fgets(buf, BUF_SIZE_MAX-1, fp);
        if (ret_buf == NULL) {
            break;
        }
        str_len = strlen(buf);
        if (head_config->buf_size < str_len + index + 1) {
            /* buffer full. re-allocate new buffer */
            new_len = head_config->buf_size + str_len + 1;
            tmp = (char*)flb_malloc(new_len);
            if (tmp == NULL) {
                flb_error("failed to allocate buffer");
                /* try to output partial data */
                break;
            }
            /* copy and release old buffer */
            strcpy(tmp, head_config->buf);
            flb_free(head_config->buf);

            head_config->buf_size = new_len;
            head_config->buf      = tmp;
        }
        strncat(&head_config->buf[index], buf, str_len);
        head_config->buf_len += str_len;
        index += str_len;
    }
    fclose(fp);
    return 0;
}

static int read_bytes(struct flb_in_head_config *head_config)
{
    int fd = -1;
    /* open at every collect callback */
    fd = open(head_config->filepath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    head_config->buf_len = read(fd, head_config->buf, head_config->buf_size);
    close(fd);
    if (head_config->buf_len < 0) {
        perror("read");
        return -1;
    }
    else {
        return 0;
    }
}

static int single_value_per_record(struct flb_input_instance *i_ins,
                      struct flb_in_head_config *head_config)
{
    int ret = -1;
    int num_map = 1;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    head_config->buf[0] = '\0'; /* clear buf */
    head_config->buf_len =   0;

    if (head_config->lines > 0) {
        read_lines(head_config);
    }
    else {
        read_bytes(head_config);
    }

    flb_trace("%s read_len=%d buf_size=%d", __FUNCTION__,
              head_config->buf_len, head_config->buf_size);

    if (head_config->add_path == FLB_TRUE) {
        num_map++;
    }

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack data */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, num_map);

    msgpack_pack_str(&mp_pck, head_config->key_len);
    msgpack_pack_str_body(&mp_pck, head_config->key,
                          head_config->key_len);
    msgpack_pack_str(&mp_pck, head_config->buf_len);
    msgpack_pack_str_body(&mp_pck,
                          head_config->buf, head_config->buf_len);

    if (head_config->add_path == FLB_TRUE) {
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "path", 4);
        msgpack_pack_str(&mp_pck, head_config->path_len);
        msgpack_pack_str_body(&mp_pck,
                              head_config->filepath, head_config->path_len);
    }

    ret = 0;

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return ret;

}

#define KEY_LEN_MAX 32
static int split_lines_per_record(struct flb_input_instance *i_ins,
                      struct flb_in_head_config *head_config)
{
    FILE *fp = NULL;
    int i;
    size_t str_len;
    size_t key_len;
    int num_map = head_config->lines;
    char *ret_buf;
    char key_str[KEY_LEN_MAX] = {0};
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    fp = fopen(head_config->filepath, "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    if (head_config->add_path == FLB_TRUE) {
        num_map++;
    }

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack data */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, num_map);

    if (head_config->add_path == FLB_TRUE) {
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "path", 4);
        msgpack_pack_str(&mp_pck, head_config->path_len);
        msgpack_pack_str_body(&mp_pck,
                              head_config->filepath, head_config->path_len);
    }

    for (i = 0; i < head_config->lines; i++) {
        ret_buf = fgets(head_config->buf, head_config->buf_size, fp);
        if (ret_buf == NULL) {
            head_config->buf[0] = '\0';
            str_len = 0;
        }
        else {
            str_len = strnlen(head_config->buf, head_config->buf_size-1);
            head_config->buf[str_len-1] = '\0';/* chomp str */
        }

        key_len = snprintf(key_str, KEY_LEN_MAX, "line%d", i);
        if (key_len > KEY_LEN_MAX) {
            key_len = KEY_LEN_MAX;
        }

        msgpack_pack_str(&mp_pck, key_len);
        msgpack_pack_str_body(&mp_pck, key_str, key_len);
        msgpack_pack_str(&mp_pck, str_len);
        msgpack_pack_str_body(&mp_pck,
                              head_config->buf, str_len);
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
    struct flb_in_head_config *head_config = in_context;
    int ret = -1;

    if (head_config->lines > 0 && head_config->split_line) {
        ret = split_lines_per_record(i_ins, head_config);
    }
    else {
        ret = single_value_per_record(i_ins, head_config);
    }

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

    pval = flb_input_get_property("key", in);
    if (pval) {
        head_config->key      = pval;
        head_config->key_len  = strlen(pval);
    }
    else {
        head_config->key      = "head";
        head_config->key_len  = 4;
    }

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

    pval = flb_input_get_property("split_line", in);
    if (pval != NULL && flb_utils_bool(pval)) {
        head_config->split_line = FLB_TRUE;
        head_config->lines      = 10;
    }
    else {
        head_config->split_line = FLB_FALSE;
    }

    pval = flb_input_get_property("lines", in);
    if (pval != NULL && atoi(pval) >= 0) {
        head_config->lines = atoi(pval);
    }
    else {
        head_config->lines = 0; /* read bytes mode */
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
    head_config->add_path = FLB_FALSE;
    head_config->lines = 0;

    /* Initialize head config */
    ret = in_head_config_read(head_config, in);
    if (ret < 0) {
        goto init_error;
    }

    head_config->buf = flb_malloc(head_config->buf_size);
    if (head_config->buf == NULL) {
        flb_error("could not allocate head buffer");
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
        flb_error("could not set collector for head input plugin");
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
