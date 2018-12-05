/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_pack.h>

#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "in_disk.h"

#define LINE_SIZE 256
#define BUF_SIZE  32

static char *shift_line(const char *line, char separator, int *idx,
                        char *buf, int buf_size)
{
    char pack_mode = FLB_FALSE;
    int  idx_buf = 0;

    while(1) {
        if (line[*idx] == '\0') {
            /* end of line */
            return NULL;
        }
        else if (line[*idx] != separator) {
            pack_mode = FLB_TRUE;
            buf[idx_buf] = line[*idx];
            idx_buf++;

            if (idx_buf >= buf_size) {
                buf[idx_buf-1] = '\0';
                return NULL;
            }
        }
        else if (pack_mode == FLB_TRUE) {
            buf[idx_buf] = '\0';
            return buf;
        }
        *idx += 1;
    }
}

static int update_disk_stats(struct flb_in_disk_config *ctx)
{
    char line[LINE_SIZE] = {0};
    char buf[BUF_SIZE] = {0};
    char skip_line = FLB_FALSE;
    uint64_t temp_total = 0;
    FILE *fp  = NULL;
    int  i_line   = 0;
    int  i_entry = 0;
    int  i_field = 0;

    fp = fopen("/proc/diskstats", "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    while (fgets(line, LINE_SIZE-1, fp) != NULL) {
        i_line = 0;
        i_field = 0;
        skip_line = FLB_FALSE;
        while (skip_line != FLB_TRUE &&
               shift_line(line, ' ', &i_line, buf, BUF_SIZE-1) != NULL) {
            i_field++;
            switch(i_field) {
            case 3: /* device name */
                if (ctx->dev_name != NULL && strstr(buf, ctx->dev_name) == NULL) {
                    skip_line = FLB_TRUE;
                }
                break;
            case 6: /* sectors read */
                temp_total = strtoull(buf, NULL, 10);
                ctx->prev_read_total[i_entry] = ctx->read_total[i_entry];
                ctx->read_total[i_entry] = temp_total;
                break;
            case 10: /* sectors written */
                temp_total = strtoull(buf, NULL, 10);
                ctx->prev_write_total[i_entry] = ctx->write_total[i_entry];
                ctx->write_total[i_entry] = temp_total;

                skip_line = FLB_TRUE;
                break;
            default:
                continue;
            }
        }
        i_entry++;
    }

    fclose(fp);
    return 0;
}


/* cb_collect callback */
static int in_disk_collect(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_in_disk_config *ctx = in_context;
    (void) *i_ins;
    (void) *config;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* The type of sector size is unsigned long in kernel source */
    unsigned long   read_total = 0;
    unsigned long  write_total = 0;

    int entry = ctx->entry;
    int i;
    int num_map = 2;/* write, read */

    update_disk_stats(ctx);

    if ( ctx->first_snapshot == FLB_TRUE ){
        ctx->first_snapshot = FLB_FALSE;    /* assign first_snapshot with FLB_FALSE */
    }
    else {
        for (i=0; i<entry; i++) {
            if (ctx->read_total[i] >= ctx->prev_read_total[i]) {
                read_total += ctx->read_total[i] - ctx->prev_read_total[i];
            }
            else {
                /* Overflow */
                read_total += ctx->read_total[i] +
                    (ULONG_MAX - ctx->prev_read_total[i]);
            }

            if (ctx->write_total[i] >= ctx->prev_write_total[i]) {
                write_total += ctx->write_total[i] - ctx->prev_write_total[i];
            }
            else {
                /* Overflow */
                write_total += ctx->write_total[i] +
                    (ULONG_MAX - ctx->prev_write_total[i]);
            }
        }

        read_total  *= 512;
        write_total *= 512;

        /* Initialize local msgpack buffer */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        /* Pack data */
        msgpack_pack_array(&mp_pck, 2);
        flb_pack_time_now(&mp_pck);
        msgpack_pack_map(&mp_pck, num_map);


        msgpack_pack_str(&mp_pck, strlen(STR_KEY_READ));
        msgpack_pack_str_body(&mp_pck, STR_KEY_READ, strlen(STR_KEY_READ));
        msgpack_pack_uint64(&mp_pck, read_total);

        msgpack_pack_str(&mp_pck, strlen(STR_KEY_WRITE));
        msgpack_pack_str_body(&mp_pck, STR_KEY_WRITE, strlen(STR_KEY_WRITE));
        msgpack_pack_uint64(&mp_pck, write_total);

        flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    return 0;
}

static int get_diskstats_entries(void)
{
    char line[LINE_SIZE] = {0};
    int   ret = 0;
    FILE *fp = NULL;

    fp = fopen("/proc/diskstats", "r");
    if (fp == NULL) {
        perror("fopen");
        return 0;
    }
    while(fgets(line, LINE_SIZE-1, fp) != NULL) {
        ret++;
    }

    fclose(fp);
    return ret;
}

static int configure(struct flb_in_disk_config *disk_config,
                               struct flb_input_instance *in)
{
    (void) *in;
    char *pval = NULL;
    int entry = 0;
    int i;

    /* interval settings */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        disk_config->interval_sec = atoi(pval);
    }
    else {
        disk_config->interval_sec = DEFAULT_INTERVAL_SEC;
    }

    pval = flb_input_get_property("interval_nsec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        disk_config->interval_nsec = atoi(pval);
    }
    else {
        disk_config->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    if (disk_config->interval_sec <= 0 && disk_config->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        disk_config->interval_sec = DEFAULT_INTERVAL_SEC;
        disk_config->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    pval = flb_input_get_property("dev_name", in);
    if (pval != NULL) {
        disk_config->dev_name = flb_strdup(pval);
    }
    else {
        disk_config->dev_name = NULL;
    }

    entry = get_diskstats_entries();
    if (entry == 0) {
        /* no entry to count */
        return -1;
    }

    disk_config->read_total = (uint64_t*)flb_malloc(sizeof(uint64_t)*entry);
    disk_config->write_total = (uint64_t*)flb_malloc(sizeof(uint64_t)*entry);
    disk_config->prev_read_total = (uint64_t*)flb_malloc(sizeof(uint64_t)*entry);
    disk_config->prev_write_total = (uint64_t*)flb_malloc(sizeof(uint64_t)*entry);
    disk_config->entry = entry;

    /* initialize */
    for (i=0; i<entry; i++) {
        disk_config->read_total[i] = 0;
        disk_config->write_total[i] = 0;
        disk_config->prev_read_total[i] = 0;
        disk_config->prev_write_total[i] = 0;
    }
    update_disk_stats(disk_config);

    disk_config->first_snapshot = FLB_TRUE;    /* assign first_snapshot with FLB_TRUE */

    return 0;
}

/* Initialize plugin */
static int in_disk_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    struct flb_in_disk_config *disk_config = NULL;
    int ret = -1;

    /* Allocate space for the configuration */
    disk_config = flb_malloc(sizeof(struct flb_in_disk_config));
    if (disk_config == NULL) {
        return -1;
    }
    disk_config->read_total = NULL;
    disk_config->write_total = NULL;
    disk_config->prev_read_total = NULL;
    disk_config->prev_write_total = NULL;

    /* Initialize head config */
    ret = configure(disk_config, in);
    if (ret < 0) {
        goto init_error;
    }

    flb_input_set_context(in, disk_config);

    ret = flb_input_set_collector_time(in,
                                       in_disk_collect,
                                       disk_config->interval_sec,
                                       disk_config->interval_nsec, config);
    if (ret < 0) {
        flb_error("could not set collector for disk input plugin");
        goto init_error;
    }

    return 0;

  init_error:
    flb_free(disk_config->read_total);
    flb_free(disk_config->write_total);
    flb_free(disk_config->prev_read_total);
    flb_free(disk_config->prev_write_total);
    flb_free(disk_config);
    return -1;
}

static int in_disk_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_disk_config *disk_config = data;

    flb_free(disk_config->read_total);
    flb_free(disk_config->write_total);
    flb_free(disk_config->prev_read_total);
    flb_free(disk_config->prev_write_total);
    flb_free(disk_config->dev_name);
    flb_free(disk_config);
    return 0;
}


struct flb_input_plugin in_disk_plugin = {
    .name         = "disk",
    .description  = "Diskstats",
    .cb_init      = in_disk_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_disk_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_disk_exit
};
