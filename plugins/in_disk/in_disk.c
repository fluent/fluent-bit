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
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_pack.h>

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

    while (1) {
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
        flb_errno();
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
    unsigned long              write_total;
    unsigned long              read_total;
    int                        entry;
    struct flb_in_disk_config *ctx;
    int                        ret;
    int                        i;

    (void) *config;

    ret = 0;
    ctx = (struct flb_in_disk_config *) in_context;
    entry = ctx->entry;

    /* The type of sector size is unsigned long in kernel source */
    read_total = 0;
    write_total = 0;

    update_disk_stats(ctx);

    if (ctx->first_snapshot == FLB_TRUE) {
        ctx->first_snapshot = FLB_FALSE;    /* assign first_snapshot with FLB_FALSE */
    }
    else {
        for (i = 0; i < entry; i++) {
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


        ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_current_timestamp(
                    &ctx->log_encoder);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(STR_KEY_READ),
                    FLB_LOG_EVENT_UINT64_VALUE(read_total),

                    FLB_LOG_EVENT_CSTRING_VALUE(STR_KEY_WRITE),
                    FLB_LOG_EVENT_UINT64_VALUE(write_total));
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
    int entry = 0;
    int i;
    int ret;

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)disk_config);
    if (ret == -1) {
        flb_plg_error(in, "unable to load configuration.");
        return -1;
    }

    /* interval settings */
    if (disk_config->interval_sec <= 0 && disk_config->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        disk_config->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        disk_config->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
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

    if ( disk_config->read_total       == NULL ||
         disk_config->write_total      == NULL ||
         disk_config->prev_read_total  == NULL ||
         disk_config->prev_write_total == NULL) {
        flb_plg_error(in, "could not allocate memory");
        return -1;
    }

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
    disk_config = flb_calloc(1, sizeof(struct flb_in_disk_config));
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
        flb_plg_error(in, "could not set collector for disk input plugin");
        goto init_error;
    }

    ret = flb_log_event_encoder_init(&disk_config->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(in, "error initializing event encoder : %d", ret);

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

    flb_log_event_encoder_destroy(&disk_config->log_encoder);

    flb_free(disk_config->read_total);
    flb_free(disk_config->write_total);
    flb_free(disk_config->prev_read_total);
    flb_free(disk_config->prev_write_total);
    flb_free(disk_config);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_in_disk_config, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_in_disk_config, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    {
      FLB_CONFIG_MAP_STR, "dev_name", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_disk_config, dev_name),
      "Set the device name"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_disk_plugin = {
    .name         = "disk",
    .description  = "Diskstats",
    .cb_init      = in_disk_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_disk_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_disk_exit,
    .config_map   = config_map
};
