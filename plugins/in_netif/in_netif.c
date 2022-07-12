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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include <stdio.h>
#include "in_netif.h"

struct entry_define entry_name_linux[] = {
    {"rx.bytes",       FLB_TRUE},
    {"rx.packets",     FLB_TRUE},
    {"rx.errors",      FLB_TRUE},
    {"rx.drop",        FLB_FALSE},
    {"rx.fifo",        FLB_FALSE},
    {"rx.frame",       FLB_FALSE},
    {"rx.compressed",  FLB_FALSE},
    {"rx.multicast",   FLB_FALSE},
    {"tx.bytes",       FLB_TRUE},
    {"tx.packets",     FLB_TRUE},
    {"tx.errors",      FLB_TRUE},
    {"tx.drop",        FLB_FALSE},
    {"tx.fifo",        FLB_FALSE},
    {"tx.collisions",  FLB_FALSE},
    {"tx.carrier",     FLB_FALSE},
    {"tx.compressepd", FLB_FALSE}
};

static int config_destroy(struct flb_in_netif_config *ctx)
{
    flb_free(ctx->entry);
    flb_free(ctx);
    return 0;
}


static int in_netif_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_netif_config *ctx = data;

    /* Destroy context */
    config_destroy(ctx);

    return 0;
}

static int init_entry_linux(struct flb_in_netif_config *ctx)
{
    int i;

    ctx->entry_len = sizeof(entry_name_linux) / sizeof(struct entry_define);
    ctx->entry = flb_malloc(sizeof(struct netif_entry) * ctx->entry_len);
    if (!ctx->entry) {
        flb_errno();
        return -1;
    }

    for(i = 0; i < ctx->entry_len; i++) {
        ctx->entry[i].name     = entry_name_linux[i].name;
        ctx->entry[i].name_len = strlen(entry_name_linux[i].name);
        ctx->entry[i].prev     = 0;
        ctx->entry[i].now      = 0;
        if (ctx->verbose){
            ctx->entry[i].checked = FLB_TRUE;
        }
        else {
            ctx->entry[i].checked = entry_name_linux[i].checked;
        }
        if (ctx->entry[i].checked) {
            ctx->map_num++;
        }
    }
    return 0;
}

static int configure(struct flb_in_netif_config *ctx,
                     struct flb_input_instance *in)
{
    int ret;
    ctx->map_num = 0;

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(in, "unable to load configuration");
        return -1;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }

    if (ctx->interface == NULL) {
        flb_plg_error(ctx->ins, "'interface' is not set");
        return -1;
    }
    ctx->interface_len = strlen(ctx->interface);

    ctx->first_snapshot = FLB_TRUE;    /* assign first_snapshot with FLB_TRUE */

    return init_entry_linux(ctx);
}

static inline int is_specific_interface(struct flb_in_netif_config *ctx,
                                        char* interface)
{
    if (ctx->interface != NULL &&
        !strncmp(ctx->interface, interface, ctx->interface_len)) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

static int parse_proc_line(char *line,
                           struct flb_in_netif_config *ctx)
{
    struct mk_list *head = NULL;
    struct mk_list *split = NULL;
    struct flb_split_entry *sentry = NULL;

    int i = 0;
    int entry_num;

    split = flb_utils_split(line, ' ', 256);
    entry_num = mk_list_size(split);
    if (entry_num != ctx->entry_len + 1) {
        flb_utils_split_free(split);
        return -1;
    }

    mk_list_foreach(head, split) {
        sentry = mk_list_entry(head, struct flb_split_entry ,_head);
        if (i==0) {
            /* interface name */
            if( is_specific_interface(ctx, sentry->value)){
                i++;
                continue;
            }
            else {
                /* skip this line */
                flb_utils_split_free(split);
                return -1;
            }
        }
        ctx->entry[i-1].now = strtoul(sentry->value ,NULL ,10);
        i++;
    }

    flb_utils_split_free(split);

    return 0;
}

static inline uint64_t calc_diff(struct netif_entry *entry)
{
    if (entry->prev <= entry->now) {
        return entry->now - entry->prev;
    }
    else {
        return entry->now + (UINT64_MAX - entry->prev);
    }
}

#define LINE_LEN 256
static int read_proc_file_linux(struct flb_in_netif_config *ctx)
{
    FILE *fp = NULL;
    char line[LINE_LEN] = {0};
    int interface_found = FLB_FALSE;

    fp = fopen("/proc/net/dev", "r");
    if (fp == NULL) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open /proc/net/dev");
        return -1;
    }
    while(fgets(line, LINE_LEN-1, fp) != NULL){
        if(parse_proc_line(line, ctx) == 0) {
            interface_found = FLB_TRUE;
        }
    }
    fclose(fp);
    if (interface_found != FLB_TRUE) {
        return -1;
    }
    return 0;
}

static int in_netif_collect_linux(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_in_netif_config *ctx = in_context;
    char key_name[LINE_LEN] = {0};
    int  key_len;
    int i;
    int entry_len = ctx->entry_len;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    read_proc_file_linux(ctx);

    if (ctx->first_snapshot == FLB_TRUE) {
        /* if in_netif are called for the first time, assign prev with now */
        for (i = 0; i < entry_len; i++) {
            ctx->entry[i].prev = ctx->entry[i].now;
        }

        /* assign first_snapshot with FLB_FALSE */
        ctx->first_snapshot = FLB_FALSE;
    }
    else {
        /* Initialize local msgpack buffer */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        /* Pack data */
        msgpack_pack_array(&mp_pck, 2);
        flb_pack_time_now(&mp_pck);
        msgpack_pack_map(&mp_pck, ctx->map_num);

        for (i = 0; i < entry_len; i++) {
            if (ctx->entry[i].checked) {
                key_len = ctx->interface_len + ctx->entry[i].name_len + 1/* '.' */;

                snprintf(key_name, key_len + 1 /* add null character */,
                         "%s.%s", ctx->interface, ctx->entry[i].name);
                msgpack_pack_str(&mp_pck, key_len);
                msgpack_pack_str_body(&mp_pck, key_name, key_len);

                msgpack_pack_uint64(&mp_pck, calc_diff(&ctx->entry[i]));

                ctx->entry[i].prev = ctx->entry[i].now;
            }
        }

        flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    return 0;
}

static int in_netif_collect(struct flb_input_instance *i_ins,
                            struct flb_config *config, void *in_context)
{
    return in_netif_collect_linux(i_ins, config, in_context);
}

static int in_netif_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    int ret;

    struct flb_in_netif_config *ctx = NULL;
    (void) data;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_netif_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    if (configure(ctx, in) < 0) {
        config_destroy(ctx);
        return -1;
    }

    /* Testing interface */
    if (ctx->test_at_init == FLB_TRUE) {
        /* Try to read procfs */
        ret = read_proc_file_linux(ctx);
        if (ret < 0) {
            flb_plg_error(in, "%s: init test failed", ctx->interface);
            config_destroy(ctx);
            return -1;
        }
        flb_plg_info(in, "%s: init test passed", ctx->interface);
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time */
    ret = flb_input_set_collector_time(in,
                                       in_netif_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for Proc input plugin");
        config_destroy(ctx);
        return -1;
    }

    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_STR, "interface", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_netif_config, interface),
      "Set the interface, eg: eth0 or enp1s0"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_in_netif_config, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_in_netif_config, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    {
      FLB_CONFIG_MAP_BOOL, "verbose", "false",
      0, FLB_TRUE, offsetof(struct flb_in_netif_config, verbose),
      "Enable verbosity"
    },
    {
      FLB_CONFIG_MAP_BOOL, "test_at_init", "false",
      0, FLB_TRUE, offsetof(struct flb_in_netif_config, test_at_init),
      "Testing interface at initialization"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_netif_plugin = {
    .name         = "netif",
    .description  = "Network Interface Usage",
    .cb_init      = in_netif_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_netif_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_netif_exit,
    .config_map   = config_map,
    .flags        = 0,
};
