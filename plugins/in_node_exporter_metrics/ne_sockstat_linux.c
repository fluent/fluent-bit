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

#define _GNU_SOURCE

#include <unistd.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

static int sockstat_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    /* node_sockstat_sockets_used */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "sockets_used",
                         "Number of IPv4 sockets in use.",
                         0, NULL);
    ctx->sockstat_sockets_used = g;

    /* node_sockstat_TCP_alloc */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "TCP_alloc",
                         "Number of TCP sockets in state alloc.",
                         0, NULL);
    ctx->sockstat_TCP_alloc = g;

    /* node_sockstat_TCP_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "TCP_inuse",
                         "Number of TCP sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_TCP_inuse = g;

    /* node_sockstat_TCP_mem */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "TCP_mem",
                         "Number of memory pages used by TCP sockets, in Kernel memory pages.",
                         0, NULL);
    ctx->sockstat_TCP_mem = g;

    /* node_sockstat_TCP_mem_bytes */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "TCP_mem_bytes",
                         "Number of bytes used by TCP sockets.",
                         0, NULL);
    ctx->sockstat_TCP_mem_bytes = g;

    /* node_sockstat_TCP_orphan */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "TCP_orphan",
                         "Number of orphaned TCP sockets in use.",
                         0, NULL);
    ctx->sockstat_TCP_orphan = g;

    /* node_sockstat_TCP_tw */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "TCP_tw",
                         "Number of TCP sockets in state TIME_WAIT.",
                         0, NULL);
    ctx->sockstat_TCP_tw = g;

    /* node_sockstat_UDP_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "UDP_inuse",
                         "Number of UDP sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_UDP_inuse = g;

    /* node_sockstat_UDP_mem */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "UDP_mem",
                         "Number of memory pages used by UDP sockets, in Kernel memory pages.",
                         0, NULL);
    ctx->sockstat_UDP_mem = g;

    /* node_sockstat_UDP_mem_bytes */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "UDP_mem_bytes",
                         "Number of bytes used by UDP sockets.",
                         0, NULL);
    ctx->sockstat_UDP_mem_bytes = g;

    /* node_sockstat_UDPLITE_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "UDPLITE_inuse",
                         "Number of UDPLITE sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_UDPLITE_inuse = g;

    /* node_sockstat_RAW_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "RAW_inuse",
                         "Number of RAW sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_RAW_inuse = g;

    /* node_sockstat_FRAG_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "FRAG_inuse",
                         "Number of FRAG sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_FRAG_inuse = g;

    /* node_sockstat_FRAG_memory */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "FRAG_memory",
                         "Memory currently used for fragment reassembly in bytes.",
                         0, NULL);
    ctx->sockstat_FRAG_memory = g;

    /* node_sockstat_TCP6_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "TCP6_inuse",
                         "Number of TCP6 sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_TCP6_inuse = g;

    /* node_sockstat_UDP6_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "UDP6_inuse",
                         "Number of UDP6 sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_UDP6_inuse = g;

    /* node_sockstat_UDPLITE6_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "UDPLITE6_inuse",
                         "Number of UDPLITE6 sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_UDPLITE6_inuse = g;

    /* node_sockstat_RAW6_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "RAW6_inuse",
                         "Number of RAW6 sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_RAW6_inuse = g;

    /* node_sockstat_FRAG6_inuse */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "FRAG6_inuse",
                         "Number of FRAG6 sockets in state inuse.",
                         0, NULL);
    ctx->sockstat_FRAG6_inuse = g;

    /* node_sockstat_FRAG6_memory */
    g = cmt_gauge_create(ctx->cmt, "node", "sockstat", "FRAG6_memory",
                         "Memory currently used for IPv6 fragment reassembly in bytes.",
                         0, NULL);
    ctx->sockstat_FRAG6_memory = g;

    return 0;
}

static int sockstat_update(struct flb_ne *ctx)
{
    int ret;
    uint64_t ts;
    size_t page_size;
    double d_val;
    struct mk_list list;
    struct mk_list *head;
    struct flb_slist_entry *line;
    struct mk_list tokens;
    int parts;
    int i;
    struct flb_slist_entry *key;
    struct flb_slist_entry *val;

    mk_list_init(&list);
    ret = ne_utils_file_read_lines(ctx->path_procfs, "/net/sockstat", &list);
    if (ret == -1) {
        return -1;
    }

    ts = cfl_time_now();
    page_size = sysconf(_SC_PAGESIZE);

    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        if (strncmp(line->str, "sockets:", 8) == 0) {
            mk_list_init(&tokens);
            ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
            if (ret >= 3) {
                val = flb_slist_entry_get(&tokens, 2);
                if (val) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_sockets_used, ts, d_val, 0, NULL);
                }
            }
            flb_slist_destroy(&tokens);
        }
        else if (strncmp(line->str, "TCP:", 4) == 0) {
            mk_list_init(&tokens);
            ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
            parts = ret;
            for (i = 1; i + 1 < parts; i += 2) {
                key = flb_slist_entry_get(&tokens, i);
                val = flb_slist_entry_get(&tokens, i + 1);
                if (!key || !val) {
                    continue;
                }
                if (strcmp(key->str, "inuse") == 0) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_TCP_inuse, ts, d_val, 0, NULL);
                }
                else if (strcmp(key->str, "orphan") == 0) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_TCP_orphan, ts, d_val, 0, NULL);
                }
                else if (strcmp(key->str, "tw") == 0) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_TCP_tw, ts, d_val, 0, NULL);
                }
                else if (strcmp(key->str, "alloc") == 0) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_TCP_alloc, ts, d_val, 0, NULL);
                }
                else if (strcmp(key->str, "mem") == 0) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_TCP_mem, ts, d_val, 0, NULL);
                    cmt_gauge_set(ctx->sockstat_TCP_mem_bytes, ts, d_val * page_size, 0, NULL);
                }
            }
            flb_slist_destroy(&tokens);
        }
        else if (strncmp(line->str, "UDP:", 4) == 0) {
            mk_list_init(&tokens);
            ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
            parts = ret;
            for (i = 1; i + 1 < parts; i += 2) {
                key = flb_slist_entry_get(&tokens, i);
                val = flb_slist_entry_get(&tokens, i + 1);
                if (!key || !val) {
                    continue;
                }
                if (strcmp(key->str, "inuse") == 0) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_UDP_inuse, ts, d_val, 0, NULL);
                }
                else if (strcmp(key->str, "mem") == 0) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_UDP_mem, ts, d_val, 0, NULL);
                    cmt_gauge_set(ctx->sockstat_UDP_mem_bytes, ts, d_val * page_size, 0, NULL);
                }
            }
            flb_slist_destroy(&tokens);
        }
        else if (strncmp(line->str, "UDPLITE:", 8) == 0) {
            mk_list_init(&tokens);
            ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
            if (ret >= 3) {
                val = flb_slist_entry_get(&tokens, 2);
                if (val && ne_utils_str_to_double(val->str, &d_val) == 0) {
                    cmt_gauge_set(ctx->sockstat_UDPLITE_inuse, ts, d_val, 0, NULL);
                }
            }
            flb_slist_destroy(&tokens);
        }
        else if (strncmp(line->str, "RAW:", 4) == 0) {
            mk_list_init(&tokens);
            ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
            if (ret >= 3) {
                val = flb_slist_entry_get(&tokens, 2);
                if (val && ne_utils_str_to_double(val->str, &d_val) == 0) {
                    cmt_gauge_set(ctx->sockstat_RAW_inuse, ts, d_val, 0, NULL);
                }
            }
            flb_slist_destroy(&tokens);
        }
        else if (strncmp(line->str, "FRAG:", 5) == 0) {
            mk_list_init(&tokens);
            ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
            parts = ret;
            for (i = 1; i + 1 < parts; i += 2) {
                key = flb_slist_entry_get(&tokens, i);
                val = flb_slist_entry_get(&tokens, i + 1);
                if (!key || !val) {
                    continue;
                }
                if (strcmp(key->str, "inuse") == 0) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_FRAG_inuse, ts, d_val, 0, NULL);
                }
                else if (strcmp(key->str, "memory") == 0) {
                    ne_utils_str_to_double(val->str, &d_val);
                    cmt_gauge_set(ctx->sockstat_FRAG_memory, ts, d_val, 0, NULL);
                }
            }
            flb_slist_destroy(&tokens);
        }
    }

    flb_slist_destroy(&list);

    /* Parse IPv6 statistics */
    mk_list_init(&list);
    ret = ne_utils_file_read_lines(ctx->path_procfs, "/net/sockstat6", &list);
    if (ret != -1) {
        mk_list_foreach(head, &list) {
            line = mk_list_entry(head, struct flb_slist_entry, _head);

            if (strncmp(line->str, "TCP6:", 5) == 0) {
                mk_list_init(&tokens);
                ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
                if (ret >= 3) {
                    val = flb_slist_entry_get(&tokens, 2);
                    if (val && ne_utils_str_to_double(val->str, &d_val) == 0) {
                        cmt_gauge_set(ctx->sockstat_TCP6_inuse, ts, d_val, 0, NULL);
                    }
                }
                flb_slist_destroy(&tokens);
            }
            else if (strncmp(line->str, "UDP6:", 5) == 0) {
                mk_list_init(&tokens);
                ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
                if (ret >= 3) {
                    val = flb_slist_entry_get(&tokens, 2);
                    if (val && ne_utils_str_to_double(val->str, &d_val) == 0) {
                        cmt_gauge_set(ctx->sockstat_UDP6_inuse, ts, d_val, 0, NULL);
                    }
                }
                flb_slist_destroy(&tokens);
            }
            else if (strncmp(line->str, "UDPLITE6:", 9) == 0) {
                mk_list_init(&tokens);
                ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
                if (ret >= 3) {
                    val = flb_slist_entry_get(&tokens, 2);
                    if (val && ne_utils_str_to_double(val->str, &d_val) == 0) {
                        cmt_gauge_set(ctx->sockstat_UDPLITE6_inuse, ts, d_val, 0, NULL);
                    }
                }
                flb_slist_destroy(&tokens);
            }
            else if (strncmp(line->str, "RAW6:", 5) == 0) {
                mk_list_init(&tokens);
                ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
                if (ret >= 3) {
                    val = flb_slist_entry_get(&tokens, 2);
                    if (val && ne_utils_str_to_double(val->str, &d_val) == 0) {
                        cmt_gauge_set(ctx->sockstat_RAW6_inuse, ts, d_val, 0, NULL);
                    }
                }
                flb_slist_destroy(&tokens);
            }
            else if (strncmp(line->str, "FRAG6:", 6) == 0) {
                mk_list_init(&tokens);
                ret = flb_slist_split_string(&tokens, line->str, ' ', -1);
                parts = ret;
                for (i = 1; i + 1 < parts; i += 2) {
                    key = flb_slist_entry_get(&tokens, i);
                    val = flb_slist_entry_get(&tokens, i + 1);
                    if (!key || !val) {
                        continue;
                    }
                    if (strcmp(key->str, "inuse") == 0) {
                        if (ne_utils_str_to_double(val->str, &d_val) == 0) {
                            cmt_gauge_set(ctx->sockstat_FRAG6_inuse, ts, d_val, 0, NULL);
                        }
                    }
                    else if (strcmp(key->str, "memory") == 0) {
                        if (ne_utils_str_to_double(val->str, &d_val) == 0) {
                            cmt_gauge_set(ctx->sockstat_FRAG6_memory, ts, d_val, 0, NULL);
                        }
                    }
                }
                flb_slist_destroy(&tokens);
            }
        }
        flb_slist_destroy(&list);
    }

    return 0;
}

static int ne_sockstat_init(struct flb_ne *ctx)
{
    sockstat_configure(ctx);
    return 0;
}

static int ne_sockstat_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *) in_context;

    sockstat_update(ctx);
    return 0;
}

struct flb_ne_collector sockstat_collector = {
    .name = "sockstat",
    .cb_init = ne_sockstat_init,
    .cb_update = ne_sockstat_update,
    .cb_exit = NULL
};

