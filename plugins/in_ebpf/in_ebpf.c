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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <bpf/libbpf.h>
#include "in_ebpf.h"
#include "traces/traces.h"

int trace_register(struct flb_in_ebpf_context *ctx, const char *name,
                   struct bpf_object *obj, trace_event_handler_t handler) {
    struct trace_context *trace;
    struct bpf_map *map, *events_map;
    int map_fd;

    flb_plg_debug(ctx->ins, "registering trace handler for: %s", name);
    ctx->traces = flb_realloc(ctx->traces, sizeof(struct trace_context) * (ctx->trace_count + 1));
    if (!ctx->traces) {
        flb_plg_error(ctx->ins, "failed to allocate memory for trace handlers");
        return -1;
    }

    trace = &ctx->traces[ctx->trace_count];
    trace->name = name;
    trace->obj = obj;
    trace->handler = handler;

    bpf_object__for_each_map(map, obj) {
        flb_plg_trace(ctx->ins, "found BPF map: %s", bpf_map__name(map));
    }

    events_map = bpf_object__find_map_by_name(obj, ctx->ringbuf_map_name);
    if (!events_map) {
        flb_plg_error(ctx->ins, "could not find '%s' map in BPF object for trace: %s",
                      ctx->ringbuf_map_name, name);
        return -1;
    }

    map_fd = bpf_map__fd(events_map);
    if (map_fd < 0) {
        flb_plg_error(ctx->ins, "failed to get file descriptor for '%s' map for trace: %s",
                      ctx->ringbuf_map_name, name);
        return -1;
    }

    trace->rb = ring_buffer__new(map_fd, (ring_buffer_sample_fn)handler, ctx, NULL);
    if (!trace->rb) {
        flb_plg_error(ctx->ins, "failed to create ring buffer for %s", name);
        return -1;
    }

    flb_plg_info(ctx->ins, "registered trace handler for: %s", name);
    ctx->trace_count++;
    return 0;
}

int trace_setup(struct flb_in_ebpf_context *ctx, const char *trace_name) {
    struct trace_registration *reg;
    void *skel;
    struct bpf_object *obj;

    flb_plg_debug(ctx->ins, "setting up trace configuration for: %s", trace_name);

    for (reg = trace_table; reg->name != NULL; reg++) {
        if (strcasecmp(trace_name, reg->name) != 0) {
            continue;
        }

        skel = reg->skel_open();
        if (!skel) {
            flb_plg_error(ctx->ins, "failed to open skeleton for trace: %s", trace_name);
            return -1;
        }

        flb_plg_debug(ctx->ins, "attaching BPF program for trace: %s", trace_name);
        if (reg->skel_attach(skel) != 0) {
            flb_plg_error(ctx->ins, "failed to attach skeleton for trace: %s", trace_name);
            reg->skel_destroy(skel);
            return -1;
        }

        obj = reg->skel_get_bpf_object(skel);
        if (!obj) {
            flb_plg_error(ctx->ins, "failed to get bpf_object from skeleton for trace: %s", trace_name);
            reg->skel_destroy(skel);
            return -1;
        }

        if (trace_register(ctx, trace_name, obj, reg->handler) != 0) {
            flb_plg_error(ctx->ins, "failed to register trace handler for: %s", trace_name);
            reg->skel_destroy(skel);
            return -1;
        }

        flb_plg_info(ctx->ins, "trace configuration completed for: %s", trace_name);
        return 0;
    }

    flb_plg_error(ctx->ins, "unknown trace name: %s", trace_name);
    return -1;
}

static int in_ebpf_collect(struct flb_input_instance *ins, struct flb_config *config, void *in_context) {
    struct flb_in_ebpf_context *ctx = in_context;
    int err;

    flb_plg_debug(ins, "collecting events from ring buffers");

    for (int i = 0; i < ctx->trace_count; i++) {
        flb_plg_debug(ctx->ins, "consuming events from ring buffer %s", ctx->traces[i].name);
        err = ring_buffer__consume(ctx->traces[i].rb);
        if (err < 0) {
            flb_plg_debug(ins, "error consuming from ring buffer: %d", err);
        }
        else {
            flb_plg_debug(ins, "successfully consumed events from ring buffer %s", ctx->traces[i].name);
        }
    }

    return 0;
}

static int in_ebpf_init(struct flb_input_instance *ins, struct flb_config *config, void *data) {
    struct flb_in_ebpf_context *ctx;
    struct mk_list *head;
    struct flb_kv *kv;
    const char *trace_name;

    flb_plg_debug(ins, "initializing eBPF input plugin");
    ctx = flb_calloc(1, sizeof(struct flb_in_ebpf_context));
    if (!ctx) {
        flb_plg_error(ins, "could not allocate memory for context");
        return -1;
    }

    ctx->ins = ins;
    ctx->trace_count = 0;
    ctx->traces = NULL;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->log_encoder) {
        flb_plg_error(ins, "could not create log event encoder");
        flb_free(ctx);
        return -1;
    }

    flb_input_config_map_set(ins, ctx);

    mk_list_foreach(head, &ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "trace") == 0) {
            trace_name = kv->val;
            flb_plg_debug(ctx->ins, "processing trace: %s", trace_name);
            if (trace_setup(ctx, trace_name) != 0) {
                flb_plg_error(ctx->ins, "failed to configure trace: %s", trace_name);
                flb_free(ctx);
                return -1;
            }
        }
    }

    flb_input_set_context(ins, ctx);

    flb_plg_debug(ctx->ins, "setting up collector with poll interval: %d ms", ctx->poll_ms);
    ctx->coll_fd = flb_input_set_collector_time(ins, in_ebpf_collect, ctx->poll_ms / 1000,
                                                (ctx->poll_ms % 1000) * 1000000, config);
    if (ctx->coll_fd < 0) {
        flb_plg_error(ctx->ins, "failed to set up collector");
        for (int i = 0; i < ctx->trace_count; i++) {
            ring_buffer__free(ctx->traces[i].rb);
            bpf_object__close(ctx->traces[i].obj);
        }
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    flb_plg_info(ins, "eBPF input plugin initialized successfully");
    return 0;
}

static void in_ebpf_pause(void *data, struct flb_config *config) {
    struct flb_in_ebpf_context *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
    flb_plg_debug(ctx->ins, "collector paused");
}

static void in_ebpf_resume(void *data, struct flb_config *config) {
    struct flb_in_ebpf_context *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
    flb_plg_debug(ctx->ins, "collector resumed");
}

static int in_ebpf_exit(void *in_context, struct flb_config *config) {
    struct flb_in_ebpf_context *ctx = in_context;

    if (!ctx) {
        return 0;
    }

    for (int i = 0; i < ctx->trace_count; i++) {
        ring_buffer__free(ctx->traces[i].rb);
        bpf_object__close(ctx->traces[i].obj);
    }

    if (ctx->log_encoder) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    flb_plg_info(ctx->ins, "eBPF input plugin exited");
    flb_free(ctx->traces);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "ringbuf_map_name", FLB_IN_EBPF_DEFAULT_RINGBUF_MAP_NAME,
     0, FLB_TRUE, offsetof(struct flb_in_ebpf_context, ringbuf_map_name),
     "Set the name of the eBPF ring buffer map to read events from"
    },
    {
     FLB_CONFIG_MAP_INT, "poll_ms", FLB_IN_EBPF_DEFAULT_POLL_MS,
     0, FLB_TRUE, offsetof(struct flb_in_ebpf_context, poll_ms),
     "Set the polling interval in milliseconds for collecting events"
    },
    {
     FLB_CONFIG_MAP_STR, "Trace", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Set the eBPF trace to enable (for example, bind, malloc, signal). Can be set multiple times"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_ebpf_plugin = {
    .name         = "ebpf",
    .description  = "eBPF input plugin",
    .cb_init      = in_ebpf_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_ebpf_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_ebpf_pause,
    .cb_resume    = in_ebpf_resume,
    .cb_exit      = in_ebpf_exit,
    .config_map   = config_map,
};
