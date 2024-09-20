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
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "in_ebpf.h"

/* Encodes log event */
int encode_log_event(struct flb_input_instance *ins,
                     struct flb_log_event_encoder *log_encoder,
                     const char *event_type_str,
                     __u32 pid,
                     const char *data, size_t data_len)
{
    int ret;

    flb_plg_trace(ins, "encoding log event");
    ret = flb_log_event_encoder_begin_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ins, "failed to begin log event record");
        return -1;
    }

    flb_plg_trace(ins, "setting current timestamp for log event");
    ret = flb_log_event_encoder_set_current_timestamp(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        flb_plg_error(ins, "failed to set timestamp");
        return -1;
    }

    if (pid > 0) {
        flb_plg_trace(ins, "appending pid: %u", pid);
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "pid");
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "failed to append pid key");
            return -1;
        }
        ret = flb_log_event_encoder_append_body_uint32(log_encoder, pid);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "failed to append pid value");
            return -1;
        }
    }

    if (event_type_str) {
        flb_plg_trace(ins, "appending event type: %s", event_type_str);
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "event_type");
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "failed to append event type key");
            return -1;
        }
        ret = flb_log_event_encoder_append_body_string(log_encoder, event_type_str, strlen(event_type_str));
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "failed to append event type value");
            return -1;
        }
    }

    if (data_len > 0) {
        flb_plg_trace(ins, "appending event data of length: %zu", data_len);
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "event_data");
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "failed to append event data key");
            return -1;
        }
        ret = flb_log_event_encoder_append_body_string(log_encoder, data, data_len);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "failed to append event data value");
            return -1;
        }
    } else {
        flb_plg_trace(ins, "no event data to append (data_len = 0)");
    }

    /* Commit the record */
    ret = flb_log_event_encoder_commit_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ins, "failed to commit log event record");
        return -1;
    }

    return 0;
}

/* Handles the event data */
int handle_ebpf_event(void *instance, void *data, size_t data_sz)
{
    struct flb_input_instance *ins = (struct flb_input_instance *)instance;
    struct flb_in_ebpf_config *ctx = (struct flb_in_ebpf_config *)ins->context;
    struct flb_log_event_encoder *log_encoder = ctx->log_encoder;
    const char *event_type_str;
    __u32 pid;
    char *event_data;
    size_t event_data_len;
    int ret;

    ret = extract_event_data(data, data_sz, &event_type_str, &pid, &event_data, &event_data_len);
    if (ret != 0) {
        flb_plg_warn(ins, "invalid event data received");
        return ret;
    }

    /* Encode the log event */
    ret = encode_log_event(ins, log_encoder, event_type_str, pid, event_data, event_data_len);
    if (ret != 0) {
        flb_plg_error(ins, "failed to encode log event");
        return ret;
    }

    /* Append the encoded log event to Fluent Bit */
    if (log_encoder->output_length > 0) {
        flb_plg_trace(ins, "appending log event of length: %zu", log_encoder->output_length);
        ret = flb_input_log_append(ins, NULL, 0,
                                   log_encoder->output_buffer,
                                   log_encoder->output_length);
        if (ret == -1) {
            flb_plg_error(ins, "failed to append log data");
            return -1;
        }
        flb_log_event_encoder_reset(log_encoder);
    }

    return 0;
}

/* Extracts event data from input */
int extract_event_data(void *data, size_t data_sz, const char **event_type_str,
                       __u32 *pid, char **event_data, size_t *event_data_len)
{
    if (data_sz == sizeof(struct flb_in_ebpf_event)) {
        struct flb_in_ebpf_event *event = (struct flb_in_ebpf_event *)data;
        *event_type_str = get_event_type_str(event->event_type);
        *pid = event->pid;
        *event_data = event->data;
        *event_data_len = strlen(event->data);
    } else if (data_sz <= MAX_EVENT_LEN) {
        *event_type_str = FLB_IN_EBPF_EVENT_TYPE_UNKNOWN;
        *pid = 0;
        *event_data = (char *)data;
        *event_data_len = strlen(*event_data);
    } else {
        return -1;
    }

    return 0;
}

/* Collect function for reading the ring buffer */
static int in_ebpf_collect(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf_config *ctx = (struct flb_in_ebpf_config *)in_context;
    int err;

    flb_plg_trace(ins, "polling on ring buffer '%s'", ctx->ringbuf_map_name);

    err = ring_buffer__consume(ctx->rb);
    if (err < 0) {
        flb_plg_error(ins, "error polling the ring buffer: %d", err);
        return -1;
    }

    return 0;
}

/* Pause function */
static void in_ebpf_pause(void *data, struct flb_config *config)
{
    struct flb_in_ebpf_config *ctx = (struct flb_in_ebpf_config *)data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

/* Resume function */
static void in_ebpf_resume(void *data, struct flb_config *config)
{
    struct flb_in_ebpf_config *ctx = (struct flb_in_ebpf_config *)data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

/* Cleanup function */
static int in_ebpf_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_ebpf_config *ctx = (struct flb_in_ebpf_config *)in_context;

    if (ctx->rb) {
        ring_buffer__free(ctx->rb);
    }

    if (ctx->obj) {
        bpf_object__close(ctx->obj);
    }

    if (ctx->log_encoder) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    flb_free(ctx);
    return 0;
}

/* Initialization function */
static int in_ebpf_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    struct flb_in_ebpf_config *ctx;
    const char *bpf_obj_file;
    const char *bpf_prog_name;
    struct bpf_map *map;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;
    int ret;
    int poll_seconds;
    int poll_nanoseconds;

    ctx = flb_calloc(1, sizeof(struct flb_in_ebpf_config));
    if (!ctx) {
        flb_plg_error(ins, "could not allocate memory for the context");
        return -1;
    }

    ctx->ins = ins;
    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->log_encoder) {
        flb_plg_error(ins, "could not create log event encoder");
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(ins, ctx);
    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "failed to load config map");
        flb_free(ctx);
        return -1;
    }

    bpf_obj_file = ctx->bpf_object_file;
    if (!bpf_obj_file) {
        flb_plg_error(ins, "no eBPF object file specified");
        flb_free(ctx);
        return -1;
    }

    bpf_prog_name = ctx->bpf_program_name;
    if (!bpf_prog_name) {
        flb_plg_error(ins, "no eBPF program name specified");
        flb_free(ctx);
        return -1;
    }

    ctx->obj = bpf_object__open_file(bpf_obj_file, NULL);
    if (!ctx->obj) {
        flb_plg_error(ins, "failed to open eBPF object file: %s", bpf_obj_file);
        flb_free(ctx);
        return -1;
    }

    err = bpf_object__load(ctx->obj);
    if (err) {
        flb_plg_error(ins, "failed to load eBPF object: %d", err);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    prog = bpf_object__find_program_by_name(ctx->obj, bpf_prog_name);
    if (!prog) {
        flb_plg_error(ins, "failed to find eBPF program: %s", bpf_prog_name);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        flb_plg_error(ins, "failed to attach eBPF program");
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    map = bpf_object__find_map_by_name(ctx->obj, ctx->ringbuf_map_name);
    if (!map) {
        flb_plg_error(ins, "failed to find the '%s' map in eBPF object", ctx->ringbuf_map_name);
        bpf_link__destroy(link);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    ctx->map_fd = bpf_map__fd(map);
    if (ctx->map_fd < 0) {
        flb_plg_error(ins, "failed to get file descriptor for '%s' map", ctx->ringbuf_map_name);
        bpf_link__destroy(link);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    ctx->rb = ring_buffer__new(ctx->map_fd, handle_ebpf_event, ins, NULL);
    if (!ctx->rb) {
        flb_plg_error(ins, "failed to create ring buffer");
        bpf_link__destroy(link);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    poll_seconds = ctx->poll_ms / 1000;
    poll_nanoseconds = (ctx->poll_ms % 1000) * 1000000;

    ctx->coll_fd = flb_input_set_collector_time(ins, in_ebpf_collect,
                                                poll_seconds, poll_nanoseconds,
                                                config);
    if (ctx->coll_fd < 0) {
        flb_plg_error(ins, "failed to set up collector");
        ring_buffer__free(ctx->rb);
        bpf_link__destroy(link);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    flb_plg_info(ins, "eBPF program '%s' loaded successfully from object file '%s' with ring buffer '%s'",
                 bpf_prog_name, bpf_obj_file, ctx->ringbuf_map_name);

    return 0;
}

/* Configuration map for the plugin */
static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "bpf_object_file", NULL,
        0, FLB_TRUE, offsetof(struct flb_in_ebpf_config, bpf_object_file),
        "path to the eBPF program object file."
    },
    {
        FLB_CONFIG_MAP_STR, "bpf_program_name", NULL,
        0, FLB_TRUE, offsetof(struct flb_in_ebpf_config, bpf_program_name),
        "name of the eBPF program to attach."
    },
    {
        FLB_CONFIG_MAP_STR, "ringbuf_map_name", FLB_IN_EBPF_DEFAULT_RINGBUF_MAP_NAME,
        0, FLB_TRUE, offsetof(struct flb_in_ebpf_config, ringbuf_map_name),
        "name of the ring buffer map in the eBPF program."
    },
    {
        FLB_CONFIG_MAP_INT, "poll_ms", FLB_IN_EBPF_DEFAULT_POLL_MS,
        0, FLB_TRUE, offsetof(struct flb_in_ebpf_config, poll_ms),
        "poll timeout in milliseconds (-1 for infinite)."
    },
    {0}
};

/* Plugin registration */
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
