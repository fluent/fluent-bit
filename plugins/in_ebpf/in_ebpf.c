#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "in_ebpf.h"

static int encode_log_event(struct flb_input_instance *ins,
                            struct flb_log_event_encoder *log_encoder,
                            const char *event_type_str,
                            __u32 pid,
                            const char *data, size_t data_len)
{
    int ret;

    flb_plg_trace(ins, "Encoding log event");
    ret = flb_log_event_encoder_begin_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ins, "Failed to begin log event record");
        return -1;
    }

    flb_plg_trace(ins, "Setting current timestamp for log event");
    ret = flb_log_event_encoder_set_current_timestamp(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        flb_plg_error(ins, "Failed to set timestamp");
        return -1;
    }

    /* Append the PID (if provided in the event) */
    if (pid > 0) {
        flb_plg_trace(ins, "Appending PID: %u", pid);
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "pid");
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "Failed to append PID key");
            return -1;
        }
        ret = flb_log_event_encoder_append_body_uint32(log_encoder, pid);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "Failed to append PID value");
            return -1;
        }
    }

    if (event_type_str) {
        flb_plg_trace(ins, "Appending event type: %s", event_type_str);
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "event_type");
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "Failed to append event type key");
            return -1;
        }
        ret = flb_log_event_encoder_append_body_string(log_encoder, event_type_str, strlen(event_type_str));
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "Failed to append event type value");
            return -1;
        }
    }

    if (data_len > 0) {
        flb_plg_trace(ins, "Appending event data of length: %zu", data_len);
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "event_data");
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "Failed to append event data key");
            return -1;
        }
        ret = flb_log_event_encoder_append_body_string(log_encoder, data, data_len);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(log_encoder);
            flb_plg_error(ins, "Failed to append event data value");
            return -1;
        }
    } else {
        flb_plg_trace(ins, "No event data to append (data_len = 0)");
    }

    /* Commit the record */
    ret = flb_log_event_encoder_commit_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ins, "Failed to commit log event record");
        return -1;
    }

    /* Append the encoded log event to Fluent Bit instance */
    if (log_encoder->output_length > 0) {
        flb_plg_trace(ins, "Appending log event of length: %zu", log_encoder->output_length);
        ret = flb_input_log_append(ins, NULL, 0,
                                   log_encoder->output_buffer,
                                   log_encoder->output_length);
        if (ret == -1) {
            flb_plg_error(ins, "Failed to append log data");
            return -1;
        }
        flb_log_event_encoder_reset(log_encoder);
    }

    return 0;
}

/* Event handler for the ring buffer */
static int handle_ebpf_event(void *instance, void *data, size_t data_sz) {
    struct flb_input_instance *ins = instance;
    struct flb_in_ebpf_config *ctx = ins->context;
    struct flb_log_event_encoder *log_encoder = ctx->log_encoder;
    const char *event_type_str = NULL;
    __u32 pid = 0;
    char *event_data = NULL;
    size_t event_data_len = 0;

    /* Check if data size is zero and discard if no valid data */
    if (data_sz == 0) {
        flb_plg_warn(ins, "Received an event with zero data size. Discarding.");
        return 0;  // No data to process, skip further actions
    }

    /* First, attempt to handle structured event */
    if (data_sz == sizeof(struct flb_in_ebpf_event)) {
        /* Structured event */
        struct flb_in_ebpf_event *event = (struct flb_in_ebpf_event *)data;
        event_type_str = get_event_type_str(event->event_type);
        pid = event->pid;
        event_data = event->data;
        event_data_len = strlen(event_data);

        flb_plg_trace(ins, "Processed structured event of type: %s", event_type_str);

    } else if (data_sz <= MAX_EVENT_LEN) {
        /* Handle raw string case (e.g., command line) */
        event_data = (char *)data;
        event_data_len = strlen(event_data);
        event_type_str = FLB_IN_EBPF_EVENT_TYPE_UNKNOWN;

        flb_plg_trace(ins, "Processed raw string event");
    }

    /* Encode the event */
    return encode_log_event(ins, log_encoder, event_type_str, pid, event_data, event_data_len);
}


/* Collect function for reading the ring buffer */
static int in_ebpf_collect(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_in_ebpf_config *ctx = in_context;
    flb_plg_trace(ins, "Polling on ring buffer '%s'", ctx->ringbuf_map_name);
    int err = ring_buffer__consume(ctx->rb);
    if (err < 0) {
        flb_plg_error(ins, "Error polling the ring buffer: %d", err);
        return -1;
    }

    return 0;
}

/* Function to initialize the eBPF program */
static int in_ebpf_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    struct flb_in_ebpf_config *ctx;
    const char *bpf_obj_file;
    const char *bpf_prog_name;
    struct bpf_map *map;
    int err;

    /* Allocate space for the configuration context */
    ctx = flb_calloc(1, sizeof(struct flb_in_ebpf_config));
    if (!ctx) {
        flb_plg_error(ins, "Could not allocate memory for the context");
        return -1;
    }
    ctx->rb = NULL;
    ctx->obj = NULL;
    ctx->ins = ins;  /* Set the input instance pointer */

    /* Initialize the log encoder */
    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->log_encoder) {
        flb_plg_error(ins, "Could not create log event encoder");
        flb_free(ctx);
        return -1;
    }

    /* Set defaults for optional parameters */
    if (!ctx->ringbuf_map_name) {
        ctx->ringbuf_map_name = FLB_IN_EBPF_DEFAULT_RINGBUF_MAP_NAME;
    }
    if (ctx->poll_ms <= 0) {
        ctx->poll_ms = atoi(FLB_IN_EBPF_DEFAULT_POLL_MS);
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    /* Load the config map */
    int ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "Failed to load config map");
        flb_free(ctx);
        return -1;
    }

    /* Get the BPF object file path */
    bpf_obj_file = ctx->bpf_object_file;
    if (!bpf_obj_file) {
        flb_plg_error(ins, "No BPF object file specified");
        flb_free(ctx);
        return -1;
    }

    /* Get the BPF program name */
    bpf_prog_name = ctx->bpf_program_name;
    if (!bpf_prog_name) {
        flb_plg_error(ins, "No BPF program name specified");
        flb_free(ctx);
        return -1;
    }

    /* Load the BPF object file */
    ctx->obj = bpf_object__open_file(bpf_obj_file, NULL);
    if (!ctx->obj) {
        flb_plg_error(ins, "Failed to open BPF object file: %s", bpf_obj_file);
        flb_free(ctx);
        return -1;
    }

    /* Load the BPF object into the kernel */
    err = bpf_object__load(ctx->obj);
    if (err) {
        flb_plg_error(ins, "Failed to load BPF object: %d", err);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    /* Find the BPF program by its name */
    struct bpf_program *prog = bpf_object__find_program_by_name(ctx->obj, bpf_prog_name);
    if (!prog) {
        flb_plg_error(ins, "Failed to find BPF program: %s", bpf_prog_name);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    /* Attach the BPF program to the tracepoint */
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        flb_plg_error(ins, "Failed to attach BPF program");
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    /* Find the ring buffer map by its name */
    map = bpf_object__find_map_by_name(ctx->obj, ctx->ringbuf_map_name);
    if (!map) {
        flb_plg_error(ins, "Failed to find the '%s' map in BPF object", ctx->ringbuf_map_name);
        bpf_link__destroy(link);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    ctx->map_fd = bpf_map__fd(map);
    if (ctx->map_fd < 0) {
        flb_plg_error(ins, "Failed to get file descriptor for '%s' map", ctx->ringbuf_map_name);
        bpf_link__destroy(link);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    /* Set up the ring buffer */
    ctx->rb = ring_buffer__new(ctx->map_fd, handle_ebpf_event, ins, NULL);
    if (!ctx->rb) {
        flb_plg_error(ins, "Failed to create ring buffer");
        bpf_link__destroy(link);
        bpf_object__close(ctx->obj);
        flb_free(ctx);
        return -1;
    }

    /* Calculate poll time in seconds and nanoseconds */
    int poll_seconds = ctx->poll_ms / 1000;
    int poll_nanoseconds = (ctx->poll_ms % 1000) * 1000000;

    /* Initialize the collector */
    ctx->coll_fd = flb_input_set_collector_time(ins,
                                                in_ebpf_collect,
                                                poll_seconds,
                                                poll_nanoseconds,
                                                config);
    if (ctx->coll_fd < 0) {
        flb_plg_error(ins, "Failed to set up collector");
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

/* Pause function to stop the collector */
static void in_ebpf_pause(void *data, struct flb_config *config)
{
    struct flb_in_ebpf_config *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

/* Resume function to start the collector */
static void in_ebpf_resume(void *data, struct flb_config *config)
{
    struct flb_in_ebpf_config *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

/* Cleanup function */
static int in_ebpf_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_ebpf_config *ctx = in_context;

    if (!ctx) {
        return 0;
    }

    /* Clean up ring buffer and BPF object */
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

/* Configuration map for the plugin */
static struct flb_config_map config_map[] = {
    /* Path to the compiled eBPF object file (*.o) */
    {
        FLB_CONFIG_MAP_STR, "bpf_object_file", NULL,
        0, FLB_TRUE, offsetof(struct flb_in_ebpf_config, bpf_object_file),
        "Path to the eBPF program object file."
    },

    /* Name of the eBPF program (function) to attach from the object file */
    {
        FLB_CONFIG_MAP_STR, "bpf_program_name", NULL,
        0, FLB_TRUE, offsetof(struct flb_in_ebpf_config, bpf_program_name),
        "Name of the eBPF program to attach."
    },

    /* Name of the ring buffer map in the eBPF program to use for event collection */
    {
        FLB_CONFIG_MAP_STR, "ringbuf_map_name", FLB_IN_EBPF_DEFAULT_RINGBUF_MAP_NAME,
        0, FLB_TRUE, offsetof(struct flb_in_ebpf_config, ringbuf_map_name),
        "Name of the ring buffer map in the eBPF program."
    },

    /* Poll timeout in milliseconds (-1 for infinite) */
    {
        FLB_CONFIG_MAP_INT, "poll_ms", FLB_IN_EBPF_DEFAULT_POLL_MS,
        0, FLB_TRUE, offsetof(struct flb_in_ebpf_config, poll_ms),
        "Poll timeout in milliseconds (-1 for infinite)."
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