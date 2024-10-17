#ifndef IN_EBPF_H
#define IN_EBPF_H

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

#define FLB_IN_EBPF_DEFAULT_RINGBUF_MAP_NAME  "events"
#define FLB_IN_EBPF_DEFAULT_POLL_MS           "1000"  // 1 second default poll timeout

/* Forward declaration */
struct trace_context;

/* Plugin configuration structure */
struct flb_in_ebpf_context {
    struct flb_input_instance *ins;                 // Fluent Bit input instance
    struct flb_log_event_encoder *log_encoder;      // Log event encoder for formatting logs
    struct trace_context *traces;                   // Array of trace contexts
    int trace_count;                                // Number of registered traces (use size_t if appropriate)
    char *ringbuf_map_name;                         // Name of the ring buffer map (ensure memory is managed)
    int poll_ms;                                    // Poll interval in milliseconds
    int coll_fd;                               // File descriptor for the event collector
};

// /* Function declarations */
// int register_trace_handler(struct flb_in_ebpf_context *ctx, const char *name, struct bpf_object *obj, trace_event_handler_t handler);
// int process_trace_config(struct flb_in_ebpf_context *ctx, const char *trace_name);

#endif // IN_EBPF_H
