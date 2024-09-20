#ifndef TRACE_EVENT_CONTEXT_H
#define TRACE_EVENT_CONTEXT_H

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

/* Minimal context for event handling */
struct trace_event_context {
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

#endif // TRACE_EVENT_CONTEXT_H
