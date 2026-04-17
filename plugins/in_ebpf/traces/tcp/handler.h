#ifndef TRACE_TCP_HANDLER_H
#define TRACE_TCP_HANDLER_H

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

int trace_tcp_handler(void *ctx, void *data, size_t data_sz);
int encode_tcp_event(struct flb_input_instance *ins,
                     struct flb_log_event_encoder *log_encoder,
                     const struct event *ev);

#endif
