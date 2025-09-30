#ifndef BIND_HANDLER_H
#define BIND_HANDLER_H

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log.h>
#include <stddef.h>  // For size_t

#include "common/events.h"

int trace_bind_handler(void *ctx, void *data, size_t data_sz);
int encode_bind_event(struct flb_input_instance *ins,
                      struct flb_log_event_encoder *log_encoder,
                      const struct event *ev);

#endif // BIND_HANDLER_H