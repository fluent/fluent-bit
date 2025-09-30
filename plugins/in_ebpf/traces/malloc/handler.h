#ifndef MALLOC_HANDLER_H
#define MALLOC_HANDLER_H

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log.h>
#include <stddef.h>  // For size_t

#include "common/events.h"

int encode_malloc_event(struct flb_input_instance *ins,
                               struct flb_log_event_encoder *log_encoder,
                               const struct event *ev);
int trace_malloc_handler(void *ctx, void *data, size_t data_sz);

#endif // MALLOC_HANDLER_H