#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log.h>
#include <stddef.h>  // For size_t

#include "common/events.h"

/* Encode a signal event into a Fluent Bit log format */
int encode_signal_event(struct flb_input_instance *ins,
                        struct flb_log_event_encoder *log_encoder,
                        const struct event *e);

/* Handler for processing a signal event */
int trace_signal_handler(void *ctx, void *data, size_t data_sz);

#endif // SIGNAL_HANDLER_H
