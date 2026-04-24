#ifndef SCHED_HANDLER_H
#define SCHED_HANDLER_H

#include <fluent-bit/flb_log_event_encoder.h>
#include <stddef.h>

#include "common/events.h"

int encode_sched_event(struct flb_log_event_encoder *log_encoder,
                       const struct event *e);
int trace_sched_handler(void *ctx, void *data, size_t data_sz);

#endif
