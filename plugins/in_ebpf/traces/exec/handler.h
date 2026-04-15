#ifndef TRACE_EXEC_HANDLER_H
#define TRACE_EXEC_HANDLER_H

#include <stddef.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include "common/events.h"

int encode_exec_event(struct flb_input_instance *ins,
                      struct flb_log_event_encoder *log_encoder,
                      const struct event *ev);
int trace_exec_handler(void *ctx, void *data, size_t data_sz);

#endif
