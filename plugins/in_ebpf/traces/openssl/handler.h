#ifndef TRACE_OPENSSL_HANDLER_H
#define TRACE_OPENSSL_HANDLER_H

#include <stddef.h>

struct event;
struct flb_log_event_encoder;

int encode_openssl_event(struct flb_log_event_encoder *log_encoder,
                         const struct event *ev);
int trace_openssl_handler(void *ctx, void *data, size_t data_sz);

#endif
