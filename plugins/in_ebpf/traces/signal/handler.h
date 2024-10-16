#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

#include <stddef.h>  // Include this to define size_t

int trace_signal_handler(void *ctx, void *data, size_t data_sz);

#endif // SIGNAL_HANDLER_H
