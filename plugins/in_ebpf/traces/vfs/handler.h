#ifndef VFS_HANDLER_H
#define VFS_HANDLER_H

#include <stddef.h>
#include "common/events.h"

int trace_vfs_handler(void *ctx, void *data, size_t data_sz);
int encode_vfs_event(struct flb_input_instance *ins,
                     struct flb_log_event_encoder *log_encoder,
                     const struct event *ev);

#endif
