#ifndef FLB_CALYPTIA_LOGS_H
#define FLB_CALYPTIA_LOGS_H

#include <fluent-bit/flb_processor_plugin.h>

int calyptia_process_logs(struct flb_processor_instance *ins, void *chunk_data,
                          const char *tag, int tag_len);

#endif
