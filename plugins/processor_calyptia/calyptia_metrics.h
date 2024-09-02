#ifndef FLB_CALYPTIA_METRICS_H
#define FLB_CALYPTIA_METRICS_H

#include <fluent-bit/flb_processor_plugin.h>

int calyptia_process_metrics(struct flb_processor_instance *ins,
                             struct cmt *metrics_context,
                             struct cmt **out_context, const char *tag,
                             int tag_len);

#endif
