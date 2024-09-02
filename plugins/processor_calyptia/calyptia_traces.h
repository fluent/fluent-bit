#ifndef CALYPTIA_TRACES_H
#define CALYPTIA_TRACES_H

#include <fluent-bit/flb_processor_plugin.h>
#include <ctraces/ctraces.h>

int calyptia_process_traces(struct flb_processor_instance *ins,
                            struct ctrace *traces_context, const char *tag,
                            int tag_len);

#endif
