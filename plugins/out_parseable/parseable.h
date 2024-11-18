#ifndef FLB_OUT_PARSEABLE_H
#define FLB_OUT_PARSEABLE_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>

struct flb_out_parseable {
    flb_sds_t p_server;
    int p_port;
    struct flb_upstream *upstream;
    struct flb_output_instance *ins;
};

#endif