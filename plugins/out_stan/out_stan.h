#ifndef FLB_OUT_NATS_H
#define FLB_OUT_NATS_H

#include <fluent-bit/flb_version.h>

#include <nats.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define strcasecmp  _stricmp
#define strdup      _strdup
#else
#include <strings.h>
#include <signal.h>
#endif

#define NATS_MAX_SERVERS     (10)

static const char *nats_setting_error = "NATS Streaming Error (%d) setting '%s': '%s'";

struct flb_out_stan_config {
    struct flb_output_instance *ins;
    stanConnection      *connection;
    stanConnOptions     *stan_options;
    natsOptions         *nats_options;
    bool                nats_closed;
    bool                stan_closed;
    natsStatus          status;
    
    const char          *subject;
    const char          *url;
    const char          *cluster;
};

#endif
