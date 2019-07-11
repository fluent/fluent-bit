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

static const char *nats_setting_error = "[NATS] Error (%d) setting '%s': '%s'";

struct flb_out_nats_config {
    struct flb_output_instance *ins;
    natsConnection      *connection;
    natsOptions         *options;
    bool                closed;
    natsStatus          status;
    
    char                *subject;
    char                *url;
};

#endif
