

#ifndef FLB_IN_NATS_H
#define FLB_IN_NATS_H

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

// TODO consolidate this duplicate code!
static const char *nats_setting_error = "NATS Error (%d) setting '%s': '%s'";

struct flb_in_nats_config {
    struct flb_input_instance *ins;
    natsConnection      *connection;
    natsOptions         *options;
    natsSubscription    *subscription;
    bool                closed;
    natsStatus          status;
    
    char                *subject;
    char                *url;
};

extern struct flb_input_plugin in_nats_plugin;

#endif
