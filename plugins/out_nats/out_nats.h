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

struct flb_out_nats_config {
    struct flb_output_instance *ins;
    //struct flb_upstream *u;
    natsConnection      *connection;
    natsOptions         *options;
    natsSubscription    *subscription;
    bool                closed;
    natsStatus          status;
    
    char                *host;
    char                *port;
    char                *username;
    char                *password;
    char                *subject;
    
    //char connect_string[NATS_CONNECT_BUF_LEN];
    //int connect_string_len;
    //int subject_len;
};

#endif
