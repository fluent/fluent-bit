#ifndef FLB_IN_SNMP_H
#define FLB_IN_SNMP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <net-snmp/net-snmp-includes.h>

struct flb_snmp {
    int  coll_fd;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder log_encoder;

    netsnmp_session session;

    char *target_host;
    int target_port;
    int timeout;
    char *version;
    char *community;
    int retries;
    char *oid_type;
    char *oid;
};

#endif