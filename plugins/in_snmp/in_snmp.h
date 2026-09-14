/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

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