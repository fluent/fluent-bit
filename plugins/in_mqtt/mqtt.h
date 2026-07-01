/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_IN_MQTT_H
#define FLB_IN_MQTT_H

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_log_event_encoder.h>

#define MQTT_MSGP_BUF_SIZE 8192

struct flb_in_mqtt_config {
    char *listen;                      /* Listen interface            */
    char *tcp_port;                    /* TCP Port                    */

    flb_sds_t payload_key;             /* payload key */
    size_t buffer_size;                /* connection buffer size      */
    
    int msgp_len;                      /* msgpack data length         */
    char msgp[MQTT_MSGP_BUF_SIZE];     /* msgpack static buffer       */
    struct flb_input_instance *ins;    /* plugin input instance       */
    struct flb_downstream *downstream; /* Client manager              */
    struct mk_list conns;              /* Active connections          */
    struct flb_log_event_encoder *log_encoder;
};

int in_mqtt_collect(struct flb_input_instance *i_ins,
                    struct flb_config *config, void *in_context);

#endif
