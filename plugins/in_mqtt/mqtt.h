/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#define MQTT_MSGP_BUF_SIZE 8192

struct flb_in_mqtt_config {
    int server_fd;                     /* TCP server file descriptor  */

    char *listen;                      /* Listen interface            */
    char *tcp_port;                    /* TCP Port                    */

    int msgp_len;                      /* msgpack data length         */
    char msgp[MQTT_MSGP_BUF_SIZE];     /* msgpack static buffer       */
    struct flb_input_instance *i_ins;  /* plugin input instance       */
    struct mk_event_loop *evl;         /* Event loop file descriptor  */
};

int in_mqtt_collect(struct flb_input_instance *i_ins,
                    struct flb_config *config, void *in_context);

#endif
