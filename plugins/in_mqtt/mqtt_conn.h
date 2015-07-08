/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#ifndef FLB_MQTT_CONN_H
#define FLB_MQTT_CONN_H

#include <mk_core/mk_core.h>

enum {
    MQTT_NEW        = 0,
    MQTT_CONNECTED
};

/* This structure respresents a MQTT connection */
struct mqtt_conn {
    struct mk_event event;           /* Built-in event data for mk_events */
    int fd;                          /* Socket file descriptor            */
    int status;                      /* Connection status                 */
    int  buf_len;                    /* Buffer content length             */
    char buf[1024];                  /* Buffer data                       */
    struct flb_in_mqtt_config *ctx;  /* Plugin configuration context      */
};

struct mqtt_conn *mqtt_conn_add(int fd, struct flb_in_mqtt_config *ctx);
int mqtt_conn_del(struct mqtt_conn *conn);

#endif
