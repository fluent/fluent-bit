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

#ifndef FLB_MQTT_CONN_H
#define FLB_MQTT_CONN_H

#include <fluent-bit/flb_connection.h>

#define MQTT_CONNECTION_DEFAULT_BUFFER_SIZE "2048"

enum {
    MQTT_NEW        = 1,  /* it's a new connection                */
    MQTT_CONNECTED  = 2,  /* MQTT connection per protocol spec OK */
    MQTT_NEXT       = 4   /* Waiting for Control packets          */
};

/* This structure respresents a MQTT connection */
struct mqtt_conn {
    int status;                      /* Connection status                 */
    int packet_type;                 /* MQTT packet type                  */
    int packet_length;
    int  buf_frame_end;              /* Frame end position                */
    int  buf_pos;                    /* Index position                    */
    int  buf_len;                    /* Buffer content length             */
    size_t  buf_size;                /* Buffer size                       */
    unsigned char *buf;              /* Buffer data                       */
    struct flb_in_mqtt_config *ctx;  /* Plugin configuration context      */
    struct flb_connection *connection;
    struct mk_list _head;            /* Link to flb_in_mqtt_config->conns */
};

struct mqtt_conn *mqtt_conn_add(struct flb_connection *connection, struct flb_in_mqtt_config *ctx);
int mqtt_conn_del(struct mqtt_conn *conn);
int mqtt_conn_destroy_all(struct flb_in_mqtt_config *ctx);

#endif
