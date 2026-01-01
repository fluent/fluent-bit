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

#ifndef FLB_MQTT_PROT_H
#define FLB_MQTT_PROT_H

#include "mqtt_conn.h"

/*
 * Specs definition from 2.2.1 MQTT Control Packet:
 *
 * http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718021
 */
#define MQTT_CONNECT      1
#define MQTT_CONNACK      2
#define MQTT_PUBLISH      3
#define MQTT_PUBACK       4
#define MQTT_PUBREC       5
#define MQTT_PUBREL       6
#define MQTT_PUBCOMP      7
#define MQTT_PINGREQ     12
#define MQTT_PINGRESP    13
#define MQTT_DISCONNECT  14

/* CONNACK status codes */
#define MQTT_CONN_ACCEPTED         0
#define MQTT_CONN_REFUSED_PROTOCOL 1
#define MQTT_CONN_REFUSED_IDENTIF  2
#define MQTT_CONN_REFUSED_SERVER   3
#define MQTT_CONN_REFUSED_BADCRED  4
#define MQTT_CONN_REFUSED_NOAUTH   5

/* QOS Flag status */
#define MQTT_QOS_LEV0              0  /* no reply      */
#define MQTT_QOS_LEV1              1  /* PUBACK packet */
#define MQTT_QOS_LEV2              2  /* PUBREC packet */

/* Specific macros for Fluent Bit handling, not related to MQTT spec */
#define MQTT_HANGUP      -2  /* MQTT client is closing      */
#define MQTT_ERROR       -1  /* MQTT protocol error, hangup */
#define MQTT_OK           0  /* Everything is OK            */
#define MQTT_MORE         1  /* need to read more data      */

int mqtt_prot_parser(struct mqtt_conn *conn);

#endif
