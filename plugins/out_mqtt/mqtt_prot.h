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

#ifndef FLB_OUT_MQTT_PROT_H
#define FLB_OUT_MQTT_PROT_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

#include <stddef.h>
#include <stdint.h>

/*
 * MQTT 3.1.1 (OASIS standard) client side encoders and decoders. Every
 * function in this file works on memory buffers only, the network I/O
 * lives in mqtt.c.
 */

/* Control packet types: high nibble of the first fixed header byte */
#define FLB_MQTT_CONNECT                     1
#define FLB_MQTT_CONNACK                     2
#define FLB_MQTT_PUBLISH                     3
#define FLB_MQTT_PUBACK                      4
#define FLB_MQTT_PUBREC                      5
#define FLB_MQTT_PUBREL                      6
#define FLB_MQTT_PUBCOMP                     7
#define FLB_MQTT_PINGREQ                    12
#define FLB_MQTT_PINGRESP                   13
#define FLB_MQTT_DISCONNECT                 14

/* Protocol level for MQTT 3.1.1 */
#define FLB_MQTT_PROTOCOL_LEVEL              4

/* Largest value encodable in the Remaining Length field (4 bytes) */
#define FLB_MQTT_MAX_REMAINING_LENGTH        268435455

/* Size limit of UTF-8 encoded strings and binary data fields */
#define FLB_MQTT_MAX_STRING_LENGTH           65535

/* Packet identifiers are non-zero 16 bit integers */
#define FLB_MQTT_MAX_PACKET_ID               65535

/* Largest fixed header: one control byte and four length bytes */
#define FLB_MQTT_MAX_FIXED_HEADER            5

/* CONNACK return codes */
#define FLB_MQTT_CONNACK_ACCEPTED            0
#define FLB_MQTT_CONNACK_BAD_PROTOCOL        1
#define FLB_MQTT_CONNACK_ID_REJECTED         2
#define FLB_MQTT_CONNACK_SERVER_UNAVAILABLE  3
#define FLB_MQTT_CONNACK_BAD_CREDENTIALS     4
#define FLB_MQTT_CONNACK_NOT_AUTHORIZED      5

/* Fixed header decoder results */
#define FLB_MQTT_DECODE_OK                   0
#define FLB_MQTT_DECODE_MORE                 1
#define FLB_MQTT_DECODE_ERROR               -1

/* Encode a Remaining Length value, returns the number of bytes or -1 */
int out_mqtt_prot_encode_length(size_t length, unsigned char *out);

/*
 * Decode the fixed header found at the beginning of 'buf'. On success the
 * packet type, the flags (low nibble), the Remaining Length and the size of
 * the fixed header are set. The packet body is not required to be complete.
 */
int out_mqtt_prot_decode_fixed_header(const unsigned char *buf, size_t size,
                                      int *type, int *flags,
                                      size_t *remaining_length,
                                      size_t *header_size);

/* Append a CONNECT packet (clean session) to 'buf' */
int out_mqtt_prot_connect(flb_sds_t *buf,
                          const char *client_id, size_t client_id_len,
                          const char *username, size_t username_len,
                          const char *password, size_t password_len,
                          int keep_alive);

/* Append a PUBLISH packet to 'buf', packet_id is ignored for QoS 0 */
int out_mqtt_prot_publish(flb_sds_t *buf,
                          const char *topic, size_t topic_len,
                          const char *payload, size_t payload_len,
                          int qos, int retain, uint16_t packet_id);

/* Append a PINGREQ packet to 'buf' */
int out_mqtt_prot_pingreq(flb_sds_t *buf);

/*
 * Write the 4 bytes acknowledgement 'type' (PUBACK, PUBREC, PUBREL or
 * PUBCOMP) for packet identifier 'id' into 'out'.
 */
void out_mqtt_prot_ack(unsigned char *out, int type, uint16_t id);

/* Append a DISCONNECT packet to 'buf' */
int out_mqtt_prot_disconnect(flb_sds_t *buf);

/*
 * Validate a string against the MQTT UTF-8 rules: well formed UTF-8 and no
 * U+0000. When 'allow_control' is false the code points a receiver may
 * reject by closing the connection (C0/C1 control characters and Unicode
 * non-characters) are refused too.
 */
int out_mqtt_prot_utf8_valid(const char *str, size_t len, int allow_control);

/*
 * Validate a full topic name for PUBLISH: non empty, at most 65535 bytes,
 * valid UTF-8 without control characters and without '+' or '#' wildcards.
 */
int out_mqtt_prot_topic_valid(const char *topic, size_t len);

/* Validate a fragment of a topic name, it can be empty */
int out_mqtt_prot_topic_fragment_valid(const char *topic, size_t len);

/* Human readable description of a CONNACK return code */
const char *out_mqtt_prot_connack_str(int code);

#endif
