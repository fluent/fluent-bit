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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

#include "mqtt_prot.h"

static int append_bytes(flb_sds_t *buf, const void *data, size_t len)
{
    if (len == 0) {
        return 0;
    }

    return flb_sds_cat_safe(buf, (const char *) data, (int) len);
}

static int append_u16(flb_sds_t *buf, uint16_t value)
{
    unsigned char tmp[2];

    tmp[0] = (value >> 8) & 0xff;
    tmp[1] = value & 0xff;

    return append_bytes(buf, tmp, sizeof(tmp));
}

/* UTF-8 encoded string or binary data: two bytes length prefix + content */
static int append_prefixed(flb_sds_t *buf, const char *data, size_t len)
{
    if (len > FLB_MQTT_MAX_STRING_LENGTH) {
        return -1;
    }

    if (append_u16(buf, (uint16_t) len) != 0) {
        return -1;
    }

    return append_bytes(buf, data, len);
}

int out_mqtt_prot_encode_length(size_t length, unsigned char *out)
{
    int i;
    unsigned char byte;

    if (length > FLB_MQTT_MAX_REMAINING_LENGTH) {
        return -1;
    }

    i = 0;
    do {
        byte = length % 128;
        length = length / 128;
        if (length > 0) {
            byte |= 0x80;
        }
        out[i] = byte;
        i++;
    } while (length > 0);

    return i;
}

int out_mqtt_prot_decode_fixed_header(const unsigned char *buf, size_t size,
                                      int *type, int *flags,
                                      size_t *remaining_length,
                                      size_t *header_size)
{
    size_t i;
    size_t length;
    size_t multiplier;

    if (size < 2) {
        return FLB_MQTT_DECODE_MORE;
    }

    length = 0;
    multiplier = 1;

    /* The Remaining Length uses one to four bytes */
    for (i = 1; i <= 4; i++) {
        if (i >= size) {
            return FLB_MQTT_DECODE_MORE;
        }

        length += (size_t) (buf[i] & 0x7f) * multiplier;

        if ((buf[i] & 0x80) == 0) {
            *type = buf[0] >> 4;
            *flags = buf[0] & 0x0f;
            *remaining_length = length;
            *header_size = i + 1;
            return FLB_MQTT_DECODE_OK;
        }

        multiplier *= 128;
    }

    /* A continuation bit on the fourth length byte is a malformed packet */
    return FLB_MQTT_DECODE_ERROR;
}

int out_mqtt_prot_connect(flb_sds_t *buf,
                          const char *client_id, size_t client_id_len,
                          const char *username, size_t username_len,
                          const char *password, size_t password_len,
                          int keep_alive)
{
    int ret;
    int len;
    size_t start;
    size_t remaining;
    unsigned char flags;
    unsigned char header[FLB_MQTT_MAX_FIXED_HEADER];
    unsigned char variable[10];

    if (client_id_len > FLB_MQTT_MAX_STRING_LENGTH ||
        username_len > FLB_MQTT_MAX_STRING_LENGTH ||
        password_len > FLB_MQTT_MAX_STRING_LENGTH) {
        return -1;
    }

    if (keep_alive < 0 || keep_alive > 65535) {
        return -1;
    }

    /* MQTT 3.1.1 only allows a password together with a user name */
    if (password != NULL && username == NULL) {
        return -1;
    }

    /* Clean Session: the broker keeps no state between connections */
    flags = 0x02;

    /* Variable header plus the client identifier */
    remaining = sizeof(variable) + 2 + client_id_len;

    if (username != NULL) {
        flags |= 0x80;
        remaining += 2 + username_len;
    }

    if (password != NULL) {
        flags |= 0x40;
        remaining += 2 + password_len;
    }

    header[0] = FLB_MQTT_CONNECT << 4;
    len = out_mqtt_prot_encode_length(remaining, header + 1);
    if (len == -1) {
        return -1;
    }

    /* Protocol Name, Protocol Level, Connect Flags and Keep Alive */
    variable[0] = 0x00;
    variable[1] = 0x04;
    variable[2] = 'M';
    variable[3] = 'Q';
    variable[4] = 'T';
    variable[5] = 'T';
    variable[6] = FLB_MQTT_PROTOCOL_LEVEL;
    variable[7] = flags;
    variable[8] = (keep_alive >> 8) & 0xff;
    variable[9] = keep_alive & 0xff;

    start = flb_sds_len(*buf);

    ret = append_bytes(buf, header, 1 + len);
    if (ret == 0) {
        ret = append_bytes(buf, variable, sizeof(variable));
    }
    if (ret == 0) {
        ret = append_prefixed(buf, client_id, client_id_len);
    }
    if (ret == 0 && username != NULL) {
        ret = append_prefixed(buf, username, username_len);
    }
    if (ret == 0 && password != NULL) {
        ret = append_prefixed(buf, password, password_len);
    }

    if (ret != 0) {
        flb_sds_len_set(*buf, start);
        return -1;
    }

    return 0;
}

int out_mqtt_prot_publish(flb_sds_t *buf,
                          const char *topic, size_t topic_len,
                          const char *payload, size_t payload_len,
                          int qos, int retain, uint16_t packet_id)
{
    int ret;
    int len;
    size_t start;
    size_t remaining;
    unsigned char header[FLB_MQTT_MAX_FIXED_HEADER];

    if (topic_len == 0 || topic_len > FLB_MQTT_MAX_STRING_LENGTH) {
        return -1;
    }

    if (qos < 0 || qos > 2) {
        return -1;
    }

    /* QoS > 0 requires a non-zero packet identifier */
    if (qos > 0 && packet_id == 0) {
        return -1;
    }

    /* Check the payload first so the sum below cannot overflow */
    if (payload_len > FLB_MQTT_MAX_REMAINING_LENGTH) {
        return -1;
    }

    remaining = 2 + topic_len + payload_len;
    if (qos > 0) {
        remaining += 2;
    }

    header[0] = (FLB_MQTT_PUBLISH << 4) | (qos << 1);
    if (retain) {
        header[0] |= 0x01;
    }

    len = out_mqtt_prot_encode_length(remaining, header + 1);
    if (len == -1) {
        return -1;
    }

    start = flb_sds_len(*buf);

    ret = append_bytes(buf, header, 1 + len);
    if (ret == 0) {
        ret = append_prefixed(buf, topic, topic_len);
    }
    if (ret == 0 && qos > 0) {
        ret = append_u16(buf, packet_id);
    }
    if (ret == 0) {
        ret = append_bytes(buf, payload, payload_len);
    }

    if (ret != 0) {
        flb_sds_len_set(*buf, start);
        return -1;
    }

    return 0;
}

int out_mqtt_prot_pingreq(flb_sds_t *buf)
{
    unsigned char packet[2];

    packet[0] = FLB_MQTT_PINGREQ << 4;
    packet[1] = 0x00;

    return append_bytes(buf, packet, sizeof(packet));
}

void out_mqtt_prot_ack(unsigned char *out, int type, uint16_t id)
{
    /* PUBREL is the only acknowledgement with fixed header flags (0010) */
    out[0] = (unsigned char) (type << 4);
    if (type == FLB_MQTT_PUBREL) {
        out[0] |= 0x02;
    }
    out[1] = 0x02;
    out[2] = (id >> 8) & 0xff;
    out[3] = id & 0xff;
}

int out_mqtt_prot_disconnect(flb_sds_t *buf)
{
    unsigned char packet[2];

    packet[0] = FLB_MQTT_DISCONNECT << 4;
    packet[1] = 0x00;

    return append_bytes(buf, packet, sizeof(packet));
}

int out_mqtt_prot_utf8_valid(const char *str, size_t len, int allow_control)
{
    size_t i;
    size_t k;
    size_t extra;
    uint32_t cp;
    unsigned char c;
    const unsigned char *s;

    s = (const unsigned char *) str;

    i = 0;
    while (i < len) {
        c = s[i];

        if (c < 0x80) {
            /* U+0000 is never allowed in MQTT UTF-8 encoded strings */
            if (c == 0x00) {
                return FLB_FALSE;
            }
            if (!allow_control && (c < 0x20 || c == 0x7f)) {
                return FLB_FALSE;
            }
            i++;
            continue;
        }

        /* 0xc0, 0xc1 and bytes above 0xf4 are never valid lead bytes */
        if (c >= 0xc2 && c <= 0xdf) {
            extra = 1;
            cp = c & 0x1f;
        }
        else if (c >= 0xe0 && c <= 0xef) {
            extra = 2;
            cp = c & 0x0f;
        }
        else if (c >= 0xf0 && c <= 0xf4) {
            extra = 3;
            cp = c & 0x07;
        }
        else {
            return FLB_FALSE;
        }

        /* Truncated sequence */
        if (extra > len - i - 1) {
            return FLB_FALSE;
        }

        for (k = 1; k <= extra; k++) {
            if ((s[i + k] & 0xc0) != 0x80) {
                return FLB_FALSE;
            }
            cp = (cp << 6) | (s[i + k] & 0x3f);
        }

        /* Overlong forms, UTF-16 surrogates and values above U+10FFFF */
        if ((extra == 2 && cp < 0x800) ||
            (extra == 3 && (cp < 0x10000 || cp > 0x10ffff)) ||
            (cp >= 0xd800 && cp <= 0xdfff)) {
            return FLB_FALSE;
        }

        /*
         * C1 control characters and Unicode non-characters: U+FDD0..U+FDEF
         * and the last two code points of every plane (U+xFFFE, U+xFFFF)
         */
        if (!allow_control &&
            ((cp >= 0x80 && cp <= 0x9f) || (cp >= 0xfdd0 && cp <= 0xfdef) ||
             (cp & 0xfffe) == 0xfffe)) {
            return FLB_FALSE;
        }

        i += extra + 1;
    }

    return FLB_TRUE;
}

int out_mqtt_prot_topic_fragment_valid(const char *topic, size_t len)
{
    size_t i;

    if (len > FLB_MQTT_MAX_STRING_LENGTH) {
        return FLB_FALSE;
    }

    /* Wildcards are only valid in subscription filters */
    for (i = 0; i < len; i++) {
        if (topic[i] == '+' || topic[i] == '#') {
            return FLB_FALSE;
        }
    }

    return out_mqtt_prot_utf8_valid(topic, len, FLB_FALSE);
}

int out_mqtt_prot_topic_valid(const char *topic, size_t len)
{
    if (topic == NULL || len == 0) {
        return FLB_FALSE;
    }

    return out_mqtt_prot_topic_fragment_valid(topic, len);
}

const char *out_mqtt_prot_connack_str(int code)
{
    switch (code) {
    case FLB_MQTT_CONNACK_ACCEPTED:
        return "connection accepted";
    case FLB_MQTT_CONNACK_BAD_PROTOCOL:
        return "unacceptable protocol version";
    case FLB_MQTT_CONNACK_ID_REJECTED:
        return "client identifier rejected";
    case FLB_MQTT_CONNACK_SERVER_UNAVAILABLE:
        return "server unavailable";
    case FLB_MQTT_CONNACK_BAD_CREDENTIALS:
        return "bad user name or password";
    case FLB_MQTT_CONNACK_NOT_AUTHORIZED:
        return "not authorized";
    }

    return "unknown return code";
}
