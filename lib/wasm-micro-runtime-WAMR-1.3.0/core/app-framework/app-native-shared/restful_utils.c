/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "bi-inc/shared_utils.h"

/* Serialization of request and response message
 *
 * Choices:
 * We considered a few options:
 * 1. coap
 * 2. flatbuffer
 * 3. cbor
 * 4. attr-containers of our own
 * 5. customized serialization for request/response
 *
 * Now we choose the #5 mainly because we need to quickly get the URL for
 * dispatching and sometimes we want to change the URL in the original packet.
 * the request format: fixed part: version: (1 byte), code (1 byte), fmt(2
 * byte), mid (4 bytes), sender_id(4 bytes),  url_len(2 bytes),
 * payload_len(4bytes) dynamic part: url (bytes in url_len), payload
 *
 * response format:
 * fixed part: (1 byte), code (1 byte), fmt(2 byte), mid (4 bytes), sender_id(4
 * bytes),   payload_len(4bytes) dynamic part: payload
 */
#define REQUES_PACKET_VER 1
#define REQUEST_PACKET_FIX_PART_LEN 18
#define REQUEST_PACKET_URL_OFFSET REQUEST_PACKET_FIX_PART_LEN
#define REQUEST_PACKET_URL_LEN \
    *((uint16 *)((char *)buffer + 12)) /* to ensure little endian */
#define REQUEST_PACKET_PAYLOAD_LEN \
    *((uint32 *)((char *)buffer + 14)) /* to ensure little endian */
#define REQUEST_PACKET_URL(buffer) ((char *)buffer + REQUEST_PACKET_URL_OFFSET)
#define REQUEST_PACKET_PAYLOAD(buffer)          \
    ((char *)buffer + REQUEST_PACKET_URL_OFFSET \
     + REQUEST_PACKET_URL_LEN(buffer))

#define RESPONSE_PACKET_FIX_PART_LEN 16

char *
pack_request(request_t *request, int *size)
{
    int url_len = strlen(request->url) + 1;
    int len = REQUEST_PACKET_FIX_PART_LEN + url_len + request->payload_len;
    uint16 u16;
    uint32 u32;
    char *packet;

    if ((packet = (char *)WA_MALLOC(len)) == NULL)
        return NULL;

    /* TODO: ensure little endian for words and dwords */
    *packet = REQUES_PACKET_VER;
    *((uint8 *)(packet + 1)) = request->action;

    u16 = htons(request->fmt);
    memcpy(packet + 2, &u16, 2);

    u32 = htonl(request->mid);
    memcpy(packet + 4, &u32, 4);

    u32 = htonl(request->sender);
    memcpy(packet + 8, &u32, 4);

    u16 = htons(url_len);
    memcpy(packet + 12, &u16, 2);

    u32 = htonl(request->payload_len);
    memcpy(packet + 14, &u32, 4);

    strcpy(packet + REQUEST_PACKET_URL_OFFSET, request->url);
    memcpy(packet + REQUEST_PACKET_URL_OFFSET + url_len, request->payload,
           request->payload_len);

    *size = len;
    return packet;
}

void
free_req_resp_packet(char *packet)
{
    WA_FREE(packet);
}

request_t *
unpack_request(char *packet, int size, request_t *request)
{
    uint16 url_len, u16;
    uint32 payload_len, u32;

    if (*packet != REQUES_PACKET_VER) {
        return NULL;
    }
    if (size < REQUEST_PACKET_FIX_PART_LEN) {
        return NULL;
    }

    memcpy(&u16, packet + 12, 2);
    url_len = ntohs(u16);

    memcpy(&u32, packet + 14, 4);
    payload_len = ntohl(u32);

    if (size != (REQUEST_PACKET_FIX_PART_LEN + url_len + payload_len)) {
        return NULL;
    }

    if (*(packet + REQUEST_PACKET_FIX_PART_LEN + url_len - 1) != 0) {
        return NULL;
    }

    request->action = *((uint8 *)(packet + 1));

    memcpy(&u16, packet + 2, 2);
    request->fmt = ntohs(u16);

    memcpy(&u32, packet + 4, 4);
    request->mid = ntohl(u32);

    memcpy(&u32, packet + 8, 4);
    request->sender = ntohl(u32);

    request->payload_len = payload_len;
    request->url = REQUEST_PACKET_URL(packet);

    if (payload_len > 0)
        request->payload = packet + REQUEST_PACKET_URL_OFFSET + url_len;
    else
        request->payload = NULL;

    return request;
}

char *
pack_response(response_t *response, int *size)
{
    int len = RESPONSE_PACKET_FIX_PART_LEN + response->payload_len;
    uint16 u16;
    uint32 u32;
    char *packet;

    if ((packet = (char *)WA_MALLOC(len)) == NULL)
        return NULL;

    /* TODO: ensure little endian for words and dwords */
    *packet = REQUES_PACKET_VER;
    *((uint8 *)(packet + 1)) = response->status;

    u16 = htons(response->fmt);
    memcpy(packet + 2, &u16, 2);

    u32 = htonl(response->mid);
    memcpy(packet + 4, &u32, 4);

    u32 = htonl(response->reciever);
    memcpy(packet + 8, &u32, 4);

    u32 = htonl(response->payload_len);
    memcpy(packet + 12, &u32, 4);

    memcpy(packet + RESPONSE_PACKET_FIX_PART_LEN, response->payload,
           response->payload_len);

    *size = len;
    return packet;
}

response_t *
unpack_response(char *packet, int size, response_t *response)
{
    uint16 u16;
    uint32 payload_len, u32;

    if (*packet != REQUES_PACKET_VER)
        return NULL;

    if (size < RESPONSE_PACKET_FIX_PART_LEN)
        return NULL;

    memcpy(&u32, packet + 12, 4);
    payload_len = ntohl(u32);
    if (size != (RESPONSE_PACKET_FIX_PART_LEN + payload_len))
        return NULL;

    response->status = *((uint8 *)(packet + 1));

    memcpy(&u16, packet + 2, 2);
    response->fmt = ntohs(u16);

    memcpy(&u32, packet + 4, 4);
    response->mid = ntohl(u32);

    memcpy(&u32, packet + 8, 4);
    response->reciever = ntohl(u32);

    response->payload_len = payload_len;
    if (payload_len > 0)
        response->payload = packet + RESPONSE_PACKET_FIX_PART_LEN;
    else
        response->payload = NULL;

    return response;
}

request_t *
clone_request(request_t *request)
{
    /* deep clone */
    request_t *req = (request_t *)WA_MALLOC(sizeof(request_t));
    if (req == NULL)
        return NULL;

    memset(req, 0, sizeof(*req));
    req->action = request->action;
    req->fmt = request->fmt;
    req->url = wa_strdup(request->url);
    req->sender = request->sender;
    req->mid = request->mid;

    if (req->url == NULL)
        goto fail;

    req->payload_len = request->payload_len;

    if (request->payload_len) {
        req->payload = (char *)WA_MALLOC(request->payload_len);
        if (!req->payload)
            goto fail;
        memcpy(req->payload, request->payload, request->payload_len);
    }
    else {
        /* when payload_len is 0, the payload may be used for
           carrying some handle or integer */
        req->payload = request->payload;
    }

    return req;

fail:
    request_cleaner(req);
    return NULL;
}

void
request_cleaner(request_t *request)
{
    if (request->url != NULL)
        WA_FREE(request->url);
    if (request->payload != NULL && request->payload_len > 0)
        WA_FREE(request->payload);

    WA_FREE(request);
}

void
response_cleaner(response_t *response)
{
    if (response->payload != NULL && response->payload_len > 0)
        WA_FREE(response->payload);

    WA_FREE(response);
}

response_t *
clone_response(response_t *response)
{
    response_t *clone = (response_t *)WA_MALLOC(sizeof(response_t));

    if (clone == NULL)
        return NULL;

    memset(clone, 0, sizeof(*clone));
    clone->fmt = response->fmt;
    clone->mid = response->mid;
    clone->status = response->status;
    clone->reciever = response->reciever;
    clone->payload_len = response->payload_len;
    if (clone->payload_len) {
        clone->payload = (char *)WA_MALLOC(response->payload_len);
        if (!clone->payload)
            goto fail;
        memcpy(clone->payload, response->payload, response->payload_len);
    }
    else {
        /* when payload_len is 0, the payload may be used for
           carrying some handle or integer */
        clone->payload = response->payload;
    }
    return clone;

fail:
    response_cleaner(clone);
    return NULL;
}

response_t *
set_response(response_t *response, int status, int fmt, const char *payload,
             int payload_len)
{
    response->payload = (void *)payload;
    response->payload_len = payload_len;
    response->status = status;
    response->fmt = fmt;
    return response;
}

response_t *
make_response_for_request(request_t *request, response_t *response)
{
    response->mid = request->mid;
    response->reciever = request->sender;

    return response;
}

static unsigned int mid = 0;

request_t *
init_request(request_t *request, char *url, int action, int fmt, void *payload,
             int payload_len)
{
    request->url = url;
    request->action = action;
    request->fmt = fmt;
    request->payload = payload;
    request->payload_len = payload_len;
    request->mid = ++mid;

    return request;
}

/*
 check if the "url" is starting with "leading_str"
 return: 0 - not match; >0 - the offset of matched url, include any "/" at the
 end notes:
 1. it ensures the leading_str "/abc" can pass "/abc/cde" and "/abc/, but fail
 "/ab" and "/abcd". leading_str "/abc/" can pass "/abc"
 2. it omit the '/' at the first char
 3. it ensure the leading_str "/abc" can pass "/abc?cde
 */

int
check_url_start(const char *url, int url_len, const char *leading_str)
{
    int offset = 0;
    if (*leading_str == '/')
        leading_str++;
    if (url_len > 0 && *url == '/') {
        url_len--;
        url++;
        offset++;
    }

    int len = strlen(leading_str);
    if (len == 0)
        return 0;

    /* ensure leading_str not end with "/" */
    if (leading_str[len - 1] == '/') {
        len--;
        if (len == 0)
            return 0;
    }

    /* equal length */
    if (url_len == len) {
        if (memcmp(url, leading_str, url_len) == 0) {
            return (offset + len);
        }
        else {
            return 0;
        }
    }

    if (url_len < len)
        return 0;
    else if (memcmp(url, leading_str, len) != 0)
        return 0;
    else if (url[len] != '/' && url[len] != '?')
        return 0;
    else
        return (offset + len + 1);
}

// * @pattern:
// * sample 1: /abcd, match /abcd only
// * sample 2: /abcd/ match match "/abcd" and "/abcd/*"
// * sample 3: /abcd*, match any url started with "/abcd"
// * sample 4: /abcd/*, exclude "/abcd"

bool
match_url(char *pattern, char *matched)
{
    if (*pattern == '/')
        pattern++;
    if (*matched == '/')
        matched++;

    int matched_len = strlen(matched);
    if (matched_len == 0)
        return false;

    if (matched[matched_len - 1] == '/') {
        matched_len--;
        if (matched_len == 0)
            return false;
    }

    int len = strlen(pattern);
    if (len == 0)
        return false;

    if (pattern[len - 1] == '/') {
        len--;
        if (strncmp(pattern, matched, len) != 0)
            return false;

        if (len == matched_len)
            return true;

        if (matched_len > len && matched[len] == '/')
            return true;

        return false;
    }
    else if (pattern[len - 1] == '*') {
        if (pattern[len - 2] == '/') {
            if (strncmp(pattern, matched, len - 1) == 0)
                return true;
            else
                return false;
        }
        else {
            return (strncmp(pattern, matched, len - 1) == 0);
        }
    }
    else {
        return (strcmp(pattern, matched) == 0);
    }
}

/*
 * get the value of the key from following format buffer:
 *  key1=value1;key2=value2;key3=value3
 */
char *
find_key_value(char *buffer, int buffer_len, char *key, char *value,
               int value_len, char delimiter)
{
    char *p = buffer;
    int remaining = buffer_len;
    int key_len = strlen(key);

    while (*p != 0 && remaining > 0) {
        while (*p == ' ' || *p == delimiter) {
            p++;
            remaining--;
        }

        if (remaining <= key_len)
            return NULL;

        /* find the key */
        if (0 == strncmp(p, key, key_len) && p[key_len] == '=') {
            p += (key_len + 1);
            remaining -= (key_len + 1);
            char *v = value;
            memset(value, 0, value_len);
            value_len--; /* ensure last char is 0 */
            while (*p != delimiter && remaining > 0 && value_len > 0) {
                *v++ = *p++;
                remaining--;
                value_len--;
            }
            return value;
        }

        /* goto next key */
        while (*p != delimiter && remaining > 0) {
            p++;
            remaining--;
        }
    }

    return NULL;
}
