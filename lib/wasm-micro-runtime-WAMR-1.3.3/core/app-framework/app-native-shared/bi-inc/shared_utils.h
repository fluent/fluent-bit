/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SHARED_UTILS_H_
#define _SHARED_UTILS_H_

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FMT_ATTR_CONTAINER 99
#define FMT_APP_RAW_BINARY 98

/* the request structure */
typedef struct request {
    // message id
    uint32 mid;

    // url of the request
    char *url;

    // action of the request, can be PUT/GET/POST/DELETE
    int action;

    // payload format, currently only support attr_container_t type
    int fmt;

    // payload of the request, currently only support attr_container_t type
    void *payload;

    // length in bytes of the payload
    int payload_len;

    // sender of the request
    unsigned long sender;
} request_t;

/* the response structure */
typedef struct response {
    // message id
    uint32 mid;

    // status of the response
    int status;

    // payload format
    int fmt;

    // payload of the response,
    void *payload;

    // length in bytes of the payload
    int payload_len;

    // receiver of the response
    unsigned long reciever;
} response_t;

int
check_url_start(const char *url, int url_len, const char *leading_str);

bool
match_url(char *pattern, char *matched);

char *
find_key_value(char *buffer, int buffer_len, char *key, char *value,
               int value_len, char delimiter);

request_t *
clone_request(request_t *request);

void
request_cleaner(request_t *request);

response_t *
clone_response(response_t *response);

void
response_cleaner(response_t *response);

/**
 * @brief Set fields of response.
 *
 * @param response pointer of the response to be set
 * @param status status of response
 * @param fmt format of the response payload
 * @param payload payload of the response
 * @param payload_len length in bytes of the response payload
 *
 * @return pointer to the response
 *
 * @warning the response pointer MUST NOT be NULL
 */
response_t *
set_response(response_t *response, int status, int fmt, const char *payload,
             int payload_len);

/**
 * @brief Make a response for a request.
 *
 * @param request pointer of the request
 * @param response pointer of the response to be made
 *
 * @return pointer to the response
 *
 * @warning the request and response pointers MUST NOT be NULL
 */
response_t *
make_response_for_request(request_t *request, response_t *response);

/**
 * @brief Initialize a request.
 *
 * @param request pointer of the request to be initialized
 * @param url url of the request
 * @param action action of the request
 * @param fmt format of the request payload
 * @param payload payload of the request
 * @param payload_len length in bytes of the request payload
 *
 * @return pointer to the request
 *
 * @warning the request pointer MUST NOT be NULL
 */
request_t *
init_request(request_t *request, char *url, int action, int fmt, void *payload,
             int payload_len);

char *
pack_request(request_t *request, int *size);

request_t *
unpack_request(char *packet, int size, request_t *request);

char *
pack_response(response_t *response, int *size);

response_t *
unpack_response(char *packet, int size, response_t *response);

void
free_req_resp_packet(char *packet);

char *
wa_strdup(const char *str);

#ifdef __cplusplus
}
#endif

#endif /* end of _SHARED_UTILS_H_ */
