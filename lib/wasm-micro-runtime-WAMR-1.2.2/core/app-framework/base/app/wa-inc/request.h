/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AEE_REQUEST_H_
#define _AEE_REQUEST_H_

#include "bi-inc/shared_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CoAP request method codes */
typedef enum {
    COAP_GET = 1,
    COAP_POST,
    COAP_PUT,
    COAP_DELETE,
    COAP_EVENT = (COAP_DELETE + 2)
} coap_method_t;

/* CoAP response codes */
typedef enum {
    NO_ERROR = 0,

    CREATED_2_01 = 65,  /* CREATED */
    DELETED_2_02 = 66,  /* DELETED */
    VALID_2_03 = 67,    /* NOT_MODIFIED */
    CHANGED_2_04 = 68,  /* CHANGED */
    CONTENT_2_05 = 69,  /* OK */
    CONTINUE_2_31 = 95, /* CONTINUE */

    BAD_REQUEST_4_00 = 128,              /* BAD_REQUEST */
    UNAUTHORIZED_4_01 = 129,             /* UNAUTHORIZED */
    BAD_OPTION_4_02 = 130,               /* BAD_OPTION */
    FORBIDDEN_4_03 = 131,                /* FORBIDDEN */
    NOT_FOUND_4_04 = 132,                /* NOT_FOUND */
    METHOD_NOT_ALLOWED_4_05 = 133,       /* METHOD_NOT_ALLOWED */
    NOT_ACCEPTABLE_4_06 = 134,           /* NOT_ACCEPTABLE */
    PRECONDITION_FAILED_4_12 = 140,      /* BAD_REQUEST */
    REQUEST_ENTITY_TOO_LARGE_4_13 = 141, /* REQUEST_ENTITY_TOO_LARGE */
    UNSUPPORTED_MEDIA_TYPE_4_15 = 143,   /* UNSUPPORTED_MEDIA_TYPE */

    INTERNAL_SERVER_ERROR_5_00 = 160,  /* INTERNAL_SERVER_ERROR */
    NOT_IMPLEMENTED_5_01 = 161,        /* NOT_IMPLEMENTED */
    BAD_GATEWAY_5_02 = 162,            /* BAD_GATEWAY */
    SERVICE_UNAVAILABLE_5_03 = 163,    /* SERVICE_UNAVAILABLE */
    GATEWAY_TIMEOUT_5_04 = 164,        /* GATEWAY_TIMEOUT */
    PROXYING_NOT_SUPPORTED_5_05 = 165, /* PROXYING_NOT_SUPPORTED */

    /* Erbium errors */
    MEMORY_ALLOCATION_ERROR = 192,
    PACKET_SERIALIZATION_ERROR,

    /* Erbium hooks */
    MANUAL_RESPONSE,
    PING_RESPONSE
} coap_status_t;

/**
 * @typedef request_handler_f
 *
 * @brief Define the signature of callback function for API
 * api_register_resource_handler() to handle request or for API
 * api_subscribe_event() to handle event.
 *
 * @param request pointer of the request to be handled
 *
 * @see api_register_resource_handler
 * @see api_subscribe_event
 */
typedef void (*request_handler_f)(request_t *request);

/**
 * @typedef response_handler_f
 *
 * @brief Define the signature of callback function for API
 * api_send_request() to handle response of a request.
 *
 * @param response pointer of the response to be handled
 * @param user_data user data associated with the request which is set when
 * calling api_send_request().
 *
 * @see api_send_request
 */
typedef void (*response_handler_f)(response_t *response, void *user_data);

/*
 *****************
 * Request APIs
 *****************
 */

/**
 * @brief Register resource.
 *
 * @param url url of the resource
 * @param handler callback function to handle the request to the resource
 *
 * @return true if success, false otherwise
 */
bool
api_register_resource_handler(const char *url, request_handler_f handler);

/**
 * @brief Send request asynchronously.
 *
 * @param request pointer of the request to be sent
 * @param response_handler callback function to handle the response
 * @param user_data user data
 */
void
api_send_request(request_t *request, response_handler_f response_handler,
                 void *user_data);

/**
 * @brief Send response.
 *
 * @param response pointer of the response to be sent
 *
 * @par
 * @code
 * void res1_handler(request_t *request)
 * {
 *     response_t response[1];
 *     make_response_for_request(request, response);
 *     set_response(response, DELETED_2_02, 0, NULL, 0);
 *     api_response_send(response);
 * }
 * @endcode
 */
void
api_response_send(response_t *response);

/*
 *****************
 * Event APIs
 *****************
 */

/**
 * @brief Publish an event.
 *
 * @param url url of the event
 * @param fmt format of the event payload
 * @param payload payload of the event
 * @param payload_len length in bytes of the event payload
 *
 * @return true if success, false otherwise
 */
bool
api_publish_event(const char *url, int fmt, void *payload, int payload_len);

/**
 * @brief Subscribe an event.
 *
 * @param url url of the event
 * @param handler callback function to handle the event.
 *
 * @return true if success, false otherwise
 */
bool
api_subscribe_event(const char *url, request_handler_f handler);

#ifdef __cplusplus
}
#endif

#endif
