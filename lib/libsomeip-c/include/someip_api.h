/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#ifndef LIB_SOMEIP_C_SOMEIP_API_H
#define LIB_SOMEIP_C_SOMEIP_API_H
#include "stdint.h"
#include "stddef.h"

#define SOMEIP_RET_SUCCESS 0
#define SOMEIP_RET_FAILURE (-1)
#define SOMEIP_RET_NO_EVENT_AVAILABLE (-2)
#define SOMEIP_RET_REQUEST_NOT_FOUND (-3)
#define SOMEIP_RET_SERVICE_NOT_AVAILABLE (-4)

/* Service available flags */
#define SOMEIP_SERVICE_NOT_AVAILABLE 0
#define SOMEIP_SERVICE_AVAILABLE 1

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Struct used to hold the data for a received SOME/IP event
 */
struct some_ip_event
{
    /* Service ID */
    uint16_t service_id;
    /* Service Instance ID */
    uint16_t instance_id;
    /* Event ID (also called Method ID in SOME/IP spec) */
    uint16_t event_id;
    /* Length of the Event payload */
    size_t event_len;
    /*
     * Event Payload contents.
     *
     * NOTE: Client must free the memory pointed to by event_data if it is not NULL
     *       after consuming the event.
     */
    uint8_t *event_data;
};

/*
 * Structure used to encapsulate the data to fully identify a RPC request
 */
struct some_ip_request_id
{
    /* Service ID */
    uint16_t service_id;

    /* Service Instance ID */
    uint16_t instance_id;

    /*
     * Request Identifier
     *
     * This is assigned by the someip-c library when a request has be sent successfully
     */
    uint32_t client_request_id;
};

/*
 * Structure used to encapsulate a SOME/IP Request
 */
struct some_ip_request
{

    /*
     * Data needed to identify the request
     *
     * Note: When sending the request, the client need not populate the client_request_id
     *       field in the request_id. The someip-c library will assign it when the RPC
     *       request is sent.
     */
    struct some_ip_request_id request_id;

    /* Method ID */
    uint16_t method_id;

    /* Length of the request payload */
    size_t payload_len;
    /* Request Payload contents */
    uint8_t *payload;
};

/*
 * Structure used to store a SOME/IP response
 */
struct some_ip_response
{
    /* Data needed to identify the request */
    struct some_ip_request_id request_id;
    /* Method ID */
    uint16_t method_id;
    /* Length of the response payload */
    size_t payload_len;
    /*
     * Response Payload contents
     *
     * NOTE: Client needs to free the payload memory after consuming the response
     */
    uint8_t *payload;
};

/*
 * Initializes use of the SOME/IP library for an application
 *
 * @param app_name C-string (null terminated) name of application using SOME/IP library
 * @param client_id Pointer to store the unique client identifier for this user of the library
 *
 * @return SOMEIP_RET_SUCCESS on success, SOMEIP_RET_FAILURE on failure
 */
int someip_initialize(const char *app_name, uint16_t * client_id);

/*
 * Shuts down the SOME/IP library for the specified application
 *
 * @param client_id Application client identifier
 *
 */
void someip_shutdown(uint16_t client_id);

/*
 * Function to access a received event notification
 *
 * This function can either be polled, or called after the notify_cb is called to indicate
 * a SOME/IP event has been received.
 *
 * @param client_id Application client identifier
 * @param event_ptr Pointer to a structure to store the event data. Must be non-NULL.
 *
 * @return SOMEIP_RET_SUCCESS if event_ptr is populated;
 *         SOMEIP_RET_NO_EVENT_AVAILABLE indicates there are no more events to retrieve
 *         SOMEIP_RET_FAILURE if there is an internal failure retrieving the event
 */
int someip_get_next_event(uint16_t client_id,
                          struct some_ip_event *event_ptr);

/*
 * Function to subscribe for a SOME/IP event
 *
 * @param client_id Application client identifier
 * @param service Service ID
 * @param instance Service instance ID
 * @param event Event ID
 * @param cookie Pointer that is passed back to client in the notify_cb
 * @param notify_cb Optional call back function to notify the client an event
 *                  notification has been received.
 *
 * @return SOMEIP_RET_SUCCESS on success, SOMEIP_RET_FAILURE on failure
 */
int someip_subscribe_event(uint16_t client_id, uint16_t service,
                           uint16_t instance, uint16_t event,
                           uint16_t event_groups[],
                           size_t num_event_groups, void *cookie,
                           void (*notify_cb)(void *));

/*
 * Function to request a SOME/IP service
 *
 * @param client_id Application client identifier
 * @param service Identifier
 * @param instance Service instance identifier
 * @param cookie Passed back to client in the avail_cb
 * @param avail_cb Callback to notify the client if the service is available or not.
 *                 Besides the cookie, the service, instance, and availability flag
 *                 (either SOMEIP_SERVICE_NOT_AVAILABLE or SOMEIP_SERVICE_AVAILABLE) is
 *                 supplied in the callback.
 */
int someip_request_service(uint16_t client_id, uint16_t service,
                           uint16_t instance, void *cookie,
                           void (*avail_cb)(void *, uint16_t, uint16_t,
                                            int));

/*
 * RPC Requests
 *
 * Each RPC request has an identifier assigned to it. However, the request identifier
 * is only unique within a transaction with a given {service, instance}.
 *
 * When initiating a request the client will provide the following:
 *    1. Service ID
 *    2. Instance ID
 *    3. Method ID of the RPC
 *    4. Payload that goes into the request
 *
 * If someip-c is able to successfully send the request, it will provide the request
 * identifier to the client.
 *
 * When a response is received for the request, someip-c will call the response_cb,
 * passing back the {service ID, instance ID, request ID} tuple to identify the request
 *
 */

/*
 * Send a SOME/IP request
 *
 * A request can only be sent to the service if it is available. A client can
 * track the availability of the service via the someip_request_service and
 * providing an avail_cb. Or it can re-attempt the RPC at a later time if
 * SOMEIP_RET_SERVICE_NOT_AVAILABLE is returned.
 *
 * @param client_id Application client identifier
 * @param parameters Request parameters. On success the request_id will be
 *                   populated with a unique identifier for this request.
 *                   The payload of the request can be safely de-allocated if
 *                   necessary after return from this method.
 * @param cookie Pointer that is passed back to client in the response_cb
 * @param response_cb Callback invoked when a response is received. The cookie and
 *                    request identifier are passed as arguments in the callback.
 *
 * @return SOMEIP_RET_SUCCESS if event_ptr is populated;
 *         SOMEIP_RET_SERVICE_NOT_AVAILABLE if the service is not available
 *         SOMEIP_RET_FAILURE if there is an internal failure
 */
int someip_send_request(uint16_t client_id,
                        struct some_ip_request *parameters, void *cookie,
                        void (*response_cb)(void *,
                                            const struct
                                            some_ip_request_id *));

/*
 * Retrieve a SOME/IP response
 *
 * @param client_id Application client identifier
 * @param response Pointer to struct that has the request information. The someip-c
 *                 library will populate the response payload in the structure.
 *
 * @return SOMEIP_RET_SUCCESS if event_ptr is populated;
 *         SOMEIP_RET_REQUEST_NOT_FOUND if a response for the request_id is not found
 *         SOMEIP_RET_FAILURE if there is an internal failure
 */
int someip_get_response(uint16_t client_id,
                        struct some_ip_response *response);

/*
 * Function to offer a SOME/IP event
 *
 * @param client_id Application client identifier
 * @param service Service ID
 * @param instance Service instance ID
 * @param event Event ID
 * @param event_groups Array of event groups this event belongs to
 * @param num_event_groups Number of event groups in the array
 * 
 * @return SOMEIP_RET_SUCCESS on success, SOMEIP_RET_FAILURE on failure
 */
int someip_offer_event(uint16_t client_id, uint16_t service,
                       uint16_t instance, uint16_t event,
                       uint16_t event_groups[], size_t num_event_groups);

/*
 * Function to offer a SOME/IP service
 *
 * @param client_id Application client identifier
 * @param service Service ID
 * @param instance Service instance ID
 * 
 * @return SOMEIP_RET_SUCCESS on success, SOMEIP_RET_FAILURE on failure
 */
int someip_offer_service(uint16_t client_id, uint16_t service,
                         uint16_t instance);

/*
 * Send/Publish an Event
 *
 * @param client_id Application client identifier
 * @param service      Identifier
 * @param instance     Service instance ID
 * @param event        Event identifier
 * @param payload      Pointer to bytes to send in event payload
 * @param payload_size Size of event payload
 *
 * @return SOMEIP_RET_SUCCESS If event is published successfully
 *         SOMEIP_RET_FAILURE if there is an internal failure
 */
int someip_send_event(uint16_t client_id, uint16_t service,
                      uint16_t instance, uint16_t event,
                      const void *payload, uint32_t payload_size);

/*
 * Registers a request handler for incoming requests for the specified
 * SOME/IP method.
 * 
 * @param client_id Application client identifier
 * @param service      Identifier
 * @param instance     Service instance ID
 * @param method        SOME/IP method
 * @param request_cb Callback function used to deliver request to client.
 *                   Note: The structure passed as an argument is owned
 *                   by the library. It does not need to be freed by the
 *                   client. The structure will be destroyed upon
 *                   return from the callback.
 * 
 */
int someip_register_request_handler(uint16_t client_id, uint16_t service,
                                    uint16_t instance, uint16_t method,
                                    void *cookie,
                                    void (*request_cb)(void*, struct
                                                        some_ip_request
                                                        *));

/*
 * Function to send an RPC response
 * 
 * @param client_id Application client identifier
 * @param request_id The unique SOME/IP identifier for the request that 
 *                   we are responding to
 * @param payload Pointer to the response payload
 * @param payload_size Size of the response payload
 */
int someip_send_response(uint16_t client_id, uint32_t request_id,
                         void *payload, uint32_t payload_size);

#ifdef __cplusplus
}
#endif

#endif
