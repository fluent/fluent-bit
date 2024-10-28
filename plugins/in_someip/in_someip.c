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
#include "in_someip.h"

#include "in_someip_config.h"

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

/* Messages sent over the notify pipe */
#define IN_SOMEIP_EVENT_RECEIVED 1

/* Messages sent over the RPC pipe */
#define IN_SOMEIP_SERVICE_AVAILABLE 1
#define IN_SOMEIP_RESPONSE_RECEIVED 2

/* Data sent over the RPC pipe */

/* Structure sent after SERVICE_AVAILABLE */
struct in_someip_service_available
{
    uint16_t service_id;
    uint16_t instance_id;
    int available_flag;
};

/* For RESPONSE_RECEIVED the some_ip_request_id is sent over the pipe */

/*
 * Base64 encode a binary buffer
 *
 * @param ctx Plugin context
 * @param binary_len Size of the binary buffer to encode
 * @param binary_data Pointer to binary data to encode
 * @param encoded_buffer Pointer to buffer to hold the base64 encoded data.
 *                       Note: Caller should call flb_sds_destroy on the encoded
 *                       buffer after using it.
 */
static void
encode_bytes(struct flb_someip *ctx, size_t binary_len,
             uint8_t *binary_data, flb_sds_t *encoded_buffer)
{
    size_t encoded_buffer_size = (binary_len * 4);
    size_t encoded_len;

    if (binary_data != NULL && binary_len > 0) {
        *encoded_buffer = flb_sds_create_size(encoded_buffer_size);
        if (0
            != flb_base64_encode((unsigned char *) (*encoded_buffer),
                                 encoded_buffer_size, &encoded_len,
                                 (unsigned char *) binary_data, binary_len)) {
            flb_plg_warn(ctx->ins, "Failed to encode binary data");
        }
        else {
            flb_plg_debug(ctx->ins, "Encoded event: %s", *encoded_buffer);
        }
    }
    else {
        flb_plg_debug(ctx->ins, "No data to encode");
    }
}

/*
 * Callback function when a SOME/IP event is received
 *
 * @param data The flb_someip context pointer
 *
 */
static void in_someip_event_notification(void *data)
{
    struct flb_someip *ctx;
    ssize_t written;
    uint8_t command;

    ctx = data;
    if (NULL != ctx) {
        command = IN_SOMEIP_EVENT_RECEIVED;
        written =
            flb_pipe_write_all(ctx->notify_pipe_fd[1], &command,
                               sizeof(command));
        if (written < 0) {
            flb_errno();
        }
    }
}

/*
 * Callback function when a SOME/IP Service availability is updated
 *
 * @param data The flb_someip context pointer
 * @param service The service identifier
 * @param instance The service instance
 * @param available The availability indication
 *
 */
static void
in_someip_avail_handler(void *data, uint16_t service,
                        uint16_t instance, int available)
{
    struct flb_someip *ctx;
    ssize_t written;
    uint8_t command;
    struct in_someip_service_available avail_indication;

    ctx = data;
    if (NULL != ctx) {
        command = IN_SOMEIP_SERVICE_AVAILABLE;
        written =
            flb_pipe_write_all(ctx->rpc_pipe_fd[1], &command,
                               sizeof(command));
        if (written < 0) {
            flb_errno();
        }
        avail_indication.service_id = service;
        avail_indication.instance_id = instance;
        avail_indication.available_flag = available;
        written = flb_pipe_write_all(ctx->rpc_pipe_fd[1], &avail_indication,
                                     sizeof(avail_indication));
        if (written < 0) {
            flb_errno();
        }
    }
}

/*
 * Callback function when a SOME/IP RPC response is received
 *
 * @param data The flb_someip context pointer
 * @param request_id Pointer to the structure identifying the request
 *
 */
static void
in_someip_response_callback(void *data,
                            const struct some_ip_request_id *request_id)
{
    struct flb_someip *ctx;
    ssize_t written;
    uint8_t command;

    ctx = data;
    if (NULL != ctx && request_id != NULL) {
        flb_plg_trace(ctx->ins, "Response received, client ID = %d",
                      request_id->client_request_id);
        command = IN_SOMEIP_RESPONSE_RECEIVED;
        written =
            flb_pipe_write_all(ctx->rpc_pipe_fd[1], &command,
                               sizeof(command));
        if (written < 0) {
            flb_errno();
        }
        written = flb_pipe_write_all(ctx->rpc_pipe_fd[1], request_id,
                                     sizeof(struct some_ip_request_id));
        if (written < 0) {
            flb_errno();
        }
    }
}

/*
 * Function to subscribe to the configured SOME/IP events
 *
 * @param ctx The plugin context
 *
 * @return int 0 on success, -1 on failure
 */
static void in_someip_subscribe_for_someip_events(struct flb_someip *ctx)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct in_someip_event_identifier *an_event;

    cfl_list_foreach_safe(head, tmp, &(ctx->someip_events)) {
        an_event =
            cfl_list_entry(head, struct in_someip_event_identifier, _head);
        if (someip_subscribe_event(ctx->someip_client_id, 
                                   an_event->service_id,
                                   an_event->instance_id, 
                                   an_event->event_id,
                                   an_event->event_groups, 
                                   an_event->number_of_event_groups, 
                                   ctx,
                                   in_someip_event_notification) != SOMEIP_RET_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "Failed to subscribe for service = %d, instance = %d, event %d",
                          an_event->service_id, an_event->instance_id,
                          an_event->event_id);
        }
        else {
            flb_plg_debug(ctx->ins,
                          "Subscribed for service = %d, instance = %d, event %d",
                          an_event->service_id, an_event->instance_id,
                          an_event->event_id);
        }
    }
}

/*
 * Function to request the services we need for performing RPC
 *
 * @param ctx The plugin context
 *
 * @return int 0 on success, -1 on failure
 */
static void in_someip_request_services(struct flb_someip *ctx)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct in_someip_rpc *an_rpc;

    cfl_list_foreach_safe(head, tmp, &(ctx->someip_pending_rpc)) {
        an_rpc = cfl_list_entry(head, struct in_someip_rpc, _head);
        if (someip_request_service(ctx->someip_client_id, 
                                   an_rpc->service_id, 
                                   an_rpc->instance_id,
                                   ctx, 
                                   in_someip_avail_handler) != SOMEIP_RET_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "Failed to request service = %d, instance = %d",
                          an_rpc->service_id, an_rpc->instance_id);
        }
        else {
            flb_plg_debug(ctx->ins, "Requested service = %d, instance = %d",
                          an_rpc->service_id, an_rpc->instance_id);
        }
    }
}

/*
 * Function to generate a record when a SOME/IP event is received
 *
 * @param ctx The plugin context
 * @param event The SOME/IP event data
 *
 * @return 0 on success, -1 on an error
 */
static int
in_someip_generate_someip_event_record(struct flb_someip *ctx,
                                       struct some_ip_event *event)
{
    struct flb_log_event_encoder *log_encoder = ctx->log_encoder;
    int encoder_result;
    int ret;
    flb_sds_t base64_buffer;

    flb_plg_debug(ctx->ins,
                  "Received event {%d, %d} with payload of %zu bytes",
                  event->service_id, event->event_id, event->event_len);

    encoder_result = flb_log_event_encoder_begin_record(log_encoder);

    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_set_current_timestamp(log_encoder);
    }
    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("record type"),
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("event"))}
    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("service"),
                                                         FLB_LOG_EVENT_UINT16_VALUE
                                                         (event->service_id))}
    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("instance"),
                                                         FLB_LOG_EVENT_UINT16_VALUE
                                                         (event->instance_id))}

    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("event"),
                                                         FLB_LOG_EVENT_UINT16_VALUE
                                                         (event->event_id))}

    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        if (event->event_len > 0) {
            encode_bytes(ctx, event->event_len, event->event_data,
                         &base64_buffer);
            encoder_result =
                flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("payload"),
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         (base64_buffer))
                flb_sds_destroy(base64_buffer);
        }
        else {
            encoder_result =
                flb_log_event_encoder_append_body_values(log_encoder,
                                                             FLB_LOG_EVENT_CSTRING_VALUE
                                                             ("payload"),
                                                             FLB_LOG_EVENT_CSTRING_VALUE
                                                             (""))
        }
    }
    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result = flb_log_event_encoder_commit_record(log_encoder);
    }

    if (encoder_result != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
    }

    flb_plg_trace(ctx->ins, "Event encoding result = %d", encoder_result);
    if (event->event_data != NULL) {
        free(event->event_data);
        event->event_data = NULL;
    }

    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        if (ctx->log_encoder->output_length > 0) {
            flb_input_log_append(ctx->ins, NULL, 0,
                                 ctx->log_encoder->output_buffer,
                                 ctx->log_encoder->output_length);
        }
        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "Error encoding record : %d", encoder_result);
        ret = -1;
    }

    flb_log_event_encoder_reset(ctx->log_encoder);
    return ret;
}

/*
 * Function to generate a record when a SOME/IP response is received
 *
 * @param ctx The plugin context
 * @param response The SOME/IP response data
 *
 * @return 0 on success, -1 on an error
 */
static int
in_someip_generate_someip_response_record(struct flb_someip *ctx,
                                          struct some_ip_response *response)
{
    struct flb_log_event_encoder *log_encoder = ctx->log_encoder;
    struct some_ip_request_id *request_ptr = &response->request_id;
    int ret;
    int encoder_result;
    flb_sds_t base64_buffer;

    flb_plg_debug(ctx->ins,
                  "Received response for {%d, %d, %d}, length = %ld",
                  response->request_id.service_id,
                  response->request_id.instance_id, response->method_id,
                  response->payload_len);

    encoder_result = flb_log_event_encoder_begin_record(log_encoder);

    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_set_current_timestamp(log_encoder);
    }
    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("record type"),
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("response"))}
    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("service"),
                                                         FLB_LOG_EVENT_UINT16_VALUE
                                                         (request_ptr->service_id))}
    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("instance"),
                                                         FLB_LOG_EVENT_UINT16_VALUE
                                                         (request_ptr->instance_id))}

    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result =
            flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                         ("method"),
                                                         FLB_LOG_EVENT_UINT16_VALUE
                                                         (response->method_id))}

    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        if (response->payload_len > 0 && response->payload != NULL) {
            encode_bytes(ctx, response->payload_len, response->payload,
                     &base64_buffer);
            encoder_result =
            flb_log_event_encoder_append_body_values(log_encoder,
                                                     FLB_LOG_EVENT_CSTRING_VALUE
                                                     ("payload"),
                                                     FLB_LOG_EVENT_CSTRING_VALUE
                                                     (base64_buffer))
            flb_sds_destroy(base64_buffer);
        }
        else {
            encoder_result =
                flb_log_event_encoder_append_body_values(log_encoder,
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                            ("payload"),
                                                         FLB_LOG_EVENT_CSTRING_VALUE
                                                            (""))
        }
    }
    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        encoder_result = flb_log_event_encoder_commit_record(log_encoder);
    }

    if (encoder_result != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
    }

    flb_plg_trace(ctx->ins, "Response encoding result = %d", encoder_result);
    if (response->payload != NULL) {
        free(response->payload);
        response->payload = NULL;
    }
    if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        if (ctx->log_encoder->output_length > 0) {
            flb_input_log_append(ctx->ins, NULL, 0,
                                 ctx->log_encoder->output_buffer,
                                 ctx->log_encoder->output_length);
        }
        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "Error encoding record : %d", encoder_result);
        ret = -1;
    }

    flb_log_event_encoder_reset(ctx->log_encoder);
    return ret;
}

/*
 * Function used when the RPC collector gets an event to indicate that a service
 * has become available (or unavailable)
 */
static void in_someip_handle_avail_event(struct flb_someip *ctx)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    ssize_t bytes_read;
    struct in_someip_service_available serv_available;
    struct in_someip_rpc *an_rpc;
    struct some_ip_request request;
    struct in_someip_response *an_response;

    // Pull the service availability off the pipe
    bytes_read = flb_pipe_read_all(ctx->rpc_pipe_fd[0], &serv_available,
                                   sizeof(serv_available));
    if (bytes_read <= 0) {
        flb_errno();
        return;
    }

    flb_plg_debug(ctx->ins, "Service = %d, Instance = %d, available = %d",
                  serv_available.service_id, serv_available.instance_id,
                  serv_available.available_flag);

    // If the service is available, and we have pending RPC, send the request
    if (SOMEIP_SERVICE_AVAILABLE == serv_available.available_flag) {
        cfl_list_foreach_safe(head, tmp, &ctx->someip_pending_rpc) {
            an_rpc = cfl_list_entry(head, struct in_someip_rpc, _head);
            if (an_rpc->service_id == serv_available.service_id
                && an_rpc->instance_id == serv_available.instance_id) {
                request.request_id.service_id = an_rpc->service_id;
                request.request_id.instance_id = an_rpc->instance_id;

                // Will be overwritten on success
                request.request_id.client_request_id = 0;
                request.method_id = an_rpc->method_id;
                request.payload_len = an_rpc->payload_len;
                request.payload = an_rpc->payload;
                if (SOMEIP_RET_SUCCESS
                    == someip_send_request(ctx->someip_client_id, &request,
                                           ctx, in_someip_response_callback))
                {
                    flb_plg_debug(ctx->ins, "Sent request method = %d",
                                  an_rpc->method_id);
                    an_response = flb_malloc(sizeof(struct in_someip_response));
                    if (NULL == an_response) {
                        flb_errno();
                        return;
                    }
                    an_response->response.request_id = request.request_id;
                    an_response->response.method_id = request.method_id;
                    an_response->response.payload = NULL;
                    an_response->response.payload_len = 0;
                    cfl_list_add(&an_response->_head,
                                 &ctx->someip_waiting_response);
                }
                else {
                    flb_plg_error(ctx->ins,
                                  "Failed to send request for method %d",
                                  an_rpc->method_id);
                }
                if (an_rpc->payload != NULL) {
                    flb_free(an_rpc->payload);
                }
                cfl_list_del(&an_rpc->_head);
                flb_free(an_rpc);
            }
        }
    }
}

/*
 * Function use to handle a response for an RPC
 */
static void in_someip_handle_response_event(struct flb_someip *ctx)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    ssize_t bytes_read;
    struct some_ip_request_id received_request_id;
    struct some_ip_request_id *pending_request_id;
    struct in_someip_response *an_response;
    int ret;

    // Pull the request id off of the pipe
    bytes_read = flb_pipe_read_all(ctx->rpc_pipe_fd[0], &received_request_id,
                                   sizeof(received_request_id));
    if (bytes_read <= 0) {
        flb_errno();
        return;
    }

    flb_plg_debug(ctx->ins,
                  "Response received for Service = %d, Instance = %d, Client Request = "
                  "0x%08x",
                  received_request_id.service_id,
                  received_request_id.instance_id,
                  received_request_id.client_request_id);

    /* Find the entry that matches this response */
    cfl_list_foreach_safe(head, tmp, &ctx->someip_waiting_response) {
        an_response = cfl_list_entry(head, struct in_someip_response, _head);
        pending_request_id = &(an_response->response.request_id);
        flb_plg_trace(ctx->ins, "Checking waiting response {%d, %d, 0x%08x}",
                      pending_request_id->service_id,
                      pending_request_id->instance_id,
                      pending_request_id->client_request_id);
        if (pending_request_id->service_id == received_request_id.service_id
            && pending_request_id->instance_id ==
            received_request_id.instance_id
            && pending_request_id->client_request_id ==
            received_request_id.client_request_id) {

            // Retrieve the response
            ret = someip_get_response(ctx->someip_client_id,
                                      &an_response->response);
            if (ret != SOMEIP_RET_SUCCESS) {
                flb_plg_error(ctx->ins,
                              "Failed to retrieve response for service = %d, instance "
                              "%d, client_request = %d, error = %d",
                              received_request_id.service_id,
                              received_request_id.instance_id,
                              received_request_id.client_request_id, ret);
            }
            else {
                in_someip_generate_someip_response_record(ctx,
                                                          &an_response->response);
            }
            cfl_list_del(&an_response->_head);
            flb_free(an_response);
            return;
        }
    }
    flb_plg_warn(ctx->ins, "Did not find request {%d, %d, 0x%08x}",
                 received_request_id.service_id,
                 received_request_id.instance_id,
                 received_request_id.client_request_id);
}

/*
 * Function called when a SOME/IP notification is received (event)
 *
 * @param in Pointer to the Fluent Bit input instance
 * @param config Not used
 * @param in_context Pointer to the Fluent Bit context
 */
static int
in_someip_collect_notify(struct flb_input_instance *in,
                         struct flb_config *config, void *in_context)
{
    int ret;
    int keep_reading;
    int someip_result;
    uint8_t val;
    struct flb_someip *context;
    struct some_ip_event event_data;

    (void) config;
    context = (struct flb_someip *) in_context;

    // Pull the byte off of the notify pipe
    ret = flb_pipe_r(context->notify_pipe_fd[0], (char *) &val, sizeof(val));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    flb_plg_debug(in, "collect called");

    /* Pull events from SOME/IP until there aren't any */
    keep_reading = 1;
    while (keep_reading) {
        someip_result = someip_get_next_event(context->someip_client_id, &event_data);
        if (someip_result == SOMEIP_RET_SUCCESS) {
            ret =
                in_someip_generate_someip_event_record(context, &event_data);
        }
        else if (someip_result == SOMEIP_RET_NO_EVENT_AVAILABLE) {
            ret = 0;
            keep_reading = 0;
        }
        else {
            ret = -1;
            keep_reading = 0;
        }
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            keep_reading = 0;
            ret = -1;
        }
    }

    return ret;
}

/*
 * Function called when a SOME/IP RPC related message is available
 *
 * @param in Pointer to the Fluent Bit input instance
 * @param config Not used
 * @param in_context Pointer to the Fluent Bit context
 */
static int
in_someip_collect_rpc(struct flb_input_instance *in,
                      struct flb_config *config, void *in_context)
{
    int ret;
    uint8_t val;
    struct flb_someip *context;

    (void) config;

    context = (struct flb_someip *) in_context;

    // Pull the byte off of the rpc pipe
    ret = flb_pipe_r(context->rpc_pipe_fd[0], (char *) &val, sizeof(val));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    flb_plg_debug(in, "collect rpc called");

    if (val == IN_SOMEIP_SERVICE_AVAILABLE) {
        in_someip_handle_avail_event(context);
    }
    else if (val == IN_SOMEIP_RESPONSE_RECEIVED) {
        in_someip_handle_response_event(context);
    }

    return 0;
}

/*
 * Callback function to initialize SOME/IP plugin
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 * @param data    Unused
 *
 * @return int 0 on success, -1 on failure
 */
static int
in_someip_init(struct flb_input_instance *in,
               struct flb_config *config, void *data)
{
    int ret;
    struct flb_someip *ctx = NULL;
    (void) data;
    (void) config;

    /* Allocate and initialize the configuration */
    ctx = in_someip_config_init(in);
    if (ctx == NULL) {
        return -1;
    }

    if (someip_initialize("in_someip", &(ctx->someip_client_id)) ==
        SOMEIP_RET_FAILURE) {
        flb_plg_error(in, "Could not initialize SOME/IP library");
        in_someip_config_destroy(ctx);
        return -1;
    }

    ctx->log_encoder =
        flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ctx->log_encoder == NULL) {
        flb_plg_error(in, "Could not initialize log encoder");
        someip_shutdown(ctx->someip_client_id);
        in_someip_config_destroy(ctx);
        return -1;
    }

    in_someip_subscribe_for_someip_events(ctx);
    in_someip_request_services(ctx);

    flb_plg_debug(in, "Initialized SOME/IP library");

    flb_input_set_context(in, ctx);

    /* Register an event collector for subscription notifications */
    ret = flb_input_set_collector_event(in, in_someip_collect_notify,
                                        ctx->notify_pipe_fd[0], config);
    if (ret == -1) {
        someip_shutdown(ctx->someip_client_id);
        in_someip_config_destroy(ctx);
        return -1;
    }

    ctx->coll_fd_notify = ret;

    ret =
        flb_input_set_collector_event(in, in_someip_collect_rpc,
                                      ctx->rpc_pipe_fd[0], config);
    if (ret == -1) {
        someip_shutdown(ctx->someip_client_id);
        in_someip_config_destroy(ctx);
        return -1;
    }

    ctx->coll_fd_rpc = ret;

    return 0;
}

/*
 * Callback used by Fluent Bit to pause collection of data
 *
 * @param data Pointer to the plugin context
 * @param config not used
 */
static void in_someip_pause(void *data, struct flb_config *config)
{
    struct flb_someip *ctx = data;
    (void) config;

    /*
     * Pause collectors
     */
    flb_input_collector_pause(ctx->coll_fd_notify, ctx->ins);
    flb_input_collector_pause(ctx->coll_fd_rpc, ctx->ins);
}

/*
 * Callback used by Fluent Bit to resume collection of data
 *
 * @param data Pointer to the plugin context
 * @param config Not used
 */
static void in_someip_resume(void *data, struct flb_config *config)
{
    struct flb_someip *ctx = data;
    (void) config;

    /*
     * Resume collectors
     */
    flb_input_collector_resume(ctx->coll_fd_notify, ctx->ins);
    flb_input_collector_resume(ctx->coll_fd_rpc, ctx->ins);
}

/*
 * Callback used by Fluent Bit when shutting down
 */
static int in_someip_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_someip *ctx = data;

    flb_plg_info(ctx->ins, "Shutting down in_someip");
    someip_shutdown(ctx->someip_client_id);
    if (ctx->log_encoder) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }
    in_someip_config_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[]
    = { {FLB_CONFIG_MAP_CLIST_4, "Event", NULL, FLB_CONFIG_MAP_MULT, FLB_TRUE,
         offsetof(struct flb_someip, events),
         "SOME/IP Event/Field to subscribe. "
         "Format: `Event <service id>,<instance id>,<event id>,<event group 1>,...`"},
{FLB_CONFIG_MAP_CLIST_3, "RPC", NULL, FLB_CONFIG_MAP_MULT, FLB_TRUE,
 offsetof(struct flb_someip, rpcs),
 "RPC to send at start up. "
 "Format: `RPC <service id>,<instance id>,<method id>,<Base64 encoded "
 "payload>`"},
{0}
};

struct flb_input_plugin in_someip_plugin = {.name = "someip",
    .description = "Interact with SOME/IP services as a client",
    .cb_init = in_someip_init,
    .cb_pre_run = NULL,
    .cb_collect = NULL,
    .cb_flush_buf = NULL,
    .config_map = config_map,
    .cb_pause = in_someip_pause,
    .cb_resume = in_someip_resume,
    .cb_exit = in_someip_exit
};
