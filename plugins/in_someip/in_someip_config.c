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
#include "in_someip_config.h"

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_input_plugin.h>

/*
 * Function to add an SOME/IP event to the cfl_list
 * @param ctx Pointer to the plugin context
 * @param service SOME/IP Service ID
 * @param service SOME/IP Service instance ID
 * @param event SOME/IP event ID
 * @param num_event_groups Number of event groups
 * @param prev Pointer to the previous configuration list item
 * @param mv Pointer to the configuration map
 *
 * @return 0 on SUCCESS, -1 on failure
 */
static int
in_someip_add_event(struct flb_someip *ctx, uint16_t service,
                    uint16_t instance, uint16_t event,
                    const size_t num_event_groups,
                    struct mk_list *prev, struct flb_config_map_val *mv)
{
    struct in_someip_event_identifier *an_event;
    struct flb_slist_entry *event_group;
    int i;

    flb_plg_trace(ctx->ins,
                  "Adding event {%d, %d, %d} to the subscription list",
                  service, instance, event);
    an_event = flb_malloc(sizeof(struct in_someip_event_identifier));
    if (an_event == NULL) {
        flb_errno();
        return -1;
    }
    an_event->service_id = service;
    an_event->instance_id = instance;
    an_event->event_id = event;

    /* Allocate memory to store the event group list */
    an_event->event_groups = flb_malloc(num_event_groups * sizeof(uint16_t));
    if (an_event->event_groups == NULL) {
        flb_errno();
        flb_free(an_event);
        return -1;
    }
    /* Populate the event group array */
    for (i = 0; i < num_event_groups; ++i) {
        event_group =
            mk_list_entry_next(prev, struct flb_slist_entry, _head,
                               mv->val.list);
        if (event_group != NULL) {
            an_event->event_groups[i] = atoi(event_group->str);
            flb_plg_trace(ctx->ins,
                          "Including event group {%d} for the event",
                          an_event->event_groups[i]);
            prev = &event_group->_head;
        }
    }
    an_event->number_of_event_groups = num_event_groups;
    cfl_list_add(&(an_event->_head), &ctx->someip_events);
    return 0;
}

/*
 * Function to add an SOME/IP RPC to the cfl_list
 *
 * @param ctx Pointer to the plugin context
 * @param service SOME/IP Service ID
 * @param service SOME/IP Service instance ID
 * @param event SOME/IP Method ID
 * @param message Message to send in the request
 *
 * @return 0 on SUCCESS, -1 on failure
 */
static int
in_someip_add_rpc(struct flb_someip *ctx, uint16_t service,
                  uint16_t instance, uint16_t method, flb_sds_t message)
{
    struct in_someip_rpc *an_rpc;
    flb_sds_t decoded_buffer;
    size_t decoded_len;
    size_t encoded_len;

    flb_plg_trace(ctx->ins, "Adding RPC {%d, %d, %d} to the pending list",
                  service, instance, method);
    an_rpc = flb_malloc(sizeof(struct in_someip_rpc));
    if (an_rpc == NULL) {
        flb_errno();
        return -1;
    }
    an_rpc->service_id = service;
    an_rpc->instance_id = instance;
    an_rpc->method_id = method;
    encoded_len = flb_sds_len(message);
    if (encoded_len > 0) {
        decoded_buffer = flb_sds_create_size(encoded_len);
        if (0
            != flb_base64_decode((unsigned char *) decoded_buffer,
                                 encoded_len, &decoded_len,
                                 (unsigned char *) message, encoded_len)) {
            flb_plg_warn(ctx->ins,
                         "Failed to decode RPC payload. Ignoring RPC.");
            flb_free(an_rpc);
            return 0;
        }
        an_rpc->payload_len = decoded_len;
        an_rpc->payload = flb_malloc(decoded_len);
        if (an_rpc->payload == NULL) {
            flb_errno();
            flb_free(an_rpc);
            return -1;
        }
        memcpy(an_rpc->payload, decoded_buffer, decoded_len);
        flb_sds_destroy(decoded_buffer);
    }
    else {
        an_rpc->payload_len = 0;
        an_rpc->payload = NULL;
    }

    cfl_list_add(&(an_rpc->_head), &ctx->someip_pending_rpc);
    return 0;
}

/*
 * Function to delete all SOME/IP events in the plugin context
 *
 * @param ctx Pointer to the plugin context
 */
static void in_someip_delete_all_events(struct flb_someip *ctx)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct in_someip_event_identifier *an_event;

    cfl_list_foreach_safe(head, tmp, &(ctx->someip_events)) {
        an_event =
            cfl_list_entry(head, struct in_someip_event_identifier, _head);
        if (!cfl_list_entry_is_orphan(&an_event->_head)) {
            cfl_list_del(&an_event->_head);
        }

        if (an_event->event_groups != NULL) {
            flb_free(an_event->event_groups);
            an_event->event_groups = NULL;
        }

        flb_free(an_event);
    }
}

/*
 * Function to delete all pending SOME/IP RPC in the plugin context
 *
 * @param ctx Pointer to the plugin context
 */
static void in_someip_delete_all_rpc(struct flb_someip *ctx)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct in_someip_rpc *rpc;

    cfl_list_foreach_safe(head, tmp, &(ctx->someip_pending_rpc)) {
        rpc = cfl_list_entry(head, struct in_someip_rpc, _head);
        if (!cfl_list_entry_is_orphan(&rpc->_head)) {
            cfl_list_del(&rpc->_head);
        }

        if (rpc->payload != NULL) {
            flb_free(rpc->payload);
        }
        flb_free(rpc);
    }
}

/*
 * Function to delete all SOME/IP RPC waiting for responses in the plugin context
 *
 * @param ctx Pointer to the plugin context
 */
static void in_someip_delete_all_responses(struct flb_someip *ctx)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct in_someip_response *response;

    cfl_list_foreach_safe(head, tmp, &(ctx->someip_waiting_response)) {
        response = cfl_list_entry(head, struct in_someip_response, _head);
        if (!cfl_list_entry_is_orphan(&response->_head)) {
            cfl_list_del(&response->_head);
        }

        flb_free(response);
    }
}

/*
 * Loads the SOME/IP plugin configuration
 *
 * @param ins Pointer to the plugin input instance
 *
 * @return Allocated SOME/IP plugin configuration structure
 */
struct flb_someip *in_someip_config_init(struct flb_input_instance *ins)
{
    int ret;
    struct flb_someip *ctx;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *service = NULL;
    struct flb_slist_entry *instance = NULL;
    struct flb_slist_entry *method = NULL;
    struct flb_slist_entry *message = NULL;
    flb_sds_t rpc_message;
    int destroy_rpc_message;
    int number_of_events;
    int event_list_size;
    int number_of_event_groups;
    int num_rpc_params;

    ctx = flb_calloc(1, sizeof(struct flb_someip));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Create the notification pipes */
    ret = flb_pipe_create(ctx->notify_pipe_fd);
    if (ret == -1) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    /* Create the rpc pipes */
    ret = flb_pipe_create(ctx->rpc_pipe_fd);
    if (ret == -1) {
        flb_errno();
        flb_pipe_destroy(ctx->notify_pipe_fd);
        flb_free(ctx);
        return NULL;
    }

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_pipe_destroy(ctx->notify_pipe_fd);
        flb_pipe_destroy(ctx->rpc_pipe_fd);
        flb_free(ctx);
        return NULL;
    }

    /* Initialize the various list */
    cfl_list_init(&(ctx->someip_events));
    cfl_list_init(&(ctx->someip_pending_rpc));
    cfl_list_init(&(ctx->someip_waiting_response));

    /* Check for pre-configured events that we want to subscribe to */
    number_of_events = mk_list_size(ctx->events);
    if (ctx->events && number_of_events > 0) {
        flb_plg_info(ctx->ins, "Received %d configured events",
                     number_of_events);
        flb_config_map_foreach(head, mv, ctx->events) {
            event_list_size = mk_list_size(mv->val.list);
            flb_plg_debug(ctx->ins, "Number of parameters for event = %d",
                          event_list_size);

            service =
                mk_list_entry_first(mv->val.list, struct flb_slist_entry,
                                    _head);

            instance =
                mk_list_entry_next(&service->_head, struct flb_slist_entry,
                                   _head, mv->val.list);

            method =
                mk_list_entry_next(&instance->_head, struct flb_slist_entry,
                                   _head, mv->val.list);

            if (service->str != NULL && instance->str != NULL
                && method->str != NULL) {

                /* Minimum numbers should be 4 (service, instance, event, event group,...) */
                number_of_event_groups = (event_list_size - 3);

                if (0 !=
                    in_someip_add_event(ctx, atoi(service->str),
                                        atoi(instance->str),
                                        atoi(method->str),
                                        number_of_event_groups,
                                        &(method->_head), mv)) {
                    flb_plg_warn(ctx->ins, "Unable to add event.");
                }
            }
        }
    }
    else {
        flb_plg_info(ctx->ins, "No events configured.");
    }

    // Create a dummy pending RPC
    if (ctx->rpcs && mk_list_size(ctx->rpcs) > 0) {
        flb_plg_info(ctx->ins, "Received %d configured RPCs",
                     mk_list_size(ctx->rpcs));
        flb_config_map_foreach(head, mv, ctx->rpcs) {
            num_rpc_params = mk_list_size(mv->val.list);
            flb_plg_debug(ctx->ins, "RPC with %d params", num_rpc_params);
            service =
                mk_list_entry_first(mv->val.list, struct flb_slist_entry,
                                    _head);

            instance =
                mk_list_entry_next(&service->_head, struct flb_slist_entry,
                                   _head, mv->val.list);

            method =
                mk_list_entry_next(&instance->_head, struct flb_slist_entry,
                                   _head, mv->val.list);

            if (num_rpc_params > 3) {
                message =   
                    mk_list_entry_last(mv->val.list, struct flb_slist_entry,
                                       _head);
                rpc_message = message->str;
                destroy_rpc_message = 0;
            }
            else {
                rpc_message = flb_sds_create("");
                destroy_rpc_message = 1;
            }

            if (service->str != NULL && instance->str != NULL
                && method->str != NULL) {
                if (0 !=
                    in_someip_add_rpc(ctx, atoi(service->str),
                                      atoi(instance->str), atoi(method->str),
                                      rpc_message)) {
                    flb_plg_warn(ctx->ins, "Unable to add RPC.");
                }
            }
            if (destroy_rpc_message) {
                flb_sds_destroy(rpc_message);
            }
        }
    }
    else {
        flb_plg_info(ctx->ins, "No RPC configured.");
    }
    return ctx;
}

/*
 * Function to destroy SOME/IP plugin configuration
 *
 * @param config  Pointer to flb_someip
 *
 * @return int 0
 */
int in_someip_config_destroy(struct flb_someip *config)
{
    flb_pipe_destroy(config->notify_pipe_fd);
    flb_pipe_destroy(config->rpc_pipe_fd);
    in_someip_delete_all_events(config);
    in_someip_delete_all_rpc(config);
    in_someip_delete_all_responses(config);
    flb_free(config);
    return 0;
}
