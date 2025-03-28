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
#ifndef FLB_IN_SOMEIP_H
#define FLB_IN_SOMEIP_H

#include <cfl/cfl.h>
#include <cfl/cfl_list.h>
#include <fluent-bit/flb_input.h>
#include <someip_api.h>
#include <stdint.h>

/*
 * Structure for events that we want to subscribe to
 */
struct in_someip_event_identifier
{
    /* SOME/IP Service ID */
    uint16_t service_id;
    /* SOME/IP Service instance ID */
    uint16_t instance_id;
    /* SOME/IP Event ID */
    uint16_t event_id;
    /* Array of SOME/IP Event Groups */
    uint16_t *event_groups;
    /* Number of Event Groups */
    size_t number_of_event_groups;
    /* Needed to store this in a cfl_list */
    struct cfl_list _head;
};

/*
 * Structure for pending RPC we want to perform
 */
struct in_someip_rpc
{
    /* SOME/IP Service ID */
    uint16_t service_id;
    /* SOME/IP Service instance ID */
    uint16_t instance_id;
    /* SOME/IP Method ID */
    uint16_t method_id;
    /* Length of the request payload */
    size_t payload_len;
    /* Request payload contents */
    uint8_t *payload;

    /* Needed to store this in a cfl_list */
    struct cfl_list _head;
};

/*
 * Structure for RPC that we are waiting for responses
 */
struct in_someip_response
{
    /* Structure with the SOME/IP response data */
    struct some_ip_response response;
    /* Needed to store this in a cfl_list */
    struct cfl_list _head;
};

/*
 * Structure holes the configuration and data for this plugin
 */
struct flb_someip
{
    /* FLB input plugin instance */
    struct flb_input_instance *ins;

    /* Pipe used to communicate when a SOME/IP notification (i.e for SOME/IP event) has
     * been received */
    flb_pipefd_t notify_pipe_fd[2];

    /* Pipe used to communicate when a RPC event has happened */
    flb_pipefd_t rpc_pipe_fd[2];

    /* Configuration */
    struct mk_list *events;
    struct mk_list *rpcs;

    /* SOME/IP client identifier */
    uint16_t someip_client_id;

    /* Holds the SOME/IP events that we are subscribed to */
    struct cfl_list someip_events;

    /* Holds the SOME/IP RPC that we want to perform */
    struct cfl_list someip_pending_rpc;

    /* Holds the SOME/IP RPC where request has been sent and waiting for a response */
    struct cfl_list someip_waiting_response;

    /* Collectors */
    int coll_fd_notify;
    int coll_fd_rpc;

    /* Log Encoder */
    struct flb_log_event_encoder *log_encoder;
};

#endif
