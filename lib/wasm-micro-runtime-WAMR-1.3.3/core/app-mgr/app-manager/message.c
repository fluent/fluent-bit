/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "app_manager.h"
#include "app_manager_host.h"
#include "event.h"
#include "bi-inc/attr_container.h"
#include "coap_ext.h"

#if 0
bool send_coap_packet_to_host(coap_packet_t * packet)
{
    int size;
    uint8_t *buf;

    size = coap_serialize_message_tcp(&packet, &buf);
    if (!buf || size == 0)
    return false;

    app_manager_host_send_msg(buf, size);
    APP_MGR_FREE(buf);

    return true;
}
#endif

bool
send_request_to_host(request_t *msg)
{
    if (COAP_EVENT == msg->action && !event_is_registered(msg->url)) {
        app_manager_printf("Event is not registered\n");
        return false;
    }

    int size;
    char *packet = pack_request(msg, &size);
    if (packet == NULL)
        return false;

    app_manager_host_send_msg(REQUEST_PACKET, packet, size);

    free_req_resp_packet(packet);

    return true;
}

bool
send_response_to_host(response_t *response)
{
    int size;
    char *packet = pack_response(response, &size);
    if (packet == NULL)
        return false;

    app_manager_host_send_msg(RESPONSE_PACKET, packet, size);

    free_req_resp_packet(packet);

    return true;
}

bool
send_error_response_to_host(int mid, int status, const char *msg)
{
    int payload_len = 0;
    attr_container_t *payload = NULL;
    response_t response[1] = { 0 };

    if (msg) {
        payload = attr_container_create("");
        if (payload) {
            attr_container_set_string(&payload, "error message", msg);
            payload_len = attr_container_get_serialize_length(payload);
        }
    }

    set_response(response, status, FMT_ATTR_CONTAINER, (const char *)payload,
                 payload_len);
    response->mid = mid;

    send_response_to_host(response);

    if (payload)
        attr_container_destroy(payload);
    return true;
}
