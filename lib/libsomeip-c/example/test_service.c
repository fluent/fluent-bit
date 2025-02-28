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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "someip_api.h"


static const char* NAME = "Test Service";
static const uint16_t SERVICE_ID     = 4;
static const uint16_t INSTANCE_ID    = 1;
static const uint16_t METHOD_ID      = 1;
static const uint16_t EVENT_ID       = 0x8000U;
static const uint16_t EVENT_GROUP_ID = 1;

static uint16_t client_id = 0;

/*
 * Function to handle callback when a request is received.
 * @param request_ptr Pointer to the structure that has the request details.
 */
void HandleRequest(void*, struct some_ip_request *request_ptr) {
    static const char* response = "This is the response to the request";
    int ret = 0;
    if (request_ptr == NULL) {
        return;
    }
    printf("Received request (method = %d)\n", request_ptr->method_id);
    printf("Payload length = %ld\n", request_ptr->payload_len);

    /* Normal service would Parse the request and perform/initiate some actions on it*/
    /* For this example just send back a canned response */
    
    ret = someip_send_response(client_id, request_ptr->request_id.client_request_id,
                               (void*)response, strlen(response));
    if (ret != SOMEIP_RET_SUCCESS) {
        printf("Failed to send response: %d\n", ret);
    }
}

/*
 * Function to initialize the test service with the SOME/IP library.
 * @return 0 on success, -1 on failure.
 */
int Initialize() {
    int ret = someip_initialize(NAME, &client_id);
    if (ret != SOMEIP_RET_SUCCESS) {
        printf("Failed to initialize SOME/IP: %d\n", ret);
        return -1;
    }

    /* Register Request Handler */
    ret = someip_register_request_handler(client_id, SERVICE_ID, INSTANCE_ID,
                                          METHOD_ID, NULL, HandleRequest);

    if (ret != SOMEIP_RET_SUCCESS) {
        printf("Failed to register request handler: %d\n", ret);
        someip_shutdown(client_id);
        return -1;
    }

    /* Offer Event */
    ret = someip_offer_event(client_id, SERVICE_ID, INSTANCE_ID, EVENT_ID, (uint16_t*)&EVENT_GROUP_ID, 1);
    if (ret != SOMEIP_RET_SUCCESS) {
        printf("Failed to Offer Event: %d\n", ret);
        someip_shutdown(client_id);
        return -1;
    }

    /* Offer Service */
    ret = someip_offer_service(client_id, SERVICE_ID, INSTANCE_ID);
    if (ret != SOMEIP_RET_SUCCESS) {
        printf("Failed to Offer Service: %d\n", ret);
        someip_shutdown(client_id);
        return -1;
    }

    return 0;
}

void Teardown() {
    someip_shutdown(client_id);
}

void SendEvent(const int num) {
    const char* base_msg = "Event Number ";
    char buffer[128];
    int ret = 0;
    strcpy(buffer, base_msg);
    sprintf(buffer + strlen(base_msg), "%d", num);

    printf("Sending event with message %s\n", buffer);

    ret = someip_send_event(client_id, SERVICE_ID, INSTANCE_ID, EVENT_ID,
                            buffer, strlen(buffer));
    if (ret != SOMEIP_RET_SUCCESS) {
        printf ("Failed to send event, %d\n", ret);
    }
}


int main() {
    int num_events = 10;
    if (Initialize() != 0) {
        return EXIT_FAILURE;
    }
    

    for (int i = 0; i <= num_events; ++i) {
        SendEvent(i);
        sleep(2);
    }

    Teardown();
    return EXIT_SUCCESS;
}