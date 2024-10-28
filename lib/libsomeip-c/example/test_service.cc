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
#include "someip_api.h"
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <sstream>
#include <thread>

/* Class declaration */
class TestService {
public:
    bool Initialize();
    void Teardown();
    void HandleRequest(const struct some_ip_request* request_ptr);
    void SendEvent(const int num);
private:
    uint16_t client_id_{0};
};

namespace {
    constexpr auto NAME               = "Test Service";
    constexpr uint16_t SERVICE_ID     = 4;
    constexpr uint16_t INSTANCE_ID    = 1;
    constexpr uint16_t METHOD_ID      = 1;
    constexpr uint16_t EVENT_ID       = 0x8000U;
    constexpr uint16_t EVENT_GROUP_ID = 1;

    void RequestCallback(void* cookie, struct some_ip_request* request_ptr) {
        if (cookie == nullptr) {
            return;
        }
        auto service_pointer{static_cast<TestService*>(cookie)};
        service_pointer->HandleRequest(request_ptr);
    }
}

bool TestService::Initialize() {
    auto ret = someip_initialize(NAME, &client_id_);
    if (ret != SOMEIP_RET_SUCCESS) {
        std::cout << "Failed to initialize SOME/IP: " << ret << std::endl;
        return false;
    }

    /* Register Request Handler */
    auto request_handler{[this](struct some_ip_request* request_ptr) {
        HandleRequest(request_ptr);
    }};
    ret = someip_register_request_handler(client_id_, SERVICE_ID, INSTANCE_ID,
                                          METHOD_ID, this, RequestCallback);

    if (ret != SOMEIP_RET_SUCCESS) {
        std::cout << "Failed to register request handler: " << ret << std::endl;
        someip_shutdown(client_id_);
        return false;
    }

    /* Offer Event */
    ret = someip_offer_event(client_id_, SERVICE_ID, INSTANCE_ID, EVENT_ID, const_cast<uint16_t*>(&EVENT_GROUP_ID), 1);
    if (ret != SOMEIP_RET_SUCCESS) {
        std::cout << "Failed to Offer Event: " << ret << std::endl;
        someip_shutdown(client_id_);
        return false;
    }

    /* Offer Service */
    ret = someip_offer_service(client_id_, SERVICE_ID, INSTANCE_ID);
    if (ret != SOMEIP_RET_SUCCESS) {
        std::cout << "Failed to Offer Service: " << ret << std::endl;
        someip_shutdown(client_id_);
        return false;
    }

    return true;
}

void TestService::Teardown() {
    someip_shutdown(client_id_);
}

void TestService::HandleRequest(const struct some_ip_request* request_ptr) {
    if (request_ptr == nullptr) {
        return;
    }
    std::cout << "Received request (method = " << request_ptr->method_id << ")" << std::endl;
    std::cout << "Payload length = " << request_ptr->payload_len << std::endl;

    /* Normal service would Parse the request and perform/initiate some actions on it*/
    /* For this example just send back a canned response */
    auto response{"This is the response to the request"};
    const auto ret = someip_send_response(client_id_, request_ptr->request_id.client_request_id,
                                          const_cast<char*>(response), strlen(response));
    if (ret != SOMEIP_RET_SUCCESS) {
        std::cout << "Failed to send response: %d" << ret << std::endl;
    }
}

void TestService::SendEvent(const int num) {
    std::stringstream ss;
    ss << "Event Number " << num;
    const auto message = ss.str();

    auto ret = someip_send_event(client_id_, SERVICE_ID, INSTANCE_ID, EVENT_ID,
    message.data(), message.size());
}


int main() {
    TestService service;
    if (!service.Initialize()) {
        return EXIT_FAILURE;
    }
    
    auto num_events{10};

    for (auto i = 0; i < num_events; ++i) {
        service.SendEvent(i);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    service.Teardown();
    return EXIT_SUCCESS;
}