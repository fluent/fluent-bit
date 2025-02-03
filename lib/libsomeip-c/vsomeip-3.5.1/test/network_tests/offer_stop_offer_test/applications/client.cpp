// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>
#include <algorithm>
#include "client.hpp"
#include "service_ids.hpp"

client_t::client_t() :
    vsomeip_utilities::base_logger("CLI", "VSOMEIP SERVICE CONSUMER"),
    vsomeip_app(vsomeip::runtime::get()->create_application("client-sample")) {

    availability_table[SERVICE_ID] = false;
    availability_table[OTHER_SERVICE_ID] = false;
}

client_t::~client_t() {
    stop();
}

bool client_t::init() {
    if (!vsomeip_app->init()) {
        VSOMEIP_ERROR << "Couldn't initialize application";
        return false;
    }

    vsomeip_app->register_message_handler(
            SERVICE_ID, INSTANCE_ID, METHOD_ID,
            std::bind(&client_t::on_message, this, std::placeholders::_1));
    vsomeip_app->register_message_handler(
            OTHER_SERVICE_ID, OTHER_INSTANCE_ID, OTHER_METHOD_ID,
            std::bind(&client_t::on_message, this, std::placeholders::_1));
    vsomeip_app->request_service(SERVICE_ID, INSTANCE_ID);

    vsomeip_app->register_availability_handler(
            SERVICE_ID, INSTANCE_ID,
            std::bind(&client_t::on_availability, this, std::placeholders::_1,
                      std::placeholders::_2, std::placeholders::_3));
    vsomeip_app->register_availability_handler(
            OTHER_SERVICE_ID, OTHER_INSTANCE_ID,
            std::bind(&client_t::on_availability, this, std::placeholders::_1,
                      std::placeholders::_2, std::placeholders::_3));
    vsomeip_app->request_service(OTHER_SERVICE_ID, OTHER_INSTANCE_ID);

    return true;
}

void client_t::start() {
    worker = std::thread([&] { vsomeip_app->start(); });
}

void client_t::stop() {
    vsomeip_app->stop();
    if (worker.joinable()) {
        worker.join();
    }
}

std::future<bool> client_t::request(bool is_tcp, vsomeip::service_t service,
                                    vsomeip::instance_t instance, vsomeip::method_t method) {
    auto promise_response = std::promise<bool>();
    auto future_response = std::future<bool>(promise_response.get_future());

    std::lock_guard<std::mutex> lk(availability_mutex);
    if (availability_table[service]) {
        auto request = vsomeip::runtime::get()->create_request(is_tcp);

        request->set_service(service);
        request->set_instance(instance);
        request->set_method(method);

        // store the pending request, so that we can set the promise later in on_message
        pending_requests.push_back({service, instance, method, std::move(promise_response)});
        vsomeip_app->send(request);

    } else {
        // set the value to false to notify the future that the request was not sent
        promise_response.set_value(false);
    }

    return future_response;
}

bool client_t::is_available() {
    std::lock_guard<std::mutex> lk(availability_mutex);

    for (const auto& availability_entry : availability_table) {
        if (!availability_entry.second) {
            return false;
        }
    }
    return true;
}

void client_t::on_message(const std::shared_ptr<vsomeip::message>& message) {
    std::lock_guard<std::mutex> lk(availability_mutex);

    if (message->get_payload()->get_data()) {
        VSOMEIP_INFO << "client_t::" << __func__ << ": "
                     << static_cast<int>(message->get_payload()->get_data()[0]) << " from 0x"
                     << std::setw(4) << std::setfill('0') << std::hex << message->get_service();
    } else {
        VSOMEIP_WARNING << "client_t::" << __func__ << ": Empty payload for service "
                        << " from 0x" << std::setw(4) << std::setfill('0') << std::hex
                        << message->get_service();
    }

    for (auto it = pending_requests.begin(); it != pending_requests.end(); ++it) {
        if (it->service == message->get_service() && it->instance == message->get_instance()
            && it->method == message->get_method()) {
            // set promise true as request was received and remove the pending_response
            it->promise_response.set_value(true);
            pending_requests.erase(it);
            break;
        }
    }
}

void client_t::on_availability(vsomeip::service_t service, vsomeip::instance_t instance,
                               bool is_available) {
    std::lock_guard<std::mutex> lk(availability_mutex);

    VSOMEIP_INFO << "client_t::" << __func__ << " Service [" << std::setw(4) << std::setfill('0')
                 << std::hex << service << "." << instance << "] is "
                 << (is_available ? "available." : "NOT available.");

    availability_table[service] = is_available;

    // Service became unavailable -> set unblock futures
    if (!is_available) {
        pending_requests.erase(std::remove_if(pending_requests.begin(), pending_requests.end(),
                                              [&](client_request_t& request) {
                                                  bool should_remove = (request.service == service)
                                                          && (request.instance == instance);
                                                  if (should_remove) {
                                                      request.promise_response.set_value(true);
                                                  }
                                                  return should_remove;
                                              }),
                               pending_requests.end());
    }
}
